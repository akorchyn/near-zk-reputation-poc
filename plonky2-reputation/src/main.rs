#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use anyhow::Result;
use clap::Parser;
use ed25519_dalek::{PublicKey, SecretKey};
use itertools::Itertools;
use log::{Level, LevelFilter};
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;
use plonky2_reputation::gadgets::reputation_list::{array_to_bits, ReputationSet};
use plonky2_reputation::{Cbn128, C, D, F};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value = "./output")]
    directory: PathBuf,

    #[arg(short, long)]
    private: String,

    #[arg(short, long)]
    topic_id: u64,

    #[arg(short, long)]
    expected_rep: u32,

    #[arg(short, long, default_value = "./merkle_path.json")]
    merkle_tree: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct VerificationData {
    pub common: String,
    pub verifier: String,
}

fn save_data(data: String, path: &str) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data.as_bytes())?;
    Ok(())
}

fn load_merkle_tree(
    path: PathBuf,
    private_key: &[u8],
) -> Result<(ReputationSet, Vec<([u8; 32], u32)>)> {
    let data = if path.exists() {
        log::info!("Loading merkle tree from {}", path.to_str().unwrap());
        let file = File::open(path)?;
        let data: Vec<([u8; 32], u32)> = serde_json::from_reader(file)?;
        data
    } else {
        log::info!("File not found generating new merkle tree");
        let mut csprng = OsRng;
        let n = (1 << 15) - 1;
        let mut private_keys: Vec<_> = (0..n)
            .map(|_| ed25519_dalek::SecretKey::generate(&mut csprng))
            .collect();
        private_keys.push(ed25519_dalek::SecretKey::from_bytes(private_key)?);

        let data: Vec<_> = private_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let pk = ed25519_dalek::PublicKey::from(sk).to_bytes();
                let reputation = i as u32;

                (pk, reputation)
            })
            .collect();

        println!("Generated merkle tree with {} leaves", data.len());
        println!("Saving merkle tree to {}", path.to_str().unwrap());
        let mut file = File::create(path)?;
        file.write_all(serde_json::to_string(&data)?.as_bytes())?;

        data
    };

    let leaves = data
        .iter()
        .map(|(pubkey, reputation)| {
            let hash_data: Vec<F> = array_to_bits(pubkey)
                .into_iter()
                .map(F::from_bool)
                .chain([F::from_canonical_u32(*reputation)])
                .collect();

            PoseidonHash::hash_no_pad(&hash_data).elements.to_vec()
        })
        .collect_vec();

    Ok((ReputationSet(MerkleTree::new(leaves, 0)), data))
}

pub fn recursive_proof<F, C, InnerC, const D: usize>(
    inner_common: &CommonCircuitData<F, D>,
    inner_verifier: &VerifierOnlyCircuitData<InnerC, D>,
    inner_proof: &ProofWithPublicInputs<F, InnerC, D>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let proof_with_pis_target = builder.add_virtual_proof_with_pis(inner_common);
    builder.register_public_inputs(&proof_with_pis_target.public_inputs);
    let verifier_circuit_target = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(inner_common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&proof_with_pis_target, inner_proof);
    pw.set_cap_target(
        &verifier_circuit_target.constants_sigmas_cap,
        &inner_verifier.constants_sigmas_cap,
    );
    pw.set_hash_target(
        verifier_circuit_target.circuit_digest,
        inner_verifier.circuit_digest,
    );
    builder.verify_proof::<InnerC>(
        &proof_with_pis_target,
        &verifier_circuit_target,
        inner_common,
    );

    let data_new = builder.build::<C>();
    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof_new: ProofWithPublicInputs<F, C, D> =
        prove(&data_new.prover_only, &data_new.common, pw, &mut timing)?;
    timing.print();

    Ok((data_new, proof_new))
}

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Info);
    builder.try_init()?;

    let args = Cli::parse();

    std::fs::create_dir_all(&args.directory)?;

    let mut config = CircuitConfig::wide_ecc_config();
    config.zero_knowledge = true;

    let private = SecretKey::from_bytes(&hex::decode(args.private)?)?;
    let private_bytes = private.to_bytes();
    let (rep_set, tree) = load_merkle_tree(args.merkle_tree, &private_bytes)?;
    let public_key = PublicKey::from(&private).to_bytes();

    let leaf_index = tree
        .iter()
        .position(|(pk, _)| pk == &public_key)
        .ok_or(anyhow::anyhow!(
            "Merkle tree doesn't contain derived public key"
        ))?;
    let reputation = tree[leaf_index].1;

    println!("Found public key with reputation {}", reputation);

    let (proof, verification) = rep_set.prove_reputation(
        config,
        &private_bytes,
        args.topic_id,
        leaf_index,
        reputation,
        args.expected_rep,
    )?;

    let proof = ReputationSet::proof_with_public_inputs(proof);
    let (cd, proof) = recursive_proof::<F, Cbn128, C, D>(
        &verification.common,
        &verification.verifier_only,
        &proof,
    )?;

    save_data(
        serde_json::to_string_pretty(&proof)?,
        args.directory
            .join("proof_with_public_inputs.json")
            .to_str()
            .unwrap(),
    )?;

    save_data(
        serde_json::to_string_pretty(&cd.verifier_only)?,
        args.directory
            .join("verifier_only_circuit_data.json")
            .to_str()
            .unwrap(),
    )?;

    save_data(
        serde_json::to_string_pretty(&cd.common)?,
        args.directory
            .join("common_circuit_data.json")
            .to_str()
            .unwrap(),
    )?;

    // save_data(
    //     serde_json::to_string(&VerificationData {
    //         common: base64::encode(
    //             verification
    //                 .common
    //                 .to_bytes(&Ed25519GateSerializer)
    //                 .unwrap(),
    //         ),
    //         verifier: base64::encode(verification.to_bytes(&Ed25519GateSerializer).unwrap()),
    //     })?,
    //     args.output_path
    //         .with_extension("verify.json")
    //         .to_str()
    //         .unwrap(),
    // )?;

    Ok(())
}
