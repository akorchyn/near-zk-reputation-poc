#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use anyhow::Result;
use clap::Parser;
use ed25519_dalek::{PublicKey, SecretKey};
use itertools::Itertools;
use log::{info, LevelFilter};
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::plonk::proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs};
use plonky2_ed25519::serialization::Ed25519GateSerializer;
use plonky2_sha512::gadgets::sha512::array_to_bits;
use plonky_reputation::gadgets::reputation_list::ReputationSet;
use plonky_reputation::F;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value = "./reputation_proof.json")]
    output_path: PathBuf,

    #[arg(short, long)]
    private: String,

    #[arg(short, long)]
    topic_id: u64,

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

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Info);
    builder.try_init()?;

    let args = Cli::parse();

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
    )?;

    save_data(
        serde_json::to_string(&proof)?,
        args.output_path.to_str().unwrap(),
    )?;

    save_data(
        serde_json::to_string(&VerificationData {
            common: base64::encode(
                verification
                    .common
                    .to_bytes(&Ed25519GateSerializer)
                    .unwrap(),
            ),
            verifier: base64::encode(verification.to_bytes(&Ed25519GateSerializer).unwrap()),
        })?,
        args.output_path
            .with_extension("verify.json")
            .to_str()
            .unwrap(),
    )?;

    ReputationSet::verify(verification, proof)?;

    Ok(())
}
