#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use anyhow::Result;
use clap::Parser;
use core::num::ParseIntError;
use log::{info, Level, LevelFilter};
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget,
    VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs};
use plonky2::plonk::prover::prove;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2_ed25519::serialization::Ed25519GateSerializer;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use plonky_reputation::gadgets::private_to_public::{fill_circuits, make_verify_circuits};
use plonky_reputation::{C, D, F};

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

fn prove_ed25519<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    config: &CircuitConfig,
    pub_key: &[u8],
    private_key: &[u8],
) -> Result<ProofTuple<F, C, D>>
where
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    let targets = make_verify_circuits(&mut builder);
    let mut pw = PartialWitness::new();
    fill_circuits::<F, D>(&mut pw, pub_key, private_key, &targets);

    println!(
        "Constructing inner proof with {} gates",
        builder.num_gates()
    );
    let data = builder.build::<C>();

    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Info);
    data.verify(proof.clone()).expect("verify error");
    timing.print();

    // test_serialization(&proof, &data.verifier_only, &data.common)?;
    Ok((proof, data.verifier_only, data.common))
}

fn recursive_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inner: &ProofTuple<F, InnerC, D>,
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
) -> Result<ProofTuple<F, C, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>,
{
    let (inner_proof, inner_vd, inner_cd) = inner;
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    let pt = builder.add_virtual_proof_with_pis(inner_cd);
    pw.set_proof_with_pis_target(&pt, inner_proof);

    let inner_data = builder.add_virtual_verifier_data(inner_cd.config.fri_config.cap_height);
    pw.set_verifier_data_target(&inner_data, inner_vd);

    builder.verify_proof::<InnerC>(&pt, &inner_data, inner_cd);
    builder.print_gate_counts(0);

    if let Some(min_degree_bits) = min_degree_bits {
        // We don't want to pad all the way up to 2^min_degree_bits, as the builder will
        // add a few special gates afterward. So just pad to 2^(min_degree_bits
        // - 1) + 1. Then the builder will pad to the next power of two,
        // 2^min_degree_bits.
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    let data = builder.build::<C>();

    let mut timing = TimingTree::new("prove", Level::Info);
    let proof = prove::<F, C, D>(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    let mut timing = TimingTree::new("verify", Level::Info);
    timed!(timing, "verify proof", data.verify(proof.clone())?);
    timing.print();

    Ok((proof, data.verifier_only, data.common))
}

fn benchmark() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let config = CircuitConfig::standard_recursion_config();

    let proof1 = prove_ed25519(&config, &PUBLIC, &PRIVATE).expect("prove error 1");
    // let proof2 = prove_ed25519(
    //     SAMPLE_MSG2.as_bytes(),
    //     SAMPLE_SIG2.as_slice(),
    //     SAMPLE_PK1.as_slice(),
    // )
    // .expect("prove error 2");

    // // Recursively verify the proof
    let middle = recursive_proof::<F, C, C, D>(&proof1, &config, None)?;
    let (_, _, cd) = &middle;
    info!(
        "Single recursion proof degree {} = 2^{}",
        cd.degree(),
        cd.degree_bits()
    );
    Ok(())
}

/// Test serialization and print some size info.
fn test_serialization<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    proof: &ProofWithPublicInputs<F, C, D>,
    vd: &VerifierOnlyCircuitData<C, D>,
    cd: &CommonCircuitData<F, D>,
) -> Result<()>
where
    [(); C::Hasher::HASH_SIZE]:,
{
    let proof_bytes = proof.to_bytes();
    info!("Proof length: {} bytes", proof_bytes.len());
    let proof_from_bytes = ProofWithPublicInputs::from_bytes(proof_bytes, cd)?;
    assert_eq!(proof, &proof_from_bytes);

    let now = std::time::Instant::now();
    let compressed_proof = proof.clone().compress(&vd.circuit_digest, cd)?;
    let decompressed_compressed_proof = compressed_proof
        .clone()
        .decompress(&vd.circuit_digest, cd)?;
    info!("{:.4}s to compress proof", now.elapsed().as_secs_f64());
    assert_eq!(proof, &decompressed_compressed_proof);

    let compressed_proof_bytes = compressed_proof.to_bytes();
    info!(
        "Compressed proof length: {} bytes",
        compressed_proof_bytes.len()
    );
    let compressed_proof_from_bytes =
        CompressedProofWithPublicInputs::from_bytes(compressed_proof_bytes, cd)?;
    assert_eq!(compressed_proof, compressed_proof_from_bytes);

    Ok(())
}

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value_t = 0)]
    benchmark: u8,
    #[arg(short, long, default_value = "./ed25519.proof")]
    output_path: PathBuf,
    #[arg(short, long)]
    pk: Option<String>,
    #[arg(short, long)]
    private: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct VerificationData {
    pub common: String,
    pub verifier: String,
}

#[derive(Serialize, Deserialize)]
struct ProofData {
    pub proof: String,
}

fn save_data(data: String, path: &str) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data.as_bytes())?;
    Ok(())
}

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Info);
    builder.try_init()?;

    let args = Cli::parse();
    if args.benchmark == 1 {
        // Run the benchmark
        benchmark()
    } else {
        if args.pk.is_none() || args.private.is_none() {
            println!("The required arguments were not provided: --pk PUBLIC_KEY_IN_HEX  --private PRIVATE_IN_HEX");
            return Ok(());
        }

        let mut config = CircuitConfig::wide_ecc_config();
        config.zero_knowledge = true;
        let mut proof = prove_ed25519::<F, C, D>(
            &config,
            hex::decode(args.pk.unwrap())?.as_slice(),
            hex::decode(args.private.unwrap())?.as_slice(),
        )?;
        let mut recursion_config = CircuitConfig::standard_recursion_zk_config();
        recursion_config.zero_knowledge = true;

        let mut length_prev = proof.0.to_bytes().len();
        println!("Proof length: {} bytes at 1", length_prev);

        for i in 0..10 {
            proof = recursive_proof::<F, C, C, D>(&proof, &recursion_config, None)?;
            let length = proof.0.to_bytes().len();
            println!("Proof length: {} bytes at {}", length, i + 1);

            if length == length_prev {
                break;
            } else {
                length_prev = length;
            }
        }

        let (inner_proof, inner_vd, inner_cd) = proof;

        let inner_proof_bytes = inner_proof.to_bytes();
        let compressed_proof = inner_proof.compress(&inner_vd.circuit_digest, &inner_cd)?;
        let cd_bytes = inner_cd.to_bytes(&Ed25519GateSerializer).unwrap();
        let vd_bytes = inner_vd.to_bytes().unwrap();
        let len2 = inner_proof_bytes.len();

        println!(
            "Compressed proof length: {} bytes",
            compressed_proof.to_bytes().len()
        );

        save_data(
            serde_json::to_string(&ProofData {
                proof: base64::encode(inner_proof_bytes),
            })
            .unwrap(),
            args.output_path.to_str().unwrap(),
        )?;

        save_data(
            serde_json::to_string(&VerificationData {
                common: base64::encode(cd_bytes),
                verifier: base64::encode(vd_bytes),
            })
            .unwrap(),
            args.output_path
                .with_extension(".verify.json")
                .to_str()
                .unwrap(),
        )?;

        Ok(())
    }
}
