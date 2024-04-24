use hex::FromHex;
use near_bigint::U256;
use near_groth16_verifier::G1Point;
use near_groth16_verifier::G2Point;
use near_groth16_verifier::Proof;
use near_sdk::json_types::Base64VecU8;
use near_sdk::json_types::U128;
use near_sdk::{Gas, NearToken};
use near_workspaces::{Account, Contract, DevNetwork, Worker};
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use serde_json::json;
use serde_json::Value;

const VERIFIER_DATA: &str =
    include_str!("../../../plonky2-reputation/reputation_proof.verify.json");
const PROOF: &str = include_str!("../../../plonky2-reputation/reputation_proof.json");

async fn init(
    worker: &Worker<impl DevNetwork>,
    initial_balance: U128,
    arguments: serde_json::Value,
) -> anyhow::Result<(Contract, Account)> {
    let contract = worker
        .dev_deploy(
            &include_bytes!("../../../target/near/testing_contract/testing_contract.wasm").to_vec(),
        )
        .await?;

    let res = contract
        .call("new")
        .args_json(arguments)
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);
    println!("{:?}", res.logs());

    let alice = contract
        .as_account()
        .create_subaccount("alice")
        .initial_balance(NearToken::from_near(10))
        .transact()
        .await?
        .into_result()?;

    return Ok((contract, alice));
}

fn parse_g1_point(point_data: &serde_json::Value) -> G1Point {
    G1Point {
        x: U256::from_dec_str(point_data["X"].as_str().unwrap()).unwrap(),
        y: U256::from_dec_str(point_data["Y"].as_str().unwrap()).unwrap(),
    }
}

fn parse_g2_point(point_data: &serde_json::Value) -> G2Point {
    G2Point {
        x: [
            U256::from_dec_str(point_data["X"]["A0"].as_str().unwrap()).unwrap(),
            U256::from_dec_str(point_data["X"]["A1"].as_str().unwrap()).unwrap(),
        ],
        y: [
            U256::from_dec_str(point_data["Y"]["A0"].as_str().unwrap()).unwrap(),
            U256::from_dec_str(point_data["Y"]["A1"].as_str().unwrap()).unwrap(),
        ],
    }
}

#[tokio::test]
async fn test_groth() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;

    let vk_json: &str = include_str!("../../../gnark-plonky2-verifier/verification_key.json");
    let vk_data: serde_json::Value =
        serde_json::from_str(&vk_json).expect("Failed to parse vk.json");
    let alfa1 = parse_g1_point(&vk_data["G1"]["Alpha"]);
    let beta2 = parse_g2_point(&vk_data["G2"]["Beta"]);
    let gamma2 = parse_g2_point(&vk_data["G2"]["Gamma"]);
    let delta2 = parse_g2_point(&vk_data["G2"]["Delta"]);

    let ic: Vec<G1Point> = vk_data["G1"]["K"]
        .as_array()
        .unwrap()
        .iter()
        .map(|point| parse_g1_point(point))
        .collect();

    let (contract, alice) = init(
        &worker,
        NearToken::from_near(10).as_yoctonear().into(),
        json!({
            "alfa1": alfa1,
            "beta2": beta2,
            "gamma2": gamma2,
            "delta2": delta2,
            "ic": ic,
        }),
    )
    .await
    .unwrap();
    let mut proof_json = include_str!("../../../gnark-plonky2-verifier/proof.json");
    let proof_data: serde_json::Value =
        serde_json::from_str(&proof_json).expect("Failed to parse proof.json");

    let a = parse_g1_point(&proof_data["Ar"]);
    let b = parse_g2_point(&proof_data["Bs"]);
    let c = parse_g1_point(&proof_data["Krs"]);

    let commitments = proof_data["Commitments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|point| parse_g1_point(point))
        .collect();

    let proof = Proof {
        a,
        b,
        c,
        commitments,
    };

    let witness_json = include_str!("../../../gnark-plonky2-verifier/pubwitness.json");
    let witness_data: serde_json::Value =
        serde_json::from_str(&witness_json).expect("Failed to parse witness.json");
    let public_inputs: Vec<_> = witness_data["PublicInputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            if input["Limb"].is_string() {
                input["Limb"].as_str().unwrap().to_string()
            } else {
                input["Limb"].as_u64().unwrap().to_string()
            }
        })
        .chain([
            "14025927619038021320133802710314150021159084526285453179597508431688164562731"
                .to_string(),
        ])
        .collect();

    println!("{:?}", public_inputs);

    let res = contract
        .call("verify_proof")
        .args_json(json!({
            "proof": proof,
            "public_inputs": public_inputs
        }))
        .gas(Gas::from_tgas(300))
        .transact()
        .await
        .unwrap();
    println!("{:?}", res.logs());
    assert!(res.logs()[0].starts_with("verify: true"));
    println!("{:?}", res.receipt_failures());
    Ok(())
}
