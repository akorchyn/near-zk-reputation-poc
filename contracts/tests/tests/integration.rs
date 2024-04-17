use serde_json::json;
use near_workspaces::{Account, Contract, DevNetwork, Worker};
use near_sdk::json_types::Base64VecU8;
use serde::{Deserialize, Serialize};
use near_sdk::{NearToken, Gas};
use near_sdk::json_types::U128;

const VERIFIER_DATA: &str = include_str!("../../../plonky2-reputation/ed25519..verify.json");
const PROOF: &str = include_str!("../../../plonky2-reputation/ed25519.proof");

#[derive(Serialize, Deserialize)]
struct VerificationData {
    pub common: String,
    pub verifier: String,
}

#[derive(Serialize, Deserialize)]
struct ProofData {
    pub proof: String,
}

pub fn verification_data() -> (Base64VecU8, Base64VecU8) {
    let data: VerificationData = serde_json::from_str(VERIFIER_DATA).unwrap();
    let common = Base64VecU8(near_sdk::base64::decode(data.common).unwrap());
    let verifier = Base64VecU8(near_sdk::base64::decode(data.verifier).unwrap());

    return (common, verifier);
}

pub fn proof_data() -> Base64VecU8 {
    let data: ProofData = serde_json::from_str(PROOF).unwrap();
    return Base64VecU8(near_sdk::base64::decode(data.proof).unwrap());
}

async fn init(
    worker: &Worker<impl DevNetwork>,
    initial_balance: U128,
) -> anyhow::Result<(Contract, Account)> {
    let contract = worker
        .dev_deploy(
            &include_bytes!("../../../target/near/testing_contract/testing_contract.wasm").to_vec(),
        )
        .await?;

    let (common, verifier) = verification_data();
    let res = contract
        .call("new")
        .args_json(json!({
            "common": common,
            "verifier": verifier,
        }))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{:?}", res);

    let alice = contract
        .as_account()
        .create_subaccount("alice")
        .initial_balance(NearToken::from_near(10))
        .transact()
        .await?
        .into_result()?;

    return Ok((contract, alice));
}

#[tokio::test]
async fn test_verification() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let (contract, alice) = init(&worker, NearToken::from_near(10).as_yoctonear().into()).await.unwrap();

    let proof = proof_data();
    println!("{:?}", Gas::from_tgas(300));
    let res = contract
        .call("verify_proof")
        .args_json(json!({
            "proof": proof,
        }))
        .gas(Gas::from_tgas(300))
        .transact()
        .await
        .unwrap();
    assert!(res.is_success(), "{:?}", res);
    Ok(())
}
