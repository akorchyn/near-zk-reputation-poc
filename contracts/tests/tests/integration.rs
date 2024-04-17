use near_sdk::json_types::Base64VecU8;
use near_sdk::json_types::U128;
use near_sdk::{Gas, NearToken};
use near_workspaces::{Account, Contract, DevNetwork, Worker};
use serde::{Deserialize, Serialize};
use serde_json::json;

const VERIFIER_DATA: &str =
    include_str!("../../../plonky2-reputation/reputation_proof.verify.json");
const PROOF: &str = include_str!("../../../plonky2-reputation/reputation_proof.json");

#[derive(Serialize, Deserialize)]
struct VerificationData {
    pub common: String,
    pub verifier: String,
}

pub fn verification_data() -> (Base64VecU8, Base64VecU8) {
    let data: VerificationData = serde_json::from_str(VERIFIER_DATA).unwrap();
    let common = Base64VecU8(near_sdk::base64::decode(data.common).unwrap());
    let verifier = Base64VecU8(near_sdk::base64::decode(data.verifier).unwrap());

    return (common, verifier);
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
    let (contract, alice) = init(&worker, NearToken::from_near(10).as_yoctonear().into())
        .await
        .unwrap();

    println!("{:?}", Gas::from_tgas(300));
    let res = contract
        .call("verify_proof")
        .args_json(json!({
            "proof": PROOF,
        }))
        .gas(Gas::from_tgas(300))
        .transact()
        .await
        .unwrap();
    println!("{:?}", res.logs());
    assert!(res.is_success(), "{:?}", res);
    Ok(())
}
