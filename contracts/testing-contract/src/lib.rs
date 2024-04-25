#![feature(stdsimd)]

use near_bigint::U256;
use near_groth16_verifier::{Proof, Verifier};
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{env, log, near_bindgen, BorshStorageKey, PanicOnDefault};

#[allow(dead_code)]
#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
enum StorageKey {
    CommonData,
    VerifierData,
}

// Define the contract structure
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Contract {
    verifier: Verifier,
}

// Implement the contract structure
#[near_bindgen]
impl Contract {
    #[private]
    #[init(ignore_state)]
    pub fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }

    pub fn verify_proof(&mut self, proof: Proof, public_inputs: Vec<U256>) {
        let verify = self.verifier.verify(public_inputs, proof);
        log!(
            "verify: {:?} with gas {}",
            verify,
            env::used_gas().as_tgas()
        );
    }
}
