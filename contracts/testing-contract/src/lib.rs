#![feature(stdsimd)]

use near_bigint::U256;
use near_groth16_verifier::{G1Point, G2Point};
// use near_groth16_verifier::Verifier;
// Find all our documentation at https://docs.near.org
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::Base64VecU8;
use near_sdk::{env, log, near_bindgen, BorshStorageKey, PanicOnDefault};

// // use plonky2_reputation::Proof;
// // use plonky2_reputation::{prelude::*, Digest};
// use rand::{RngCore, SeedableRng};

// #[cfg(target_arch = "wasm32")]
// mod custom_getrandom {
//     #![allow(clippy::no_mangle_with_rust_abi)]

//     use core::num::NonZeroU32;
//     use getrandom::{register_custom_getrandom, Error};
//     use near_sdk::env;
//     use rand::{RngCore, SeedableRng};

//     register_custom_getrandom!(custom_getrandom);

//     #[allow(clippy::unnecessary_wraps)]
//     pub fn custom_getrandom(buf: &mut [u8]) -> Result<(), Error> {
//         let near_seed = env::random_seed_array();
//         let mut rng = rand::rngs::StdRng::from_seed(
//             near_seed
//                 .try_into()
//                 .map_err(|_| Error::from(NonZeroU32::new(1).unwrap()))?,
//         );
//         rng.fill_bytes(buf);
//         Ok(())
//     }
// }

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
    verifier: near_groth16_verifier::Verifier,
}

// #[derive(Debug, Clone, Deserialize, Serialize, NearSchema, BorshDeserialize, BorshSerialize)]
// #[borsh(crate = "near_sdk::borsh")]
// #[serde(crate = "near_sdk::serde")]
// pub struct ProofInput {
//     pub proof: Base64VecU8,
//     pub merkle_root: [u64; 4],
//     pub nullifier: [u64; 4],
//     pub reputation: u32,
//     pub topic_id: u64,
// }

// Implement the contract structure
#[near_bindgen]
impl Contract {
    #[private]
    #[init(ignore_state)]
    pub fn new(
        alfa1: G1Point,
        beta2: G2Point,
        gamma2: G2Point,
        delta2: G2Point,
        ic: Vec<G1Point>,
    ) -> Self {
        let verifier = near_groth16_verifier::Verifier::new(alfa1, beta2, gamma2, delta2, ic);
        Self { verifier }
    }

    pub fn verify_proof(&mut self, proof: near_groth16_verifier::Proof, public_inputs: Vec<U256>) {
        let verify = self.verifier.verify(public_inputs, proof);
        log!(
            "verify: {:?} with gas {}",
            verify,
            env::used_gas().as_tgas()
        );
    }
}
