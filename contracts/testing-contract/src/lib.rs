#![feature(stdsimd)]

// Find all our documentation at https://docs.near.org
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::Base64VecU8;
use near_sdk::store::Vector;
use near_sdk::{env, json_types, log, near_bindgen, BorshStorageKey, NearSchema, PanicOnDefault};

use plonky2_reputation::Proof;
use plonky2_reputation::{prelude::*, Digest};
use rand::{RngCore, SeedableRng};

#[cfg(target_arch = "wasm32")]
mod custom_getrandom {
    #![allow(clippy::no_mangle_with_rust_abi)]

    use core::num::NonZeroU32;
    use getrandom::{register_custom_getrandom, Error};
    use near_sdk::env;
    use rand::{RngCore, SeedableRng};

    register_custom_getrandom!(custom_getrandom);

    #[allow(clippy::unnecessary_wraps)]
    pub fn custom_getrandom(buf: &mut [u8]) -> Result<(), Error> {
        let near_seed = env::random_seed_array();
        let mut rng = rand::rngs::StdRng::from_seed(
            near_seed
                .try_into()
                .map_err(|_| Error::from(NonZeroU32::new(1).unwrap()))?,
        );
        rng.fill_bytes(buf);
        Ok(())
    }
}

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
    common_data_bytes: Vec<u8>,
    verifier_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize, NearSchema, BorshDeserialize, BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct ProofInput {
    pub proof: Base64VecU8,
    pub merkle_root: [u64; 4],
    pub nullifier: [u64; 4],
    pub reputation: u32,
    pub topic_id: u64,
}

// Implement the contract structure
#[near_bindgen]
impl Contract {
    #[private]
    #[init(ignore_state)]
    pub fn new(common: Base64VecU8, verifier: Base64VecU8) -> Self {
        Self {
            verifier_bytes: verifier.0,
            common_data_bytes: common.0,
        }
    }

    pub fn verify_proof(&mut self, proof: ProofInput) -> bool {
        let common: CommonCircuitData<_, 2> = CommonCircuitData::<F, D>::from_bytes(
            self.common_data_bytes.clone(),
            &Ed25519GateSerializer,
        )
        .unwrap();

        let verifier_only =
            VerifierOnlyCircuitData::<C, D>::from_bytes(self.verifier_bytes.clone()).unwrap();

        let verifier = VerifierCircuitData {
            common,
            verifier_only,
        };

        let reputation = proof.reputation;

        env::log!("Used gas {}", env::used_gas());

        if let Ok(_) = ReputationSet::verify(verifier, proof) {
            log!("Proof is valid with reputation: {}!", reputation);
            return true;
        }
        return false;
    }
}
