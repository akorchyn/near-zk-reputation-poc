#![feature(stdsimd)]

// Find all our documentation at https://docs.near.org
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::Base64VecU8;
use near_sdk::store::Vector;
use near_sdk::{env, json_types, log, near_bindgen, BorshStorageKey, PanicOnDefault};
use plonky2::field::types::Field;
use plonky2::plonk::circuit_data::{
    CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs};
use plonky2_ed25519::serialization::Ed25519GateSerializer;
use rand::{RngCore, SeedableRng};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

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

    pub fn verify_proof(&mut self, proof: json_types::Base64VecU8) -> bool {
        let common: CommonCircuitData<_, 2> = CommonCircuitData::<F, D>::from_bytes(
            self.common_data_bytes.clone(),
            &Ed25519GateSerializer,
        )
        .unwrap();

        let verifier_only =
            VerifierOnlyCircuitData::<C, D>::from_bytes(self.verifier_bytes.clone()).unwrap();
        let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof.0, &common).unwrap();

        // let address = proof
        //     .public_inputs
        //     .to_vec()
        //     .chunks(8)
        //     .into_iter()
        //     .map(|chunk| {
        //         let mut byte = 0u8;
        //         for (i, bit) in chunk.iter().rev().enumerate() {
        //             if bit.is_one() {
        //                 byte |= 1 << i;
        //             }
        //         }
        //         byte
        //     })
        //     .collect::<Vec<u8>>();

        let verifier = VerifierCircuitData {
            common,
            verifier_only,
        };
        log!("Used gas: {}", env::used_gas().as_tgas());
        if let Ok(_) = verifier.verify(proof) {
            log!("Proof is valid");

            // log!(
            //     "Proof is valid. Verified address: {}",
            //     near_sdk::bs58::encode(&address).into_string()
            // );
            return true;
        }
        return false;
    }
}
