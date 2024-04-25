use std::ops::Mul;

use merlin::Transcript;
use near_bigint::U256;
use near_sdk::{
    borsh::{BorshDeserialize, BorshSerialize},
    serde::{Deserialize, Serialize},
};

use crate::{check_scalar_field_element, pairing::pairing_prod_2, G1Point, G2Point};

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct CommitmentKey {
    pub g: G2Point,
    pub g_root_sigma_neg: G2Point,
}

impl CommitmentKey {
    pub fn verify(&self, commitment: G1Point, knowledge_proof: G1Point, scalar: U256) -> bool {
        check_scalar_field_element(commitment.x, scalar);
        check_scalar_field_element(knowledge_proof.x, scalar);

        pairing_prod_2(
            &commitment,
            &self.g,
            &knowledge_proof,
            &self.g_root_sigma_neg,
        )
    }
}

pub fn fold_commitments(commitments: &[G1Point], fiatshamir_seeds: &[Vec<u8>]) -> Option<G1Point> {
    if commitments.len() == 1 {
        return Some(commitments[0].clone());
    } else if commitments.is_empty() {
        return None;
    }

    let mut r = Vec::with_capacity(commitments.len());
    r.push(U256::one());
    r.push(get_challenge(fiatshamir_seeds));
    for i in 2..commitments.len() {
        r.push(r[i - 1].mul(&r[1]));
    }

    let mut res = G1Point {
        x: U256::zero(),
        y: U256::zero(),
    };
    for i in 0..commitments.len() {
        res = G1Point::addition(&res, &commitments[i].scalar_mul(r[i]));
    }
    Some(res)
}

fn get_challenge(fiatshamir_seeds: &[Vec<u8>]) -> U256 {
    const ID: [u8; 1] = [b'r'];
    let mut t = Transcript::new(&ID);
    for seed in fiatshamir_seeds {
        t.append_message(&ID, seed);
    }

    let mut result_bytes = [0u8; 32];
    t.challenge_bytes(&ID, &mut result_bytes);
    U256::from_big_endian(&result_bytes)
}
