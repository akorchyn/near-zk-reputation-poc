use near_bigint::{U256, U512};
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::env::{sha256, sha256_array};
use near_sdk::serde::{Deserialize, Serialize};
pub use pairing::{pairing_prod_4, G1Point, G2Point};

mod pairing;

const COMMITMENT_DST: &[u8] = b"bsb22-commitment";

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct Verifier {
    pub alfa1: G1Point,
    pub beta2: G2Point,
    pub gamma2: G2Point,
    pub delta2: G2Point,
    pub ic: Vec<G1Point>,
    pub snark_scalar_field: U256,
    pub public_and_commitment_commited: Vec<Vec<U256>>,
    pub commitment_key: CommitmentKey,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct CommitmentKey {
    pub a: G2Point,
    pub b: G2Point,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Proof {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
    pub commitments: Vec<G1Point>,
    pub commitments_pok: G1Point,
}

impl Verifier {
    pub fn new(
        alfa1: G1Point,
        beta2: G2Point,
        gamma2: G2Point,
        delta2: G2Point,
        ic: Vec<G1Point>,
        public_and_commitment_commited: Vec<Vec<U256>>,
        commitment_key: CommitmentKey,
    ) -> Self {
        Self {
            alfa1,
            beta2,
            gamma2,
            delta2,
            ic,
            snark_scalar_field: U256::from_dec_str(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            )
            .unwrap(),
            public_and_commitment_commited,
            commitment_key,
        }
    }

    pub fn verify(&self, mut input: Vec<U256>, proof: Proof) -> bool {
        let public_inputs = self.ic.len() - self.public_and_commitment_commited.len();
        assert_eq!(input.len() + 1, public_inputs, "verifier-bad-input");

        // todo!("Commitment verification with commitment_pok");

        let max_nb_commitments = self
            .public_and_commitment_commited
            .iter()
            .map(|x| x.len())
            .max()
            .unwrap_or_default();
        let mut pre_hash_bytes = Vec::with_capacity(64 + max_nb_commitments * 32);

        let module = U512::from_big_endian(&self.snark_scalar_field.to_be_bytes());
        for i in 0..self.public_and_commitment_commited.len() {
            pre_hash_bytes.clear();
            let commitment = &proof.commitments[i];
            pre_hash_bytes.extend(commitment.x.to_be_bytes());
            pre_hash_bytes.extend(commitment.y.to_be_bytes());

            for j in 0..self.public_and_commitment_commited[i].len() {
                pre_hash_bytes.extend(self.public_and_commitment_commited[i][j].to_be_bytes());
            }

            let public_commitments = hash_to_field(&pre_hash_bytes, COMMITMENT_DST, module)
                .expect("hash-to-field error");
            input.push(public_commitments);
        }

        let mut vk_x = G1Point {
            x: U256::zero(),
            y: U256::zero(),
        };
        vk_x = G1Point::addition(&vk_x, &self.ic[0]);
        for i in 0..input.len() {
            assert!(
                input[i] < self.snark_scalar_field,
                "verifier-gte-snark-scalar-field"
            );

            vk_x = G1Point::addition(&vk_x, &self.ic[i + 1].scalar_mul(input[i]));
        }

        for i in 0..proof.commitments.len() {
            assert!(
                proof.commitments[i].x < self.snark_scalar_field,
                "verifier-gte-snark-scalar-field"
            );

            vk_x = G1Point::addition(&vk_x, &proof.commitments[i]);
        }

        pairing_prod_4(
            &proof.a.negate(),
            &proof.b,
            &self.alfa1,
            &self.beta2,
            &vk_x,
            &self.gamma2,
            &proof.c,
            &self.delta2,
        )
    }
}

pub fn hash_to_field(msg: &[u8], dst: &[u8], modulus: U512) -> Result<U256, String> {
    // 128 bits of security
    // L = ceil((ceil(log2(p)) + k) / 8), where k is the security parameter = 128
    const BYTES: usize = 1 + (254 - 1) / 8;
    const L: usize = 16 + BYTES;

    let pseudo_random_bytes = expand_msg_xmd(msg, dst, L)?;
    let u512 = U512::from_big_endian(&pseudo_random_bytes);
    let u512_modulus = u512.div_mod(modulus).1;
    // Skip the first 32 bytes that would be 0
    Ok(U256::from_big_endian(&u512_modulus.to_be_bytes()[32..]))
}

fn expand_msg_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>, String> {
    const H_SIZE: usize = 32; // Size of SHA-256 hash output
    let ell = (len_in_bytes + H_SIZE - 1) / H_SIZE; // ceil(len_in_bytes / h_size)
    if ell > 255 {
        return Err("invalid lenInBytes".to_string());
    }
    if dst.len() > 255 {
        return Err("invalid domain size (>255 bytes)".to_string());
    }
    let size_domain = dst.len() as u8;

    // Z_pad = I2OSP(0, r_in_bytes)
    // l_i_b_str = I2OSP(len_in_bytes, 2)
    // DST_prime = I2OSP(len(DST), 1) ∥ DST
    // b₀ = H(Z_pad ∥ msg ∥ l_i_b_str ∥ I2OSP(0, 1) ∥ DST_prime)
    let b0 = sha256_array(
        &[
            &[0u8; 64],
            msg,
            &[0, len_in_bytes as u8, 0u8],
            dst,
            &[size_domain],
        ]
        .concat(),
    );

    // b₁ = H(b₀ ∥ I2OSP(1, 1) ∥ DST_prime)
    let mut b1 = sha256(&[b0.as_slice(), &[1u8], dst, &[size_domain]].concat());

    let mut res = vec![0u8; len_in_bytes];
    res[..H_SIZE].copy_from_slice(&b1);

    for i in 2..=ell {
        // b_i = H(strxor(b₀, b_(i - 1)) ∥ I2OSP(i, 1) ∥ DST_prime)
        let strxor: Vec<u8> = b0.iter().zip(b1.iter()).map(|(x, y)| x ^ y).collect();
        b1 = sha256(&[&strxor, &[i as u8].to_vec(), dst, &[size_domain]].concat());
        let start = H_SIZE * (i - 1);
        let end = std::cmp::min(H_SIZE * i, len_in_bytes);
        res[start..end].copy_from_slice(&b1[..end - start]);
    }

    Ok(res)
}
