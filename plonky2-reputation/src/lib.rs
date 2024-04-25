use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use plonky2_bn128::config::PoseidonBN128GoldilocksConfig;
use serde::{Deserialize, Serialize};

pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField;
// Recursive
pub type Cbn128 = PoseidonBN128GoldilocksConfig;
pub type Digest = [F; 4];
pub type PlonkProof = plonky2::plonk::proof::Proof<F, C, D>;

pub mod gadgets;

pub mod prelude {
    pub use plonky2::field::types::Field;
    pub use plonky2::plonk::circuit_data::{
        CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
    };
    pub use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    pub use plonky2::plonk::proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs};
}

#[cfg(test)]
pub mod test_utils;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Proof {
    pub proof: PlonkProof,
    pub merkle_root: Digest,
    pub nullifier: Digest,
    pub expected_reputation: u32,
    pub topic_id: u64,
}
