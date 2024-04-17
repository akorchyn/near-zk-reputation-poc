use std::simd::ToBytes;

use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use serde::{Deserialize, Serialize};

pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField;
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
    pub use plonky2_ed25519::serialization::Ed25519GateSerializer;

    pub use crate::{gadgets::reputation_list::ReputationSet, C, D, F};
}

#[cfg(test)]
pub mod test_utils;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Proof {
    pub proof: PlonkProof,
    pub merkle_root: Digest,
    pub nullifier: Digest,
    pub reputation: u32,
    pub topic_id: u64,
}
