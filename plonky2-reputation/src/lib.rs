use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField;
pub type Digest = [F; 4];
pub type PlonkProof = plonky2::plonk::proof::Proof<F, C, D>;

pub mod gadgets;

#[cfg(test)]
pub mod test_utils;

#[derive(Debug, Clone)]
pub struct Proof {
    pub proof: PlonkProof,
    pub nullifier: Digest,
    pub reputation: u32,
    pub topic_id: u64,
}
