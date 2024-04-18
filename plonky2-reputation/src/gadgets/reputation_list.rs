use itertools::Itertools;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2::{
    hash::{
        hash_types::HashOutTarget, merkle_proofs::MerkleProofTarget, merkle_tree::MerkleTree,
        poseidon::PoseidonHash,
    },
    iop::target::{BoolTarget, Target},
};
use plonky2_crypto::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};
use plonky2_crypto::u32::multiple_comparison::list_le_u32_circuit;
use plonky2_crypto::u32::witness::WitnessU32;
use plonky2_ed25519::gadgets::eddsa::bits_in_le;
use plonky2_sha512::gadgets::sha512::array_to_bits;

use crate::{Proof, C, D, F};

use super::private_to_public::PrivateToPublic;

pub struct ReputationSet(pub MerkleTree<F, PoseidonHash>);

pub struct ReputationTargets {
    merkle_root: HashOutTarget,
    merkle_proof: MerkleProofTarget,

    private_key: Vec<BoolTarget>,
    reputation: U32Target,
    expected_reputation: U32Target,

    topic_id: Target,

    leaf_index: Target,
}

impl ReputationSet {
    pub fn verify(verifier_data: VerifierCircuitData<F, C, D>, proof: Proof) -> anyhow::Result<()> {
        let proof_with_public_input = ProofWithPublicInputs {
            proof: proof.proof,
            public_inputs: proof
                .merkle_root
                .into_iter()
                .chain(proof.nullifier)
                .chain([
                    F::from_canonical_u64(proof.topic_id),
                    F::from_canonical_u32(proof.expected_reputation),
                ])
                .collect_vec(),
        };

        verifier_data.verify(proof_with_public_input)
    }

    pub fn prove_reputation(
        &self,
        config: CircuitConfig,
        private_key: &[u8],
        topic_id: u64,
        leaf_index: usize,
        reputation: u32,
        expected_reputation: u32,
    ) -> anyhow::Result<(Proof, VerifierCircuitData<F, C, D>)> {
        let nullifier = array_to_bits(private_key)
            .into_iter()
            .map(F::from_bool)
            .chain([
                F::from_canonical_u64(topic_id),
                F::from_canonical_u32(reputation),
            ])
            .collect::<Vec<F>>();
        let nullifier = PoseidonHash::hash_no_pad(&nullifier).elements;

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut pw = PartialWitness::new();

        let targets = self.circuit(&mut builder);
        self.fill_circuit(
            &mut pw,
            targets,
            private_key,
            topic_id,
            leaf_index,
            reputation,
            expected_reputation,
        );

        let data = builder.build();

        let mut timer = TimingTree::new("ReputationSet", log::Level::Info);
        let proof = timed!(timer, "Proving time", data.prove(pw));
        timer.print();

        let merkle_root = self.0.cap.0[0].elements;

        Ok((
            Proof {
                nullifier,
                expected_reputation,
                proof: proof?.proof,
                topic_id,
                merkle_root,
            },
            data.verifier_data(),
        ))
    }

    pub fn tree_height(&self) -> usize {
        self.0.leaves.len().trailing_zeros() as usize
    }

    pub fn circuit(&self, builder: &mut CircuitBuilder<F, 2>) -> ReputationTargets {
        // Register public inputs
        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);
        let nullifier = builder.add_virtual_hash();
        builder.register_public_inputs(&nullifier.elements);
        let topic_id = builder.add_virtual_target();
        builder.register_public_input(topic_id);
        let expected_reputation = builder.add_virtual_u32_target();
        builder.register_public_input(expected_reputation.0);

        // Merkle proof
        let merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(self.tree_height()),
        };

        // Register private input
        let priv_to_pub = PrivateToPublic::make_circuit(builder, false);
        let pk_bits = bits_in_le(priv_to_pub.pk);

        let leaf_index = builder.add_virtual_target();
        let leaf_index_bits = builder.split_le(leaf_index, self.tree_height());

        // User reputation is private, but user can prove that he has at least X reputation
        let reputation = builder.add_virtual_u32_target();

        // Verify that user has more than X reputation
        let expected_is_le = list_le_u32_circuit(
            builder,
            [expected_reputation].to_vec(),
            [reputation].to_vec(),
        );
        let true_stm = builder._true();
        builder.connect(expected_is_le.target, true_stm.target);

        // Verify the merkle proof
        builder.verify_merkle_proof::<PoseidonHash>(
            pk_bits
                .iter()
                .map(|e| e.target)
                .chain([reputation.0])
                .collect_vec(),
            &leaf_index_bits,
            merkle_root,
            &merkle_proof,
        );

        let should_be_nullifier = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            priv_to_pub
                .priv_key
                .iter()
                .map(|e: &BoolTarget| e.target)
                .chain([topic_id, reputation.0])
                .collect_vec(),
        );
        builder.connect_hashes(should_be_nullifier, nullifier);

        ReputationTargets {
            private_key: priv_to_pub.priv_key,
            merkle_root,
            topic_id,
            reputation,
            leaf_index,
            merkle_proof,
            expected_reputation,
        }
    }

    pub fn fill_circuit(
        &self,
        pw: &mut PartialWitness<F>,
        targets: ReputationTargets,
        private_key: &[u8],
        topic_id: u64,
        leaf_index: usize,
        reputation: u32,
        expected_reputation: u32,
    ) {
        assert_eq!(private_key.len(), 32);

        let ReputationTargets {
            merkle_root,
            topic_id: topic_id_target,
            merkle_proof: merkle_proof_target,
            private_key: private_key_target,
            reputation: reputation_target,
            leaf_index: leaf_index_target,
            expected_reputation: expected_reputation_target,
        } = targets;

        pw.set_hash_target(merkle_root, self.0.cap.0[0]);
        pw.set_u32_target(reputation_target, reputation);
        pw.set_u32_target(expected_reputation_target, expected_reputation);
        pw.set_target(leaf_index_target, F::from_canonical_usize(leaf_index));
        pw.set_target(topic_id_target, F::from_canonical_u64(topic_id));
        PrivateToPublic::fill_circuit(pw, private_key, private_key_target);

        let merkle_proof = self.0.prove(leaf_index);
        for (ht, h) in merkle_proof_target
            .siblings
            .into_iter()
            .zip(merkle_proof.siblings)
        {
            pw.set_hash_target(ht, h);
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{plonk::config::Hasher, util::serialization::Write};
    use plonky2_sha512::gadgets::sha512::array_to_bits;
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_set() {
        let _ = env_logger::builder().is_test(true).try_init();
        // 32768
        let n = 1 << 15;
        let mut csprng = thread_rng();

        let private_keys: Vec<_> = (0..n)
            .map(|_| ed25519_dalek::SecretKey::generate(&mut csprng))
            .collect();

        let leaves: Vec<_> = private_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let pk = ed25519_dalek::PublicKey::from(sk).to_bytes();
                let reputation = i as u32;

                let hash_data: Vec<F> = array_to_bits(&pk)
                    .into_iter()
                    .map(F::from_bool)
                    .chain([F::from_canonical_u32(reputation)])
                    .collect();

                PoseidonHash::hash_no_pad(&hash_data).elements.to_vec()
            })
            .collect();
        let reputatition_set = ReputationSet(MerkleTree::new(leaves, 0));

        let i = 1000;
        let topic = 103222;
        let expected_rep = 500;

        let mut config = CircuitConfig::wide_ecc_config();
        config.zero_knowledge = true;
        let (proof, verifier_data) = reputatition_set
            .prove_reputation(
                config,
                &private_keys[i].to_bytes(),
                topic,
                i,
                i as u32,
                expected_rep,
            )
            .unwrap();
        let mut data = vec![];
        data.write_proof(&proof.proof).unwrap();
        println!("Proof length: {}", data.len());

        ReputationSet::verify(verifier_data, proof).unwrap();
    }
}
