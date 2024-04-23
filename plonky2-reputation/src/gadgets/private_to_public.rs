use plonky2::{
    iop::{target::BoolTarget, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};

use plonky2_ecdsa::gadgets::biguint::CircuitBuilderBiguint;
use plonky2_sha512_u32::{
    sha512::{CircuitBuilderHashSha2, WitnessHashSha2},
    types::{CircuitBuilderHash, HashInputTarget},
};
use plonky2_u32::gadgets::{
    arithmetic_u32::CircuitBuilderU32,
    binary_u32::{Bin32Target, CircuitBuilderBU32},
    interleaved_u32::CircuitBuilderB32,
};

use plonky2_ed25519::{
    curve::{curve_types::Curve, ed25519::Ed25519},
    gadgets::nonnative::CircuitBuilderNonNative,
    gadgets::{curve::CircuitBuilderCurve, curve_fixed_base::fixed_base_curve_mul_circuit},
};

use crate::{D, F};

use super::common::bits_in_le;

pub struct PrivateToPublic {}

pub struct PubVerifyTargets {
    pub pk: Vec<BoolTarget>,
    pub priv_key: HashInputTarget,
}

impl PrivateToPublic {
    pub fn make_circuit(
        builder: &mut CircuitBuilder<F, D>,
        with_public_input: bool,
    ) -> PubVerifyTargets {
        // Private key
        let block_count = (256 + 128 + 1024) / 1024;
        let hash_target = builder.add_virtual_hash_input_target(block_count, 1024);

        let hash_output: Vec<plonky2_sha512_u32::types::U64Target> =
            builder.hash_sha512(&hash_target);
        // We need to mirror the bits in the hash_output
        let mut limbs = hash_output[..4]
            .iter()
            .flat_map(|x| [x.hi, x.lo])
            .map(|x| {
                let bits = bits_in_le(builder.convert_u32_bin32(x).bits);
                builder.convert_bin32_u32(Bin32Target { bits })
            })
            .collect::<Vec<_>>();

        // Set the first 3 bits to 0 (248 & first_byte)
        let mask = builder.constant_u32(0xFF_FF_FF_F8);
        limbs[0] = builder.and_u32(limbs[0], mask);

        // Set the last bit to 0 (127 & last_byte)
        let mask = builder.constant_u32(0x7F_FF_FF_FF);
        limbs[7] = builder.and_u32(limbs[7], mask);
        // (64 | last_byte). There is no OR operation in the API, so we need to do it manually
        // A OR B = NOT(NOT(A) AND NOT(B))
        let not_a = builder.not_u32(limbs[7]);
        let not_b = builder.constant_u32(0xBFFFFFFF);
        let and = builder.and_u32(not_a, not_b);
        limbs[7] = builder.not_u32(and);

        let mut k_biguint = builder.add_virtual_biguint_target(8);
        k_biguint.limbs = limbs;

        let k_scalar = builder.biguint_to_nonnative(&k_biguint);

        let kb = fixed_base_curve_mul_circuit(builder, Ed25519::GENERATOR_AFFINE, &k_scalar);
        let pk = builder.point_compress(&kb);

        if with_public_input {
            pk.iter()
                .for_each(|pk| builder.register_public_input(pk.target));
        }

        PubVerifyTargets {
            priv_key: hash_target,
            pk,
        }
    }

    pub fn fill_circuit(
        pw: &mut PartialWitness<F>,
        priv_key: &[u8],
        private_target: HashInputTarget,
    ) {
        assert_eq!(priv_key.len(), 32);
        pw.set_sha512_input_target(&private_target, priv_key);
    }
}

#[cfg(test)]
mod test {
    use plonky2::{field::types::Field, plonk::circuit_data::CircuitConfig};

    use crate::{
        test_utils::{PRIVATE, PUBLIC},
        C,
    };

    use super::*;

    #[test]
    fn test_private_to_public() {
        let mut config = CircuitConfig::wide_ecc_config();
        config.zero_knowledge = true;
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let priv_to_pub = PrivateToPublic::make_circuit(&mut builder, true);
        let private_key = PRIVATE;
        PrivateToPublic::fill_circuit(&mut pw, &private_key, priv_to_pub.priv_key);
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        let address = proof
            .public_inputs
            .to_vec()
            .chunks_exact(8)
            .map(|chunk| {
                let mut byte = 0u8;
                for (i, bit) in chunk.iter().rev().enumerate() {
                    if bit.is_one() {
                        byte |= 1 << i;
                    }
                }
                byte
            })
            .rev()
            .collect::<Vec<u8>>();

        assert_eq!(address, PUBLIC);

        // data.verify(proof).unwrap();
    }
}
