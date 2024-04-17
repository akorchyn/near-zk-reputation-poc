use plonky2::{
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use plonky2_crypto::u32::{arithmetic_u32::CircuitBuilderU32, interleaved_u32::CircuitBuilderB32};
use plonky2_sha512::gadgets::sha512::{array_to_bits, make_sha512_circuit};

use plonky2_ed25519::{
    curve::{curve_types::Curve, ed25519::Ed25519},
    field::ed25519_scalar::Ed25519Scalar,
    gadgets::curve::CircuitBuilderCurve,
    gadgets::eddsa::{bits_in_le, bits_to_biguint_target, connect_bool_targets},
    gadgets::nonnative::CircuitBuilderNonNative,
};

use crate::{D, F};

pub struct PrivateToPublic {}

pub struct PubVerifyTargets {
    pub pk: Vec<BoolTarget>,
    pub priv_key: Vec<BoolTarget>,
}

impl PrivateToPublic {
    pub fn make_circuit(
        builder: &mut CircuitBuilder<F, D>,
        with_public_input: bool,
    ) -> PubVerifyTargets {
        // Private key
        let mut private_key = Vec::new();

        private_key.resize_with(256, || builder.add_virtual_bool_target_unsafe());

        let sha512_instance = make_sha512_circuit(builder, 256_u128);

        connect_bool_targets(
            builder,
            &sha512_instance.message[..256],
            &private_key[..256],
        );

        let digest_bits_le = bits_in_le(sha512_instance.digest);
        let mut k_biguint = bits_to_biguint_target(builder, digest_bits_le);

        // Set the first 3 bits to 0 (248 & first_byte)
        let mask = builder.constant_u32(0xFF_FF_FF_F8);
        k_biguint.limbs[0] = builder.and_u32(k_biguint.limbs[0], mask);
        // Set the last bit to 0 (127 & last_byte)
        let mask = builder.constant_u32(0x7F_FF_FF_FF);
        k_biguint.limbs[7] = builder.and_u32(k_biguint.limbs[7], mask);
        // (64 | last_byte). There is no OR operation in the API, so we need to do it manually
        // A OR B = NOT(NOT(A) AND NOT(B))
        let not_a = builder.not_u32(k_biguint.limbs[7]);
        let not_b = builder.constant_u32(0xBFFFFFFF);
        let and = builder.and_u32(not_a, not_b);
        k_biguint.limbs[7] = builder.not_u32(and);

        let k_scalar = builder.biguint_to_nonnative::<Ed25519Scalar>(&k_biguint);

        let b = builder.constant_affine_point(Ed25519::GENERATOR_AFFINE);

        let kb = builder.curve_scalar_mul_windowed(&b, &k_scalar);

        let pk = builder.point_compress(&kb);

        if with_public_input {
            pk.iter()
                .for_each(|pk| builder.register_public_input(pk.target));
        }

        PubVerifyTargets {
            priv_key: private_key,
            pk,
        }
    }

    pub fn fill_circuit(
        pw: &mut PartialWitness<F>,
        priv_key: &[u8],
        private_target: Vec<BoolTarget>,
    ) {
        assert_eq!(priv_key.len(), 32);
        assert_eq!(private_target.len(), 256);

        let priv_bits = array_to_bits(priv_key);

        for i in 0..256 {
            pw.set_bool_target(private_target[i], priv_bits[i]);
        }
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
            .chunks(8)
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

        data.verify(proof).unwrap();
    }
}
