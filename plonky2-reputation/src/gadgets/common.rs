use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};

pub fn connect_bool_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    src: &[BoolTarget],
    dest: &[BoolTarget],
) {
    assert_eq!(src.len(), dest.len());
    for (src_bit, dest_bit) in src.iter().zip(dest) {
        builder.connect(src_bit.target, dest_bit.target);
    }
}

pub fn bits_in_le(input_vec: Vec<BoolTarget>) -> Vec<BoolTarget> {
    let mut result = Vec::with_capacity(input_vec.len());

    input_vec
        .chunks_exact(8)
        .for_each(|chunk| result.extend(chunk.iter().rev()));

    result.reverse();
    result
}
