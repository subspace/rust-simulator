use crate::utils;
use ocl::core::{Uchar16, Uint};
use std::convert::TryInto;

pub fn u8_slice_to_uchar16_vec(input: &[u8]) -> Vec<Uchar16> {
    assert_eq!(input.len() % 4, 0);

    input
        .chunks_exact(16)
        .map(|chunk| chunk.try_into().unwrap())
        .map(|chunk: [u8; 16]| Uchar16::from(chunk))
        .collect()
}

pub fn u128_slice_to_uchar16_vec(input: &[u128]) -> Vec<Uchar16> {
    input
        .iter()
        .map(|num| utils::usize_to_bytes(*num as usize))
        .map(|chunk: [u8; 16]| Uchar16::from(chunk))
        .collect()
    // TODO: Probably this should have been made instead:
    // input
    //     .iter()
    //     .map(|num| num.to_le_bytes().try_into().unwrap())
    //     .map(|chunk: [u8; 16]| Uchar16::from(chunk))
    //     .collect()
}

pub fn u32_slice_to_uint_vec(input: &[u32]) -> Vec<Uint> {
    input
        .iter()
        .map(|chunk| Uint::from(chunk.to_owned()))
        .collect()
}
