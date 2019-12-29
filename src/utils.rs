extern crate bitintr;
extern crate hex;
extern crate num_bigint;
extern crate num_traits;

use itertools::izip;
use bitintr::Lzcnt;
use num_bigint::{BigUint, ToBigUint};
use num_traits::cast::ToPrimitive;
use std::io::Write;

pub fn are_arrays_equal(a: &[u8], b: &[u8]) -> bool {
    a.cmp(b) == std::cmp::Ordering::Equal
}

pub fn measure_quality(tag: &[u8]) -> u8 {
    let mut quality: u8 = 0;
    for byte in tag.iter() {
        let zero_bits = byte.lzcnt();
        quality += zero_bits;
        if zero_bits < 8 {
            break;
        }
    }
    quality
}

pub fn xor_bytes(a: &mut [u8], b: &[u8]) {
    for i in 0..a.len() {
        a[i] ^= b[i];
    }
}

pub fn modulo(a: &[u8], n: usize) -> usize {
    let big_int_a = bytes_to_bigint(&a);
    let big_int_n = usize_to_bigint(n);
    let big_int_modulus = big_int_a % big_int_n;
    bigint_to_usize(big_int_modulus)
}

pub fn bytes_to_bigint(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

pub fn usize_to_bigint(number: usize) -> BigUint {
    ToBigUint::to_biguint(&number).unwrap()
}

pub fn bigint_to_usize(bigint: BigUint) -> usize {
    bigint.to_usize().unwrap()
}

// built in function
// u32::from_le_bytes
// to_le_bytes().as_ref()
pub fn usize_to_bytes(number: usize) -> [u8; 16] {
    let mut iv = [0u8; 16];
    // TODO: We probably want to use LE instead for performance reasons
    iv.as_mut().write_all(&(number as u32).to_be_bytes()).unwrap();
    iv
}

pub fn print_bytes(bytes: Vec<u8>) {
    for (i, slice) in bytes.chunks(16).enumerate() {
        println!("Block {}:\t {}", i, hex::encode(slice.to_vec()));
    }
}

pub fn compare_bytes(a: Vec<u8>, b: Vec<u8>, c: Vec<u8>) {
    let chunk_size = 16;
    let zipped_iterator = izip!(
        a.chunks(chunk_size),
        b.chunks(chunk_size),
        c.chunks(chunk_size)
    );
    for (i, (a, b, c)) in zipped_iterator.enumerate() {
        println!(
            "Block {}:\t {} \t{} \t{}",
            i,
            hex::encode(a),
            hex::encode(b),
            hex::encode(c)
        );
        if i % 8 == 7 {
            println!();
        }
    }
}
