use bitintr;
use bitintr::Lzcnt;
use hex;
use itertools::izip;
use num_bigint;
use num_bigint::{BigUint, ToBigUint};
use num_traits;
use num_traits::cast::ToPrimitive;
use std::collections::HashMap;
use std::io::Write;

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
    for (i, a_byte) in a.iter_mut().enumerate() {
        *a_byte ^= b[i];
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
    iv.as_mut()
        .write_all(&(number as u32).to_be_bytes())
        .unwrap();
    iv
}

pub fn print_bytes(bytes: &[u8]) {
    for (i, slice) in bytes.chunks(16).enumerate() {
        println!("Block {}:\t {}", i, hex::encode(slice.to_vec()));
    }
}

pub fn compare_bytes(a: &[u8], b: &[u8], c: &[u8]) {
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

pub fn average(numbers: &[u128]) -> f32 {
    numbers.iter().sum::<u128>() as f32 / numbers.len() as f32
}

pub fn median(numbers: &mut [u128]) -> u128 {
    numbers.sort();
    let mid = numbers.len() / 2;
    numbers[mid]
}

pub fn mode(numbers: &[u128]) -> u128 {
    let mut occurrences = HashMap::new();

    for &value in numbers {
        *occurrences.entry(value).or_insert(0) += 1;
    }

    occurrences
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map(|(val, _)| val)
        .expect("Cannot compute the mode of zero numbers")
}
