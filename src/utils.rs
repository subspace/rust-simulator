extern crate num_bigint;
extern crate num_traits;
extern crate bitintr;

use num_bigint::{BigUint, ToBigUint};
use num_traits::cast::ToPrimitive;
use bitintr::Lzcnt;
use byteorder::BigEndian;
use byteorder::WriteBytesExt;

pub fn are_arrays_equal(a: &[u8], b: &[u8]) -> bool {
  a.cmp(b) == std::cmp::Ordering::Equal
}

pub fn measure_quality(tag: &[u8]) -> u8 {
  let mut quality: u8 = 0;
  for byte in tag.iter() {
    let zero_bits = byte.lzcnt();
    quality += zero_bits;
    if zero_bits < 8 {
      break
    }
  }
  quality
}

pub fn xor_bytes(a: &mut [u8], b: &[u8]) {
  for i in 0..a.len() {
    a[i] ^=  b[i];
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

pub fn usize_to_bytes(number: usize) -> [u8; 16] {
  let mut iv = [0u8; 16];
  iv.as_mut().write_u32::<BigEndian>(number as u32).unwrap();
  iv
}