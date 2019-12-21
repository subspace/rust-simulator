extern crate num_bigint;
extern crate num_traits;

use num_bigint::{BigUint, ToBigUint};
use num_traits::cast::ToPrimitive;

pub fn bytes_to_bigint(bytes: &[u8]) -> BigUint {
  BigUint::from_bytes_be(bytes)
}

pub fn usize_to_bigint(number: usize) -> BigUint {
  ToBigUint::to_biguint(&number).unwrap()
}

pub fn bigint_to_usize(bigInt: BigUint) -> usize {
  bigInt.to_usize().unwrap()
}