use super::expand;
use crate::arch::*;
use block_cipher_trait::generic_array::typenum::{U16, U32, U8};
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::BlockCipher;
use core::mem;

// Code below is a refactored version of aesni crate that doesn't use any macros

type Block128 = GenericArray<u8, U16>;
type Block128x8 = GenericArray<Block128, U8>;

#[derive(Copy, Clone)]
pub struct Cipher {
    encrypt_keys: [__m128i; 15],
    decrypt_keys: [__m128i; 15],
}

impl Cipher {
    pub fn new(key: &GenericArray<u8, U32>) -> Self {
        let key = unsafe { mem::transmute(key) };
        let (encrypt_keys, decrypt_keys) = expand::expand(key);
        Self {
            encrypt_keys,
            decrypt_keys,
        }
    }

    fn encrypt_blocks_dynamic(&self, blocks: &mut Block128x8, parallel_blocks: usize) {
        let keys = self.encrypt_keys;
        unsafe {
            let mut b: [__m128i; 32] = mem::uninitialized();
            for block in 0..parallel_blocks {
                b[block] = _mm_loadu_si128(blocks[block].as_ptr() as *const __m128i);
                b[block] = _mm_xor_si128(b[block], keys[0]);
            }
            for round in 1..=13 {
                for block in 0..parallel_blocks {
                    b[block] = _mm_aesenc_si128(b[block], keys[round]);
                }
            }
            for block in 0..parallel_blocks {
                b[block] = _mm_aesenclast_si128(b[block], keys[14]);
            }
            for block in 0..parallel_blocks {
                _mm_storeu_si128(blocks[block].as_mut_ptr() as *mut __m128i, b[block]);
            }
        }
    }

    fn decrypt_blocks_dynamic(&self, blocks: &mut Block128x8, parallel_blocks: usize) {
        let keys = self.decrypt_keys;
        unsafe {
            let mut b: [__m128i; 32] = mem::uninitialized();
            for block in 0..parallel_blocks {
                b[block] = _mm_loadu_si128(blocks[block].as_ptr() as *const __m128i);
                b[block] = _mm_xor_si128(b[block], keys[14]);
            }
            for round in (1..=13).rev() {
                for block in 0..parallel_blocks {
                    b[block] = _mm_aesdec_si128(b[block], keys[round]);
                }
            }
            for block in 0..parallel_blocks {
                b[block] = _mm_aesdeclast_si128(b[block], keys[0]);
            }
            for block in 0..parallel_blocks {
                _mm_storeu_si128(blocks[block].as_mut_ptr() as *mut __m128i, b[block]);
            }
        }
    }

    pub fn encrypt_blocks(&self, blocks: &mut Block128x8) {
        self.encrypt_blocks_dynamic(blocks, 8);
    }

    pub fn decrypt_blocks(&self, blocks: &mut Block128x8) {
        self.decrypt_blocks_dynamic(blocks, 8);
    }
}
