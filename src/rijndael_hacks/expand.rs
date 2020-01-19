// Code below is copied from aesni crate
// (https://github.com/RustCrypto/block-ciphers/blob/master/aes/aesni/src/aes256/expand.rs) under
// following license:
//
//Copyright (c) 2017 Artyom Pavlov
//
// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
use crate::arch::*;

use core::mem;

macro_rules! expand_round {
    ($enc_keys:expr, $dec_keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = _mm_load_si128($enc_keys.as_ptr().offset($pos - 2));
        let mut t2;
        let mut t3 = _mm_load_si128($enc_keys.as_ptr().offset($pos - 1));
        let mut t4;

        t2 = _mm_aeskeygenassist_si128(t3, $round);
        t2 = _mm_shuffle_epi32(t2, 0xff);
        t4 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t1 = _mm_xor_si128(t1, t2);

        _mm_store_si128($enc_keys.as_mut_ptr().offset($pos), t1);
        let t = _mm_aesimc_si128(t1);
        _mm_store_si128($dec_keys.as_mut_ptr().offset($pos), t);

        t4 = _mm_aeskeygenassist_si128(t1, 0x00);
        t2 = _mm_shuffle_epi32(t4, 0xaa);
        t4 = _mm_slli_si128(t3, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t3 = _mm_xor_si128(t3, t2);

        _mm_store_si128($enc_keys.as_mut_ptr().offset($pos + 1), t3);
        let t = _mm_aesimc_si128(t3);
        _mm_store_si128($dec_keys.as_mut_ptr().offset($pos + 1), t);
    };
}

macro_rules! expand_round_last {
    ($enc_keys:expr, $dec_keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = _mm_load_si128($enc_keys.as_ptr().offset($pos - 2));
        let mut t2;
        let t3 = _mm_load_si128($enc_keys.as_ptr().offset($pos - 1));
        let mut t4;

        t2 = _mm_aeskeygenassist_si128(t3, $round);
        t2 = _mm_shuffle_epi32(t2, 0xff);
        t4 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t1 = _mm_xor_si128(t1, t2);

        _mm_store_si128($enc_keys.as_mut_ptr().offset($pos), t1);
        _mm_store_si128($dec_keys.as_mut_ptr().offset($pos), t1);
    };
}

#[inline(always)]
pub(super) fn expand(key: &[u8; 32]) -> ([__m128i; 15], [__m128i; 15]) {
    unsafe {
        let mut enc_keys: [__m128i; 15] = mem::uninitialized();
        let mut dec_keys: [__m128i; 15] = mem::uninitialized();

        let kp = key.as_ptr() as *const __m128i;
        let k1 = _mm_loadu_si128(kp);
        let k2 = _mm_loadu_si128(kp.offset(1));
        _mm_store_si128(enc_keys.as_mut_ptr(), k1);
        _mm_store_si128(dec_keys.as_mut_ptr(), k1);
        _mm_store_si128(enc_keys.as_mut_ptr().offset(1), k2);
        _mm_store_si128(dec_keys.as_mut_ptr().offset(1), _mm_aesimc_si128(k2));

        expand_round!(enc_keys, dec_keys, 2, 0x01);
        expand_round!(enc_keys, dec_keys, 4, 0x02);
        expand_round!(enc_keys, dec_keys, 6, 0x04);
        expand_round!(enc_keys, dec_keys, 8, 0x08);
        expand_round!(enc_keys, dec_keys, 10, 0x10);
        expand_round!(enc_keys, dec_keys, 12, 0x20);
        expand_round_last!(enc_keys, dec_keys, 14, 0x40);

        (enc_keys, dec_keys)
    }
}
