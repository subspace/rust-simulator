use core::arch::x86_64::*;

pub fn decode_aes_ni_128_pipelined_x4(
    keys: &[[u8; 16]; 11],
    blocks: [&mut [u8; 16]; 4],
    rounds: usize,
) {
    unsafe {
        let mut block0 = _mm_loadu_si128(blocks[0].as_ptr() as *const __m128i);
        let mut block1 = _mm_loadu_si128(blocks[1].as_ptr() as *const __m128i);
        let mut block2 = _mm_loadu_si128(blocks[2].as_ptr() as *const __m128i);
        let mut block3 = _mm_loadu_si128(blocks[3].as_ptr() as *const __m128i);

        let key0 = _mm_loadu_si128(keys[0].as_ptr() as *const __m128i);
        let key1 = _mm_loadu_si128(keys[1].as_ptr() as *const __m128i);
        let key2 = _mm_loadu_si128(keys[2].as_ptr() as *const __m128i);
        let key3 = _mm_loadu_si128(keys[3].as_ptr() as *const __m128i);
        let key4 = _mm_loadu_si128(keys[4].as_ptr() as *const __m128i);
        let key5 = _mm_loadu_si128(keys[5].as_ptr() as *const __m128i);
        let key6 = _mm_loadu_si128(keys[6].as_ptr() as *const __m128i);
        let key7 = _mm_loadu_si128(keys[7].as_ptr() as *const __m128i);
        let key8 = _mm_loadu_si128(keys[8].as_ptr() as *const __m128i);
        let key9 = _mm_loadu_si128(keys[9].as_ptr() as *const __m128i);
        let key10 = _mm_loadu_si128(keys[10].as_ptr() as *const __m128i);

        // let key1 = _mm_aesimc_si128(key1);
        // let key2 = _mm_aesimc_si128(key2);
        // let key3 = _mm_aesimc_si128(key3);
        // let key4 = _mm_aesimc_si128(key4);
        // let key5 = _mm_aesimc_si128(key5);
        // let key6 = _mm_aesimc_si128(key6);
        // let key7 = _mm_aesimc_si128(key7);
        // let key8 = _mm_aesimc_si128(key8);
        // let key9 = _mm_aesimc_si128(key9);

        for _ in 0..rounds {
            block0 = _mm_xor_si128(block0, key10);
            block1 = _mm_xor_si128(block1, key10);
            block2 = _mm_xor_si128(block2, key10);
            block3 = _mm_xor_si128(block3, key10);

            block0 = _mm_aesdec_si128(block0, key9);
            block1 = _mm_aesdec_si128(block1, key9);
            block2 = _mm_aesdec_si128(block2, key9);
            block3 = _mm_aesdec_si128(block3, key9);

            block0 = _mm_aesdec_si128(block0, key8);
            block1 = _mm_aesdec_si128(block1, key8);
            block2 = _mm_aesdec_si128(block2, key8);
            block3 = _mm_aesdec_si128(block3, key8);

            block0 = _mm_aesdec_si128(block0, key7);
            block1 = _mm_aesdec_si128(block1, key7);
            block2 = _mm_aesdec_si128(block2, key7);
            block3 = _mm_aesdec_si128(block3, key7);

            block0 = _mm_aesdec_si128(block0, key6);
            block1 = _mm_aesdec_si128(block1, key6);
            block2 = _mm_aesdec_si128(block2, key6);
            block3 = _mm_aesdec_si128(block3, key6);

            block0 = _mm_aesdec_si128(block0, key5);
            block1 = _mm_aesdec_si128(block1, key5);
            block2 = _mm_aesdec_si128(block2, key5);
            block3 = _mm_aesdec_si128(block3, key5);

            block0 = _mm_aesdec_si128(block0, key4);
            block1 = _mm_aesdec_si128(block1, key4);
            block2 = _mm_aesdec_si128(block2, key4);
            block3 = _mm_aesdec_si128(block3, key4);

            block0 = _mm_aesdec_si128(block0, key3);
            block1 = _mm_aesdec_si128(block1, key3);
            block2 = _mm_aesdec_si128(block2, key3);
            block3 = _mm_aesdec_si128(block3, key3);

            block0 = _mm_aesdec_si128(block0, key2);
            block1 = _mm_aesdec_si128(block1, key2);
            block2 = _mm_aesdec_si128(block2, key2);
            block3 = _mm_aesdec_si128(block3, key2);

            block0 = _mm_aesdec_si128(block0, key1);
            block1 = _mm_aesdec_si128(block1, key1);
            block2 = _mm_aesdec_si128(block2, key1);
            block3 = _mm_aesdec_si128(block3, key1);

            block0 = _mm_aesdeclast_si128(block0, key0);
            block1 = _mm_aesdeclast_si128(block1, key0);
            block2 = _mm_aesdeclast_si128(block2, key0);
            block3 = _mm_aesdeclast_si128(block3, key0);
        }

        _mm_storeu_si128(blocks[0].as_mut_ptr() as *mut __m128i, block0);
        _mm_storeu_si128(blocks[1].as_mut_ptr() as *mut __m128i, block1);
        _mm_storeu_si128(blocks[2].as_mut_ptr() as *mut __m128i, block2);
        _mm_storeu_si128(blocks[3].as_mut_ptr() as *mut __m128i, block3);
    }
}
