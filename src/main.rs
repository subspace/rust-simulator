extern crate ocl;
use ocl::flags;
use ocl::ProQue;
use ocl::prm::Uint4;
use std::convert::{TryInto, TryFrom};
use std::ops::Deref;

mod aes_soft;

// From this repo: https://github.com/zliuva/OpenCL-AES
const AES_OPENCL: &str = include_str!("aes_gpu/OpenCL-AES/eng_opencl_aes.cl");

fn u8_slice_to_u32_vec(input: &[u8]) -> Vec<u32> {
    assert_eq!(input.len() % 4, 0);

    input
        .chunks_exact(4)
        .map(|chunk| chunk.try_into().unwrap())
        .map(|chunk: [u8; 4]| u32::from_be_bytes(chunk))
        .collect()
}

fn u32_slice_to_uint4_vec(input: &[u32]) -> Vec<Uint4> {
    assert_eq!(input.len() % 4, 0);

    input
        .chunks_exact(4)
        .map(|chunk| chunk.try_into().unwrap())
        .map(|chunk: [u32; 4]| Uint4::from(chunk))
        .collect()
}

fn uint4_slice_to_u8_vec(input: &[Uint4]) -> Vec<u8> {
    input.iter()
        .flat_map(|chunks| chunks.deref())
        .flat_map(|chunks: &u32| chunks.to_be_bytes().as_ref().to_owned())
        .collect()
}

fn main() -> ocl::Result<()> {
    let key = vec![210, 51, 245, 243, 109, 154, 58, 127, 99, 229, 195, 34, 103, 170, 183, 16, 61, 83, 196, 156, 124, 20, 16, 161, 3, 25, 180, 170, 26, 19, 163, 12];
    let block = vec![206, 213, 196, 136, 255, 138, 90, 170, 236, 76, 241, 48, 122, 18, 42, 189];

    let mut keys = [0u32; 60];
    aes_soft::setkey_enc_k256(&key, &mut keys);

    let mut res = [0u8; 16];
    aes_soft::block_enc_k256(&block, &mut res, &keys);
    println!("Correct result: {:?}", res);

    let pro_que = ProQue::builder()
        .src(AES_OPENCL)
        .dims(1 << 5)
        .build()?;

    let state = pro_que.buffer_builder::<Uint4>()
        .flags(flags::MEM_READ_WRITE)
        .len(1)
        .copy_host_slice(
            &u32_slice_to_uint4_vec(
                &u8_slice_to_u32_vec(&block)
            )
        )
        .build()?;

    let round_keys = pro_que.buffer_builder::<Uint4>()
        .flags(flags::MEM_READ_ONLY)
        .len(15)
        .copy_host_slice(
            &u32_slice_to_uint4_vec(&keys)
        )
        .build()?;

    let kernel = pro_que.kernel_builder("AES_encrypt")
        .arg(&state)
        .arg(&round_keys)
        .arg(14)
        .build()?;

    unsafe { kernel.enq()?; }

    let mut res = vec![Uint4::from([0u32; 4])];
    state.read(res.as_mut_slice()).enq()?;

    println!("GPU result: {:?}", uint4_slice_to_u8_vec(&res));

//    println!("The value at index [{}] is now '{}'!", 200007, vec[200007]);
    Ok(())
}
