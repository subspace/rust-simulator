extern crate ocl;
use ocl::core::{
    build_program, create_buffer, create_command_queue, create_context, create_kernel,
    create_program_with_source, enqueue_kernel, enqueue_read_buffer, enqueue_write_buffer,
    set_kernel_arg, ArgVal, ContextProperties, Event,
};
use ocl::flags;
use ocl::prm::Uint4;
use ocl::Device;
use ocl::Platform;
use std::convert::TryInto;
use std::ffi::CString;
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
    input
        .iter()
        .flat_map(|chunks| chunks.deref())
        .flat_map(|chunks: &u32| chunks.to_be_bytes().as_ref().to_owned())
        .collect()
}

fn main() -> ocl::Result<()> {
    let rounds: usize = 15;
    let key = vec![
        210, 51, 245, 243, 109, 154, 58, 127, 99, 229, 195, 34, 103, 170, 183, 16, 61, 83, 196,
        156, 124, 20, 16, 161, 3, 25, 180, 170, 26, 19, 163, 12,
    ];
    let block = vec![
        206, 213, 196, 136, 255, 138, 90, 170, 236, 76, 241, 48, 122, 18, 42, 189,
    ];

    let mut keys = [0u32; 60];
    aes_soft::setkey_enc_k256(&key, &mut keys);

    let mut res = [0u8; 16];
    aes_soft::block_enc_k256(&block, &mut res, &keys);
    println!("Correct result: {:?}", res);

    // Init start
    let platform = Platform::first()?;

    let device = Device::first(platform)?;

    let context_properties = ContextProperties::new().platform(platform);
    let context = create_context(Some(&context_properties), &[&device], None, None)?;

    let queue = create_command_queue(&context, &device, None)?;

    let program = create_program_with_source(&context, &[CString::new(AES_OPENCL)?])?;

    let options = CString::new("").unwrap();
    build_program(&program, Some(&[&device]), &options, None, None)?;

    let encrypt_kernel = create_kernel(&program, "AES_encrypt".to_string())?;

    let max_buffer_size = 128 * 1024 * 1024;
    let buffer_state = unsafe {
        create_buffer(
            &context,
            flags::MEM_READ_WRITE | flags::MEM_ALLOC_HOST_PTR,
            max_buffer_size,
            None::<&[Uint4]>,
        )?
    };
    let buffer_round_keys = unsafe {
        create_buffer(
            &context,
            flags::MEM_READ_ONLY,
            16 * rounds,
            None::<&[Uint4]>,
        )?
    };

    set_kernel_arg(&encrypt_kernel, 0, ArgVal::mem(&buffer_state))?;
    set_kernel_arg(&encrypt_kernel, 1, ArgVal::mem(&buffer_round_keys))?;
    set_kernel_arg(&encrypt_kernel, 2, ArgVal::scalar(&(rounds as u32)))?;
    // Init end

    {
        let mut event = Event::null();
        unsafe {
            enqueue_write_buffer(
                &queue,
                &buffer_state,
                true,
                0,
                &u32_slice_to_uint4_vec(&u8_slice_to_u32_vec(&block)),
                None::<Event>,
                Some(&mut event),
            )?;
        }
    }

    {
        let mut event = Event::null();
        unsafe {
            enqueue_write_buffer(
                &queue,
                &buffer_round_keys,
                true,
                0,
                &u32_slice_to_uint4_vec(&keys),
                None::<Event>,
                Some(&mut event),
            )?;
        }
    }

    {
        let local_work_dims: [usize; 3] = [128, 0, 0];
        let global_work_dims: [usize; 3] = [
            (15 + local_work_dims[0] - 1) / local_work_dims[0] * local_work_dims[0],
            0,
            0,
        ];
        unsafe {
            enqueue_kernel(
                &queue,
                &encrypt_kernel,
                1,
                None,
                &global_work_dims,
                Some(local_work_dims),
                None::<Event>,
                None::<&mut Event>,
            )
        }?;
    }

    let mut res = vec![Uint4::from([0u32; 4])];
    {
        let mut event = Event::null();
        unsafe {
            enqueue_read_buffer(
                &queue,
                &buffer_state,
                true,
                0,
                &mut res,
                None::<Event>,
                Some(&mut event),
            )?;
        };
    }

    println!("GPU result: {:?}", uint4_slice_to_u8_vec(&res));

    Ok(())
}
