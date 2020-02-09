use ocl::core::{
    self, build_program, create_buffer, create_command_queue, create_context, create_kernel,
    create_program_with_source, enqueue_kernel, enqueue_read_buffer, enqueue_write_buffer,
    set_kernel_arg, ArgVal, ContextProperties, Event, Uchar, Uchar16, Uchar4, Uint,
};
use ocl::flags;
use ocl::Device;
use ocl::Platform;
use std::convert::TryInto;
use std::ffi::CString;

mod aes_soft;

const AES_OPENCL: &str = include_str!("aes_kernels.cl");
const ROUND_KEYS: usize = 60;
const BLOCK_SIZE: usize = 16;

fn u8_slice_to_uchar4_vec(input: &[u8]) -> Vec<Uchar4> {
    assert_eq!(input.len() % 4, 0);

    input
        .chunks_exact(4)
        .map(|chunk| chunk.try_into().unwrap())
        .map(|chunk: [u8; 4]| Uchar4::from(chunk))
        .collect()
}

fn u32_slice_to_uchar4_vec(input: &[u32]) -> Vec<Uchar4> {
    assert_eq!(input.len() % 4, 0);

    input
        .iter()
        .map(|chunk| Uchar4::from(chunk.to_le_bytes()))
        .collect()
}

fn main() -> ocl::Result<()> {
    let key = vec![
        210, 51, 245, 243, 109, 154, 58, 127, 99, 229, 195, 34, 103, 170, 183, 16, 61, 83, 196,
        156, 124, 20, 16, 161, 3, 25, 180, 170, 26, 19, 163, 12,
    ];
    let block = vec![
        206, 213, 196, 136, 255, 138, 90, 170, 236, 76, 241, 48, 122, 18, 42, 189,
    ];

    let mut keys = [0u32; ROUND_KEYS];
    aes_soft::setkey_enc_k256(&key, &mut keys);

    let mut res = [0u8; BLOCK_SIZE];
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

    let encrypt_kernel = create_kernel(&program, "aes_256")?;

    let buffer_in = unsafe {
        create_buffer(
            &context,
            flags::MEM_READ_ONLY | flags::MEM_ALLOC_HOST_PTR,
            BLOCK_SIZE,
            None::<&[Uchar]>,
        )?
    };
    let buffer_out = unsafe {
        create_buffer(
            &context,
            flags::MEM_WRITE_ONLY | flags::MEM_ALLOC_HOST_PTR,
            BLOCK_SIZE,
            None::<&[Uchar]>,
        )?
    };
    let buffer_round_keys =
        unsafe { create_buffer(&context, flags::MEM_READ_ONLY, ROUND_KEYS, None::<&[Uint]>)? };

    set_kernel_arg(&encrypt_kernel, 0, ArgVal::mem(&buffer_in))?;
    set_kernel_arg(&encrypt_kernel, 1, ArgVal::mem(&buffer_out))?;
    set_kernel_arg(&encrypt_kernel, 2, ArgVal::mem(&buffer_round_keys))?;
    // Init end

    {
        let mut event = Event::null();
        unsafe {
            enqueue_write_buffer(
                &queue,
                &buffer_in,
                true,
                0,
                &&u8_slice_to_uchar4_vec(&block),
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
                &u32_slice_to_uchar4_vec(&keys),
                None::<Event>,
                Some(&mut event),
            )?;
        }
    }

    unsafe {
        enqueue_kernel(
            &queue,
            &encrypt_kernel,
            1,
            None,
            // TODO: Figure out what is the optimal size
            &[128, 0, 0],
            None,
            None::<Event>,
            None::<&mut Event>,
        )
    }?;

    let mut res = vec![Uchar16::from([0u8; BLOCK_SIZE])];
    {
        let mut event = Event::null();
        unsafe {
            enqueue_read_buffer(
                &queue,
                &buffer_out,
                true,
                0,
                &mut res,
                None::<Event>,
                Some(&mut event),
            )?;
        };
    }

    println!("GPU result: {:?}", res);

    Ok(())
}
