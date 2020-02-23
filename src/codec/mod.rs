mod utils;

use ocl::{
    core::{
        build_program, create_buffer, create_command_queue, create_context, create_kernel,
        create_program_with_source, enqueue_kernel, enqueue_read_buffer, enqueue_write_buffer,
        finish, set_kernel_arg, ArgVal, CommandQueue, Context, ContextProperties, Event, Kernel,
        Mem, Uchar16, Uint,
    },
    flags, Device, Platform, Result,
};
use std::ffi::CString;

const AES_OPEN_CL: &str = include_str!("codec.cl");
const ROUND_KEYS_LENGTH: usize = 60;
const BLOCK_SIZE: usize = 16;

pub struct Codec {
    buffer_round_keys: Mem,
    context: Context,
    // decrypt_kernel: Kernel,
    aes_256_enc_iterations_kernel: Kernel,
    queue: CommandQueue,
}

impl Codec {
    pub fn new() -> Result<Self> {
        let platform = Platform::first()?;

        let device = Device::first(platform)?;

        let context_properties = ContextProperties::new().platform(platform);
        let context = create_context(Some(&context_properties), &[&device], None, None)?;

        let queue = create_command_queue(&context, &device, None)?;

        let program = create_program_with_source(&context, &[CString::new(AES_OPEN_CL)?])?;

        let options = CString::new("").unwrap();
        build_program(&program, Some(&[&device]), &options, None, None)?;

        let aes_256_enc_iterations_kernel = create_kernel(&program, "aes_256_enc_iterations")?;
        // let decrypt_kernel = create_kernel(&program, "aes_256_dec")?;

        let buffer_round_keys = unsafe {
            create_buffer(
                &context,
                flags::MEM_READ_ONLY,
                ROUND_KEYS_LENGTH,
                None::<&[Uint]>,
            )?
        };

        set_kernel_arg(
            &aes_256_enc_iterations_kernel,
            2,
            ArgVal::mem(&buffer_round_keys),
        )?;
        // set_kernel_arg(&decrypt_kernel, 2, ArgVal::mem(&buffer_round_keys))?;

        Ok(Self {
            buffer_round_keys,
            context,
            // decrypt_kernel,
            aes_256_enc_iterations_kernel,
            queue,
        })
    }

    /// Takes plaintext input that is multiple of block size (16 bytes) and expanded round keys
    /// Produces ciphertext
    pub fn aes_256_enc_iterations(
        &self,
        input: &[u8],
        keys: &[u32; ROUND_KEYS_LENGTH],
        iterations: u32,
    ) -> Result<Vec<u8>> {
        assert_eq!(input.len() % BLOCK_SIZE, 0);

        let buffer_in = unsafe {
            create_buffer(
                &self.context,
                flags::MEM_READ_ONLY,
                input.len(),
                None::<&[Uchar16]>,
            )?
        };
        let buffer_out = unsafe {
            create_buffer(
                &self.context,
                flags::MEM_WRITE_ONLY,
                input.len(),
                None::<&[Uchar16]>,
            )?
        };

        // TODO: Set these to `null` afterwards?
        set_kernel_arg(
            &self.aes_256_enc_iterations_kernel,
            0,
            ArgVal::mem(&buffer_in),
        )?;
        set_kernel_arg(
            &self.aes_256_enc_iterations_kernel,
            1,
            ArgVal::mem(&buffer_out),
        )?;
        set_kernel_arg(
            &self.aes_256_enc_iterations_kernel,
            3,
            ArgVal::scalar(&iterations),
        )?;

        {
            let mut event = Event::null();
            unsafe {
                enqueue_write_buffer(
                    &self.queue,
                    &buffer_in,
                    true,
                    0,
                    &utils::u8_slice_to_uchar16_vec(input),
                    None::<Event>,
                    Some(&mut event),
                )?;
            }
        }

        {
            let mut event = Event::null();
            unsafe {
                enqueue_write_buffer(
                    &self.queue,
                    &self.buffer_round_keys,
                    true,
                    0,
                    &utils::u32_slice_to_uint_vec(keys),
                    None::<Event>,
                    Some(&mut event),
                )?;
            }
        }

        unsafe {
            let iterations = input.len() / BLOCK_SIZE;

            enqueue_kernel(
                &self.queue,
                &self.aes_256_enc_iterations_kernel,
                1,
                None,
                // TODO: This will not handle too big inputs that exceed VRAM
                &[iterations, 0, 0],
                None,
                None::<Event>,
                None::<&mut Event>,
            )
        }?;

        let mut output = Vec::<u8>::with_capacity(input.len());
        {
            let mut event = Event::null();
            let mut result = Uchar16::from([0u8; BLOCK_SIZE]);
            for offset in (0..input.len()).step_by(BLOCK_SIZE) {
                unsafe {
                    enqueue_read_buffer(
                        &self.queue,
                        &buffer_out,
                        true,
                        offset,
                        &mut result,
                        None::<Event>,
                        Some(&mut event),
                    )?;
                }
                output.extend_from_slice(&result);
            }
        }

        finish(&self.queue)?;

        Ok(output)
    }
}
