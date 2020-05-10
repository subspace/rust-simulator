mod utils;

use crate::BLOCK_SIZE;
use crate::PIECE_SIZE;
use ocl::{
    core::{
        build_program, create_buffer, create_command_queue, create_context, create_kernel,
        create_program_with_source, enqueue_kernel, enqueue_read_buffer, enqueue_write_buffer,
        finish, set_kernel_arg, ArgVal, CommandQueue, Context, ContextProperties, Event, Kernel,
        Mem, Uchar16, Uint,
    },
    flags, Device, MemFlags, OclPrm, Platform, Result,
};
use std::ffi::CString;

const AES_OPEN_CL: &str = include_str!("codec.cl");
const ROUND_KEYS_LENGTH_128: usize = 44;

struct CachedBuffer {
    mem: Mem,
    buffer_size: usize,
}

pub struct Codec {
    buffer_state: Option<CachedBuffer>,
    buffer_iv: Option<CachedBuffer>,
    buffer_round_keys: Mem,
    context: Context,
    por_128_enc_kernel: Kernel,
    por_128_dec_kernel: Kernel,
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

        let por_128_enc_kernel = create_kernel(&program, "por_128_enc")?;
        let por_128_dec_kernel = create_kernel(&program, "por_128_dec")?;

        let buffer_round_keys = unsafe {
            create_buffer(
                &context,
                flags::MEM_READ_ONLY | flags::MEM_ALLOC_HOST_PTR,
                ROUND_KEYS_LENGTH_128,
                None::<&[Uint]>,
            )?
        };

        set_kernel_arg(&por_128_enc_kernel, 2, ArgVal::mem(&buffer_round_keys))?;
        set_kernel_arg(&por_128_dec_kernel, 2, ArgVal::mem(&buffer_round_keys))?;

        let buffer_state = Default::default();
        let buffer_iv = Default::default();
        Ok(Self {
            buffer_state,
            buffer_iv,
            buffer_round_keys,
            context,
            por_128_enc_kernel,
            por_128_dec_kernel,
            queue,
        })
    }

    /// Takes plaintext input that is multiple of piece size (4096 bytes), same number of IVs and
    /// expanded round keys
    ///
    /// Produces ciphertext
    pub fn por_128_enc(
        &mut self,
        input: &[u8],
        ivs: &[u128],
        keys: &[u32; ROUND_KEYS_LENGTH_128],
    ) -> Result<Vec<u8>> {
        assert_eq!(input.len() % PIECE_SIZE, 0);

        let blocks_count = input.len() / PIECE_SIZE;
        assert_eq!(blocks_count, ivs.len());

        let buffer_state = Self::validate_or_allocate_buffer::<Uchar16>(
            &self.context,
            &mut self.buffer_state,
            input.len(),
            flags::MEM_READ_WRITE | flags::MEM_ALLOC_HOST_PTR,
        )?;

        let buffer_ivs = Self::validate_or_allocate_buffer::<Uchar16>(
            &self.context,
            &mut self.buffer_iv,
            ivs.len(),
            flags::MEM_READ_WRITE | flags::MEM_ALLOC_HOST_PTR,
        )?;

        set_kernel_arg(&self.por_128_enc_kernel, 0, ArgVal::mem(&buffer_state))?;
        set_kernel_arg(&self.por_128_enc_kernel, 1, ArgVal::mem(&buffer_ivs))?;

        {
            unsafe {
                enqueue_write_buffer(
                    &self.queue,
                    &buffer_state,
                    true,
                    0,
                    &utils::u8_slice_to_uchar16_vec(input),
                    None::<Event>,
                    None::<&mut Event>,
                )?;
            }
        }

        {
            unsafe {
                enqueue_write_buffer(
                    &self.queue,
                    &buffer_ivs,
                    true,
                    0,
                    &utils::u128_slice_to_uchar16_vec(ivs),
                    None::<Event>,
                    None::<&mut Event>,
                )?;
            }
        }

        {
            unsafe {
                enqueue_write_buffer(
                    &self.queue,
                    &self.buffer_round_keys,
                    true,
                    0,
                    &utils::u32_slice_to_uint_vec(keys),
                    None::<Event>,
                    None::<&mut Event>,
                )?;
            }
        }

        unsafe {
            enqueue_kernel(
                &self.queue,
                &self.por_128_enc_kernel,
                1,
                None,
                // TODO: This will not handle too big inputs that exceed VRAM
                &[blocks_count, 0, 0],
                None,
                None::<Event>,
                None::<&mut Event>,
            )
        }?;

        let mut output = Vec::<u8>::with_capacity(input.len());
        {
            let mut result = Uchar16::from([0u8; BLOCK_SIZE]);
            for offset in (0..input.len()).step_by(BLOCK_SIZE) {
                unsafe {
                    enqueue_read_buffer(
                        &self.queue,
                        &buffer_state,
                        true,
                        offset,
                        &mut result,
                        None::<Event>,
                        None::<&mut Event>,
                    )?;
                }
                output.extend_from_slice(&result);
            }
        }

        finish(&self.queue)?;

        Ok(output)
    }

    /// Takes ciphertext input that is multiple of piece size (4096 bytes), same number of IVs and
    /// expanded round keys
    ///
    /// Produces plaintext
    pub fn por_128_dec(
        &mut self,
        input: &[u8],
        ivs: &[u128],
        keys: &[u32; ROUND_KEYS_LENGTH_128],
    ) -> Result<Vec<u8>> {
        assert_eq!(input.len() % PIECE_SIZE, 0);

        let blocks_count = input.len() / PIECE_SIZE;
        assert_eq!(blocks_count, ivs.len());

        let buffer_state = Self::validate_or_allocate_buffer::<Uchar16>(
            &self.context,
            &mut self.buffer_state,
            input.len(),
            flags::MEM_READ_WRITE | flags::MEM_ALLOC_HOST_PTR,
        )?;

        let buffer_ivs = Self::validate_or_allocate_buffer::<Uchar16>(
            &self.context,
            &mut self.buffer_iv,
            ivs.len(),
            flags::MEM_READ_WRITE | flags::MEM_ALLOC_HOST_PTR,
        )?;

        set_kernel_arg(&self.por_128_dec_kernel, 0, ArgVal::mem(&buffer_state))?;
        set_kernel_arg(&self.por_128_dec_kernel, 1, ArgVal::mem(&buffer_ivs))?;

        {
            unsafe {
                enqueue_write_buffer(
                    &self.queue,
                    &buffer_state,
                    true,
                    0,
                    &utils::u8_slice_to_uchar16_vec(input),
                    None::<Event>,
                    None::<&mut Event>,
                )?;
            }
        }

        {
            unsafe {
                enqueue_write_buffer(
                    &self.queue,
                    &buffer_ivs,
                    true,
                    0,
                    &utils::u128_slice_to_uchar16_vec(ivs),
                    None::<Event>,
                    None::<&mut Event>,
                )?;
            }
        }

        {
            unsafe {
                enqueue_write_buffer(
                    &self.queue,
                    &self.buffer_round_keys,
                    true,
                    0,
                    &utils::u32_slice_to_uint_vec(keys),
                    None::<Event>,
                    None::<&mut Event>,
                )?;
            }
        }

        unsafe {
            enqueue_kernel(
                &self.queue,
                &self.por_128_dec_kernel,
                1,
                None,
                // TODO: This will not handle too big inputs that exceed VRAM
                &[blocks_count, 0, 0],
                None,
                None::<Event>,
                None::<&mut Event>,
            )
        }?;

        let mut output = Vec::<u8>::with_capacity(input.len());
        {
            let mut result = Uchar16::from([0u8; BLOCK_SIZE]);
            for offset in (0..input.len()).step_by(BLOCK_SIZE) {
                unsafe {
                    enqueue_read_buffer(
                        &self.queue,
                        &buffer_state,
                        true,
                        offset,
                        &mut result,
                        None::<Event>,
                        None::<&mut Event>,
                    )?;
                }
                output.extend_from_slice(&result);
            }
        }

        finish(&self.queue)?;

        Ok(output)
    }

    fn validate_or_allocate_buffer<T: OclPrm>(
        context: &Context,
        buffer: &mut Option<CachedBuffer>,
        buffer_size: usize,
        flags: MemFlags,
    ) -> Result<Mem> {
        if let Some(cached_buffer) = buffer {
            if cached_buffer.buffer_size == buffer_size {
                return Ok(cached_buffer.mem.clone());
            }
        }

        let mem = unsafe { create_buffer(context, flags, buffer_size, None::<&[T]>)? };
        buffer.replace({
            let mem = mem.clone();
            CachedBuffer { mem, buffer_size }
        });

        Ok(mem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes_soft;
    use crate::crypto;

    #[test]
    fn test() {
        let mut codec = Codec::new().unwrap();

        // PoR
        let iv = vec![13u128];
        let id = crypto::random_bytes_32();
        let input = crypto::random_bytes_4096();
        let correct_encryption =
            crypto::por_encode_single_block_software(&input, &id, iv[0] as usize).to_vec();

        let mut keys = [0u32; 44];
        aes_soft::setkey_enc_k128(&id, &mut keys);

        let encryption = codec.por_128_enc(&input, &iv, &keys).unwrap();
        assert_eq!(correct_encryption, encryption);

        let ivs = vec![13u128, 13u128];
        let encryptions = codec
            .por_128_enc(
                &(0..2)
                    .flat_map(|_| input.as_ref().to_vec())
                    .collect::<Vec<u8>>()
                    .as_ref(),
                &ivs,
                &keys,
            )
            .unwrap();
        assert_eq!(
            encryptions[..PIECE_SIZE].to_vec(),
            encryptions[PIECE_SIZE..].to_vec()
        );
        assert_eq!(correct_encryption, encryptions[PIECE_SIZE..].to_vec());

        // Simple test, unrelated, but I had to put it somewhere
        assert_eq!(
            input.to_vec(),
            crypto::por_decode_single_block_software(
                &crypto::por_encode_single_block_software(&input, &id, ivs[0] as usize),
                &id,
                ivs[0] as usize
            )
            .to_vec()
        );

        let mut keys = [0u32; 44];
        aes_soft::setkey_dec_k128(&id, &mut keys);

        let decryption = codec.por_128_dec(&encryption, &iv, &keys).unwrap();
        assert_eq!(input.to_vec(), decryption);

        let decryptions = codec.por_128_dec(&encryptions, &ivs, &keys).unwrap();
        assert_eq!(
            decryptions[..PIECE_SIZE].to_vec(),
            decryptions[PIECE_SIZE..].to_vec()
        );
        assert_eq!(input.to_vec(), decryptions[PIECE_SIZE..].to_vec());
    }
}
