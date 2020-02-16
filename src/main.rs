use std::time::Instant;

mod aes_open_cl;
mod aes_soft;

const ROUND_KEYS: usize = 60;
const BLOCK_SIZE: usize = 16;
const ITERATIONS: usize = 10;

fn main() -> ocl::Result<()> {
    let key = vec![
        210, 51, 245, 243, 109, 154, 58, 127, 99, 229, 195, 34, 103, 170, 183, 16, 61, 83, 196,
        156, 124, 20, 16, 161, 3, 25, 180, 170, 26, 19, 163, 12,
    ];
    let block = vec![
        206, 213, 196, 136, 255, 138, 90, 170, 236, 76, 241, 48, 122, 18, 42, 189,
    ];

    let mut keys = [0u32; ROUND_KEYS];
    aes_soft::setkey_dec_k256(&key, &mut keys);

    let mut res = [0u8; BLOCK_SIZE];
    {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            aes_soft::block_dec_k256(&block, &mut res, &keys);
        }
        println!("{}us", start.elapsed().as_micros());
    }
    println!("Correct result: {:?}", res);

    let aes_256_opencl = aes_open_cl::Aes256OpenCL::new()?;

    let mut output = Default::default();
    {
        let start = Instant::now();
        for _ in 0..1 {
            output = aes_256_opencl.decrypt(&block, &keys)?;
        }
        println!("{}us", start.elapsed().as_micros());
    }

    println!("GPU result: {:?}", output);

    Ok(())
}
