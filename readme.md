## Rust Simulator

A collection of optimal benchmarking scripts for analyzing the security of the Subspace Ledger.

Install [Rust](https://www.rust-lang.org/tools/install)

```bash
git clone https://github.com/subspace/rust-simulator.git
cd rust-simulator
cargo run --release /optional/storage/path/for/plotting
```

Plot will be written to `./src/results/plot.bin` unless a path is provided as the first argument on run. Allow at least 110 GB of free space to run tests.

#### Installing system dependencies for OpenCL
Besides Rust compiler itself you'll need following components installed on your machine:
* gcc
* OpenCL drivers and development files

On Ubuntu 18.04 for AMD GPUs they can be installed like this:
```bash
sudo apt-get install gcc ocl-icd-opencl-dev mesa-opencl-icd
```
On Ubuntu 18.04 for Intel iGPU they can be installed like this:
```bash
sudo apt-get install gcc ocl-icd-opencl-dev beignet-opencl-icd
```

#### Running test and benchmarks
To run tests execute regular `cargo test`, for benchmarks `cargo bench`
