## Rust Simulator

A collection of optimal benchmarking scripts for analyzing the security of the Subspace Ledger.

Install [Rust](https://www.rust-lang.org/tools/install)

```bash
git clone https://github.com/subspace/rust-simulator.git
cd rust-simulator
cargo run --release /optional/storage/path/for/plotting
```

Plot will be written to `./src/results/plot.bin` unless a path is provided as the first argument on run. Allow at least 110 GB of free space to run tests.
