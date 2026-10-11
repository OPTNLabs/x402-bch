# x402-BCH Rust package

The Rust package contains the `x402-chain-bch` crate and its workspace-owned
toolchain configuration. It is independent of the other language packages and
keeps its conformance fixture under `spec/conformance/v1`.

Run the crate tests from this directory:

```bash
cargo test --locked -p x402-chain-bch --lib
```

The crate README in `x402-chain-bch/README.md` documents the BCH transaction,
wallet, provider, and settlement APIs.
