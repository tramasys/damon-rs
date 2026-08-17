# Contributing

Contributions are welcome. Keep changes focused, document public API behavior,
and preserve compatibility with the declared MSRV.

Before opening a pull request, run:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo package --allow-dirty
```

Kernel ABI changes should cite the exact upstream tag or commit and update
`docs/kernel-abi.md`. Tests that need a live DAMON instance should state the
required kernel configuration and privileges and must not replace an existing
system configuration.

