# Contributing

Keep changes focused, document public behavior, and preserve Rust 1.85 support.

Before opening a pull request, run:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo test --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo package --allow-dirty
cargo deny check
```

Kernel ABI changes must cite an upstream tag or commit and update
`docs/kernel-abi.md`. Live tests must state their privileges and must not
replace an existing DAMON configuration.
