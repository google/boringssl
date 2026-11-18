---
name: update-rust-deps
description: How to update Rust crate dependencies in rust/Cargo.lock.
---

# Updating Rust Dependencies (`rust/Cargo.lock`)

1.  **Update [rust/Cargo.lock](../../../rust/Cargo.lock)**:
    ```bash
    cd rust && cargo update
    ```
    (Pass `-p <crate>` for a targeted update.)

2.  **Build and Verify**:
    *   Build BoringSSL with Rust bindings enabled as described in [rust/bssl-sys/README.md](../../../rust/bssl-sys/README.md).
    *   Run workspace tests and the checks described in [rust/bssl-crypto/README.md](../../../rust/bssl-crypto/README.md) (`cargo test` and `cargo clippy --all-targets` in `rust/`; `cargo deny check` in each crate directory that has a `deny.toml`: `bssl-crypto`, `bssl-tls`, `bssl-rustls-adapters`).
    *   Note: CQ enforces `cargo build` and `cargo test` (`--all-targets` and `--all-features`). `cargo clippy` and `cargo deny check` are not enforced by CQ, so treat a missing local `cargo-deny` as non-blocking (while still respecting `deny.toml` license and duplicate-version rules).
