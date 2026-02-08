// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![deny(
    missing_docs,
    unsafe_op_in_unsafe_fn,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used
)]
#![allow(private_bounds)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

//! BoringSSL-backed [`rustls`] adapters.
//!
//! This crate provides a [`rustls::crypto::CryptoProvider`] backed by
//! BoringSSL, for use with the [`rustls`] TLS stack. See
//! [`rustls_provider`] for details and examples.

extern crate alloc;
extern crate core;

#[cfg(feature = "rustls-adapters")]
pub mod rustls_provider;
