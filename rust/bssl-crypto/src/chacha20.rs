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

//! ChaCha20 stream cipher.
//!
//! ChaCha20 is a stream cipher described in [RFC 8439].
//!
//! ```
//! use bssl_crypto::chacha20;
//!
//! let key = bssl_crypto::rand_array();
//! let nonce = bssl_crypto::rand_array();
//! let plaintext = *b"hello world";
//! let mut buf = plaintext;
//!
//! chacha20::apply_keystream(&key, &nonce, 0, &mut buf);
//! chacha20::apply_keystream(&key, &nonce, 0, &mut buf);
//! assert_eq!(buf, plaintext);
//! ```
//!
//! [RFC 8439]: https://datatracker.ietf.org/doc/html/rfc8439

use crate::{FfiMutSlice, FfiSlice};

/// ChaCha20 key size in bytes.
pub const KEY_LEN: usize = 32;

/// ChaCha20 nonce size in bytes.
pub const NONCE_LEN: usize = 12;

/// Encrypts or decrypts `data` in place using ChaCha20 with `key`, `nonce`,
/// and initial 32-bit block `counter`. Calling this function twice with the
/// same inputs yields the same `data`.
///
/// Because ChaCha20 XORs its generated keystream with `data`, encryption and
/// decryption are the same operation.
///
/// Reusing a `(key, nonce, counter)` combination is not secure. On block
/// counter overflow past `u32::MAX`, the counter wraps around as in BoringSSL's
/// `CRYPTO_chacha_20`, which callers should avoid.
pub fn apply_keystream(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    counter: u32,
    data: &mut [u8],
) {
    // Safety:
    // - `data.as_mut_ffi_ptr()` and `data.as_ffi_ptr()` are equal (or both null when `data` is
    //   empty), which `CRYPTO_chacha_20` explicitly allows for in-place operation over `data.len()`
    //   bytes.
    // - `key` and `nonce` point to valid 32-byte and 12-byte arrays.
    unsafe {
        bssl_sys::CRYPTO_chacha_20(
            data.as_mut_ffi_ptr(),
            data.as_ffi_ptr(),
            data.len(),
            key.as_ffi_ptr(),
            nonce.as_ffi_ptr(),
            counter,
        );
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod test {
    use super::*;
    use crate::test_helpers::decode_hex;

    #[test]
    fn chacha20_test_vector_and_counter_offset() {
        // Test vector from crypto/chacha/chacha_test.cc (first two 64-byte blocks).
        let key: [u8; KEY_LEN] =
            decode_hex("98bef1469be7269837a45bfbc92a5a6ac762507cf96443bf33b96b1bd4c6f8f6");
        let nonce: [u8; NONCE_LEN] = decode_hex("44e792d63335abb1582e9253");
        let input: [u8; 128] = decode_hex(
            "5828d530362c605529f8e18cae151526f23a73a0f312a388\
             5f2b74233dc90523c654491e448814d9da3715dcb7e423b3\
             9d7e166835fc026dcc8ae5dd5fe4d2566f129c9c7d6a3848\
             bddfd9ac1ba24dc543043cd799e1a7139c51c26df9cf073b\
             e4bf93a3a9b4c5f01ae48d5fc6c47c697ade1ac1c9cfc24e\
             7a252c32e917ba68",
        );
        let expected: [u8; 128] = decode_hex(
            "54306a13da596b6d5949c8c5ab26d48aadc03daf14b915b8\
             cadf17a703d3c50601ef21dda30b9e48b85e0b879f952368\
             8569d25daf57e927113d49faf108cc15ec1d1916129bc866\
             1ffa2c93f4991127310ed8464740117001cae85bc591c83a\
             dcaaf34b80e5bc03d08972bcce2a760cf5da4c10063541b1\
             e6b4aa7aeff0624a",
        );

        let mut buf = input;
        apply_keystream(&key, &nonce, 42, &mut buf);
        assert_eq!(buf, expected);

        // Decrypting in place with the same key, nonce, and counter recovers the input.
        apply_keystream(&key, &nonce, 42, &mut buf);
        assert_eq!(buf, input);

        // Encrypting the second 64-byte block directly with counter = 43 matches expected[64..].
        let mut second_block = [0u8; 64];
        second_block.copy_from_slice(&input[64..128]);
        apply_keystream(&key, &nonce, 43, &mut second_block);
        assert_eq!(&second_block[..], &expected[64..128]);
    }

    #[test]
    fn chacha20_empty_slice() {
        let key = [0x11u8; KEY_LEN];
        let nonce = [0x22u8; NONCE_LEN];
        let mut empty: [u8; 0] = [];
        apply_keystream(&key, &nonce, 0, &mut empty);
    }
}
