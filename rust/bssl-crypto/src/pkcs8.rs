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

//! PKCS#8 support
//!
//! This module houses PKCS#8 private key parsing facility.

use crate::{ec, ecdsa, ed25519, rsa, scoped::EvpPkey};

/// PKCS#8 Signing Key
pub enum SigningKey {
    /// An RSA private key
    Rsa(rsa::PrivateKey),
    /// An NIST P-256 private key
    EcP256(ecdsa::PrivateKey<ec::P256>),
    /// An NIST P-384 private key
    EcP384(ecdsa::PrivateKey<ec::P384>),
    /// An Ed25519 key
    Ed25519(ed25519::PrivateKey),
}

impl SigningKey {
    /// Parse a DER-encoded PKCS#8 PrivateKeyInfo structure.
    pub fn from_der_private_key_info(data: &[u8]) -> Option<Self> {
        // Safety:
        // - data buffer is guaranteed to be initialised
        // - all the algorithm descriptors are static items and remain live at call time
        let mut pkey = unsafe {
            EvpPkey::from_der_private_key_info(
                data,
                &[
                    bssl_sys::EVP_pkey_rsa(),
                    bssl_sys::EVP_pkey_ec_p256(),
                    bssl_sys::EVP_pkey_ec_p384(),
                    bssl_sys::EVP_pkey_ed25519(),
                ],
            )
        }?;
        // Safety: pkey is initialised
        let id = unsafe { bssl_sys::EVP_PKEY_id(pkey.as_ffi_ptr()) };
        unsafe {
            // Safety: the pkey is completely owned here
            Some(match id {
                bssl_sys::EVP_PKEY_RSA => Self::Rsa(rsa::PrivateKey::from_evp_pkey(pkey)?),
                bssl_sys::EVP_PKEY_EC => {
                    let key = ec::Key::from_evp_pkey(pkey)?;
                    match key.get_group()? {
                        ec::Group::P256 => Self::EcP256(ecdsa::PrivateKey::from_ec_key(key)),
                        ec::Group::P384 => Self::EcP384(ecdsa::PrivateKey::from_ec_key(key)),
                    }
                }
                bssl_sys::EVP_PKEY_ED25519 => {
                    // Safety: we are sure that the key is for ED25519
                    Self::Ed25519(ed25519::PrivateKey::from_evp_pkey(pkey))
                }
                _ => return None,
            })
        }
    }
}
