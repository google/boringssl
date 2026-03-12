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

//! Private keys
//!
//! The private keys processed here can be paired with certificates to perform further
//! authentication.
//!
//! ```rust
//! # use bssl_x509::certificates::X509Certificate;
//! # use bssl_x509::keys::PrivateKey;
//! # let pem = include_bytes!("tests/BoringSSLTestCA.key");
//! # let crt = include_bytes!("tests/BoringSSLTestCA.crt");
//! # let crt = X509Certificate::parse_one_from_pem(crt).unwrap();
//! let key = PrivateKey::from_pem(
//!     pem, /*password_callback=*/ || b"BoringSSL is awesome!").unwrap();
//! assert!(crt.matches_private_key(&key));
//! ```

use core::ffi::{c_char, c_int, c_void};
use core::panic::AssertUnwindSafe;
use core::ptr::NonNull;
use core::ptr::null_mut;

use bssl_crypto::FfiSlice;
use bssl_macros::bssl_enum;

use crate::ffi::maybe_panic;
use crate::{errors::PkiError, ffi::Bio};

bssl_enum! {
    /// EVP public key algorithm types.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum PrivateKeyAlgorithm: i32 {
        /// RSA
        Rsa = bssl_sys::EVP_PKEY_RSA as i32,
        /// RSA-PSS
        RsaPss = bssl_sys::EVP_PKEY_RSA_PSS as i32,
        /// EC
        Ec = bssl_sys::EVP_PKEY_EC as i32,
        /// Ed25519
        Ed25519 = bssl_sys::EVP_PKEY_ED25519 as i32,
        /// X25519
        X25519 = bssl_sys::EVP_PKEY_X25519 as i32,
        /// DSA
        Dsa = bssl_sys::EVP_PKEY_DSA as i32,
        /// DH
        Dh = bssl_sys::EVP_PKEY_DH as i32,
    }
}

/// A private key.
pub struct PrivateKey(NonNull<bssl_sys::EVP_PKEY>);
// Safety: `PrivateKey` is locked as immutable at this type state.
unsafe impl Send for PrivateKey {}
unsafe impl Sync for PrivateKey {}

impl PrivateKey {
    /// Parse a `PrivateKey` from PEM encoding.
    pub fn from_pem<'a, F: 'a + FnMut() -> &'a [u8]>(
        pem: &[u8],
        mut password_callback: F,
    ) -> Result<Self, PkiError> {
        let mut bio = Bio::from_bytes(pem)?;

        let mut priv_key = null_mut();

        unsafe extern "C" fn write_password<'a, F: 'a + FnMut() -> &'a [u8]>(
            out: *mut c_char,
            size: c_int,
            _rwflag: c_int,
            ctxt: *mut c_void,
        ) -> c_int {
            if size < 0 {
                return -1;
            }
            let password_callback = AssertUnwindSafe(unsafe {
                // Safety: `ctxt` is a valid callback pointer and outlived by `'a`, so it must be
                // valid when invoked.
                &mut *(ctxt as *mut F)
            });
            let get_password = move || {
                let AssertUnwindSafe(pass_callback) = { password_callback };
                let password = pass_callback();
                let Ok(len) = password.len().try_into() else {
                    return -1;
                };
                if len > size {
                    return -1;
                }
                unsafe {
                    // Safety:
                    // - `src` is valid and not larger than `out`.
                    // - `out` is valid per BoringSSL specification.
                    // - `src` and `out` are both 1-aligned.
                    core::ptr::copy(password.as_ffi_void_ptr(), out as _, password.len());
                }
                len
            };
            maybe_panic(get_password)
        }

        let evp_pkey = unsafe {
            // Safety:
            // - the BIO is still valid;
            // - the `&raw mut priv_key` pointer is not null, so the function will allocate
            //   a new structure;
            // - the return value can be discarded since we provided a location to hold the handle,
            //   whose lifetime will be managed from this function.
            bssl_sys::PEM_read_bio_PrivateKey(
                bio.ptr(),
                &raw mut priv_key,
                Some(write_password::<'a, F>),
                &raw mut password_callback as _,
            )
        };
        NonNull::new(evp_pkey)
            .map(Self)
            .ok_or_else(PkiError::extract_lib_err)
    }

    /// Get the algorithm ID of the private key.
    ///
    /// This method returns [`None`] if the key algorithm is unrecognised.
    pub fn algorithm(&self) -> Option<PrivateKeyAlgorithm> {
        let id = unsafe {
            // Safety: self.0 is valid.
            bssl_sys::EVP_PKEY_id(self.ptr())
        };
        let id = i32::try_from(id).ok()?;
        PrivateKeyAlgorithm::try_from(id).ok()
    }

    /// This method releases ownership of the internal key handle.
    ///
    /// This method should only be used for cross-language interoperability.
    pub fn into_raw(self) -> *mut bssl_sys::EVP_PKEY {
        let ptr = self.ptr();
        core::mem::forget(self);
        ptr
    }

    pub(crate) fn ptr(&self) -> *mut bssl_sys::EVP_PKEY {
        self.0.as_ptr()
    }

    /// Extract the handle
    ///
    /// # Safety
    ///
    /// `self` **must** outlive the uses of the returned handle.
    /// Verify the callsite contract to honour the lifetime contracts.
    pub unsafe fn as_raw(&self) -> *mut bssl_sys::EVP_PKEY {
        self.ptr()
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        unsafe {
            // Safety: `self.0` is still valid at cloning.
            bssl_sys::EVP_PKEY_up_ref(self.ptr());
        }
        Self(self.0)
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe {
            // Safety: `self.0` is still valid at dropping.
            bssl_sys::EVP_PKEY_free(self.ptr());
        }
    }
}
