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

//! X.509 certificate verification process.
//!
//! To verify certificates, one may use [`X509Verifier`] which requires a fully constructed
//! [`X509Store`] certificate store, [`X509CertificateList`] a list of untrusted immediate
//! certificates and [`X509Certificate`] the final end-entity certificate.
//!
//! ```rust
//! # use bssl_x509::certificates::X509Certificate;
//! # use bssl_x509::store::{X509Store, X509StoreBuilder};
//! # use bssl_x509::verify::X509CertificateList;
//! # use bssl_x509::verify::X509Verifier;
//! # let ca = X509Certificate::parse_one_from_pem(include_bytes!("tests/BoringSSLTestCA.crt")).unwrap();
//! # let cert = X509Certificate::parse_one_from_pem(include_bytes!("tests/BoringSSLServerTest-RSA.crt")).unwrap();
//! # let chain = X509CertificateList::new();
//! # let mut store = X509StoreBuilder::new();
//! # store.add_cert(ca).unwrap();
//! # let store = store.build();
//! let mut verifier = X509Verifier::new(&cert, &chain, &store).unwrap();
//! assert!(verifier.verify().is_ok());
//! ```

use alloc::vec::Vec;
use core::{marker::PhantomData, mem::transmute, ptr::NonNull};

use crate::{
    certificates::X509Certificate,
    check_lib_error,
    errors::{PkiError, X509VerifyResult},
    store::X509Store,
};

/// A context for X.509 certificate verification.
///
/// This corresponds to `X509_STORE_CTX` in BoringSSL.
pub struct X509Verifier<'a> {
    ptr: NonNull<bssl_sys::X509_STORE_CTX>,
    verified: bool,
    _p: PhantomData<&'a ()>,
}

// Safety: X509_STORE_CTX is not thread-safe for concurrent access, but can be moved.
unsafe impl Send for X509Verifier<'_> {}

impl Drop for X509Verifier<'_> {
    fn drop(&mut self) {
        unsafe {
            // Safety: The pointer is valid and owned by this struct.
            bssl_sys::X509_STORE_CTX_free(self.ptr.as_ptr());
        }
    }
}

impl<'a> X509Verifier<'a> {
    /// Creates a new `X509StoreContext`.
    pub fn new(
        cert: &'a X509Certificate,
        chain: &'a X509CertificateList,
        store: &'a X509Store,
    ) -> Result<Self, PkiError> {
        let this = Self::alloc();
        check_lib_error!(unsafe {
            // Safety:
            // - `self.0` is valid.
            // - `store.as_raw()` returns a valid X509_STORE pointer.
            // - `cert.ptr()` returns a valid X509 pointer.
            // - `chain_ptr` is either NULL or a valid stack pointer.
            // - The input objects will outlive `'a`, so much so that the verifier is outlived by
            //   these objects.
            bssl_sys::X509_STORE_CTX_init(this.ptr(), store.as_raw(), cert.ptr(), chain.ptr())
        });
        Ok(this)
    }

    fn alloc() -> Self {
        let Some(ctx) = NonNull::new(unsafe {
            // Safety: This function creates a new object and returns NULL on allocation failure.
            bssl_sys::X509_STORE_CTX_new()
        }) else {
            panic!("allocation error");
        };

        Self {
            ptr: ctx,
            verified: false,
            _p: PhantomData,
        }
    }

    pub(crate) fn ptr(&self) -> *mut bssl_sys::X509_STORE_CTX {
        self.ptr.as_ptr()
    }

    /// Performs the certificate verification.
    ///
    /// Returns `Ok(())` if verification succeeds.
    /// Returns `Err(X509VerifyResult)` if verification fails.
    pub fn verify(&mut self) -> Result<(), X509VerifyResult> {
        self.verified = true;
        if unsafe {
            // Safety: `self.0` is valid. The context must have been initialized.
            bssl_sys::X509_verify_cert(self.ptr()) == 1
        } {
            Ok(())
        } else {
            Err(self.get_error())
        }
    }

    fn get_error(&self) -> X509VerifyResult {
        let error_code = unsafe {
            // Safety: `self.0` is valid.
            bssl_sys::X509_STORE_CTX_get_error(self.ptr())
        };
        X509VerifyResult::try_from(error_code as i32).unwrap_or(X509VerifyResult::Unspecified)
    }

    /// Returns the verified certificate chain.
    ///
    /// The first certificate will be the leaf certificate and the last certificate will be one of
    /// the trust anchor.
    ///
    /// This method returns [`None`] if [`Self::verify_cert`] has not been called.
    pub fn chain(&self) -> Option<Vec<X509Certificate>> {
        if !self.verified {
            return None;
        }
        let chain = NonNull::new(unsafe {
            // Safety: `self.0` is valid.
            bssl_sys::X509_STORE_CTX_get0_chain(self.ptr())
        })?;
        let chain: &X509CertificateList = unsafe {
            // Safety: `X509CertificateList` is a transparent wrapper around the handle
            transmute(&chain)
        };
        let mut res = Vec::new();
        for i in 0..chain.len() {
            res.push(chain.get(i)?);
        }
        Some(res)
    }
}

/// A list of certificates.
#[repr(transparent)]
pub struct X509CertificateList(NonNull<bssl_sys::stack_st_X509>);

// Safety: `X509CertificateList` is not clonable and contains no thread-local data.
unsafe impl Send for X509CertificateList {}

impl X509CertificateList {
    /// Create an empty certificate list.
    pub fn new() -> Self {
        let Some(cert_list) = NonNull::new(unsafe {
            // Safety: we only make allocation here.
            bssl_sys::sk_X509_new_null()
        }) else {
            panic!("allocation error");
        };
        Self(cert_list)
    }

    pub(crate) fn ptr(&self) -> *mut bssl_sys::stack_st_X509 {
        self.0.as_ptr()
    }

    /// Get the size of the list.
    pub fn len(&self) -> usize {
        unsafe {
            // Safety: `self` is valid.
            bssl_sys::sk_X509_num(self.ptr())
        }
    }

    /// Get a certificate.
    pub fn get(&self, index: usize) -> Option<X509Certificate> {
        if index < self.len() {
            let cert = unsafe {
                // Safety: `self` is valid.
                NonNull::new(bssl_sys::sk_X509_value(self.ptr(), index))?
            };
            unsafe {
                // Safety: `cert` has the right ref-count now, so we have valid ownership.
                Some(X509Certificate::from_borrowed_raw(cert))
            }
        } else {
            None
        }
    }

    /// Append a certificate into the list.
    pub fn push(&mut self, cert: X509Certificate) -> Result<&mut Self, PkiError> {
        if unsafe {
            // Safety: `cert` is still valid and exclusively owned.
            bssl_sys::sk_X509_push(self.ptr(), cert.ptr()) == 0
        } {
            panic!("allocation failure")
        }
        // We should transfer the ownership to the stack.
        core::mem::forget(cert);
        Ok(self)
    }
}

impl Drop for X509CertificateList {
    fn drop(&mut self) {
        unsafe {
            // Safety: `self` is valid.
            bssl_sys::sk_X509_pop_free(self.ptr(), Some(bssl_sys::X509_free));
        }
    }
}
