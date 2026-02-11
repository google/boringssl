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

//! TLS credentials

use alloc::boxed::Box;
use core::{ffi::c_int, marker::PhantomData, mem::forget, ptr::NonNull};

pub(crate) mod methods;

/// TLS credentials builder
pub struct TlsCredentialBuilder<Mode>(NonNull<bssl_sys::SSL_CREDENTIAL>, PhantomData<fn() -> Mode>);

/// X.509 credential
pub enum X509Mode {}

// Safety: At this type state, the credential handle is exclusively owned.
unsafe impl<M> Send for TlsCredentialBuilder<M> {}

impl<M> Drop for TlsCredentialBuilder<M> {
    fn drop(&mut self) {
        unsafe {
            // Safety: `self.0` is still valid at dropping.
            bssl_sys::SSL_CREDENTIAL_free(self.0.as_ptr());
        }
    }
}

impl<M> TlsCredentialBuilder<M> {
    fn ptr(&mut self) -> *mut bssl_sys::SSL_CREDENTIAL {
        self.0.as_ptr()
    }

    fn set_ex_data(mut self) -> Self {
        let rc = unsafe {
            // Safety:
            // - this method is called exactly once during construction.
            // - the ex_data index will be generated correctly and exactly once.
            // - the `SSL_CREDENTIAL*` handle is already valid, witnessed by `self`.
            bssl_sys::SSL_CREDENTIAL_set_ex_data(
                self.ptr(),
                *methods::TLS_CREDENTIAL_METHOD,
                Box::into_raw(Box::new(methods::RustCredentialMethods::default())) as _,
            )
        };
        assert_eq!(rc, 1);
        self
    }
}

impl TlsCredentialBuilder<X509Mode> {
    /// Construct X.509-powered credential instance.
    pub fn new() -> Self {
        let this = Self(
            NonNull::new(unsafe {
                // Safety: this call has no side-effect other than allocation.
                bssl_sys::SSL_CREDENTIAL_new_x509()
            })
            .expect("allocation failure"),
            PhantomData,
        );
        this.set_ex_data()
    }
}

impl<M> TlsCredentialBuilder<M> {
    /// Finalise the credential.
    pub fn build(mut self) -> Option<TlsCredential> {
        if unsafe {
            // Safety: `self.0` is still valid.
            bssl_sys::SSL_CREDENTIAL_is_complete(self.ptr()) == 1
        } {
            let Self(cred, _) = self;
            forget(self);
            Some(TlsCredential(cred))
        } else {
            None
        }
    }
}

/// A completely constructed TLS credential.
pub struct TlsCredential(NonNull<bssl_sys::SSL_CREDENTIAL>);

// Safety: `TlsCredential` is locked as immutable at this type state.
unsafe impl Send for TlsCredential {}
unsafe impl Sync for TlsCredential {}

impl TlsCredential {
    pub(crate) fn ptr(&self) -> *mut bssl_sys::SSL_CREDENTIAL {
        self.0.as_ptr()
    }

    /// This method releases the ownership.
    pub(crate) fn into_raw(self) -> *mut bssl_sys::SSL_CREDENTIAL {
        let ptr = self.0.as_ptr();
        forget(self);
        ptr
    }
}

impl Clone for TlsCredential {
    fn clone(&self) -> Self {
        unsafe {
            // Safety: this handle is already valid by the witness of self.
            bssl_sys::SSL_CREDENTIAL_up_ref(self.ptr());
        }
        Self(self.0)
    }
}

impl Drop for TlsCredential {
    fn drop(&mut self) {
        unsafe {
            // Safety: `self.0` is still valid at dropping.
            bssl_sys::SSL_CREDENTIAL_free(self.ptr());
        }
    }
}

bssl_macros::bssl_enum! {
    /// Certificate verification mode
    pub enum CertificateVerificationMode: i8 {
        /// Verifies the server certificate on a client but does not make errors fatal.
        None = bssl_sys::SSL_VERIFY_NONE as i8,
        /// Verifies the server certificate on a client and makes errors fatal.
        PeerCertRequested = bssl_sys::SSL_VERIFY_PEER as i8,
        /// Configures a server to request a client certificate and **reject** connections if
        /// the client declines to send a certificate.
        PeerCertMandatory =
            (bssl_sys::SSL_VERIFY_FAIL_IF_NO_PEER_CERT | bssl_sys::SSL_VERIFY_PEER) as i8,
    }
}

impl TryFrom<c_int> for CertificateVerificationMode {
    type Error = c_int;
    fn try_from(mode: c_int) -> Result<Self, Self::Error> {
        let Ok(value) = i8::try_from(mode) else {
            return Err(mode);
        };
        if let Ok(mode) = Self::try_from(value) {
            Ok(mode)
        } else {
            Err(mode)
        }
    }
}
