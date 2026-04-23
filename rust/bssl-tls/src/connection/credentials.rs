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

use alloc::ffi::CString;
use core::{
    ffi::CStr,
    ptr::null, //
};

use bssl_x509::store::X509Store;

use super::{
    Client,
    methods::HasTlsConnectionMethod, //
};
use crate::{
    check_lib_error,
    config::ConfigurationError,
    connection::{
        TlsConnectionBuilder,
        lifecycle::{
            EstablishedTlsConnection,
            TlsConnectionInHandshake, //
        }, //
    }, //
    credentials::{
        CertificateVerificationMode,
        TlsCredential, //
    },
    errors::Error,
    ffi::slice_into_ffi_raw_parts, //
};

impl<R, M> TlsConnectionBuilder<R, M> {
    /// Configure the certificate verification mode.
    pub fn with_certificate_verification_mode(
        &mut self,
        mode: CertificateVerificationMode,
    ) -> &mut Self {
        let ctx = self.ptr();
        unsafe {
            // Safety: `ctx` is still valid here, `mode` has a correct value by construction and
            // `NULL` is a valid callback handle.
            bssl_sys::SSL_set_custom_verify(ctx, mode as _, None);
        }
        self
    }
}

/// # Custom certificate verification
impl<M> TlsConnectionInHandshake<'_, Client, M>
where
    M: HasTlsConnectionMethod,
{
    /// Get the certificate verification mode set by [`Self::set_certificate_verification_mode`].
    pub fn get_certificate_verification_mode(&self) -> Option<CertificateVerificationMode> {
        unsafe {
            // Safety: the validity of the handle `self.0` is witnessed by `self`.
            bssl_sys::SSL_get_verify_mode(self.ptr())
        }
        .try_into()
        .ok()
    }
}

/// # Authenticating with the peer
impl<M> TlsConnectionInHandshake<'_, Client, M>
where
    M: HasTlsConnectionMethod,
{
    /// Append `credential` to the list of credentials of this connection.
    ///
    /// Earlier calls to this method appends a credential that is preferred over those added
    /// in the later calls.
    pub fn add_credential(&mut self, credential: &TlsCredential) -> Result<&mut Self, Error> {
        check_lib_error!(unsafe {
            // Safety: `credential` is still valid.
            bssl_sys::SSL_add1_credential(self.ptr(), credential.ptr())
        });
        Ok(self)
    }

    /// Clear all credentials.
    pub fn clear_credentials(&mut self) -> &mut Self {
        unsafe {
            // Safety: `credential` is still valid.
            bssl_sys::SSL_certs_clear(self.ptr());
        }
        self
    }
}

/// # Certificate verification
impl<M> TlsConnectionInHandshake<'_, Client, M> {
    /// Set certificate verification store.
    pub fn set_certificate_store(&mut self, store: &X509Store) -> &mut Self {
        unsafe {
            // Safety:
            // - the validity of the handle `self.0` is witnessed by `self`.
            // - when pending handshake, the assignment is always successful.
            // - `SSL_set1_verify_cert_store` bumps the ref-count on the store.
            bssl_sys::SSL_set1_verify_cert_store(self.ptr(), store.as_mut_ptr());
        }
        self
    }
}

/// # Certificate verification.
impl<M> TlsConnectionInHandshake<'_, Client, M> {
    /// Set host name.
    pub fn set_host(&mut self, host_name: &str) -> Result<&mut Self, Error> {
        let host_name = CString::new(host_name)
            .map_err(|_| Error::Configuration(ConfigurationError::InvalidString))?;
        check_lib_error!(unsafe {
            // Safety:
            // - the validity of the handle `self.0` is witnessed by `self`.
            // - the host name string has been sanitised for internal NUL-bytes and NUL-terminated.
            bssl_sys::SSL_set1_host(self.ptr(), host_name.as_ptr())
        });
        Ok(self)
    }
}

impl<'a, R, M> EstablishedTlsConnection<'a, R, M> {
    /// Export keying material from this connection into a buffer of a chosen length,
    /// as per [RFC 5705].
    ///
    /// To derive the same value, both sides of a connection must use the same output length, label
    /// and context.
    /// - In TLS 1.2 and earlier, using a zero-length context and using no context would give
    /// different output.
    /// - In TLS 1.3 and later, the output length controls the derivation so that a truncated
    /// longer export will not match a shorter export.
    ///
    /// [RFC 5705]: <https://datatracker.ietf.org/doc/html/rfc5705>
    pub fn export_keying_material(
        &self,
        label: &CStr,
        context: Option<&[u8]>,
        output: &mut [u8],
    ) -> Result<(), Error> {
        let (context, context_len, use_context) = if let Some(context) = context {
            let (context, context_len) = slice_into_ffi_raw_parts(context);
            (context, context_len, 1)
        } else {
            (null(), 0, 0)
        };
        let (output, output_len) = crate::ffi::mut_slice_into_ffi_raw_parts(output);
        check_lib_error!(unsafe {
            // Safety:
            // - the validity of the handle `self.0` is witnessed by `self`.
            bssl_sys::SSL_export_keying_material(
                self.ptr(),
                output,
                output_len,
                label.as_ptr(),
                label.count_bytes(),
                context,
                context_len,
                use_context,
            )
        });
        Ok(())
    }
}
