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

//! TLS context builder and context type

use alloc::{boxed::Box, sync::Arc};
use core::{marker::PhantomData, mem::forget, ptr::NonNull};

use crate::{
    config::CompliancePolicy,
    connection::{Client, Server, TlsConnection, methods::HasTlsConnectionMethod},
    context::methods::HasTlsContextMethod,
    errors::Error,
};

mod credentials;
mod methods;

/// TLS or DTLS mode
pub enum TlsMode {}

/// QUIC mode
pub enum QuicMode {}

/// A collection of supported mode of operations.
pub trait SupportedMode: HasTlsContextMethod + HasTlsConnectionMethod {}

impl SupportedMode for TlsMode {}
impl SupportedMode for QuicMode {}

/// General TLS configuration
///
/// The `Mode` generic can be either [`TlsMode`] or [`QuicMode`].
/// This generic governs the kind of [`TlsConnection`] that can be constructed.
pub struct TlsContextBuilder<Mode = TlsMode> {
    ptr: NonNull<bssl_sys::SSL_CTX>,
    cert_cache: Option<Arc<CertificateCache>>,
    _p: PhantomData<fn() -> Mode>,
}

impl<M> TlsContextBuilder<M> {
    fn ptr(&self) -> *mut bssl_sys::SSL_CTX {
        self.ptr.as_ptr()
    }
}

impl<M> TlsContextBuilder<M>
where
    M: HasTlsContextMethod,
{
    fn new_inner(method: *const bssl_sys::SSL_METHOD) -> Self {
        let Some(ptr) = NonNull::new(unsafe {
            // Safety: this call only makes allocations
            bssl_sys::SSL_CTX_new(method)
        }) else {
            panic!("allocation failure")
        };
        let this = TlsContextBuilder {
            ptr,
            cert_cache: None,
            _p: PhantomData,
        };
        let rc = unsafe {
            // Safety: `ctx` is still valid
            bssl_sys::SSL_CTX_set_ex_data(
                ptr.as_ptr(),
                M::registration(),
                Box::into_raw(Box::new(methods::RustContextMethods::<M>::new())) as _,
            )
        };
        assert!(rc == 1);
        this
    }
}

/// # Make a TLS context builder
impl TlsContextBuilder<TlsMode> {
    /// Creates a new TLS context builder.
    pub fn new_tls() -> Self {
        Self::new_inner(unsafe {
            // Safety: this call returns a static immutable data
            bssl_sys::TLS_method()
        })
    }

    /// Creates a new DTLS context builder.
    pub fn new_dtls() -> Self {
        Self::new_inner(unsafe {
            // Safety: this call returns a static immutable data
            bssl_sys::DTLS_method()
        })
    }
}

/// # Configure the context through a context builder
impl<M> TlsContextBuilder<M>
where
    M: HasTlsContextMethod,
{
    /// Builds and returns the configured TLS context.
    pub fn build(mut self) -> TlsContext<M> {
        let TlsContextBuilder {
            ptr,
            ref mut cert_cache,
            ..
        } = self;
        let cert_cache = cert_cache.take();
        // We must disarm the drop activated by the builder and pass on the ownership.
        // Now `self` has no destructors to call.
        forget(self);
        TlsContext {
            ptr,
            cert_cache,
            _p: PhantomData,
        }
    }

    #[allow(unused)]
    fn get_context_methods(&mut self) -> &mut methods::RustContextMethods<M> {
        let methods = unsafe {
            // Safety: the validity of the handle `self.0` is witnessed by `self`.
            bssl_sys::SSL_CTX_get_ex_data(self.ptr(), M::registration())
        };
        if methods.is_null() {
            panic!("context method goes missing")
        }
        unsafe {
            // Safety: `methods` must be constructed by `new_inner`
            &mut *(methods as *mut methods::RustContextMethods<M>)
        }
    }
}

impl<M> Drop for TlsContextBuilder<M> {
    fn drop(&mut self) {
        unsafe {
            // Safety: self.0 is created from SSL_CTX_new so it is a valid pointer
            bssl_sys::SSL_CTX_free(self.ptr());
        }
    }
}

/// A TLS context that is finalised and can be shared across connections
pub struct TlsContext<M = TlsMode> {
    ptr: NonNull<bssl_sys::SSL_CTX>,
    cert_cache: Option<Arc<CertificateCache>>,
    _p: PhantomData<fn() -> M>,
}

impl<M> TlsContext<M> {
    pub(crate) fn ptr(&self) -> *mut bssl_sys::SSL_CTX {
        self.ptr.as_ptr()
    }
}

/// # Create new connections associated to a context
impl<M> TlsContext<M>
where
    M: HasTlsContextMethod + HasTlsConnectionMethod,
{
    fn new_connection(
        &self,
        compliance_policy: Option<CompliancePolicy>,
    ) -> NonNull<bssl_sys::SSL> {
        let conn = unsafe {
            // Safety: in this type-state, our SSL_CTX is effectively immutable,
            // so we can freely alias.
            bssl_sys::SSL_new(self.ptr())
        };
        if let Some(policy) = compliance_policy {
            unsafe {
                // Safety: `policy` is a valid enum value per construction.
                bssl_sys::SSL_set_compliance_policy(conn, policy as _);
            }
        }
        NonNull::new(conn).expect("allocation failure")
    }

    /// Make a new client-half connection inheriting the configuration of this context
    pub fn new_client_connection(
        &self,
        compliance_policy: Option<CompliancePolicy>,
    ) -> Result<TlsConnection<Client, M>, Error> {
        let conn = self.new_connection(compliance_policy);
        unsafe {
            // Safety: the connection is still valid here
            bssl_sys::SSL_set_connect_state(conn.as_ptr());
        }
        Ok(TlsConnection::from_ssl(conn))
    }

    /// Make a new server-half connection inheriting the configuration of this context
    pub fn new_server_connection(
        &self,
        compliance_policy: Option<CompliancePolicy>,
    ) -> Result<TlsConnection<Server, M>, Error> {
        let conn = self.new_connection(compliance_policy);
        unsafe {
            // Safety: the connection is still valid here
            bssl_sys::SSL_set_accept_state(conn.as_ptr());
        }
        Ok(TlsConnection::from_ssl(conn))
    }
}

/// Safety: at this type state, most of the underlying context is immutable,
/// while methods on shared accesses are protected behind a mutex, so they are thread-safe.
unsafe impl<M> Send for TlsContext<M> {}
unsafe impl<M> Sync for TlsContext<M> {}

impl<M> Drop for TlsContext<M> {
    fn drop(&mut self) {
        unsafe {
            // Safety: this handle is taken from the builder, so it must be
            // live and valid.
            bssl_sys::SSL_CTX_free(self.ptr());
        }
    }
}

impl<M> Clone for TlsContext<M> {
    fn clone(&self) -> Self {
        unsafe {
            // Safety: this handle is already valid by the witness of self.
            bssl_sys::SSL_CTX_up_ref(self.ptr());
            // BoringSSL will always return success on bumping reference.
        }
        TlsContext {
            ptr: self.ptr,
            cert_cache: self.cert_cache.clone(),
            _p: PhantomData,
        }
    }
}

/// A reusable certificate cache shared across [`TlsContext`]
pub struct CertificateCache(pub(crate) NonNull<bssl_sys::CRYPTO_BUFFER_POOL>);

// Safety: `CRYPTO_BUFFER_POOL` is mutex-protected
unsafe impl Send for CertificateCache {}
unsafe impl Sync for CertificateCache {}

impl CertificateCache {
    /// Construct a new certificate cache.
    pub fn new() -> Self {
        let pool = unsafe {
            // Safety: this call does not have side-effect other than allocation
            bssl_sys::CRYPTO_BUFFER_POOL_new()
        };
        Self(NonNull::new(pool).expect("allocation failure"))
    }

    pub(crate) fn ptr(&self) -> *mut bssl_sys::CRYPTO_BUFFER_POOL {
        self.0.as_ptr()
    }
}

impl Drop for CertificateCache {
    fn drop(&mut self) {
        unsafe {
            // Safety: the validity of `self.0` is witnessed by `self`
            bssl_sys::CRYPTO_BUFFER_POOL_free(self.0.as_ptr());
        }
    }
}
