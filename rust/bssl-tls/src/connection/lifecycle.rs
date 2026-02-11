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

//! TLS Connection lifecycle controls

use core::ops::{Deref, DerefMut};

use crate::{
    check_tls_error,
    connection::{Client, Server, TlsConnectionRef, methods::HasTlsConnectionMethod},
    context::TlsMode,
    errors::Error,
};

/// # Connection initialisation state
///
/// There are methods and accessors that become available only when the connection is in the right
/// state.
///
/// Please refer to [`EstablishedTlsConnection`] and [`TlsConnectionInHandshake`] for allowed
/// operations.
impl<R, M> TlsConnectionRef<R, M> {
    /// Access handshake-related options if the connection is in handshake mode.
    pub fn in_handshake<'a>(&'a mut self) -> Option<TlsConnectionInHandshake<'a, R, M>> {
        if self.is_in_handshake() {
            Some(TlsConnectionInHandshake(self))
        } else {
            None
        }
    }

    /// Access handshake-related options if a handshake is completed and
    /// the connection is initialised.
    pub fn established<'a>(&'a mut self) -> Option<EstablishedTlsConnection<'a, R, M>> {
        let session = unsafe {
            // Safety: the validity of the handle `self.0` is witnessed by `self`.
            bssl_sys::SSL_get_session(self.ptr())
        };
        if session.is_null() {
            return None;
        }
        Some(EstablishedTlsConnection(self))
    }
}

bssl_macros::bssl_enum! {
    /// TLS data-pending reasons
    pub enum TlsPendingData: i32 {
        /// TLS connection wants to read more data.
        WantRead = bssl_sys::SSL_READING as i32,
        /// TLS connection wants to write more data.
        WantWrite = bssl_sys::SSL_WRITING as i32,
    }
}

/// # Connection state
///
/// When operations on [`TlsConnectionRef`] return with pending status,
/// there will be reasons why the operations should be retried.
impl<R, M> TlsConnectionRef<R, M> {
    /// Check the connection if it needs additional data.
    pub fn wants_data(&self) -> Option<TlsPendingData> {
        let code = unsafe {
            // Safety: the validity of the handle is witnessed by `self`.
            bssl_sys::SSL_want(self.ptr())
        };
        let code = i32::try_from(code).ok()?;
        TlsPendingData::try_from(code).ok()
    }
}

/// A handle to the connection that is valid only during handshake.
#[repr(transparent)]
pub struct TlsConnectionInHandshake<'a, R, M>(pub(crate) &'a mut TlsConnectionRef<R, M>);

impl<R, M> Deref for TlsConnectionInHandshake<'_, R, M> {
    type Target = TlsConnectionRef<R, M>;
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<R, M> DerefMut for TlsConnectionInHandshake<'_, R, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}

impl<R, M> TlsConnectionInHandshake<'_, R, M>
where
    M: HasTlsConnectionMethod,
{
    #[allow(unused)] // This method will be used in the following patch to support some async tasks.
    pub(super) fn get_connection_methods(
        &mut self,
    ) -> &mut super::methods::RustConnectionMethods<M> {
        unsafe {
            // Safety: the validity of the handle `self.0` is witnessed by `self`.
            super::get_connection_methods(self.ptr())
        }
    }
}

impl<M> TlsConnectionInHandshake<'_, Server, M>
where
    M: HasTlsConnectionMethod,
{
    /// Accept a connection by responding to `ClientHello` with `ServerHello`.
    pub fn accept(&mut self) -> Result<&mut Self, Error> {
        let conn = self.ptr();
        check_tls_error!(conn, bssl_sys::SSL_accept(conn));
        Ok(self)
    }
}

impl<M> TlsConnectionInHandshake<'_, Client, M>
where
    M: HasTlsConnectionMethod,
{
    /// Initiate a connection by sending a `ClientHello`.
    pub fn connect(&mut self) -> Result<&mut Self, Error> {
        let conn = self.ptr();
        check_tls_error!(conn, bssl_sys::SSL_connect(conn));
        Ok(self)
    }
}

/// A handle to the connection that is valid only after initialization, or in other words after
/// handshake.
#[repr(transparent)]
pub struct EstablishedTlsConnection<'a, R, M = TlsMode>(&'a mut TlsConnectionRef<R, M>);

impl<R, M> Deref for EstablishedTlsConnection<'_, R, M> {
    type Target = TlsConnectionRef<R, M>;
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<R, M> DerefMut for EstablishedTlsConnection<'_, R, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}
