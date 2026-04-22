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

use alloc::{
    boxed::Box,
    string::ToString, //
};
use core::{
    future::poll_fn,
    ops::{
        Deref,
        DerefMut, //
    },
    task::Poll, //
};

use crate::{
    check_tls_error,
    connection::{
        Client,
        Server,
        TlsConnectionRef,
        methods::HasTlsConnectionMethod, //
    },
    context::{
        HasBasicIo,
        SupportedMode,
        TlsMode, //
    },
    errors::{
        Error,
        TlsErrorReason,
        TlsRetryReason, //
    },
    io::IoStatus, //
};

/// # Connection shutdown
impl<R, M> TlsConnectionRef<R, M> {
    /// Set whether shutting down this connection sends out a `close_notify` alert.
    pub fn set_quiet_shutdown(&mut self, quiet: bool) -> &mut Self {
        unsafe {
            // Safety: the validity of the handle `self.0` is witnessed by `self`.
            bssl_sys::SSL_set_quiet_shutdown(self.ptr(), if quiet { 1 } else { 0 });
        }
        self
    }

    /// Check whether shutting down this connection sends out a `close_notify` alert.
    pub fn get_quiet_shutdown(&self) -> bool {
        let rc = unsafe {
            // Safety: the validity of the handle `self.0` is witnessed by `self`.
            bssl_sys::SSL_get_quiet_shutdown(self.ptr())
        };
        rc == 1
    }
}

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

impl<R> TlsConnectionRef<R, TlsMode> {
    /// Inspect if the connection is suspended for which reason, after invocation of I/O methods.
    pub fn take_pending_reason(&mut self) -> Option<TlsRetryReason> {
        let methods = self.get_connection_methods();
        methods.take_pending_reason()
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

/// # Handshake
impl<R, M> TlsConnectionInHandshake<'_, R, M>
where
    M: HasTlsConnectionMethod,
{
    /// Continue the handshake.
    ///
    /// Call this method after the initial [`Self::accept`] or [`Self::connect`],
    /// should the handshake be suspended.
    pub fn do_handshake(&mut self) -> Result<&mut Self, Error> {
        let conn = self.ptr();
        check_tls_error!(conn, bssl_sys::SSL_do_handshake(conn));
        Ok(self)
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

impl<R, M> EstablishedTlsConnection<'_, R, M>
where
    M: HasTlsConnectionMethod + HasBasicIo,
{
    /// Perform synchronising shutdown.
    ///
    /// # Shutdown protocol
    /// A live connection can be actively shut down by calling this method at most two times.
    /// The first call will send `close_notify` down the transport.
    /// On `Ok` the first call is considered successful with the following return value.
    /// - [`ShutdownStatus::CloseNotifyReceived`] signifies that a `close_notify` is received from the peer, too.
    /// - [`ShutdownStatus::CloseNotifyPosted`] signifies that a `close_notify` from our end is sent but that from the peer
    ///   has not arrived.
    ///
    /// In case of no reception of peer `close_notify`, it is necessary to call this method again.
    /// There are two possible outcomes.
    /// - [`ShutdownStatus::RemainingApplicationData`] signifies that there are pending application data.
    ///   Process it until the stream ends.
    /// - [`ShutdownStatus::CloseNotifyReceived`] signifies that a `close_notify` is received from the peer, too.
    ///   The connection is then in terminal state.
    /// To process the remaining application data, normal reading should continue until the end of
    /// stream, at which [`Self::sync_shutdown`] can be called again to set the connection to the terminal state.
    pub fn sync_shutdown(&mut self) -> Result<ShutdownStatus, Error> {
        let rc = unsafe {
            // Safety: we have exclusive access to the connection state.
            bssl_sys::SSL_shutdown(self.ptr())
        };
        if self.is_write_closed() {
            return Ok(ShutdownStatus::EndOfStream);
        }
        match rc {
            0 => Ok(ShutdownStatus::CloseNotifyPosted),
            1 => Ok(ShutdownStatus::CloseNotifyReceived),
            _ => match self.categorise_error_for_io(rc) {
                Ok(IoStatus::Ok(_)) => unreachable!(),
                Ok(IoStatus::Empty | IoStatus::EndOfStream) => Ok(ShutdownStatus::EndOfStream),
                Ok(IoStatus::Retry(reason)) => Err(Error::TlsRetry(reason)),
                Err(Error::TlsReason(TlsErrorReason::ApplicationDataOnShutdown)) => {
                    Ok(ShutdownStatus::RemainingApplicationData)
                }
                Err(Error::Library(0, _, _)) => Ok(ShutdownStatus::CloseNotifyReceived),
                Ok(IoStatus::Err) => Err(Error::Unknown(Box::new("transport error".to_string()))),
                Err(e) => Err(e),
            },
        }
    }
}

impl<R, M> TlsConnectionInHandshake<'_, R, M>
where
    M: SupportedMode,
{
    /// Perform asynchronous handshake, until completion or until pending on non-I/O operations.
    ///
    /// The caller needs to ensure that any pending operations during the handshake are resolved,
    /// before polling [`async_handshake`] again.
    pub fn async_handshake(&mut self) -> impl Send + Future<Output = Result<(), Error>> + '_ {
        poll_fn(move |cx| {
            self.set_waker(cx.waker());
            match self.do_handshake() {
                Ok(_) => Poll::Ready(Ok(())),
                Err(Error::TlsRetry(r)) => {
                    if matches!(r, TlsRetryReason::WantRead | TlsRetryReason::WantWrite) {
                        Poll::Pending
                    } else {
                        Poll::Ready(Err(Error::TlsRetry(r)))
                    }
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        })
    }

    /// Perform asynchronous handshake, until completion, knowing that all possible pending reasons
    /// will resolve themselves.
    ///
    /// The caller needs to ensure that any pending operations due to asynchronous operations such as
    /// certificate verification and private key operations will eventually resolve and wake up
    /// the handshake task.
    /// Otherwise the handshake task will never complete.
    pub fn async_nonstop_handshake(
        &mut self,
    ) -> impl Send + Future<Output = Result<(), Error>> + '_ {
        poll_fn(move |cx| {
            self.set_waker(cx.waker());
            match self.do_handshake() {
                Ok(_) => Poll::Ready(Ok(())),
                Err(Error::TlsRetry(_)) => Poll::Pending,
                Err(e) => Poll::Ready(Err(e)),
            }
        })
    }
}

/// Shutdown progress
pub enum ShutdownStatus {
    /// `close_notify` has been sent.
    CloseNotifyPosted,
    /// Peer `close_notify` has been received. The connection is now in terminal state.
    CloseNotifyReceived,
    /// There are remaining application data. Consume them first before calling `shutdown` again.
    RemainingApplicationData,
    /// The read half of the connection reaches the end of the stream.
    EndOfStream,
}
