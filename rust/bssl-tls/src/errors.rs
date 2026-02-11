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

//! TLS Errors

use alloc::boxed::Box;
use core::{
    any::Any,
    ffi::{CStr, c_int, c_uint},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

use bssl_macros::bssl_enum;
use bssl_sys::LibCode;
use bssl_x509::errors::{PemReason, PkiError};

use crate::config::ConfigurationError;

/// Top-level errors
#[derive(Debug)]
pub enum Error {
    /// Error reported by the BoringSSL library
    #[allow(private_interfaces)]
    Library(u32, Option<LibCode>, Option<i32>),
    /// Configuration errors
    Configuration(ConfigurationError),
    /// TLS retryable errors
    TlsRetry(TlsRetryReason),
    /// PEM encoding failures
    PemReason(PemReason),
    /// Quic errors,
    Quic(QuicError),
    /// IO errors
    Io(IoError),
    /// PKI errors
    Pki(PkiError),
    /// Unknown error which should be reported as bug
    Unknown(Box<dyn Any + Send + Sync>),
}

impl From<PkiError> for Error {
    fn from(err: PkiError) -> Self {
        Self::Pki(err)
    }
}

impl Error {
    #[allow(irrefutable_let_patterns)]
    fn extract_err_from_code(packed_error: c_uint) -> Self {
        let lib = unsafe {
            // Safety: extracting error source does not have side-effect and only access static data.
            bssl_sys::ERR_GET_LIB(packed_error)
        };
        let Ok(lib) = i32::try_from(lib) else {
            return Self::Library(packed_error, None, None);
        };
        let Ok(lib) = LibCode::try_from(lib) else {
            return Self::Library(packed_error, None, None);
        };
        let reason = unsafe {
            // Safety: extracting error reason does not have side-effect and only access static data.
            bssl_sys::ERR_GET_REASON(packed_error)
        };
        let Ok(reason) = i32::try_from(reason) else {
            return Self::Library(packed_error, Some(lib), None);
        };
        let ret_unknown_reason = || Self::Library(packed_error, Some(lib), Some(reason));
        match lib {
            LibCode::Pem => {
                let Ok(reason) = PemReason::try_from(reason) else {
                    return ret_unknown_reason();
                };
                Self::PemReason(reason)
            }
            _ => Self::Library(packed_error, Some(lib), Some(reason)),
        }
    }

    pub(crate) fn extract_lib_err() -> Self {
        let packed_error = unsafe {
            // Safety: extracting error code does not have side-effect
            bssl_sys::ERR_get_error()
        };
        let error = Self::extract_err_from_code(packed_error);
        unsafe {
            // Safety: we only clear the error queue on the current thread.
            bssl_sys::ERR_clear_error();
        }
        error
    }

    pub(crate) fn extract_tls_err(code: c_int) -> Self {
        if code == bssl_sys::SSL_ERROR_SSL {
            return Self::extract_lib_err();
        }
        if let Ok(err) = TlsRetryReason::try_from(code) {
            return Self::TlsRetry(err);
        }
        Self::Unknown(Box::new(alloc::format!("unknown tls error ({code})")))
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "BoringSSL error; use Display for details"
    }

    fn cause(&self) -> Option<&dyn core::error::Error> {
        self.source()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            &Error::Library(code, _, _) => {
                // Here the buffer is 120 bytes and BoringSSL uses this buffer size
                // to hold the error string.
                // Therefore, this ought to be sufficient for a human-readable message.
                let mut err_str = [0; bssl_sys::ERR_ERROR_STRING_BUF_LEN as usize];
                unsafe {
                    // Safety:
                    // - err_str is non-null and valid, so we do not need FFI-specific pointer conversion.
                    bssl_sys::ERR_error_string_n(code, err_str.as_mut_ptr(), err_str.len());
                }
                let err_str = unsafe {
                    // Safety:
                    // - err_str is still valid;
                    // - `ERR_error_string_n` guarantees that
                    CStr::from_ptr(err_str.as_ptr())
                };
                f.write_str(&err_str.to_string_lossy())
            }
            Error::Configuration(err) => Display::fmt(err, f),
            Error::TlsRetry(err) => Display::fmt(err, f),
            Error::PemReason(err) => Debug::fmt(err, f),
            Error::Quic(err) => Display::fmt(err, f),
            Error::Io(err) => Display::fmt(err, f),
            Error::Pki(err) => Display::fmt(err, f),
            Error::Unknown(err) => err.fmt(f),
        }
    }
}

bssl_enum! {
    /// TLS errors
    #[derive(Debug, Clone, Copy)]
    pub enum TlsRetryReason: i32 {
        /// TLS is blocked on read.
        WantRead = bssl_sys::SSL_ERROR_WANT_READ as i32,
        /// TLS is blocked on write.
        WantWrite = bssl_sys::SSL_ERROR_WANT_WRITE as i32,
        /// Pending session.
        /// Caller may retry the last operation when the session lookup is ready.
        PendingSession = bssl_sys::SSL_ERROR_PENDING_SESSION as i32,
        /// Pending certificate.
        /// Caller may retry the last operation when the certificate lookup is ready.
        PendingCertificate = bssl_sys::SSL_ERROR_PENDING_CERTIFICATE as i32,
        /// Pending certification verification.
        /// Caller may retry the last operation when the certification verification is ready.
        PendingCertificateVerify = bssl_sys::SSL_ERROR_WANT_CERTIFICATE_VERIFY as i32,
        /// Pending ticket.
        /// Caller may retry the last operation when the ticket decryption is ready.
        PendingTicket = bssl_sys::SSL_ERROR_PENDING_TICKET as i32,
        /// End of stream, due to peer close_notify.
        PeerCloseNotify = bssl_sys::SSL_ERROR_ZERO_RETURN as i32,
        /// Want to (re)connect.
        /// Caller may retry the last operation when the transport becomes ready.
        WantConnect = bssl_sys::SSL_ERROR_WANT_CONNECT as i32,
        /// Want to (re)accept.
        /// Caller may retry the last operation when the transport becomes ready.
        WantAccept = bssl_sys::SSL_ERROR_WANT_ACCEPT as i32,
        /// Pending private key operation.
        /// Caller may retry the last operation when the private key operation might be ready.
        PendingPrivateKeyOperation = bssl_sys::SSL_ERROR_WANT_PRIVATE_KEY_OPERATION as i32,
        /// Early data was rejected.
        /// Caller may call `reset_early_data_reject` to start from a clean state.
        EarlyDataRejected = bssl_sys::SSL_ERROR_EARLY_DATA_REJECTED as i32,
        /// Handshake Hints becomes ready.
        HandshakeHintsReady = bssl_sys::SSL_ERROR_HANDSHAKE_HINTS_READY as i32,
    }
}

impl Display for TlsRetryReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            TlsRetryReason::WantRead => f.write_str("want to read"),
            TlsRetryReason::WantWrite => f.write_str("want to write"),
            TlsRetryReason::PendingSession => f.write_str("pending session"),
            TlsRetryReason::PendingCertificate => f.write_str("pending certificate"),
            TlsRetryReason::PendingTicket => f.write_str("pending ticket"),
            TlsRetryReason::PendingCertificateVerify => f.write_str("pending certificate verify"),
            TlsRetryReason::WantConnect => f.write_str("want to (re)connect connection"),
            TlsRetryReason::WantAccept => f.write_str("want to (re)accept connection"),
            TlsRetryReason::PendingPrivateKeyOperation => {
                f.write_str("pending private key operation")
            }
            TlsRetryReason::EarlyDataRejected => f.write_str("early data rejected"),
            TlsRetryReason::HandshakeHintsReady => f.write_str("handshake hints ready"),
            TlsRetryReason::PeerCloseNotify => f.write_str("peer close notify"),
        }
    }
}

/// QUIC errors.
#[derive(Debug)]
pub enum QuicError {}

impl Display for QuicError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("quic error")
    }
}

/// I/O errors
#[derive(Debug)]
pub enum IoError {
    /// Buffer sizes are too long.
    TooLong,
    /// Reached the end of stream.
    EndOfStream,
    /// Error during I/O operation in the underlying transport.
    Transport(Box<dyn core::error::Error + Send + Sync>),
}

impl Display for IoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            IoError::TooLong => f.write_str("data too long"),
            IoError::EndOfStream => f.write_str("end of stream"),
            IoError::Transport(e) => write!(f, "transport: {e}"),
        }
    }
}
