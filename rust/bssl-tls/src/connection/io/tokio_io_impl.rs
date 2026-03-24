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

use std::{
    fmt::Display,
    io,
    pin::Pin,
    task::{
        Context,
        Poll, //
    }, //
};

use tokio::io::{
    AsyncRead,
    AsyncWrite,
    ReadBuf, //
};

use super::{
    IoStatus,
    TlsConnectionRef,
    TlsMode, //
};
use crate::connection::lifecycle::ShutdownStatus;

#[inline]
fn handle_io_status<T>(status: IoStatus) -> Poll<io::Result<T>> {
    match status {
        IoStatus::EndOfStream | IoStatus::Ok(_) => unreachable!(),
        IoStatus::Retry(_) => unreachable!("we should have handled retry earlier"),
        IoStatus::Err => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Other,
            "The transport has failed the I/O operation",
        ))),
        IoStatus::Empty => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "TlsConnection has no backing transport or the transport has panicked",
        ))),
    }
}

impl<R> AsyncRead for TlsConnectionRef<R, TlsMode> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let status = match self.as_mut().aread_inner(buf.initialize_unfilled(), cx) {
            Ok(status) => status,
            Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
        };
        match status {
            None => Poll::Pending,
            Some(IoStatus::Ok(bytes)) => {
                buf.advance(bytes);
                Poll::Ready(Ok(()))
            }
            Some(IoStatus::EndOfStream) => Poll::Ready(Ok(())),
            Some(status) => handle_io_status(status),
        }
    }
}

impl<R> AsyncWrite for TlsConnectionRef<R, TlsMode> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let status = match self.as_mut().awrite_inner(buf, cx) {
            Ok(status) => status,
            Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
        };
        match status {
            None => Poll::Pending,
            Some(IoStatus::Ok(bytes)) => Poll::Ready(Ok(bytes)),
            Some(IoStatus::EndOfStream) => Poll::Ready(Ok(0)),
            Some(status) => handle_io_status(status),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let status = match self.as_mut().aflush_inner(cx) {
            Ok(status) => status,
            Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
        };
        match status {
            None => Poll::Pending,
            Some(IoStatus::Ok(_)) => Poll::Ready(Ok(())),
            Some(IoStatus::EndOfStream) => Poll::Ready(Ok(())),
            Some(status) => handle_io_status(status),
        }
    }

    /// # Warning ⚠️
    ///
    /// Calling this may fail with error [`NeedToDrainAppData`].
    /// This is not a hard error.
    /// Caller should continue reading from the connection until the end of the stream.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().ashutdown_inner(cx) {
            Ok(Some(ShutdownStatus::CloseNotifyReceived)) => Poll::Ready(Ok(())),
            Ok(Some(ShutdownStatus::RemainingApplicationData)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                NeedToDrainAppData,
            ))),
            Ok(Some(ShutdownStatus::EndOfStream)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof while waiting for peek close_notify",
            ))),
            Ok(Some(ShutdownStatus::CloseNotifyPosted)) => unreachable!(),
            Ok(None) => Poll::Pending,
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
        }
    }
}

#[derive(Debug)]
pub struct NeedToDrainAppData;

impl Display for NeedToDrainAppData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "caller needs to drain application data before polling on shutdown again"
        )
    }
}

impl std::error::Error for NeedToDrainAppData {}
