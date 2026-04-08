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

#![cfg(feature = "tokio_net")]

use std::{
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

use crate::io::{
    AbstractReader,
    AbstractSocket,
    AbstractSocketResult,
    AbstractWriter,
    NoAsyncContext, //
};

/// IO object implementing [`tokio::io::AsyncRead`] or [`tokio::io::AsyncWrite`] protocol.
pub struct TokioIo<T>(pub T);

fn tokio_async_read<T: AsyncRead>(
    mut this: Pin<&mut T>,
    ctx: &mut Context<'_>,
    buffer: &mut [u8],
) -> AbstractSocketResult {
    let mut buf = ReadBuf::new(buffer);
    loop {
        return match this.as_mut().poll_read(ctx, &mut buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().is_empty() && buf.remaining() > 0 {
                    AbstractSocketResult::EndOfStream
                } else {
                    AbstractSocketResult::Ok(buf.filled().len())
                }
            }
            Poll::Pending => AbstractSocketResult::Retry,
            Poll::Ready(Err(e)) => crate::retry_on_interrupt!(e),
        };
    }
}

fn tokio_async_write<T: AsyncWrite>(
    mut this: Pin<&mut T>,
    ctx: &mut Context<'_>,
    buffer: &[u8],
) -> AbstractSocketResult {
    loop {
        return match this.as_mut().poll_write(ctx, buffer) {
            Poll::Ready(Ok(bytes)) => {
                if buffer.is_empty() {
                    AbstractSocketResult::Ok(0)
                } else if bytes == 0 {
                    AbstractSocketResult::EndOfStream
                } else {
                    AbstractSocketResult::Ok(bytes)
                }
            }
            Poll::Pending => AbstractSocketResult::Retry,
            Poll::Ready(Err(e)) => crate::retry_on_interrupt!(e),
        };
    }
}

fn tokio_async_flush<T: AsyncWrite>(
    mut this: Pin<&mut T>,
    ctx: &mut Context<'_>,
) -> AbstractSocketResult {
    loop {
        return match this.as_mut().poll_flush(ctx) {
            Poll::Ready(Ok(())) => AbstractSocketResult::Ok(0),
            Poll::Pending => AbstractSocketResult::Retry,
            Poll::Ready(Err(e)) => crate::retry_on_interrupt!(e),
        };
    }
}

impl<T: AsyncRead + Send + Unpin> AbstractReader for TokioIo<T> {
    fn read(
        &mut self,
        async_ctx: Option<&mut Context<'_>>,
        buffer: &mut [u8],
    ) -> AbstractSocketResult {
        let Some(ctx) = async_ctx else {
            return AbstractSocketResult::Err(Box::new(NoAsyncContext));
        };
        tokio_async_read(Pin::new(&mut self.0), ctx, buffer)
    }
}

impl<T: AsyncWrite + Send + Unpin> AbstractWriter for TokioIo<T> {
    fn write(
        &mut self,
        async_ctx: Option<&mut Context<'_>>,
        buffer: &[u8],
    ) -> AbstractSocketResult {
        let Some(ctx) = async_ctx else {
            return AbstractSocketResult::Err(Box::new(NoAsyncContext));
        };
        tokio_async_write(Pin::new(&mut self.0), ctx, buffer)
    }

    fn flush(&mut self, async_ctx: Option<&mut Context<'_>>) -> AbstractSocketResult {
        let Some(ctx) = async_ctx else {
            return AbstractSocketResult::Err(Box::new(NoAsyncContext));
        };
        tokio_async_flush(Pin::new(&mut self.0), ctx)
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> AbstractSocket for TokioIo<T> {}
