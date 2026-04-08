use std::{
    io,
    os::fd::{AsRawFd, RawFd},
    task::{Context, Poll, ready},
};

use tokio::io::{Interest, ReadBuf, Ready, unix::AsyncFd};

use crate::io::{
    AbstractReader, AbstractSocket, AbstractSocketResult, AbstractWriter, NoAsyncContext,
    stdio::PollFor,
    unix::{StdDatagram, UseFd, translate_stdio_err},
};

/// Reactor that operate over file descriptor.
pub struct TokioOverFd(AsyncFd<RawFd>);

impl<T: AsRawFd> StdDatagram<UseFd<T>, TokioOverFd> {
    /// Construct a datagram IO object driven by [`tokio`].
    pub fn new_with_tokio(inner: T) -> Result<Self, io::Error> {
        let reactor = TokioOverFd::new(inner.as_raw_fd())?;
        let fd = UseFd(inner);
        Ok(Self::new(fd, reactor))
    }
}

impl TokioOverFd {
    /// A trivial constructor to signal use of `tokio` reactor and register events with
    /// file descriptors.
    pub fn new(fd: RawFd) -> Result<Self, io::Error> {
        Ok(Self(AsyncFd::try_with_interest(
            fd,
            Interest::READABLE | Interest::WRITABLE | Interest::ERROR,
        )?))
    }
}

impl<T> PollFor<T> for TokioOverFd {
    fn poll_read(&mut self, async_ctx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match ready!(self.0.poll_read_ready_mut(async_ctx)) {
            Ok(mut guard) => {
                guard.clear_ready_matching(Ready::READABLE);
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_write(&mut self, async_ctx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match ready!(self.0.poll_write_ready_mut(async_ctx)) {
            Ok(mut guard) => {
                guard.clear_ready_matching(Ready::WRITABLE);
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

macro_rules! gen_impl_datagram {
    ($ty:ty) => {
        impl AbstractReader for $ty {
            fn read(
                &mut self,
                async_ctx: Option<&mut Context<'_>>,
                buffer: &mut [u8],
            ) -> AbstractSocketResult {
                let Some(cx) = async_ctx else {
                    return AbstractSocketResult::Err(Box::new(NoAsyncContext));
                };
                let mut buf = ReadBuf::new(buffer);
                match self.poll_recv(cx, &mut buf) {
                    Poll::Pending => AbstractSocketResult::Retry,
                    Poll::Ready(Ok(_)) => AbstractSocketResult::Ok(buf.filled().len()),
                    Poll::Ready(Err(e)) => translate_stdio_err(e),
                }
            }
        }

        impl AbstractWriter for $ty {
            fn write(
                &mut self,
                async_ctx: Option<&mut Context<'_>>,
                buf: &[u8],
            ) -> AbstractSocketResult {
                let Some(cx) = async_ctx else {
                    return AbstractSocketResult::Err(Box::new(NoAsyncContext));
                };
                match self.poll_send(cx, buf) {
                    Poll::Pending => AbstractSocketResult::Retry,
                    Poll::Ready(Ok(len)) => AbstractSocketResult::Ok(len),
                    Poll::Ready(Err(e)) => translate_stdio_err(e),
                }
            }

            fn flush(&mut self, _: Option<&mut Context<'_>>) -> AbstractSocketResult {
                AbstractSocketResult::Ok(0)
            }
        }

        impl AbstractSocket for $ty {}
    };
}

gen_impl_datagram!(tokio::net::UdpSocket);
gen_impl_datagram!(tokio::net::UnixDatagram);
