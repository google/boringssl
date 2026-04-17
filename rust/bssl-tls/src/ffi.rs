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

use core::{
    marker::PhantomData,
    ptr::{
        NonNull,
        null,
        null_mut, //
    },
    slice::{
        from_raw_parts,
        from_raw_parts_mut, //
    }, //
};

use bssl_crypto::FfiSlice;

use crate::{
    context::CertificateCache,
    errors::{
        Error,
        IoError, //
    }, //
};

pub(crate) fn slice_into_ffi_raw_parts<T>(slice: &[T]) -> (*const T, usize) {
    if slice.is_empty() {
        (null(), 0)
    } else {
        (slice.as_ptr(), slice.len())
    }
}

pub(crate) fn mut_slice_into_ffi_raw_parts<T>(slice: &mut [T]) -> (*mut T, usize) {
    if slice.is_empty() {
        (null_mut(), 0)
    } else {
        (slice.as_mut_ptr(), slice.len())
    }
}

/// Safety: use it to wrap allocation only if the pointer is
/// to be freed with `OPENSSL_free`.
pub(crate) struct Alloc<T>(pub *mut T);

impl<T> Drop for Alloc<T> {
    fn drop(&mut self) {
        unsafe {
            // Safety: `self.0` is still valid at dropping, even if it is `NULL`.
            bssl_sys::OPENSSL_free(self.0 as _);
        }
    }
}

/// Sanitize the data pointer and length and reconstitute the slice.
///
/// This method returns an empty slice if the length is 0 or the pointer is NULL.
/// # Safety
/// Caller must ensure that `'a` outlives `input`.
#[inline]
pub(crate) unsafe fn sanitize_slice<'a, T>(input: *const T, len: usize) -> Option<&'a [T]> {
    if len == 0 || input.is_null() {
        return Some(&[]);
    }
    if !input.is_aligned() || len.checked_mul(size_of::<T>())? > isize::MAX as usize {
        return None;
    }
    unsafe {
        // Safety: the pointer and the size has been sanitised.
        Some(from_raw_parts(input, len))
    }
}

/// Sanitize the data pointer and length and reconstitute the mutable slice.
///
/// `capacity` counts the number of `T`s that `out` can hold, **not number of bytes**.
///
/// This method returns an empty slice if the length is 0 or the pointer is NULL.
/// # Safety
/// Caller must ensure that `'a` outlives `input`.
#[inline]
pub(crate) unsafe fn sanitise_mut_byteslice<'a>(
    out: *mut u8,
    capacity: usize,
) -> Option<&'a mut [u8]> {
    if capacity == 0 || out.is_null() {
        return Some(&mut []);
    }
    if capacity > isize::MAX as usize {
        return None;
    }
    unsafe {
        // Safety: `out` is 1-aligned and `0` is a valid pattern for `u8`.
        core::ptr::write_bytes(out, 0, capacity);
        Some(from_raw_parts_mut(out, capacity))
    }
}

pub(crate) fn crypto_buffer_from_buf(
    buf: &[u8],
    pool: Option<&CertificateCache>,
) -> Result<NonNull<bssl_sys::CRYPTO_BUFFER>, Error> {
    let pool = if let Some(pool) = pool {
        pool.ptr()
    } else {
        null_mut()
    };
    let (ptr, len) = slice_into_ffi_raw_parts(buf);
    let buf = unsafe {
        // Safety: `ptr` and `len` are valid and sanitised.
        bssl_sys::CRYPTO_BUFFER_new(ptr, len, pool)
    };
    let buf = NonNull::new(buf).expect("allocation failure");
    Ok(buf)
}

/// BIO wrapper only for internal use.
pub(crate) struct Bio<'a>(NonNull<bssl_sys::BIO>, PhantomData<&'a ()>);

impl<'a> Bio<'a> {
    /// # Safety
    /// Caller must ensure that the lifetime of this BIO outlives the backing object.
    /// It is strongly recommended to call the builder functions.
    pub(crate) unsafe fn new(bio: NonNull<bssl_sys::BIO>) -> Self {
        Bio(bio, PhantomData)
    }

    pub fn from_bytes(buf: &'a [u8]) -> Result<Self, Error> {
        let len = if let Ok(len) = buf.len().try_into() {
            len
        } else {
            return Err(Error::Io(IoError::TooLong));
        };
        let mem_buf = unsafe {
            // Safety: buf is still valid
            bssl_sys::BIO_new_mem_buf(buf.as_ffi_void_ptr(), len)
        };
        let mem_buf = NonNull::new(mem_buf).expect("allocation failure");
        Ok(unsafe {
            // Safety: our returned object is outlived by the input buffer.
            Self::new(mem_buf)
        })
    }

    pub fn ptr(&mut self) -> *mut bssl_sys::BIO {
        self.0.as_ptr()
    }
}

impl<'a> Drop for Bio<'a> {
    fn drop(&mut self) {
        unsafe {
            // Safety: the BIO handle should still be valid
            bssl_sys::BIO_free(self.0.as_ptr());
        }
    }
}
