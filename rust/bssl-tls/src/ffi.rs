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
    ptr::null,
    slice::{from_raw_parts, from_raw_parts_mut},
};

/// We follow the convention in [`bssl_crypto::FfiSlice`] by which we signal empty arrays as `null`.
/// An empty Rust slice has a non-zero address value, out of the necessity of enabling pointer-niche
/// optimisation.
#[allow(unused)]
pub(crate) fn slice_into_ffi_raw_parts<T>(slice: &[T]) -> (*const T, usize) {
    if slice.is_empty() {
        (null(), 0)
    } else {
        (slice.as_ptr(), slice.len())
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
    if !input.is_aligned() || len.checked_mul(size_of::<T>())? >= isize::MAX as usize {
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
pub(crate) unsafe fn sanitise_mut_slice<'a, T>(
    out: *mut T,
    capacity: usize,
) -> Option<&'a mut [T]> {
    if capacity == 0 || out.is_null() || !out.is_aligned() {
        return Some(&mut []);
    }
    if capacity.checked_mul(size_of::<T>())? >= isize::MAX as usize {
        return None;
    }
    unsafe {
        // Safety: `out` is 1-aligned and `0` is a valid pattern for `u8`.
        core::ptr::write_bytes(out, 0, capacity);
        Some(from_raw_parts_mut(out, capacity))
    }
}
