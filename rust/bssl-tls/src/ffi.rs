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

use core::ptr::null;

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
