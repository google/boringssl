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

//! TLS Connection transport settings
//!

use crate::{
    connection::{
        TlsConnectionRef,
        methods::HasTlsConnectionMethod, //
    },
    context::HasBasicIo,
    errors::Error,
    io::{
        AbstractReader,
        AbstractSocket,
        AbstractWriter,
        RustBio, //
    }, //
};

/// # Transport configurations
///
/// These are the methods to configure the underlying IO drivers and transport configurations.
impl<R, M> TlsConnectionRef<R, M>
where
    M: HasBasicIo + HasTlsConnectionMethod,
{
    /// Set up underlying transport driver.
    pub fn set_io<S: 'static + AbstractSocket>(&mut self, socket: S) -> Result<&mut Self, Error> {
        let bio = RustBio::new_duplex(socket)?;
        unsafe {
            // Safety: the additional ref-count is to compensate for `SSL` taking ownership.
            bssl_sys::BIO_up_ref(bio.ptr());
            // Safety: the `bio` pointer has been sanitised and `self.0` is still valid.
            bssl_sys::SSL_set_bio(self.ptr(), bio.ptr(), bio.ptr());
        }
        let methods = self.get_connection_methods();
        methods.bio = Some(bio);
        Ok(self)
    }

    /// Set up underlying transport driver, with a pair of read and write ends.
    pub fn set_split_io<Reader, Writer>(
        &mut self,
        read: Reader,
        write: Writer,
    ) -> Result<&mut Self, Error>
    where
        Reader: 'static + AbstractReader,
        Writer: 'static + AbstractWriter,
    {
        let bio = RustBio::new_split(read, write)?;
        unsafe {
            // Safety: the additional ref-count is to compensate for `SSL` taking ownership.
            bssl_sys::BIO_up_ref(bio.ptr());
            // Safety: the `bio` pointer has been sanitised and `self.0` is still valid.
            bssl_sys::SSL_set_bio(self.ptr(), bio.ptr(), bio.ptr());
        }
        let methods = self.get_connection_methods();
        methods.bio = Some(bio);
        Ok(self)
    }

    /// Check if the underlying **transport** has closed its write end.
    pub fn is_write_closed(&self) -> bool {
        self.get_connection_methods_ref()
            .bio
            .as_ref()
            .map_or(true, |bio| bio.as_ref().write_eos)
    }

    /// Check if the underlying **transport** has closed its read end.
    pub fn is_read_closed(&self) -> bool {
        self.get_connection_methods_ref()
            .bio
            .as_ref()
            .map_or(true, |bio| bio.as_ref().read_eos)
    }

    /// Check if the underlying **transport** has closed either its read end or its write end.
    pub fn is_one_side_closed(&self) -> bool {
        self.get_connection_methods_ref()
            .bio
            .as_ref()
            .map_or(true, |bio| bio.as_ref().read_eos || bio.as_ref().write_eos)
    }
}
