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

//! TLS Configurations

use alloc::string::String;
use core::ffi::c_int;

use bssl_macros::bssl_enum;

bssl_enum! {
    /// Protocol version for TLS or DTLS
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum ProtocolVersion: u16 {
        /// TLS version 1.2
        Tls12 = bssl_sys::TLS1_2_VERSION as u16,
        /// TLS version 1.3
        Tls13 = bssl_sys::TLS1_3_VERSION as u16,
        /// DTLS version 1.2
        Dtls12 = bssl_sys::DTLS1_2_VERSION as u16,
        /// DTLS version 1.3
        Dtls13 = bssl_sys::DTLS1_3_VERSION as u16,
    }
}

impl TryFrom<c_int> for ProtocolVersion {
    type Error = c_int;

    fn try_from(version: c_int) -> Result<Self, Self::Error> {
        let Ok(val) = u16::try_from(version) else {
            return Err(version);
        };
        if let Ok(version) = ProtocolVersion::try_from(val) {
            Ok(version)
        } else {
            Err(version)
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone)]
    pub(crate) struct ConnectionMode: u32 {
        /// Deny session creation.
        const MODE_NO_SESSION_CREATION = bssl_sys::SSL_MODE_NO_SESSION_CREATION as u32;
        /// Allow moving write buffer.
        /// This is indispensable for async I/O because the future could be freely cancelled.
        const ACCEPT_MOVING_WRITE_BUFFER = bssl_sys::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER as u32;
    }
}

bssl_enum! {
    /// Key exchange groups for TLS or DTLS
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum KeyExchangeGroups: u16 {
        /// Key exchange using `ECDH-P256`
        Secp256r1 = bssl_sys::SSL_GROUP_SECP256R1 as u16,
        /// Key exchange using `ECDH-P384`
        Secp384r1 = bssl_sys::SSL_GROUP_SECP384R1 as u16,
        /// Key exchange using `ECDH-P521`
        Secp521r1 = bssl_sys::SSL_GROUP_SECP521R1 as u16,
        /// Key exchange using `X25519`
        X25519 = bssl_sys::SSL_GROUP_X25519 as u16,
        /// Key exchange using post-quantum hybrid scheme `X25519MLKEM768`
        X25519Mlkem768 = bssl_sys::SSL_GROUP_X25519_MLKEM768 as u16,
        /// Key exchange using `MLKEM-1024`
        Mlkem1024 = bssl_sys::SSL_GROUP_MLKEM1024 as u16,
    }
}

bitflags::bitflags! {
    /// Flags to control how key exchange group could be chosen
    #[repr(transparent)]
    #[derive(Debug, Copy, Clone)]
    pub struct KeyExchangeGroupFlag: u32 {
        /// `EQUAL_PREFERENCE_WITH_NEXT` indicates that the corresponding group has equal preference
        /// with the next member of the list of groups being configured.
        const EQUAL_PREFERENCE_WITH_NEXT = 0x01;
    }
}

/// Configuration errors
#[derive(Debug)]
pub enum ConfigurationError {
    /// Some parameters are specified twice in the list.
    DuplicatedParameters,
    /// Some string is not acceptable.
    InvalidString,
    /// Session ID context data is too large.
    SessionIdContextTooLarge,
    /// Preshared Key is too long.
    PskTooLong,
    /// Value is out of range.
    ValueOutOfRange,
    /// Mismatching private and public key pair.
    MismatchingKeyPair,
    /// IP address is invalid.
    /// It should either be 4 bytes for IPv4 addresses or 16 bytes for IPv6 addresses.
    InvalidIp,
    /// Invalid parameters.
    InvalidParameters,
}

impl core::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigurationError::DuplicatedParameters => f.write_str("duplicated parameters"),
            ConfigurationError::InvalidString => f.write_str("invalid string"),
            ConfigurationError::SessionIdContextTooLarge => {
                f.write_str("session ID context data is too large")
            }
            ConfigurationError::PskTooLong => f.write_str("preshared key is too long"),
            ConfigurationError::MismatchingKeyPair => {
                f.write_str("mismatching private and public key pair")
            }
            ConfigurationError::ValueOutOfRange => f.write_str("value is out of range"),
            ConfigurationError::InvalidIp => f.write_str("invalid IP address"),
            ConfigurationError::InvalidParameters => f.write_str("invalid parameters"),
        }
    }
}

/// Cipher information
#[derive(Clone)]
#[non_exhaustive]
pub struct CipherInfo {
    /// Protocol ID as assigned by [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
    pub id: u32,
    /// IETF Name of the cipher
    pub ietf_name: String,
    /// Indicates whether this cipher is an AEAD cipher
    pub is_aead: bool,
    /// Indicates whether this cipher is a block cipher
    pub is_block_cipher: bool,
    /// Cipher strength in bits
    pub strength: u16,
}

/// Supported cipher suites as registered with [IANA].
///
/// The following cipher suite values are assigned by IANA and correspond to
/// both TLS 1.3 and TLS 1.2 suites.
/// TLS 1.3 suites are mentioned again in [RFC 8446].
/// TLS 1.2 suites are defined in the relevant RFCs for each algorithm family.
///
/// [IANA]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
/// [RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446
/// [RFC 5489]: https://www.rfc-editor.org/rfc/rfc5489
/// [RFC 8422]: https://www.rfc-editor.org/rfc/rfc8422
/// [RFC 7905]: https://www.rfc-editor.org/rfc/rfc7905
/// [RFC 5288]: https://www.rfc-editor.org/rfc/rfc5288
/// [RFC 5246]: https://www.rfc-editor.org/rfc/rfc5246
/// [RFC 4279]: https://www.rfc-editor.org/rfc/rfc4279
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CipherSuite(pub u16);

#[allow(non_upper_case_globals)]
impl CipherSuite {
    /// TLS 1.3 cipher suite `TLS_AES_128_GCM_SHA256`.
    pub const Aes128GcmSha256: Self = Self(bssl_sys::SSL_CIPHER_AES_128_GCM_SHA256 as u16);
    /// TLS 1.3 cipher suite `TLS_AES_256_GCM_SHA384`.
    pub const Aes256GcmSha384: Self = Self(bssl_sys::SSL_CIPHER_AES_256_GCM_SHA384 as u16);
    /// TLS 1.3 cipher suite `TLS_CHACHA20_POLY1305_SHA256`.
    pub const Chacha20Poly1305Sha256: Self =
        Self(bssl_sys::SSL_CIPHER_CHACHA20_POLY1305_SHA256 as u16);
    /// TLS 1.2 cipher suite `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` from RFC 5288.
    pub const EcdheEcdsaWithAes128GcmSha256: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 as u16);
    /// TLS 1.2 cipher suite `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` from RFC 5288.
    pub const EcdheEcdsaWithAes256GcmSha384: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 as u16);
    /// TLS 1.2 cipher suite `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` from RFC 5288.
    pub const EcdheRsaWithAes128GcmSha256: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as u16);
    /// TLS 1.2 cipher suite `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` from RFC 5288.
    pub const EcdheRsaWithAes256GcmSha384: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_RSA_WITH_AES_256_GCM_SHA384 as u16);
    /// TLS 1.2 cipher suite `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` from RFC 7905.
    pub const EcdheRsaWithChacha20Poly1305Sha256: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 as u16);
    /// TLS 1.2 cipher suite `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` from RFC 7905.
    pub const EcdheEcdsaWithChacha20Poly1305Sha256: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 as u16);
    /// TLS cipher suite `TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256` from RFC 7905.
    pub const EcdhePskWithChacha20Poly1305Sha256: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 as u16);
    /// TLS 1.2 cipher suite `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` from RFC 8422.
    pub const EcdheEcdsaWithAes128CbcSha: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_ECDSA_WITH_AES_128_CBC_SHA as u16);
    /// TLS 1.2 cipher suite `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` from RFC 8422.
    pub const EcdheEcdsaWithAes256CbcSha: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_ECDSA_WITH_AES_256_CBC_SHA as u16);
    /// TLS 1.2 cipher suite `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` from RFC 8422.
    pub const EcdheRsaWithAes128CbcSha: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_RSA_WITH_AES_128_CBC_SHA as u16);
    /// TLS 1.2 cipher suite `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` from RFC 8422.
    pub const EcdheRsaWithAes256CbcSha: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_RSA_WITH_AES_256_CBC_SHA as u16);
    /// TLS cipher suite `TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA` from RFC 5489.
    pub const EcdhePskWithAes128CbcSha: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_PSK_WITH_AES_128_CBC_SHA as u16);
    /// TLS cipher suite `TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA` from RFC 5489.
    pub const EcdhePskWithAes256CbcSha: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_PSK_WITH_AES_256_CBC_SHA as u16);
    /// TLS 1.2 cipher suite `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256` from RFC 5289.
    pub const EcdheEcdsaWithAes128CbcSha256: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 as u16);
    /// TLS 1.2 cipher suite `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` from RFC 5289.
    pub const EcdheRsaWithAes128CbcSha256: Self =
        Self(bssl_sys::SSL_CIPHER_ECDHE_RSA_WITH_AES_128_CBC_SHA256 as u16);
    /// TLS 1.2 cipher suite `TLS_RSA_WITH_AES_128_GCM_SHA256` from RFC 5288.
    pub const RsaWithAes128GcmSha256: Self =
        Self(bssl_sys::SSL_CIPHER_RSA_WITH_AES_128_GCM_SHA256 as u16);
    /// TLS 1.2 cipher suite `TLS_RSA_WITH_AES_256_GCM_SHA384` from RFC 5288.
    pub const RsaWithAes256GcmSha384: Self =
        Self(bssl_sys::SSL_CIPHER_RSA_WITH_AES_256_GCM_SHA384 as u16);
    /// TLS 1.2 cipher suite `TLS_RSA_WITH_AES_128_CBC_SHA` from RFC 5246.
    pub const RsaWithAes128CbcSha: Self =
        Self(bssl_sys::SSL_CIPHER_RSA_WITH_AES_128_CBC_SHA as u16);
    /// TLS 1.2 cipher suite `TLS_RSA_WITH_AES_256_CBC_SHA` from RFC 5246.
    pub const RsaWithAes256CbcSha: Self =
        Self(bssl_sys::SSL_CIPHER_RSA_WITH_AES_256_CBC_SHA as u16);
    /// TLS cipher suite `TLS_PSK_WITH_AES_128_CBC_SHA` from RFC 4279.
    pub const PskWithAes128CbcSha: Self =
        Self(bssl_sys::SSL_CIPHER_PSK_WITH_AES_128_CBC_SHA as u16);
    /// TLS cipher suite `TLS_PSK_WITH_AES_256_CBC_SHA` from RFC 4279.
    pub const PskWithAes256CbcSha: Self =
        Self(bssl_sys::SSL_CIPHER_PSK_WITH_AES_256_CBC_SHA as u16);
    /// TLS 1.2 cipher suite `TLS_RSA_WITH_3DES_EDE_CBC_SHA` from RFC 5246.
    pub const RsaWith3desEdeCbcSha: Self =
        Self(bssl_sys::SSL_CIPHER_RSA_WITH_3DES_EDE_CBC_SHA as u16);
}

bssl_enum! {
    /// Compliance Policy.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum CompliancePolicy: u8 {
        /// FIPS 202205
        ///
        /// This policy configures a TLS connection to use:
        /// - TLS 1.2 or 1.3;
        /// - For TLS 1.2, only `ECDHE_[RSA|ECDSA]_WITH_AES_*_GCM_SHA*`;
        /// - For TLS 1.3, only `AES-GCM`;
        /// - P-256 or P-384 for key agreement;
        /// - For server signatures, only PKCS#1/PSS with SHA256/384/512,
        ///   or ECDSA with P-256 or P-384 and SHA256/SHA384.
        Fips202205 = bssl_sys::ssl_compliance_policy_t_ssl_compliance_policy_fips_202205 as u8,
        /// WPA3-192 202304
        ///
        /// This policy configures a TLS connection to use:
        /// - TLS 1.2 or 1.3.
        /// - For TLS 1.2, only `TLS_ECDHE_[ECDSA|RSA]_WITH_AES_256_GCM_SHA384`.
        /// - For TLS 1.3, only `AES-256-GCM`.
        /// - P-384 for key agreement.
        /// - For handshake signatures, only ECDSA with P-384 and SHA-384, or RSA
        ///     with SHA-384 or SHA-512.
        ///
        /// No limitations on the certificate chain nor leaf public key are imposed,
        /// other than by the supported signature algorithms.
        /// But WPA3's "192-bit" mode requires at least P-384 or 3072-bit RSA along the chain.
        /// The caller must enforce this themselves on the verified chain using functions such as
        /// [`crate::credentials::TlsCredentialBuilder::with_certificate_chain`].
        ///
        /// Note that this setting is less secure than the default.
        /// The implementation risks of using a more obscure primitive like P-384 dominate other
        /// considerations.
        Wpa3_192_202304 = bssl_sys::ssl_compliance_policy_t_ssl_compliance_policy_wpa3_192_202304 as u8,
        /// CNSA 202407
        ///
        /// This policy configures a TLS connection to use:
        /// - For TLS 1.3, AES-256-GCM over AES-128-GCM over ChaCha20-Poly1305.
        ///
        /// I.e. it ensures that AES-GCM will be used whenever the client supports it.
        /// The cipher suite configuration mini-language can be used to similarly
        /// configure prior TLS versions if they are enabled.
        Cnsa202407 = bssl_sys::ssl_compliance_policy_t_ssl_compliance_policy_cnsa_202407 as u8,
    }
}
