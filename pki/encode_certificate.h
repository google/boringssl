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

#ifndef BSSL_PKI_ENCODE_CERTIFICATE_H_
#define BSSL_PKI_ENCODE_CERTIFICATE_H_

#include <stdint.h>

#include <openssl/base.h>
#include <openssl/pool.h>
#include <openssl/span.h>

#include "signature_algorithm.h"

BSSL_NAMESPACE_BEGIN

// Returns an MTC CA certificate encoded according to
// draft-ietf-plants-merkle-tree-certs-07, Section 5.5, or nullptr on error.
// The certificate is allocated from `pool` (which may be null). `ca_id`
// contains the DER encoding of the relative OID of the CA's ID, and
// `ca_cosign_sigalg` and `ca_cosign_key` (a DER-encoded SubjectPublicKeyInfo)
// describe the CA cosigner algorithm and key. Its allowed serial number range
// is set to `min_serial`..`max_serial`, inclusive, which is empty if
// `min_serial` > `max_serial`. The certificate is unsigned (RFC 9925).
OPENSSL_EXPORT UniquePtr<CRYPTO_BUFFER> EncodeMtcCaCertificate(
    Span<const uint8_t> ca_id, SignatureAlgorithm ca_cosign_sigalg,
    Span<const uint8_t> ca_cosign_key, uint64_t min_serial, uint64_t max_serial,
    CRYPTO_BUFFER_POOL *pool);

BSSL_NAMESPACE_END

#endif  // BSSL_PKI_ENCODE_CERTIFICATE_H_
