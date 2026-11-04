// Copyright 2016 The Chromium Authors
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

#ifndef BSSL_DER_ENCODE_VALUES_H_
#define BSSL_DER_ENCODE_VALUES_H_

#include <stddef.h>
#include <stdint.h>

#include <openssl/base.h>
#include <openssl/span.h>

BSSL_NAMESPACE_BEGIN
namespace der {

struct GeneralizedTime;

// Encodes `posix_time`, a posix time in seconds, to DER `generalized_time`, for
// comparing against other GeneralizedTime objects, returning true on success or
// false if `posix_time` is outside of the range from year 0000 to 9999.
OPENSSL_EXPORT bool EncodePosixTimeAsGeneralizedTime(
    int64_t posix_time, GeneralizedTime *generalized_time);

// Converts a GeneralizedTime struct to a posix time in seconds in `result`,
// returning true on success or false if `generalized` was invalid or cannot be
// represented as a posix time in the range from the year 0000 to 9999.
OPENSSL_EXPORT bool GeneralizedTimeToPosixTime(
    const der::GeneralizedTime &generalized, int64_t *result);

static const size_t kGeneralizedTimeLength = 15;

// Encodes `time` to `out` as a DER GeneralizedTime value. Returns true on
// success and false on error.
OPENSSL_EXPORT bool EncodeGeneralizedTime(const GeneralizedTime &time,
                                          uint8_t out[kGeneralizedTimeLength]);

static const size_t kUTCTimeLength = 13;

// Encodes `time` to `out` as a DER UTCTime value. Returns true on success and
// false on error.
OPENSSL_EXPORT bool EncodeUTCTime(const GeneralizedTime &time,
                                  uint8_t out[kUTCTimeLength]);

// Writes the DER encoding of the id-alg-unsigned AlgorithmIdentifier (RFC 9925,
// Section 3.1) to `cbb`, for the signature algorithm of an unsigned
// certificate. Returns true on success and false on error.
OPENSSL_EXPORT bool EncodeUnsignedAlgorithmIdentifier(CBB *cbb);

// Writes the DER encoding of the placeholder issuer Name for an unsigned
// certificate (RFC 9925, Section 3.2) to `cbb`. Returns true on success and
// false on error.
OPENSSL_EXPORT bool EncodeUnsignedIssuerName(CBB *cbb);

// Writes the DER encoding of an X.509 Extension (RFC 5280, Section 4.2) with
// OID `oid`, criticality `critical`, and DER-encoded extension value `value`
// to `cbb`. Returns true on success and false on error.
OPENSSL_EXPORT bool EncodeExtension(CBB *cbb, Span<const uint8_t> oid,
                                    bool critical, Span<const uint8_t> value);

}  // namespace der
BSSL_NAMESPACE_END

#endif  // BSSL_DER_ENCODE_VALUES_H_
