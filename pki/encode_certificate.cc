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

#include "encode_certificate.h"

#include <openssl/bytestring.h>
#include <openssl/nid.h>
#include <openssl/pool.h>

#include "../crypto/bytestring/internal.h"
#include "encode_values.h"

BSSL_NAMESPACE_BEGIN

namespace {

// draft-ietf-plants-merkle-tree-certs-07, Section 5.5: mtcMinSerial.
constexpr uint64_t kMtcMinSerial = uint64_t{1} << 48;

// `EncodeMtcCaCertificate` produces a certificate that is not issued by anyone,
// so its serial number is arbitrary, but RFC 5280, Section 4.1.2.2, requires it
// to be positive.
constexpr uint64_t kMtcCaCertSerialNumber = 1;

constexpr uint8_t kRdnaTrustAnchorIDOid[] = {OBJ_ENC_rdna_trustAnchorID};
constexpr uint8_t kKeyUsageOid[] = {OBJ_ENC_key_usage};
constexpr uint8_t kBasicConstraintsOid[] = {OBJ_ENC_basic_constraints};
constexpr uint8_t kMtcCertificationAuthoritySha256Oid[] = {
    OBJ_ENC_pe_mtcCertificationAuthority_SHA256};

// The validity for MTC CA certificates is as wide as possible, to never
// constrain path building.
// notBefore is the earliest time representable as a GeneralizedTime,
// 00000101000000Z. notAfter is the value from RFC 5280, Section 4.1.2.5, for
// a certificate with no well-defined expiration date, 99991231235959Z.
// clang-format off
constexpr uint8_t kMtcCaCertValidity[] = {
    0x30, 34,  // SEQUENCE (34 bytes)
    0x18, 15,  //   GeneralizedTime (15 bytes)
    '0', '0', '0', '0', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
    0x18, 15,  //   GeneralizedTime (15 bytes)
    '9', '9', '9', '9', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9', 'Z',
};
// clang-format on

// KeyUsage extension for MTC CA certificates: a BIT STRING with keyCertSign
// (bit 5) and cRLSign (bit 6) set.
// clang-format off
constexpr uint8_t kMtcCaCertKeyUsage[] = {
    0x03, 2, 1, 0b00000110,  // BIT STRING (2 bytes, 1 unused bit)
};
// clang-format on

// BasicConstraints extension for CA certificates: a SEQUENCE with cA set to
// TRUE.
// clang-format off
constexpr uint8_t kMtcCaCertBasicConstraints[] = {
    0x30, 3,        // SEQUENCE (3 bytes)
    0x01, 1, 0xff,  //   BOOLEAN (1 byte)
};
// clang-format on

}  // namespace

UniquePtr<CRYPTO_BUFFER> EncodeMtcCaCertificate(
    Span<const uint8_t> ca_id, SignatureAlgorithm ca_cosign_sigalg,
    Span<const uint8_t> ca_cosign_key, uint64_t min_serial, uint64_t max_serial,
    CRYPTO_BUFFER_POOL *pool) {
  if (ca_cosign_sigalg == SignatureAlgorithm::kMtcProof) {
    return nullptr;
  }
  // minSerial and maxSerial are INTEGER (mtcMinSerial..mtcMaxSerial), where
  // mtcMaxSerial is the largest uint64_t. If `min_serial` > `max_serial`, the
  // range is empty, and the MTC CA has no valid serial numbers.
  if (min_serial < kMtcMinSerial || max_serial < kMtcMinSerial) {
    return nullptr;
  }
  CBS key_cbs(ca_cosign_key), ca_id_cbs(ca_id);
  // Ensure `ca_cosign_key` is a single SEQUENCE, so it cannot be misparsed as
  // other Certificate fields.
  if (!CBS_get_asn1(&key_cbs, nullptr, CBS_ASN1_SEQUENCE) ||
      CBS_len(&key_cbs) != 0) {
    return nullptr;
  }
  if (!CBS_is_valid_asn1_relative_oid(&ca_id_cbs)) {
    return nullptr;
  }

  // MTCCertificationAuthority
  ScopedCBB mtc_ca_cbb;
  CBB mtc_ca;
  if (!CBB_init(mtc_ca_cbb.get(), 32) ||
      !CBB_add_asn1(mtc_ca_cbb.get(), &mtc_ca, CBS_ASN1_SEQUENCE) ||
      // sigAlg
      !AddSignatureAlgorithmIdentifier(&mtc_ca, ca_cosign_sigalg) ||
      // minSerial, maxSerial
      !CBB_add_asn1_uint64(&mtc_ca, min_serial) ||
      !CBB_add_asn1_uint64(&mtc_ca, max_serial) ||
      !CBB_flush(mtc_ca_cbb.get())) {
    return nullptr;
  }

  ScopedCBB cbb;
  CBB cert, tbs_cert, version, subject, rdn, attr, extensions_wrapper,
      extensions, signature;
  if (!CBB_init(cbb.get(), 256 + ca_cosign_key.size()) ||
      !CBB_add_asn1(cbb.get(), &cert, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&cert, &tbs_cert, CBS_ASN1_SEQUENCE) ||
      // version: v3
      !CBB_add_asn1(&tbs_cert, &version,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
      !CBB_add_asn1_uint64(&version, 2) ||
      // serialNumber
      !CBB_add_asn1_uint64(&tbs_cert, kMtcCaCertSerialNumber) ||
      // signature (TBSCertificate)
      !der::EncodeUnsignedAlgorithmIdentifier(&tbs_cert) ||
      // issuer
      !der::EncodeUnsignedIssuerName(&tbs_cert) ||
      // validity
      !CBB_add_bytes(&tbs_cert, kMtcCaCertValidity,
                     sizeof(kMtcCaCertValidity)) ||
      // subject
      !CBB_add_asn1(&tbs_cert, &subject, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&subject, &rdn, CBS_ASN1_SET) ||
      !CBB_add_asn1(&rdn, &attr, CBS_ASN1_SEQUENCE)) {
    return nullptr;
  }

  // draft-ietf-plants-merkle-tree-certs, Section 5.1: The CA ID's distinguished
  // name has a single attribute of type id-rdna-trustAnchorID, whose value is a
  // RELATIVE-OID containing the CA ID.
  if (!CBB_add_asn1_element(&attr, CBS_ASN1_OBJECT, kRdnaTrustAnchorIDOid,
                            sizeof(kRdnaTrustAnchorIDOid)) ||
      !CBB_add_asn1_element(&attr, CBS_ASN1_RELATIVE_OID, ca_id.data(),
                            ca_id.size())) {
    return nullptr;
  }

  // subjectPublicKeyInfo
  if (!CBB_add_bytes(&tbs_cert, ca_cosign_key.data(), ca_cosign_key.size()) ||
      // extensions
      !CBB_add_asn1(&tbs_cert, &extensions_wrapper,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 3) ||
      !CBB_add_asn1(&extensions_wrapper, &extensions, CBS_ASN1_SEQUENCE) ||
      !der::EncodeExtension(&extensions, kKeyUsageOid, /*critical=*/true,
                            kMtcCaCertKeyUsage) ||
      !der::EncodeExtension(&extensions, kBasicConstraintsOid,
                            /*critical=*/true, kMtcCaCertBasicConstraints) ||
      !der::EncodeExtension(&extensions, kMtcCertificationAuthoritySha256Oid,
                            /*critical=*/true, CBBAsSpan(mtc_ca_cbb.get())) ||
      // Outer signatureAlgorithm in the Certificate
      !der::EncodeUnsignedAlgorithmIdentifier(&cert) ||
      // signatureValue (BIT STRING of length zero, per RFC 9925)
      !CBB_add_asn1(&cert, &signature, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&signature, 0)) {
    return nullptr;
  }

  if (!CBB_flush(cbb.get())) {
    return nullptr;
  }
  CBS der(CBBAsSpan(cbb.get()));
  return UniquePtr<CRYPTO_BUFFER>(CRYPTO_BUFFER_new_from_CBS(&der, pool));
}

BSSL_NAMESPACE_END
