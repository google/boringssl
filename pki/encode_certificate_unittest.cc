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

#include <vector>

#include <gtest/gtest.h>

#include <openssl/pool.h>

#include "../crypto/test/test_util.h"
#include "input.h"
#include "parsed_certificate.h"
#include "signature_algorithm.h"
#include "test_helpers.h"

BSSL_NAMESPACE_BEGIN

namespace {

// The widest valid serial number range for an MTC CA.
constexpr uint64_t kMinSerial = uint64_t{1} << 48;
constexpr uint64_t kMaxSerial = UINT64_MAX;

// Encodes an MTC CA certificate and parses it as for any other certificate.
std::shared_ptr<const ParsedCertificate> EncodeAndParseMtcCaCertificate(
    Span<const uint8_t> ca_id, SignatureAlgorithm ca_cosign_sigalg,
    Span<const uint8_t> ca_cosign_key, uint64_t min_serial,
    uint64_t max_serial) {
  UniquePtr<CRYPTO_BUFFER> cert =
      EncodeMtcCaCertificate(ca_id, ca_cosign_sigalg, ca_cosign_key, min_serial,
                             max_serial, /*pool=*/nullptr);
  if (!cert) {
    return nullptr;
  }
  return ParsedCertificate::Create(std::move(cert), {}, nullptr);
}

}  // namespace

// Tests that the encoded MTC CA certificate exactly matches a certificate
// generated independently with the same fields, by the demo tool in
// crypto/x509/test/mtc.
TEST(EncodeCertificateTest, EncodeMtcCaCertificate) {
  std::shared_ptr<const ParsedCertificate> expected =
      ReadCryptoX509MTCTestCert("ca_widest_validity/ca_cert.pem");
  ASSERT_TRUE(expected);

  static const uint8_t kCaId[] = {0x81, 0xfd, 0x59, 0x01};  // 32473.1
  UniquePtr<CRYPTO_BUFFER> cert = EncodeMtcCaCertificate(
      kCaId, SignatureAlgorithm::kMldsa44, expected->tbs().spki_tlv,
      /*min_serial=*/(uint64_t{1} << 48) | 8,
      /*max_serial=*/(uint64_t{1} << 48) | 4096, /*pool=*/nullptr);
  ASSERT_TRUE(cert);
  EXPECT_EQ(
      Bytes(CRYPTO_BUFFER_data(cert.get()), CRYPTO_BUFFER_len(cert.get())),
      Bytes(expected->der_cert().data(), expected->der_cert().size()));
}

TEST(EncodeCertificateTest, EncodeMtcCaCertificateSignatureAlgorithms) {
  std::shared_ptr<const ParsedCertificate> ca_cert =
      ReadCryptoX509MTCTestCert("ca_cert.pem");
  ASSERT_TRUE(ca_cert);
  static const uint8_t kCaId[] = {42};

  for (int i = 0; i <= static_cast<int>(SignatureAlgorithm::kMaxValue); i++) {
    SignatureAlgorithm alg = static_cast<SignatureAlgorithm>(i);
    SCOPED_TRACE(i);
    std::shared_ptr<const ParsedCertificate> cert =
        EncodeAndParseMtcCaCertificate(kCaId, alg, ca_cert->tbs().spki_tlv,
                                       kMinSerial, kMaxSerial);
    if (alg == SignatureAlgorithm::kMtcProof) {
      EXPECT_FALSE(cert);
      continue;
    }
    ASSERT_TRUE(cert);
    EXPECT_EQ(
        ParseSignatureAlgorithm(cert->mtc_ca_info()->ca_cosign_algorithm_tlv),
        alg);
  }
}

TEST(EncodeCertificateTest, EncodeMtcCaCertificateInvalid) {
  std::shared_ptr<const ParsedCertificate> ca_cert =
      ReadCryptoX509MTCTestCert("ca_cert.pem");
  ASSERT_TRUE(ca_cert);
  der::Input spki = ca_cert->tbs().spki_tlv;
  static const uint8_t kCaId[] = {42};
  // A non-minimal RELATIVE-OID component.
  static const uint8_t kInvalidCaId[] = {0x80, 0x01};
  static const uint8_t kInvalidSpki[] = {0x01, 0x02, 0x03};
  // A valid SubjectPublicKeyInfo followed by trailing data.
  std::vector<uint8_t> spki_trailing_data(spki.begin(), spki.end());
  spki_trailing_data.push_back(0x05);
  spki_trailing_data.push_back(0x00);

  auto encode = [](Span<const uint8_t> ca_id, Span<const uint8_t> key,
                   uint64_t min_serial = kMinSerial,
                   uint64_t max_serial = kMaxSerial) {
    return EncodeMtcCaCertificate(ca_id, SignatureAlgorithm::kMldsa44, key,
                                  min_serial, max_serial, /*pool=*/nullptr);
  };
  EXPECT_TRUE(encode(kCaId, spki));
  EXPECT_FALSE(encode(kInvalidCaId, spki));
  EXPECT_FALSE(encode({}, spki));
  EXPECT_FALSE(encode(kCaId, kInvalidSpki));
  EXPECT_FALSE(encode(kCaId, {}));
  EXPECT_FALSE(encode(kCaId, spki_trailing_data));

  // Serial numbers must be at least mtcMinSerial. The range may be empty.
  EXPECT_TRUE(encode(kCaId, spki, kMinSerial, kMinSerial));
  EXPECT_TRUE(encode(kCaId, spki, kMinSerial + 1, kMinSerial));
  EXPECT_FALSE(encode(kCaId, spki, kMinSerial - 1, kMaxSerial));
  EXPECT_FALSE(encode(kCaId, spki, kMinSerial, kMinSerial - 1));
}

// Tests that the certificate is allocated from the given pool.
TEST(EncodeCertificateTest, EncodeMtcCaCertificatePool) {
  std::shared_ptr<const ParsedCertificate> ca_cert =
      ReadCryptoX509MTCTestCert("ca_cert.pem");
  ASSERT_TRUE(ca_cert);
  static const uint8_t kCaId[] = {42};

  UniquePtr<CRYPTO_BUFFER_POOL> pool(CRYPTO_BUFFER_POOL_new());
  ASSERT_TRUE(pool);
  UniquePtr<CRYPTO_BUFFER> cert1 = EncodeMtcCaCertificate(
      kCaId, SignatureAlgorithm::kMldsa44, ca_cert->tbs().spki_tlv, kMinSerial,
      kMaxSerial, pool.get());
  ASSERT_TRUE(cert1);
  UniquePtr<CRYPTO_BUFFER> cert2 = EncodeMtcCaCertificate(
      kCaId, SignatureAlgorithm::kMldsa44, ca_cert->tbs().spki_tlv, kMinSerial,
      kMaxSerial, pool.get());
  ASSERT_TRUE(cert2);
  EXPECT_EQ(cert1.get(), cert2.get());
}

BSSL_NAMESPACE_END
