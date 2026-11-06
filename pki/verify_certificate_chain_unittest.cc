// Copyright 2015 The Chromium Authors
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

#include "verify_certificate_chain.h"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/pool.h>

#include "cert_error_id.h"
#include "cert_errors.h"
#include "common_cert_errors.h"
#include "encode_certificate.h"
#include "encode_values.h"
#include "mock_signature_verify_cache.h"
#include "simple_path_builder_delegate.h"
#include "test_helpers.h"
#include "trust_store.h"
#include "trust_store_in_memory.h"
#include "verify_certificate_chain_typed_unittest.h"
#include "verify_signed_data.h"

BSSL_NAMESPACE_BEGIN

namespace {

class VerifyCertificateChainTestDelegate {
 public:
  static void Verify(const VerifyCertChainTest &test,
                     const std::string &test_file_path) {
    SimplePathBuilderDelegate delegate(1024, test.digest_policy);

    CertPathErrors errors;
    std::set<der::Input> user_constrained_policy_set;
    VerifyCertificateChain(
        test.chain, TrustAnchor(test.last_cert_trust), &delegate, test.time,
        test.key_purpose, test.initial_explicit_policy,
        test.user_initial_policy_set, test.initial_policy_mapping_inhibit,
        test.initial_any_policy_inhibit, &user_constrained_policy_set, &errors);
    VerifyCertPathErrors(test.expected_errors, errors, test.chain,
                         test_file_path);
    VerifyUserConstrainedPolicySet(test.expected_user_constrained_policy_set,
                                   user_constrained_policy_set, test_file_path);
  }
};

}  // namespace

INSTANTIATE_TYPED_TEST_SUITE_P(VerifyCertificateChain,
                               VerifyCertificateChainSingleRootTest,
                               VerifyCertificateChainTestDelegate);

TEST(VerifyCertificateIsSelfSigned, TargetOnly) {
  auto cert = ReadCertFromFile(
      "testdata/verify_certificate_chain_unittest/target-only/chain.pem");
  ASSERT_TRUE(cert);

  // Test with null cache and errors.
  EXPECT_FALSE(VerifyCertificateIsSelfSigned(*cert, /*cache=*/nullptr,
                                             /*errors=*/nullptr));

  // Test with cache and errors.
  CertErrors errors;
  MockSignatureVerifyCache cache;
  EXPECT_FALSE(VerifyCertificateIsSelfSigned(*cert, &cache, &errors));

  EXPECT_TRUE(
      errors.ContainsAnyErrorWithSeverity(CertError::Severity::SEVERITY_HIGH));
  EXPECT_TRUE(errors.ContainsError(cert_errors::kSubjectDoesNotMatchIssuer));

  // Should not try to verify signature if names don't match.
  EXPECT_EQ(cache.CacheHits(), 0U);
  EXPECT_EQ(cache.CacheMisses(), 0U);
  EXPECT_EQ(cache.CacheStores(), 0U);
}

TEST(VerifyCertificateIsSelfSigned, SelfIssued) {
  auto cert = ReadCertFromFile(
      "testdata/verify_certificate_chain_unittest/target-selfissued/chain.pem");
  ASSERT_TRUE(cert);

  // Test with null cache and errors.
  EXPECT_FALSE(VerifyCertificateIsSelfSigned(*cert, /*cache=*/nullptr,
                                             /*errors=*/nullptr));

  // Test with cache and errors.
  CertErrors errors;
  MockSignatureVerifyCache cache;
  EXPECT_FALSE(VerifyCertificateIsSelfSigned(*cert, &cache, &errors));

  EXPECT_TRUE(
      errors.ContainsAnyErrorWithSeverity(CertError::Severity::SEVERITY_HIGH));
  EXPECT_TRUE(errors.ContainsError(cert_errors::kVerifySignedDataFailed));

  EXPECT_EQ(cache.CacheHits(), 0U);
  EXPECT_EQ(cache.CacheMisses(), 1U);
  EXPECT_EQ(cache.CacheStores(), 1U);

  // Trying again should use cached signature verification result.
  EXPECT_FALSE(VerifyCertificateIsSelfSigned(*cert, &cache, &errors));
  EXPECT_EQ(cache.CacheHits(), 1U);
  EXPECT_EQ(cache.CacheMisses(), 1U);
  EXPECT_EQ(cache.CacheStores(), 1U);
}

TEST(VerifyCertificateIsSelfSigned, SelfSigned) {
  auto cert = ReadCertFromFile(
      "testdata/verify_certificate_chain_unittest/target-selfsigned/chain.pem");
  ASSERT_TRUE(cert);

  // Test with null cache and errors.
  EXPECT_TRUE(VerifyCertificateIsSelfSigned(*cert, /*cache=*/nullptr,
                                            /*errors=*/nullptr));

  // Test with cache and errors.
  CertErrors errors;
  MockSignatureVerifyCache cache;
  EXPECT_TRUE(VerifyCertificateIsSelfSigned(*cert, &cache, &errors));

  EXPECT_FALSE(errors.ContainsAnyErrorWithSeverity(
      CertError::Severity::SEVERITY_WARNING));
  EXPECT_FALSE(
      errors.ContainsAnyErrorWithSeverity(CertError::Severity::SEVERITY_HIGH));

  EXPECT_EQ(cache.CacheHits(), 0U);
  EXPECT_EQ(cache.CacheMisses(), 1U);
  EXPECT_EQ(cache.CacheStores(), 1U);

  // Trying again should use cached signature verification result.
  EXPECT_TRUE(VerifyCertificateIsSelfSigned(*cert, &cache, &errors));
  EXPECT_EQ(cache.CacheHits(), 1U);
  EXPECT_EQ(cache.CacheMisses(), 1U);
  EXPECT_EQ(cache.CacheStores(), 1U);
}

namespace {

DEFINE_CERT_ERROR_ID(kTestDisallowedPublicKeyWarning,
                     "Public key is disallowed by policy");

// A delegate that rejects a particular public key.
class MtcTestDelegate : public SimplePathBuilderDelegate {
 public:
  explicit MtcTestDelegate(DigestPolicy digest_policy = DigestPolicy::kStrong,
                           const EVP_PKEY *disallowed_public_key = nullptr)
      : SimplePathBuilderDelegate(1024, digest_policy),
        disallowed_public_key_(disallowed_public_key) {}

  bool IsPublicKeyAcceptable(const EVP_PKEY *public_key,
                             CertErrors *errors) override {
    if (disallowed_public_key_ &&
        EVP_PKEY_cmp(public_key, disallowed_public_key_) == 1) {
      errors->AddWarning(kTestDisallowedPublicKeyWarning);
      return false;
    }
    return SimplePathBuilderDelegate::IsPublicKeyAcceptable(public_key, errors);
  }

  bool IsDebugLogEnabled() override { return true; }

  void DebugLog(std::string_view msg) override {
    debug_logs_.emplace_back(msg);
  }

  const std::vector<std::string> &debug_logs() const { return debug_logs_; }

 private:
  const EVP_PKEY *disallowed_public_key_;
  std::vector<std::string> debug_logs_;
};

CertPathErrors VerifyMtcTestChain(
    const ParsedCertificateList &chain, const CertificateTrust &trust,
    VerifyCertificateChainDelegate *delegate = nullptr) {
  SimplePathBuilderDelegate default_delegate(
      1024, SimplePathBuilderDelegate::DigestPolicy::kStrong);
  if (!delegate) {
    delegate = &default_delegate;
  }
  der::GeneralizedTime time;
  EXPECT_TRUE(der::EncodePosixTimeAsGeneralizedTime(test::kMtcTestTime, &time));
  CertPathErrors errors;
  VerifyCertificateChain(
      chain, trust, delegate, time, KeyPurpose::ANY_EKU,
      InitialExplicitPolicy::kFalse, {der::Input(kAnyPolicyOid)},
      InitialPolicyMappingInhibit::kFalse, InitialAnyPolicyInhibit::kFalse,
      /*user_constrained_policy_set=*/nullptr, &errors);
  return errors;
}

}  // namespace

// Tests that a certificate is verified as an MTC if the trust anchor
// certificate has an MTC CA extension.
TEST(VerifyCertificateChainMtcTest, MtcCaCertificateAsTrustAnchor) {
  std::shared_ptr<const ParsedCertificate> ca =
      ReadCryptoX509MTCTestCert("ca_cert.pem");
  ASSERT_TRUE(ca);
  std::shared_ptr<const ParsedCertificate> leaf =
      ReadCryptoX509MTCTestCert("cert_33_0.pem");
  ASSERT_TRUE(leaf);
  // A certificate with an invalid MTC proof.
  std::shared_ptr<const ParsedCertificate> bad_leaf =
      ReadCryptoX509MTCTestCert("cert_33_2.pem");
  ASSERT_TRUE(bad_leaf);

  for (const CertificateTrust &trust :
       {CertificateTrust::ForTrustAnchor(),
        // The MTC CA extension counts as a handled critical extension when
        // enforcing trust anchor constraints.
        CertificateTrust::ForTrustAnchor().WithEnforceAnchorConstraints()}) {
    SCOPED_TRACE(trust.ToDebugString());
    MtcTestDelegate delegate;
    CertPathErrors errors = VerifyMtcTestChain({leaf, ca}, trust, &delegate);
    EXPECT_FALSE(errors.ContainsHighSeverityErrors())
        << errors.ToDebugString({leaf, ca});
    EXPECT_THAT(delegate.debug_logs(),
                ::testing::Contains("VerifyMTC: CA signature valid"));

    MtcTestDelegate bad_leaf_delegate;
    errors = VerifyMtcTestChain({bad_leaf, ca}, trust, &bad_leaf_delegate);
    EXPECT_TRUE(errors.ContainsError(cert_errors::kVerifySignedDataFailed))
        << errors.ToDebugString({bad_leaf, ca});
    EXPECT_THAT(bad_leaf_delegate.debug_logs(),
                ::testing::Contains("VerifyMTC: CA signature invalid"));
  }
}

// Tests that an MTC CA trust anchor must have the basic constraints and key
// usage extensions required by draft-ietf-plants-merkle-tree-certs-07, Section
// 5.5, when trust anchor constraints are being enforced.
TEST(VerifyCertificateChainMtcTest, MtcCaCertificateEnforceAnchorConstraints) {
  struct {
    const char *dir;
    std::optional<CertErrorId> expected_error;
  } kTests[] = {
      {"ca_no_basic_constraints", cert_errors::kMissingBasicConstraints},
      {"ca_not_ca", cert_errors::kBasicConstraintsIndicatesNotCa},
      {"ca_no_key_cert_sign", cert_errors::kKeyCertSignBitNotSet},
      // keyUsage is only checked if present, as with other trust anchors.
      {"ca_no_key_usage", std::nullopt},
  };
  for (const auto &test : kTests) {
    SCOPED_TRACE(test.dir);
    std::shared_ptr<const ParsedCertificate> ca =
        ReadCryptoX509MTCTestCert(std::string(test.dir) + "/ca_cert.pem");
    ASSERT_TRUE(ca);
    std::shared_ptr<const ParsedCertificate> leaf =
        ReadCryptoX509MTCTestCert(std::string(test.dir) + "/cert_1_0.pem");
    ASSERT_TRUE(leaf);
    ParsedCertificateList chain = {leaf, ca};

    for (const bool enforce : {true, false}) {
      SCOPED_TRACE(enforce);
      CertPathErrors errors = VerifyMtcTestChain(
          chain, CertificateTrust::ForTrustAnchor()
                     .WithEnforceAnchorConstraints(enforce)
                     .WithRequireAnchorBasicConstraints(enforce));
      if (enforce && test.expected_error) {
        EXPECT_TRUE(
            errors.GetErrorsForCert(1)->ContainsError(*test.expected_error))
            << errors.ToDebugString(chain);
      } else {
        EXPECT_FALSE(errors.ContainsHighSeverityErrors())
            << errors.ToDebugString(chain);
      }
    }
  }
}

// Tests that an MTC is only verified if its serial number is within the MTC CA
// certificate's serial number range, inclusive.
TEST(VerifyCertificateChainMtcTest, MtcSerialNumberRange) {
  struct {
    const char *dir;
    bool expect_valid;
  } kTests[] = {
      // The serial number is equal to both minSerial and maxSerial.
      {"serial_at_min_and_max", true},
      // The serial number is one less than minSerial.
      {"serial_below_min", false},
      // The serial number is one more than maxSerial.
      {"serial_above_max", false},
  };
  for (const auto &test : kTests) {
    SCOPED_TRACE(test.dir);
    std::shared_ptr<const ParsedCertificate> ca =
        ReadCryptoX509MTCTestCert(std::string(test.dir) + "/ca_cert.pem");
    ASSERT_TRUE(ca);
    std::shared_ptr<const ParsedCertificate> leaf =
        ReadCryptoX509MTCTestCert(std::string(test.dir) + "/cert_1_0.pem");
    ASSERT_TRUE(leaf);
    ParsedCertificateList chain = {leaf, ca};

    CertPathErrors errors =
        VerifyMtcTestChain(chain, CertificateTrust::ForTrustAnchor());
    if (test.expect_valid) {
      EXPECT_FALSE(errors.ContainsHighSeverityErrors())
          << errors.ToDebugString(chain);
    } else {
      EXPECT_TRUE(errors.GetErrorsForCert(0)->ContainsError(
          cert_errors::kVerifySignedDataFailed))
          << errors.ToDebugString(chain);
    }
  }
}

// Tests that a chain with an MTC CA certificate as an intermediate is rejected.
// MTC CAs are only used as trust anchors.
TEST(VerifyCertificateChainMtcTest, MtcCaCertificateAsIntermediate) {
  // The MTC CA certificate from crypto/x509/test/mtc/ca_cert.pem, re-issued by
  // a conventional root. See generate_mtc_ca_intermediate_certs.cc.
  std::shared_ptr<const ParsedCertificate> root =
      ReadCertFromFile("testdata/verify_unittest/mtc-ca-intermediate-root.pem");
  ASSERT_TRUE(root);
  std::shared_ptr<const ParsedCertificate> intermediate =
      ReadCertFromFile("testdata/verify_unittest/mtc-ca-intermediate.pem");
  ASSERT_TRUE(intermediate);
  ASSERT_TRUE(intermediate->mtc_ca_info());
  std::shared_ptr<const ParsedCertificate> leaf =
      ReadCryptoX509MTCTestCert("cert_33_0.pem");
  ASSERT_TRUE(leaf);

  ParsedCertificateList chain = {leaf, intermediate, root};
  CertPathErrors errors =
      VerifyMtcTestChain(chain, CertificateTrust::ForTrustAnchor());
  EXPECT_TRUE(errors.GetErrorsForCert(0)->ContainsError(
      cert_errors::kMtcCaIsNotTrustAnchor))
      << errors.ToDebugString(chain);
}

TEST(VerifyCertificateChainMtcTest, MtcCaCosignerSignatureAlgorithm) {
  std::shared_ptr<const ParsedCertificate> ca =
      ReadCryptoX509MTCTestCert("ca_sha1_cosigner/ca_cert.pem");
  ASSERT_TRUE(ca);
  std::shared_ptr<const ParsedCertificate> leaf =
      ReadCryptoX509MTCTestCert("ca_sha1_cosigner/cert_1_0.pem");
  ASSERT_TRUE(leaf);
  ParsedCertificateList chain = {leaf, ca};

  // The strong delegate rejects SHA-1.
  MtcTestDelegate strong_delegate(
      SimplePathBuilderDelegate::DigestPolicy::kStrong);
  CertPathErrors errors = VerifyMtcTestChain(
      chain, CertificateTrust::ForTrustAnchor(), &strong_delegate);
  EXPECT_TRUE(errors.GetErrorsForCert(0)->ContainsError(
      cert_errors::kVerifySignedDataFailed))
      << errors.ToDebugString(chain);
  EXPECT_THAT(strong_delegate.debug_logs(),
              ::testing::Contains("VerifyMTC: CA signature invalid:\n"
                                  "ERROR: Unacceptable signature algorithm\n"));

  MtcTestDelegate allow_sha1_delegate(
      SimplePathBuilderDelegate::DigestPolicy::kWeakAllowSha1);
  errors = VerifyMtcTestChain(chain, CertificateTrust::ForTrustAnchor(),
                              &allow_sha1_delegate);
  EXPECT_FALSE(errors.ContainsHighSeverityErrors())
      << errors.ToDebugString(chain);
  EXPECT_THAT(allow_sha1_delegate.debug_logs(),
              ::testing::Contains("VerifyMTC: CA signature valid"));
}

TEST(VerifyCertificateChainMtcTest, MtcCaCosignerPublicKey) {
  std::shared_ptr<const ParsedCertificate> ca =
      ReadCryptoX509MTCTestCert("ca_cert.pem");
  ASSERT_TRUE(ca);
  ASSERT_TRUE(ca->mtc_ca_info());
  std::shared_ptr<const ParsedCertificate> leaf =
      ReadCryptoX509MTCTestCert("cert_33_0.pem");
  ASSERT_TRUE(leaf);

  // Rejecting the MTC CA's cosigner key via IsPublicKeyAcceptable (for example,
  // due to a key blocklist policy) fails verification even though
  // ParsePublicKey succeeds and the proof is valid.
  {
    UniquePtr<EVP_PKEY> ca_key;
    ASSERT_TRUE(ParsePublicKey(ca->tbs().spki_tlv, &ca_key));

    ParsedCertificateList chain = {leaf, ca};
    MtcTestDelegate reject_key_delegate(
        SimplePathBuilderDelegate::DigestPolicy::kStrong, ca_key.get());
    CertPathErrors errors = VerifyMtcTestChain(
        chain, CertificateTrust::ForTrustAnchor(), &reject_key_delegate);
    EXPECT_TRUE(errors.GetErrorsForCert(0)->ContainsError(
        cert_errors::kVerifySignedDataFailed))
        << errors.ToDebugString(chain);
    EXPECT_THAT(
        reject_key_delegate.debug_logs(),
        ::testing::Contains("VerifyMTC: CA signature invalid:\n"
                            "WARNING: Public key is disallowed by policy\n"
                            "ERROR: Unacceptable public key\n"));
  }

  // An MTC CA certificate with an unparsable SubjectPublicKeyInfo fails
  // verification.
  {
    static constexpr uint8_t kUnparsableSpki[] = {0x30, 0x00};
    UniquePtr<CRYPTO_BUFFER> bad_spki_ca_buf = EncodeMtcCaCertificate(
        ca->mtc_ca_info()->ca_id, SignatureAlgorithm::kMldsa44, kUnparsableSpki,
        ca->mtc_ca_info()->min_serial, ca->mtc_ca_info()->max_serial,
        /*pool=*/nullptr);
    ASSERT_TRUE(bad_spki_ca_buf);
    std::shared_ptr<const ParsedCertificate> bad_spki_ca =
        ParsedCertificate::Create(std::move(bad_spki_ca_buf), {},
                                  /*errors=*/nullptr);
    ASSERT_TRUE(bad_spki_ca);

    ParsedCertificateList chain = {leaf, bad_spki_ca};
    MtcTestDelegate delegate;
    CertPathErrors errors = VerifyMtcTestChain(
        chain, CertificateTrust::ForTrustAnchor(), &delegate);
    EXPECT_TRUE(errors.GetErrorsForCert(0)->ContainsError(
        cert_errors::kVerifySignedDataFailed))
        << errors.ToDebugString(chain);
    EXPECT_THAT(
        delegate.debug_logs(),
        ::testing::Contains("VerifyMTC: CA signature invalid:\n"
                            "ERROR: Couldn't parse SubjectPublicKeyInfo\n"));
  }
}

BSSL_NAMESPACE_END
