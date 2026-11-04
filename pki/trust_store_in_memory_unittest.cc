// Copyright 2023 The BoringSSL Authors
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

#include "trust_store_in_memory.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/span.h>

#include "merkle_tree.h"
#include "test_helpers.h"
#include "trust_store.h"

BSSL_NAMESPACE_BEGIN
namespace {

class TrustStoreInMemoryTest : public testing::Test {
 public:
  void SetUp() override {
    ParsedCertificateList chain;
    ASSERT_TRUE(ReadCertChainFromFile(
        "testdata/verify_certificate_chain_unittest/key-rollover/oldchain.pem",
        &chain));

    ASSERT_EQ(3U, chain.size());
    target_ = chain[0];
    oldintermediate_ = chain[1];
    oldroot_ = chain[2];
    ASSERT_TRUE(target_);
    ASSERT_TRUE(oldintermediate_);
    ASSERT_TRUE(oldroot_);

    ASSERT_TRUE(
        ReadCertChainFromFile("testdata/verify_certificate_chain_unittest/"
                              "key-rollover/longrolloverchain.pem",
                              &chain));

    ASSERT_EQ(5U, chain.size());
    newintermediate_ = chain[1];
    newroot_ = chain[2];
    newrootrollover_ = chain[3];
    ASSERT_TRUE(newintermediate_);
    ASSERT_TRUE(newroot_);
    ASSERT_TRUE(newrootrollover_);
  }

 protected:
  std::shared_ptr<const ParsedCertificate> oldroot_;
  std::shared_ptr<const ParsedCertificate> newroot_;
  std::shared_ptr<const ParsedCertificate> newrootrollover_;

  std::shared_ptr<const ParsedCertificate> target_;
  std::shared_ptr<const ParsedCertificate> oldintermediate_;
  std::shared_ptr<const ParsedCertificate> newintermediate_;
};

TEST_F(TrustStoreInMemoryTest, OneRootTrusted) {
  TrustStoreInMemory in_memory;
  in_memory.AddTrustAnchor(newroot_);

  // newroot_ is trusted.
  CertificateTrust trust = in_memory.GetTrust(newroot_.get());
  EXPECT_EQ(CertificateTrust::ForTrustAnchor().ToDebugString(),
            trust.ToDebugString());

  // oldroot_ is not.
  trust = in_memory.GetTrust(oldroot_.get());
  EXPECT_EQ(CertificateTrust::ForUnspecified().ToDebugString(),
            trust.ToDebugString());
}

TEST_F(TrustStoreInMemoryTest, DistrustBySPKI) {
  TrustStoreInMemory in_memory;
  in_memory.AddDistrustedCertificateBySPKI(
      std::string(BytesAsStringView(newroot_->tbs().spki_tlv)));

  // newroot_ is distrusted.
  CertificateTrust trust = in_memory.GetTrust(newroot_.get());
  EXPECT_EQ(CertificateTrust::ForDistrusted().ToDebugString(),
            trust.ToDebugString());

  // oldroot_ is unspecified.
  trust = in_memory.GetTrust(oldroot_.get());
  EXPECT_EQ(CertificateTrust::ForUnspecified().ToDebugString(),
            trust.ToDebugString());

  // newrootrollover_ is also distrusted because it has the same key.
  trust = in_memory.GetTrust(newrootrollover_.get());
  EXPECT_EQ(CertificateTrust::ForDistrusted().ToDebugString(),
            trust.ToDebugString());
}

TEST_F(TrustStoreInMemoryTest, DistrustBySPKIOverridesTrust) {
  TrustStoreInMemory in_memory;
  in_memory.AddTrustAnchor(newroot_);
  in_memory.AddDistrustedCertificateBySPKI(
      std::string(BytesAsStringView(newroot_->tbs().spki_tlv)));

  // newroot_ is distrusted.
  CertificateTrust trust = in_memory.GetTrust(newroot_.get());
  EXPECT_EQ(CertificateTrust::ForDistrusted().ToDebugString(),
            trust.ToDebugString());
}

TEST_F(TrustStoreInMemoryTest, IsEmptyClear) {
  TrustStoreInMemory in_memory;

  // Trust store is empty with nothing in it.
  EXPECT_TRUE(in_memory.IsEmpty());

  // After adding a classical trust anchor, it is no longer empty:
  in_memory.AddTrustAnchor(oldroot_);
  EXPECT_FALSE(in_memory.IsEmpty());

  // It is empty again after a call to Clear:
  in_memory.Clear();
  EXPECT_TRUE(in_memory.IsEmpty());

  // After adding an MTC root, it is no longer empty:
  static const uint8_t kMtcCaId[] = {42};  // relative OID of 42
  UniquePtr<CRYPTO_BUFFER> ca_spki = ReadCryptoX509MtcTestCaKey();
  std::vector<LogTrustedSubtrees> trusted_subtrees;
  auto mtc_anchor = MTCAnchor::CreatePlants07(MakeSpan(kMtcCaId),
                                              SignatureAlgorithm::kMldsa44,
                                              UpRef(ca_spki), trusted_subtrees);
  ASSERT_TRUE(mtc_anchor);
  EXPECT_TRUE(in_memory.AddMTCTrustAnchor(mtc_anchor));
  EXPECT_FALSE(in_memory.IsEmpty());

  // It is empty again after a call to Clear:
  in_memory.Clear();
  EXPECT_TRUE(in_memory.IsEmpty());
}

TEST_F(TrustStoreInMemoryTest, MTCAnchors) {
  TrustStoreInMemory in_memory;

  // AddMTCTrustAnchor should fail if the MTCAnchor is invalid.
  static const uint8_t kValidCaId[] = {42};  // relative OID of 42
  static const uint8_t kValidCaId2[] = {43};  // relative OID of 43
  TrustedSubtree a;
  a.range = Subtree{0, 4};
  TrustedSubtree b;
  b.range = Subtree{0, 6};
  TrustedSubtree c;
  c.range = Subtree{8, 9};
  std::vector<LogTrustedSubtrees> valid_subtrees = {{1, {a, b, c}}};
  UniquePtr<CRYPTO_BUFFER> ca_spki = ReadCryptoX509MtcTestCaKey();
  {
    std::shared_ptr<const MTCAnchor> valid_anchor =
        MTCAnchor::CreatePlants07(kValidCaId, SignatureAlgorithm::kMldsa44,
                                  UpRef(ca_spki), valid_subtrees);
    ASSERT_TRUE(valid_anchor);
    EXPECT_EQ(valid_anchor->ca_id(), kValidCaId);
    EXPECT_TRUE(in_memory.AddMTCTrustAnchor(valid_anchor));
  }

  {
    // Attempting to add another MTCTrustAnchor with the same CA ID should fail
    TrustedSubtree d;
    d.range = Subtree{16, 17};
    std::vector<LogTrustedSubtrees> subtrees = {{1, {d}}};
    std::shared_ptr<const MTCAnchor> anchor = MTCAnchor::CreatePlants07(
        kValidCaId, SignatureAlgorithm::kMldsa44, UpRef(ca_spki), subtrees);
    ASSERT_TRUE(anchor);
    EXPECT_FALSE(in_memory.AddMTCTrustAnchor(anchor));
  }

  {
    static const uint8_t kInvalidCaId[] = {
        255};  // The high bit is set, indicating this relative OID has more
               // bytes, but there are no more bytes.
    EXPECT_FALSE(MTCAnchor::CreatePlants07(kInvalidCaId,
                                           SignatureAlgorithm::kMldsa44,
                                           UpRef(ca_spki), valid_subtrees));
  }

  {
    std::vector<LogTrustedSubtrees> invalid_subtrees = {{1, {b, a, c}}};
    EXPECT_FALSE(MTCAnchor::CreatePlants07(kValidCaId2,
                                           SignatureAlgorithm::kMldsa44,
                                           UpRef(ca_spki), invalid_subtrees));
  }

  {
    TrustedSubtree subtree;
    subtree.range = Subtree{4, 9};
    std::vector<LogTrustedSubtrees> invalid_subtrees = {{1, {subtree}}};
    EXPECT_FALSE(MTCAnchor::CreatePlants07(kValidCaId2,
                                           SignatureAlgorithm::kMldsa44,
                                           UpRef(ca_spki), invalid_subtrees));
  }

  {
    std::vector<LogTrustedSubtrees> invalid_log_order = {
        {2, {a}},
        {1, {b}},
    };
    EXPECT_FALSE(MTCAnchor::CreatePlants07(kValidCaId2,
                                           SignatureAlgorithm::kMldsa44,
                                           UpRef(ca_spki), invalid_log_order));
  }

  {
    std::vector<LogTrustedSubtrees> duplicate_log_number = {
        {1, {a}},
        {1, {b}},
    };
    EXPECT_FALSE(
        MTCAnchor::CreatePlants07(kValidCaId2, SignatureAlgorithm::kMldsa44,
                                  UpRef(ca_spki), duplicate_log_number));
  }

  {
    std::vector<LogTrustedSubtrees> valid_multiple_logs = {
        {1, {a, c}},
        {2, {b}},
    };
    std::shared_ptr<const MTCAnchor> valid_anchor =
        MTCAnchor::CreatePlants07(kValidCaId2, SignatureAlgorithm::kMldsa44,
                                  UpRef(ca_spki), valid_multiple_logs);
    ASSERT_TRUE(valid_anchor);
    EXPECT_TRUE(in_memory.AddMTCTrustAnchor(valid_anchor));
  }
}

TEST_F(TrustStoreInMemoryTest, ContainsMTCAnchor) {
  TrustStoreInMemory in_memory1;
  TrustStoreInMemory in_memory2;

  static const uint8_t kValidCaId1[] = {42};  // relative OID of 42
  static const uint8_t kValidCaId2[] = {43};  // relative OID of 43
  std::vector<LogTrustedSubtrees> subtrees;
  UniquePtr<CRYPTO_BUFFER> ca_spki = ReadCryptoX509MtcTestCaKey();

  std::shared_ptr<const MTCAnchor> anchor1 = MTCAnchor::CreatePlants07(
      kValidCaId1, SignatureAlgorithm::kMldsa44, UpRef(ca_spki), subtrees);
  std::shared_ptr<const MTCAnchor> anchor1_dup = MTCAnchor::CreatePlants07(
      kValidCaId1, SignatureAlgorithm::kMldsa44, UpRef(ca_spki), subtrees);
  std::shared_ptr<const MTCAnchor> anchor2 = MTCAnchor::CreatePlants07(
      kValidCaId2, SignatureAlgorithm::kMldsa44, UpRef(ca_spki), subtrees);
  std::shared_ptr<const MTCAnchor> anchor2_dup = MTCAnchor::CreatePlants07(
      kValidCaId2, SignatureAlgorithm::kMldsa44, UpRef(ca_spki), subtrees);

  ASSERT_TRUE(in_memory1.AddMTCTrustAnchor(anchor1));
  ASSERT_TRUE(in_memory2.AddMTCTrustAnchor(anchor2));

  EXPECT_TRUE(in_memory1.ContainsMTCAnchor(anchor1.get()));
  EXPECT_TRUE(in_memory1.ContainsMTCAnchor(anchor1_dup.get()));
  EXPECT_FALSE(in_memory1.ContainsMTCAnchor(anchor2.get()));
  EXPECT_TRUE(in_memory2.ContainsMTCAnchor(anchor2.get()));
  EXPECT_TRUE(in_memory2.ContainsMTCAnchor(anchor2_dup.get()));
  EXPECT_FALSE(in_memory2.ContainsMTCAnchor(anchor1.get()));
}

class TrustedSubtreeSetTest : public testing::Test {
 protected:
  // Returns a TrustedSubtree for [start, end) whose hash is filled with
  // `hash_byte`, so that lookup results can be told apart.
  static TrustedSubtree MakeSubtree(uint64_t start, uint64_t end,
                                    uint8_t hash_byte) {
    TrustedSubtree subtree;
    subtree.range = Subtree{start, end};
    subtree.hash.fill(hash_byte);
    return subtree;
  }

  // Returns the expected hash for a subtree made with MakeSubtree(...,
  // `hash_byte`).
  static std::vector<uint8_t> ExpectedHash(uint8_t hash_byte) {
    return std::vector<uint8_t>(SHA256_DIGEST_LENGTH, hash_byte);
  }

  static std::optional<std::vector<uint8_t>> Lookup(
      const TrustedSubtreeSet &set, uint16_t log_number, Subtree range) {
    std::optional<TreeHashConstSpan> hash =
        set.LookupSubtreeHash(log_number, range);
    if (!hash) {
      return std::nullopt;
    }
    return std::vector<uint8_t>(hash->begin(), hash->end());
  }

  static std::shared_ptr<const MTCAnchor> MakeMTCAnchor(
      std::vector<LogTrustedSubtrees> subtrees) {
    static const uint8_t kCaId[] = {42};  // relative OID of 42
    UniquePtr<CRYPTO_BUFFER> ca_spki = ReadCryptoX509MtcTestCaKey();
    return MTCAnchor::CreatePlants07(kCaId, SignatureAlgorithm::kMldsa44,
                                     std::move(ca_spki), std::move(subtrees));
  }
};

TEST_F(TrustedSubtreeSetTest, CreateValid) {
  const TrustedSubtree a = MakeSubtree(0, 4, 1);
  const TrustedSubtree b = MakeSubtree(0, 6, 2);
  const TrustedSubtree c = MakeSubtree(8, 9, 3);

  const struct {
    const char *name;
    std::vector<LogTrustedSubtrees> subtrees;
  } kTests[] = {
      {"Empty", {}},
      {"OneLogNoSubtrees", {{1, {}}}},
      {"OneLogOneSubtree", {{1, {a}}}},
      {"OneLogSortedSubtrees", {{1, {a, b, c}}}},
      {"MultipleSortedLogs", {{1, {a, c}}, {2, {b}}, {7, {a}}}},
      {"MaxLogNumber", {{1, {a}}, {UINT16_MAX, {b}}}},
  };
  for (const auto &t : kTests) {
    SCOPED_TRACE(t.name);
    EXPECT_TRUE(TrustedSubtreeSet::Create(t.subtrees));
  }
}

TEST_F(TrustedSubtreeSetTest, CreateInvalid) {
  const TrustedSubtree a = MakeSubtree(0, 4, 1);
  const TrustedSubtree b = MakeSubtree(0, 6, 2);
  const TrustedSubtree c = MakeSubtree(8, 9, 3);
  // Ragged left edge: 4 is only divisible by 4, but the subtree has 5 elements.
  const TrustedSubtree ragged = MakeSubtree(4, 9, 4);
  const TrustedSubtree backwards = MakeSubtree(9, 8, 5);

  const struct {
    const char *name;
    std::vector<LogTrustedSubtrees> subtrees;
  } kTests[] = {
      {"LogNumberZero", {{0, {a}}}},
      {"LogNumberZeroBeforeValid", {{0, {a}}, {1, {b}}}},
      {"LogsOutOfOrder", {{2, {a}}, {1, {b}}}},
      {"DuplicateLogNumber", {{1, {a}}, {1, {b}}}},
      {"RaggedSubtree", {{1, {ragged}}}},
      {"BackwardsSubtree", {{1, {backwards}}}},
      {"InvalidSubtreeInSecondLog", {{1, {a}}, {2, {ragged}}}},
      {"SubtreesOutOfOrder", {{1, {b, a, c}}}},
      {"SubtreesOutOfOrderInSecondLog", {{1, {a}}, {2, {c, a}}}},
  };
  for (const auto &t : kTests) {
    SCOPED_TRACE(t.name);
    EXPECT_FALSE(TrustedSubtreeSet::Create(t.subtrees));
  }
}

// Duplicate subtree ranges within a log are accepted as valid, because
// validation only rejects ranges that sort strictly before their predecessor.
TEST_F(TrustedSubtreeSetTest, CreateDuplicateRanges) {
  std::vector<LogTrustedSubtrees> subtrees = {
      {1, {MakeSubtree(0, 4, 1), MakeSubtree(0, 4, 2)}}};
  EXPECT_TRUE(TrustedSubtreeSet::Create(subtrees));
}

TEST_F(TrustedSubtreeSetTest, LookupSubtreeHash) {
  std::shared_ptr<const TrustedSubtreeSet> set = TrustedSubtreeSet::Create({
      {1, {MakeSubtree(0, 4, 1), MakeSubtree(0, 8, 2), MakeSubtree(8, 12, 3)}},
      {3, {MakeSubtree(0, 4, 4), MakeSubtree(16, 32, 5)}},
  });
  ASSERT_TRUE(set);

  // First, middle and last subtree in the first log.
  EXPECT_EQ(Lookup(*set, 1, Subtree{0, 4}), ExpectedHash(1));
  EXPECT_EQ(Lookup(*set, 1, Subtree{0, 8}), ExpectedHash(2));
  EXPECT_EQ(Lookup(*set, 1, Subtree{8, 12}), ExpectedHash(3));

  // The same range in a different log has a different hash.
  EXPECT_EQ(Lookup(*set, 3, Subtree{0, 4}), ExpectedHash(4));
  EXPECT_EQ(Lookup(*set, 3, Subtree{16, 32}), ExpectedHash(5));

  // Unknown log numbers, including one between two known logs.
  EXPECT_FALSE(Lookup(*set, 0, Subtree{0, 4}));
  EXPECT_FALSE(Lookup(*set, 2, Subtree{0, 4}));
  EXPECT_FALSE(Lookup(*set, 4, Subtree{0, 4}));

  // Ranges not in the log: before the first, between two existing ranges,
  // sharing only a start or end with an existing range, after the last, and a
  // range present only in the other log.
  EXPECT_FALSE(Lookup(*set, 3, Subtree{0, 2}));
  EXPECT_FALSE(Lookup(*set, 1, Subtree{0, 6}));
  EXPECT_FALSE(Lookup(*set, 1, Subtree{4, 8}));
  EXPECT_FALSE(Lookup(*set, 1, Subtree{8, 10}));
  EXPECT_FALSE(Lookup(*set, 1, Subtree{12, 16}));
  EXPECT_FALSE(Lookup(*set, 1, Subtree{16, 32}));
}

TEST_F(TrustedSubtreeSetTest, LookupSubtreeHashEmpty) {
  std::shared_ptr<const TrustedSubtreeSet> empty =
      TrustedSubtreeSet::Create({});
  ASSERT_TRUE(empty);
  EXPECT_FALSE(Lookup(*empty, 1, Subtree{0, 4}));

  std::shared_ptr<const TrustedSubtreeSet> empty_log =
      TrustedSubtreeSet::Create({{1, {}}});
  ASSERT_TRUE(empty_log);
  EXPECT_FALSE(Lookup(*empty_log, 1, Subtree{0, 4}));
}

TEST_F(TrustedSubtreeSetTest, DebugString) {
  std::shared_ptr<const TrustedSubtreeSet> set = TrustedSubtreeSet::Create({});
  ASSERT_TRUE(set);
  EXPECT_EQ(set->DebugString(), "none");

  set = TrustedSubtreeSet::Create({{1, {}}});
  ASSERT_TRUE(set);
  EXPECT_EQ(set->DebugString(), "log 1:empty");

  set = TrustedSubtreeSet::Create({
      {1, {MakeSubtree(0, 4, 1), MakeSubtree(8, 12, 2)}},
      {2, {}},
      {3, {MakeSubtree(16, 32, 3)}},
  });
  ASSERT_TRUE(set);
  EXPECT_EQ(set->DebugString(),
            "log 1:2 subtrees(0..12), log 2:empty, log 3:1 subtrees(16..32)");
}

TEST_F(TrustedSubtreeSetTest, MTCAnchorCertTrust) {
  std::shared_ptr<const MTCAnchor> anchor =
      MakeMTCAnchor({{1, {MakeSubtree(0, 4, 1), MakeSubtree(8, 12, 2)}}});
  ASSERT_TRUE(anchor);

  CertificateTrust trust = anchor->CertTrust();
  EXPECT_TRUE(trust.IsTrustAnchor());
  ASSERT_TRUE(trust.trusted_subtrees);
  // CertTrust() shares the MTCAnchor's TrustedSubtreeSet rather than copying.
  EXPECT_EQ(trust.trusted_subtrees.get(),
            anchor->CertTrust().trusted_subtrees.get());

  // The CertificateTrust's subtrees agree with the MTCAnchor.
  for (Subtree range : {Subtree{0, 4}, Subtree{8, 12}, Subtree{4, 8}}) {
    SCOPED_TRACE(std::to_string(range.start) + ".." +
                 std::to_string(range.end));
    std::optional<std::vector<uint8_t>> from_trust =
        Lookup(*trust.trusted_subtrees, 1, range);
    std::optional<TreeHashConstSpan> from_anchor =
        anchor->SubtreeHash(1, range);
    ASSERT_EQ(from_trust.has_value(), from_anchor.has_value());
    if (from_trust) {
      EXPECT_EQ(*from_trust,
                std::vector<uint8_t>(from_anchor->begin(), from_anchor->end()));
    }
  }

  EXPECT_EQ(trust.ToDebugString(),
            "TRUSTED_ANCHOR+trusted_subtrees(log 1:2 subtrees(0..12))");
}

TEST_F(TrustedSubtreeSetTest, MTCAnchorCertTrustNoSubtrees) {
  std::shared_ptr<const MTCAnchor> anchor = MakeMTCAnchor({});
  ASSERT_TRUE(anchor);

  CertificateTrust trust = anchor->CertTrust();
  ASSERT_TRUE(trust.trusted_subtrees);
  EXPECT_EQ(trust.ToDebugString(), "TRUSTED_ANCHOR+trusted_subtrees(none)");
}

TEST_F(TrustedSubtreeSetTest, NonMTCCertTrust) {
  for (const CertificateTrust &trust :
       {CertificateTrust::ForTrustAnchor(),
        CertificateTrust::ForTrustAnchorOrLeaf(),
        CertificateTrust::ForTrustedLeaf(), CertificateTrust::ForUnspecified(),
        CertificateTrust::ForDistrusted()}) {
    SCOPED_TRACE(trust.ToDebugString());
    EXPECT_FALSE(trust.trusted_subtrees);
    EXPECT_EQ(trust.ToDebugString().find("trusted_subtrees"),
              std::string::npos);
  }
}

TEST_F(TrustedSubtreeSetTest, MTCAnchorInvalidSubtrees) {
  EXPECT_FALSE(
      MakeMTCAnchor({{1, {MakeSubtree(8, 12, 1), MakeSubtree(0, 4, 2)}}}));
}

TEST(MTCAnchorTest, Create) {
  std::shared_ptr<const ParsedCertificate> ca_cert =
      ReadCryptoX509MTCTestCert("ca_cert.pem");
  ASSERT_TRUE(ca_cert);
  CertificateTrust trust = CertificateTrust::ForTrustAnchor();
  trust.trusted_subtrees = TrustedSubtreeSet::Create({});
  ASSERT_TRUE(trust.trusted_subtrees);

  std::optional<MTCAnchor> anchor = MTCAnchor::Create(ca_cert, trust);
  ASSERT_TRUE(anchor);
  EXPECT_EQ(anchor->AsCert(), ca_cert);
  EXPECT_TRUE(anchor->CertTrust().IsTrustAnchor());
  EXPECT_EQ(anchor->CertTrust().trusted_subtrees, trust.trusted_subtrees);
  static const uint8_t kExpectedCaId[] = {0x81, 0xfd, 0x59, 0x01};
  EXPECT_EQ(Span(anchor->ca_id()), Span(kExpectedCaId));
  EXPECT_EQ(anchor->ca_signature_algorithm(), SignatureAlgorithm::kMldsa44);
  EXPECT_EQ(anchor->ca_key(), Span(ca_cert->tbs().spki_tlv));
  EXPECT_EQ(anchor->NormalizedSubject(),
            Span<const uint8_t>(ca_cert->normalized_subject()));

  // The MTCAnchor shares ownership of the certificate, so it remains usable
  // after the caller's reference is released.
  der::Input spki = ca_cert->tbs().spki_tlv;
  ca_cert = nullptr;
  EXPECT_EQ(Span(anchor->ca_id()), Span(kExpectedCaId));
  EXPECT_EQ(anchor->ca_key(), Span(spki));

  TrustStoreInMemory store;
  EXPECT_TRUE(store.AddMTCTrustAnchor(std::make_shared<MTCAnchor>(*anchor)));
}

TEST(MTCAnchorTest, CreateNotMtcCa) {
  // A draft-05 MTC CA certificate is not recognized as an MTC CA.
  std::shared_ptr<const ParsedCertificate> draft05_cert =
      ReadCryptoX509MTCTestCert("old_draft_version/ca_cert.pem");
  ASSERT_TRUE(draft05_cert);
  CertificateTrust trust = CertificateTrust::ForTrustAnchor();
  EXPECT_FALSE(MTCAnchor::Create(draft05_cert, trust));

  ParsedCertificateList chain;
  ASSERT_TRUE(ReadCertChainFromFile(
      "testdata/verify_certificate_chain_unittest/key-rollover/oldchain.pem",
      &chain));
  ASSERT_FALSE(chain.empty());
  EXPECT_FALSE(MTCAnchor::Create(chain.back(), trust));
}

// Tests that an MTCAnchor created from MTC CA fields is backed by an MTC CA
// certificate, which copies of the MTCAnchor share ownership of.
TEST(MTCAnchorTest, FromFields) {
  static const uint8_t kCaId[] = {42};
  UniquePtr<CRYPTO_BUFFER> ca_key = ReadCryptoX509MtcTestCaKey();
  ASSERT_TRUE(ca_key);
  Span<const uint8_t> ca_key_der(CRYPTO_BUFFER_data(ca_key.get()),
                                 CRYPTO_BUFFER_len(ca_key.get()));

  std::shared_ptr<const MTCAnchor> anchor = MTCAnchor::CreatePlants07(
      kCaId, SignatureAlgorithm::kMldsa65, UpRef(ca_key),
      std::vector<LogTrustedSubtrees>());
  ASSERT_TRUE(anchor);
  ASSERT_TRUE(anchor->AsCert());
  EXPECT_EQ(Span(anchor->AsCert()->tbs().spki_tlv), ca_key_der);

  MTCAnchor copy = *anchor;
  anchor = nullptr;
  EXPECT_EQ(copy.ca_id(), Span(kCaId));
  EXPECT_EQ(copy.ca_signature_algorithm(), SignatureAlgorithm::kMldsa65);
  EXPECT_EQ(copy.ca_key(), ca_key_der);
  EXPECT_TRUE(copy.CertTrust().IsTrustAnchor());
  EXPECT_TRUE(copy.CertTrust().trusted_subtrees);
}

TEST(MTCAnchorTest, FromInvalidFields) {
  static const uint8_t kInvalidCaId[] = {0x80, 0x01};
  UniquePtr<CRYPTO_BUFFER> ca_key = ReadCryptoX509MtcTestCaKey();
  ASSERT_TRUE(ca_key);
  EXPECT_FALSE(MTCAnchor::CreatePlants07(
      kInvalidCaId, SignatureAlgorithm::kMldsa44, UpRef(ca_key),
      std::vector<LogTrustedSubtrees>()));

  // The CA key must be a SubjectPublicKeyInfo.
  static const uint8_t kCaId[] = {42};
  UniquePtr<CRYPTO_BUFFER> invalid_key(CRYPTO_BUFFER_new({}, 0, nullptr));
  EXPECT_FALSE(MTCAnchor::CreatePlants07(kCaId, SignatureAlgorithm::kMldsa44,
                                         UpRef(invalid_key),
                                         std::vector<LogTrustedSubtrees>()));
}

}  // namespace
BSSL_NAMESPACE_END
