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

#include "trust_store.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <openssl/base.h>
#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include <openssl/pool.h>
#include <openssl/span.h>

#include "encode_certificate.h"
#include "merkle_tree.h"
#include "parse_certificate.h"
#include "parsed_certificate.h"
#include "signature_algorithm.h"
#include "string_util.h"

BSSL_NAMESPACE_BEGIN

namespace {

constexpr char kUnspecifiedStr[] = "UNSPECIFIED";
constexpr char kDistrustedStr[] = "DISTRUSTED";
constexpr char kTrustedAnchorStr[] = "TRUSTED_ANCHOR";
constexpr char kTrustedAnchorOrLeafStr[] = "TRUSTED_ANCHOR_OR_LEAF";
constexpr char kTrustedLeafStr[] = "TRUSTED_LEAF";

constexpr char kEnforceAnchorExpiry[] = "enforce_anchor_expiry";
constexpr char kEnforceAnchorConstraints[] = "enforce_anchor_constraints";
constexpr char kRequireAnchorBasicConstraints[] =
    "require_anchor_basic_constraints";
constexpr char kRequireLeafSelfsigned[] = "require_leaf_selfsigned";

}  // namespace

TrustedSubtreeSet::TrustedSubtreeSet(
    TrustedSubtreeSet::Token, std::vector<LogTrustedSubtrees> trusted_subtrees)
    : trusted_subtrees_(std::move(trusted_subtrees)) {}

// static
std::shared_ptr<const TrustedSubtreeSet> TrustedSubtreeSet::Create(
    std::vector<LogTrustedSubtrees> trusted_subtrees) {
  if (!IsValid(trusted_subtrees)) {
    return nullptr;
  }
  return std::make_shared<TrustedSubtreeSet>(Token(),
                                             std::move(trusted_subtrees));
}

std::optional<TreeHashConstSpan> TrustedSubtreeSet::LookupSubtreeHash(
    uint16_t log_number, Subtree target_range) const {
  // The `trusted_subtrees_` is generally expected to have one, or rarely two,
  // elements, so just using a simple find rather than a binary search.
  auto subtrees_it =
      std::find_if(trusted_subtrees_.begin(), trusted_subtrees_.end(),
                   [log_number](const LogTrustedSubtrees &logsubtree) -> bool {
                     return logsubtree.log_number == log_number;
                   });
  if (subtrees_it == trusted_subtrees_.end()) {
    return std::nullopt;
  }

  const auto &subtrees = subtrees_it->trusted_subtrees;
  auto it = std::lower_bound(
      subtrees.begin(), subtrees.end(), target_range,
      [](const TrustedSubtree &subtree, Subtree range) -> bool {
        return subtree.range < range;
      });
  if (it == subtrees.end() || it->range != target_range) {
    return std::nullopt;
  }
  return it->hash;
}

std::string TrustedSubtreeSet::DebugString() const {
  if (trusted_subtrees_.empty()) {
    return "none";
  }
  std::string result;

  for (const auto &[log_number, subtrees] : trusted_subtrees_) {
    if (!result.empty()) {
      result += ", ";
    }
    result += "log " + std::to_string(log_number) + ":";
    if (subtrees.empty()) {
      result += "empty";
    } else {
      // Just showing the start of first range to end of last range is an
      // oversimplification, but showing every single range is probably too
      // verbose.
      result += std::to_string(subtrees.size()) + " subtrees(" +
                std::to_string(subtrees.front().range.start) + ".." +
                std::to_string(subtrees.back().range.end) + ")";
    }
  }
  return result;
}

// static
bool TrustedSubtreeSet::IsValid(
    const std::vector<LogTrustedSubtrees> &trusted_subtrees) {
  uint16_t min_log_number = 0;
  for (const auto &[log_number, subtrees] : trusted_subtrees) {
    if (log_number <= min_log_number) {
      // Log numbers must be greater than zero, and `trusted_subtrees` must be
      // in sorted order without repeated log numbers.
      return false;
    }
    min_log_number = log_number;
    Subtree min_subtree;
    for (const auto &subtree : subtrees) {
      if (!subtree.range.IsValid() || subtree.range < min_subtree) {
        return false;
      }
      min_subtree = subtree.range;
    }
  }
  return true;
}

bool CertificateTrust::IsTrustAnchor() const {
  switch (type) {
    case CertificateTrustType::DISTRUSTED:
    case CertificateTrustType::UNSPECIFIED:
    case CertificateTrustType::TRUSTED_LEAF:
      return false;
    case CertificateTrustType::TRUSTED_ANCHOR:
    case CertificateTrustType::TRUSTED_ANCHOR_OR_LEAF:
      return true;
  }

  assert(0);  // NOTREACHED
  return false;
}

bool CertificateTrust::IsTrustLeaf() const {
  switch (type) {
    case CertificateTrustType::TRUSTED_LEAF:
    case CertificateTrustType::TRUSTED_ANCHOR_OR_LEAF:
      return true;
    case CertificateTrustType::DISTRUSTED:
    case CertificateTrustType::UNSPECIFIED:
    case CertificateTrustType::TRUSTED_ANCHOR:
      return false;
  }

  assert(0);  // NOTREACHED
  return false;
}

bool CertificateTrust::IsDistrusted() const {
  switch (type) {
    case CertificateTrustType::DISTRUSTED:
      return true;
    case CertificateTrustType::UNSPECIFIED:
    case CertificateTrustType::TRUSTED_ANCHOR:
    case CertificateTrustType::TRUSTED_ANCHOR_OR_LEAF:
    case CertificateTrustType::TRUSTED_LEAF:
      return false;
  }

  assert(0);  // NOTREACHED
  return false;
}

bool CertificateTrust::HasUnspecifiedTrust() const {
  switch (type) {
    case CertificateTrustType::UNSPECIFIED:
      return true;
    case CertificateTrustType::DISTRUSTED:
    case CertificateTrustType::TRUSTED_ANCHOR:
    case CertificateTrustType::TRUSTED_ANCHOR_OR_LEAF:
    case CertificateTrustType::TRUSTED_LEAF:
      return false;
  }

  assert(0);  // NOTREACHED
  return true;
}

std::string CertificateTrust::ToDebugString() const {
  std::string result;
  switch (type) {
    case CertificateTrustType::UNSPECIFIED:
      result = kUnspecifiedStr;
      break;
    case CertificateTrustType::DISTRUSTED:
      result = kDistrustedStr;
      break;
    case CertificateTrustType::TRUSTED_ANCHOR:
      result = kTrustedAnchorStr;
      break;
    case CertificateTrustType::TRUSTED_ANCHOR_OR_LEAF:
      result = kTrustedAnchorOrLeafStr;
      break;
    case CertificateTrustType::TRUSTED_LEAF:
      result = kTrustedLeafStr;
      break;
  }
  if (enforce_anchor_expiry) {
    result += '+';
    result += kEnforceAnchorExpiry;
  }
  if (enforce_anchor_constraints) {
    result += '+';
    result += kEnforceAnchorConstraints;
  }
  if (require_anchor_basic_constraints) {
    result += '+';
    result += kRequireAnchorBasicConstraints;
  }
  if (require_leaf_selfsigned) {
    result += '+';
    result += kRequireLeafSelfsigned;
  }
  if (trusted_subtrees != nullptr) {
    result += "+trusted_subtrees(";
    result += trusted_subtrees->DebugString();
    result += ')';
  }
  return result;
}

// static
std::optional<CertificateTrust> CertificateTrust::FromDebugString(
    const std::string &trust_string) {
  std::vector<std::string_view> split =
      string_util::SplitString(trust_string, '+');

  if (split.empty()) {
    return std::nullopt;
  }

  CertificateTrust trust;

  if (string_util::IsEqualNoCase(split[0], kUnspecifiedStr)) {
    trust = CertificateTrust::ForUnspecified();
  } else if (string_util::IsEqualNoCase(split[0], kDistrustedStr)) {
    trust = CertificateTrust::ForDistrusted();
  } else if (string_util::IsEqualNoCase(split[0], kTrustedAnchorStr)) {
    trust = CertificateTrust::ForTrustAnchor();
  } else if (string_util::IsEqualNoCase(split[0], kTrustedAnchorOrLeafStr)) {
    trust = CertificateTrust::ForTrustAnchorOrLeaf();
  } else if (string_util::IsEqualNoCase(split[0], kTrustedLeafStr)) {
    trust = CertificateTrust::ForTrustedLeaf();
  } else {
    return std::nullopt;
  }

  for (auto i = ++split.begin(); i != split.end(); ++i) {
    if (string_util::IsEqualNoCase(*i, kEnforceAnchorExpiry)) {
      trust = trust.WithEnforceAnchorExpiry();
    } else if (string_util::IsEqualNoCase(*i, kEnforceAnchorConstraints)) {
      trust = trust.WithEnforceAnchorConstraints();
    } else if (string_util::IsEqualNoCase(*i, kRequireAnchorBasicConstraints)) {
      trust = trust.WithRequireAnchorBasicConstraints();
    } else if (string_util::IsEqualNoCase(*i, kRequireLeafSelfsigned)) {
      trust = trust.WithRequireLeafSelfSigned();
    } else {
      return std::nullopt;
    }
  }

  return trust;
}

// static
std::optional<MTCAnchor> MTCAnchor::Create(
    std::shared_ptr<const ParsedCertificate> cert, CertificateTrust trust) {
  if (!cert->mtc_ca_info()) {
    return std::nullopt;
  }
  return std::optional<MTCAnchor>(std::in_place, Token(), std::move(cert),
                                  std::move(trust));
}

// static
std::shared_ptr<const MTCAnchor> MTCAnchor::CreatePlants07(
    Span<const uint8_t> ca_id, SignatureAlgorithm ca_signature_algorithm,
    UniquePtr<CRYPTO_BUFFER> ca_key,
    std::vector<LogTrustedSubtrees> log_trusted_subtrees) {
  CBS ca_id_cbs(ca_id);
  if (!CBS_is_valid_asn1_relative_oid(&ca_id_cbs)) {
    return nullptr;
  }
  CertificateTrust trust = CertificateTrust::ForTrustAnchor();
  trust.trusted_subtrees =
      TrustedSubtreeSet::Create(std::move(log_trusted_subtrees));
  if (!trust.trusted_subtrees) {
    return nullptr;
  }
  // The fields do not include a serial number range, so allow all valid serial
  // numbers (mtcMinSerial..mtcMaxSerial).
  UniquePtr<CRYPTO_BUFFER> cert_der = EncodeMtcCaCertificate(
      ca_id, ca_signature_algorithm,
      Span(CRYPTO_BUFFER_data(ca_key.get()), CRYPTO_BUFFER_len(ca_key.get())),
      /*min_serial=*/uint64_t{1} << 48, /*max_serial=*/UINT64_MAX,
      /*pool=*/nullptr);
  if (!cert_der) {
    return nullptr;
  }
  std::shared_ptr<const ParsedCertificate> cert = ParsedCertificate::Create(
      std::move(cert_der), ParseCertificateOptions{}, nullptr);
  return std::make_shared<const MTCAnchor>(Token(), std::move(cert),
                                           std::move(trust));
}

MTCAnchor::MTCAnchor(Token, std::shared_ptr<const ParsedCertificate> cert,
                     CertificateTrust trust)
    : cert_(std::move(cert)), trust_(std::move(trust)) {
  BSSL_CHECK(cert_ && cert_->mtc_ca_info());
}

Span<const uint8_t> MTCAnchor::ca_id() const {
  return cert_->mtc_ca_info()->ca_id;
}

std::optional<SignatureAlgorithm> MTCAnchor::ca_signature_algorithm() const {
  return ParseSignatureAlgorithm(cert_->mtc_ca_info()->ca_cosign_algorithm_tlv);
}

Span<const uint8_t> MTCAnchor::ca_key() const {
  return cert_->tbs().spki_tlv;
}

Span<const uint8_t> MTCAnchor::NormalizedSubject() const {
  return cert_->normalized_subject();
}

std::optional<TreeHashConstSpan> MTCAnchor::SubtreeHash(
    uint16_t log_number, Subtree target_range) const {
  if (trust_.trusted_subtrees == nullptr) {
    return std::nullopt;
  }
  return trust_.trusted_subtrees->LookupSubtreeHash(log_number, target_range);
}

std::string MTCAnchor::TrustedSubtreesDebugString() const {
  if (trust_.trusted_subtrees == nullptr) {
    return "Invalid";
  }
  return trust_.trusted_subtrees->DebugString();
}

void TrustAnchor::OverrideCertTrust(CertificateTrust new_trust) {
  trust_ = new_trust;
}

const CertificateTrust &TrustAnchor::CertTrust() const { return trust_; }

std::shared_ptr<const MTCAnchor> TrustAnchor::MTCAnchor() const {
  return mtc_anchor_;
}

std::shared_ptr<const MTCAnchor> TrustStore::GetTrustedMTCIssuerOf(
    const ParsedCertificate *cert) {
  return nullptr;
}

void TrustStore::AsyncGetIssuersOf(const ParsedCertificate *cert,
                                   std::unique_ptr<Request> *out_req) {
  out_req->reset();
}

BSSL_NAMESPACE_END
