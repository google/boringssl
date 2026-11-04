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

#ifndef BSSL_PKI_TRUST_STORE_H_
#define BSSL_PKI_TRUST_STORE_H_

#include <array>
#include <memory>
#include <optional>

#include <openssl/base.h>
#include <openssl/pool.h>
#include <openssl/sha2.h>

#include "cert_issuer_source.h"
#include "merkle_tree.h"
#include "parsed_certificate.h"
#include "signature_algorithm.h"

BSSL_NAMESPACE_BEGIN

enum class CertificateTrustType {
  // This certificate is explicitly blocked (distrusted).
  DISTRUSTED,

  // The trustedness of this certificate is unknown (inherits trust from
  // its issuer).
  UNSPECIFIED,

  // This certificate is a trust anchor (as defined by RFC 5280).
  TRUSTED_ANCHOR,

  // This certificate can be used as a trust anchor (as defined by RFC 5280) or
  // a trusted leaf, depending on context.
  TRUSTED_ANCHOR_OR_LEAF,

  // This certificate is a directly trusted leaf.
  TRUSTED_LEAF,

  LAST = TRUSTED_ANCHOR
};

struct OPENSSL_EXPORT TrustedSubtree {
  Subtree range;
  std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
};

struct OPENSSL_EXPORT LogTrustedSubtrees {
  uint16_t log_number;
  std::vector<TrustedSubtree> trusted_subtrees;
};

// Represents an ordered list of trusted subtrees for an MTC CA.
class OPENSSL_EXPORT TrustedSubtreeSet {
 public:
  class Token {
   private:
    explicit Token() = default;
    friend TrustedSubtreeSet;
  };

  // Wraps `trusted_subtrees` in a TrustedSubtreeSet instance if valid,
  // otherwise returns nullptr. Returned TrustedSubtreeSet is guaranteed to be
  // valid.
  static std::shared_ptr<const TrustedSubtreeSet> Create(
      std::vector<LogTrustedSubtrees> trusted_subtrees);

  // This constructor is conceptually private, but needs to be public for
  // make_shared to work. Uses the "passkey idiom" to prevent callers outside
  // of the class from calling it. Outside callers should use Create().
  TrustedSubtreeSet(Token, std::vector<LogTrustedSubtrees> trusted_subtrees);

  TrustedSubtreeSet(const TrustedSubtreeSet &) = delete;
  TrustedSubtreeSet &operator=(const TrustedSubtreeSet &) = delete;

  ~TrustedSubtreeSet() = default;

  // Looks up a `target_range`'s subtree hash within the trusted subtrees for
  // `log_number`. Returns std::nullopt if not found.
  std::optional<TreeHashConstSpan> LookupSubtreeHash(
      uint16_t log_number, Subtree target_range) const;

  std::string DebugString() const;

 private:
  // Returns whether log numbers are greater than zero, and are in sorted order
  // without repeated log numbers, and within each log number the subtrees are
  // valid and listed in order. (An empty list for a log number is valid, and
  // equivalent to that log number being absent.)
  static bool IsValid(const std::vector<LogTrustedSubtrees> &trusted_subtrees);

  // Entries in the vector must be sorted by log number, and each
  // `TrustedSubtree` within must be sorted by their subtree ranges.
  std::vector<LogTrustedSubtrees> trusted_subtrees_;
};

// Describes the level of trust in a certificate.
struct OPENSSL_EXPORT CertificateTrust {
  static CertificateTrust ForTrustAnchor() {
    CertificateTrust result;
    result.type = CertificateTrustType::TRUSTED_ANCHOR;
    return result;
  }

  static CertificateTrust ForTrustAnchorOrLeaf() {
    CertificateTrust result;
    result.type = CertificateTrustType::TRUSTED_ANCHOR_OR_LEAF;
    return result;
  }

  static CertificateTrust ForTrustedLeaf() {
    CertificateTrust result;
    result.type = CertificateTrustType::TRUSTED_LEAF;
    return result;
  }

  static CertificateTrust ForUnspecified() {
    CertificateTrust result;
    return result;
  }

  static CertificateTrust ForDistrusted() {
    CertificateTrust result;
    result.type = CertificateTrustType::DISTRUSTED;
    return result;
  }

  CertificateTrust WithEnforceAnchorExpiry(bool value = true) const {
    CertificateTrust result = *this;
    result.enforce_anchor_expiry = value;
    return result;
  }

  CertificateTrust WithEnforceAnchorConstraints(bool value = true) const {
    CertificateTrust result = *this;
    result.enforce_anchor_constraints = value;
    return result;
  }

  CertificateTrust WithRequireAnchorBasicConstraints(bool value = true) const {
    CertificateTrust result = *this;
    result.require_anchor_basic_constraints = value;
    return result;
  }

  CertificateTrust WithRequireLeafSelfSigned(bool value = true) const {
    CertificateTrust result = *this;
    result.require_leaf_selfsigned = value;
    return result;
  }

  bool IsTrustAnchor() const;
  bool IsTrustLeaf() const;
  bool IsDistrusted() const;
  bool HasUnspecifiedTrust() const;

  std::string ToDebugString() const;

  // FromDebugString does not parse trusted subtrees from the debug string. If
  // there are any trusted_subtrees, they will not round-trip.
  static std::optional<CertificateTrust> FromDebugString(
      const std::string &trust_string);

  // The overall type of trust.
  CertificateTrustType type = CertificateTrustType::UNSPECIFIED;

  // Optionally, enforce extra bits on trust anchors. If these are false, the
  // only fields in a trust anchor certificate that are meaningful are its
  // name and SPKI.
  bool enforce_anchor_expiry = false;
  bool enforce_anchor_constraints = false;
  // Require that X.509v3 trust anchors have a basicConstraints extension.
  // X.509v1 and X.509v2 trust anchors do not support basicConstraints and are
  // not affected.
  // Additionally, this setting only has effect if `enforce_anchor_constraints`
  // is true, which also requires that the extension assert CA=true.
  bool require_anchor_basic_constraints = false;

  // Optionally, require trusted leafs to be self-signed to be trusted.
  bool require_leaf_selfsigned = false;

  // For an MTC CA, a list of trusted subtrees
  // (draft-ietf-plants-merkle-tree-certs, Section 7.4) that are known to be
  // consistent with the relying party's cosigner requirements. A null pointer
  // is equivalent to an empty set (no landmark-relative MTCs from this MTC CA
  // are recognized). Ignored (and should be null) unless this is the trust for
  // an MTC CA.
  std::shared_ptr<const TrustedSubtreeSet> trusted_subtrees;
};

// MTCAnchor is an MTC CA (draft-ietf-plants-merkle-tree-certs) trust anchor:
// an MTC CA certificate (a ParsedCertificate with an MTC CA extension) and the
// CertificateTrust for it. It shares ownership of the certificate and the
// CertificateTrust's trusted subtrees. The MTC CA fields are read from the
// certificate's MTC CA extension.
//
// TODO(crbug.com/575507260): Remove this class. MTC CA trust anchors will be
// represented by their MTC CA certificate and CertificateTrust, like any other
// trust anchor.
class OPENSSL_EXPORT MTCAnchor {
 public:
  enum MtcSpecVersion {
    // draft-ietf-plants-merkle-tree-certs-07
    kPlants07
  };

  class Token {
   private:
    explicit Token() = default;
    friend MTCAnchor;
  };

  // Returns an MTCAnchor for the MTC CA certificate `cert`, trusted with
  // `trust`, or nullopt if `cert` does not have an MTC CA extension. `cert`
  // must be non-null.
  //
  // TODO(crbug.com/575507260): Remove this compatibility shim once callers no
  // longer use it.
  static std::optional<MTCAnchor> Create(
      std::shared_ptr<const ParsedCertificate> cert, CertificateTrust trust);

  // Legacy code path for MTC CAs configured by individual fields rather than by
  // a certificate. This builds an MTC CA certificate from the fields (see
  // `EncodeMtcCaCertificate`), with the widest valid serial number range, and
  // returns an MTCAnchor for it, trusted as a trust anchor with
  // `log_trusted_subtrees`.
  //
  // `ca_id` is a valid DER-encoded relative OID specifying the CA's ID.
  // `ca_signature_algorithm` and `ca_key` configure the CA cosigner key.
  // `ca_key` must be a DER-encoded SubjectPublicKeyInfo.
  // The `log_trusted_subtrees` must be sorted by log number, and each
  // `trusted_subtrees` within must be sorted by their subtree ranges.
  // Returns nullptr on error.
  //
  // TODO(crbug.com/575507260): Remove this once callers configure MTC CAs by
  // certificate.
  static std::shared_ptr<const MTCAnchor> CreatePlants07(
      Span<const uint8_t> ca_id, SignatureAlgorithm ca_signature_algorithm,
      UniquePtr<CRYPTO_BUFFER> ca_key,
      std::vector<LogTrustedSubtrees> log_trusted_subtrees);

  // This constructor is conceptually private, but needs to be public for
  // make_shared to work. Uses the "passkey idiom" to prevent callers outside
  // of the class from calling it.
  // Outside callers should use the Create* static method(s).
  MTCAnchor(Token, std::shared_ptr<const ParsedCertificate> cert,
            CertificateTrust trust);

  // Accessors that return `Span` point into the certificate, so they are only
  // valid while any copy of the certificate is alive. Note that this
  // `MTCAnchor` may be the only owner of the certificate.

  // Returns the spec version of the MTC CA. Only the draft-07 MTC CA extension
  // is supported.
  MtcSpecVersion spec_version() const { return kPlants07; }

  // Returns the DER-encoded contents (without ASN.1 header bytes) of the CA's
  // ID as a RELATIVE-OID.
  Span<const uint8_t> ca_id() const;

  // Returns the CA cosigner's signature algorithm, or nullopt if it is not
  // supported.
  std::optional<SignatureAlgorithm> ca_signature_algorithm() const;

  // Returns the CA cosigner's DER-encoded SubjectPublicKeyInfo.
  Span<const uint8_t> ca_key() const;

  Span<const uint8_t> NormalizedSubject() const;

  const CertificateTrust &CertTrust() const { return trust_; }

  // Returns the MTC CA certificate. This is never null.
  const std::shared_ptr<const ParsedCertificate> &AsCert() const {
    return cert_;
  }

  // Looks up a `target_range`'s subtree hash within the trusted subtrees for
  // `log_number`. Returns std::nullopt if not found, including if `CertTrust()`
  // does not have trusted subtrees.
  std::optional<TreeHashConstSpan> SubtreeHash(uint16_t log_number,
                                               Subtree target_range) const;
  std::string TrustedSubtreesDebugString() const;

 private:
  // Non-null, and has an MTC CA extension.
  std::shared_ptr<const ParsedCertificate> cert_;
  CertificateTrust trust_;
};

// A TrustAnchor contains information about how a trust anchor is trusted and
// what is trusted.
//
// TODO(crbug.com/575507260): This class was formerly the first step of a large
// refactor to use TrustAnchor in place of a (ParsedCertificate,
// CertificateTrust) tuple as some trust information, e.g. MTC anchors, was not
// representable by such a tuple.
// Original internal TrustAnchor design doc:
// https://docs.google.com/document/d/1wqHAmZqtF8oJzNObFBm41lzDt2JWRhjM32A3z6ampJE/edit
//
// The current plan is to align with the X.509 certificate representation of MTC
// CAs in draft-ietf-plants-merkle-tree-certs-05 and up, and make the
// (ParsedCertificate, CertificateTrust) representation work for all trust
// anchors. After migrating to the X.509 representation, TrustAnchor will be
// removed.
class OPENSSL_EXPORT TrustAnchor {
 public:
  // Creates a default TrustAnchor with an unspecified CertificateTrust.
  TrustAnchor() = default;

  // Creates a TrustAnchor with no associated MTCAnchor.
  explicit TrustAnchor(CertificateTrust trust) : TrustAnchor(trust, nullptr) {}

  // Creates a TrustAnchor with an associated MTCAnchor.
  TrustAnchor(CertificateTrust trust,
              std::shared_ptr<const MTCAnchor> mtc_anchor)
      : trust_(trust), mtc_anchor_(std::move(mtc_anchor)) {}

  // TODO(nharper): Temporarily add ParsedCertificate member and accessor.

  // TODO(nharper): Add accessors to get information about the trust anchor that
  // is currently found in the ParsedCertificate:
  // - `der::Input NormalizedSubject() const;`
  // - `UniquePtr<EVP_PKEY> PublicKey() const;`

  // Modifies the CertificateTrust for this TrustAnchor. Should only be called
  // by path_builder.cc.
  //
  // TODO(nharper): Remove this function as part of the larger TrustAnchor
  // refactor.
  void OverrideCertTrust(CertificateTrust new_trust);
  const CertificateTrust &CertTrust() const;
  std::shared_ptr<const bssl::MTCAnchor> MTCAnchor() const;

 private:
  CertificateTrust trust_;
  std::shared_ptr<const bssl::MTCAnchor> mtc_anchor_ = nullptr;
};

// Interface for finding intermediates / trust anchors, and testing the
// trustedness of certificates.
class OPENSSL_EXPORT TrustStore : public CertIssuerSource {
 public:
  TrustStore() = default;

  TrustStore(const TrustStore &) = delete;
  TrustStore &operator=(const TrustStore &) = delete;

  // Returns the trusted of `cert`, which must be non-null.
  virtual CertificateTrust GetTrust(const ParsedCertificate *cert) = 0;

  // Returns the TrustAnchor that issued `cert`, if one exists.
  //
  // TODO(nharper): Make this a pure virtual function once all TrustStore
  // implementations have implemented this.
  virtual std::shared_ptr<const MTCAnchor> GetTrustedMTCIssuerOf(
      const ParsedCertificate *cert);

  // Disable async issuers for TrustStore, as it isn't needed.
  void AsyncGetIssuersOf(const ParsedCertificate *cert,
                         std::unique_ptr<Request> *out_req) final;
};

BSSL_NAMESPACE_END

#endif  // BSSL_PKI_TRUST_STORE_H_
