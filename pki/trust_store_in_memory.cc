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

#include "trust_store_in_memory.h"

#include <openssl/span.h>

#include <optional>

BSSL_NAMESPACE_BEGIN

bool TrustStoreInMemory::IsEmpty() const { return entries_.empty(); }

void TrustStoreInMemory::Clear() {
  entries_.clear();
}

void TrustStoreInMemory::AddTrustAnchor(
    std::shared_ptr<const ParsedCertificate> cert) {
  AddCertificate(std::move(cert), CertificateTrust::ForTrustAnchor());
}

void TrustStoreInMemory::AddTrustAnchorWithExpiration(
    std::shared_ptr<const ParsedCertificate> cert) {
  AddCertificate(std::move(cert),
                 CertificateTrust::ForTrustAnchor().WithEnforceAnchorExpiry());
}

void TrustStoreInMemory::AddTrustAnchorWithConstraints(
    std::shared_ptr<const ParsedCertificate> cert) {
  AddCertificate(
      std::move(cert),
      CertificateTrust::ForTrustAnchor().WithEnforceAnchorConstraints());
}

void TrustStoreInMemory::AddDistrustedCertificateForTest(
    std::shared_ptr<const ParsedCertificate> cert) {
  AddCertificate(std::move(cert), CertificateTrust::ForDistrusted());
}

void TrustStoreInMemory::AddDistrustedCertificateBySPKI(std::string spki) {
  distrusted_spkis_.insert(std::move(spki));
}

void TrustStoreInMemory::AddCertificateWithUnspecifiedTrust(
    std::shared_ptr<const ParsedCertificate> cert) {
  AddCertificate(std::move(cert), CertificateTrust::ForUnspecified());
}
bool TrustStoreInMemory::AddMTCTrustAnchor(
    std::shared_ptr<const MTCAnchor> mtc_anchor) {
  if (GetMTCAnchorEntry(mtc_anchor->NormalizedSubject())) {
    return false;
  }
  AddCertificate(mtc_anchor->AsCert(), mtc_anchor->CertTrust());
  return true;
}

void TrustStoreInMemory::SyncGetIssuersOf(const ParsedCertificate *cert,
                                          ParsedCertificateList *issuers) {
  auto range =
      entries_.equal_range(BytesAsStringView(cert->normalized_issuer()));
  for (auto it = range.first; it != range.second; ++it) {
    issuers->push_back(it->second.cert);
  }
}

CertificateTrust TrustStoreInMemory::GetTrust(const ParsedCertificate *cert) {
  // Check SPKI distrust first.
  if (distrusted_spkis_.find(BytesAsStringView(cert->tbs().spki_tlv)) !=
      distrusted_spkis_.end()) {
    return CertificateTrust::ForDistrusted();
  }

  const Entry *entry = GetEntry(cert);
  return entry ? entry->trust : CertificateTrust::ForUnspecified();
}

std::shared_ptr<const MTCAnchor> TrustStoreInMemory::GetTrustedMTCIssuerOf(
    const ParsedCertificate *cert) {
  const Entry* entry = GetMTCAnchorEntry(cert->normalized_issuer());
  if (!entry) {
    return nullptr;
  }
  std::optional<MTCAnchor> anchor =
      MTCAnchor::Create(entry->cert, entry->trust);
  if (!anchor) {
    return nullptr;
  }
  return std::make_shared<const MTCAnchor>(std::move(*anchor));
}

bool TrustStoreInMemory::Contains(const ParsedCertificate *cert) const {
  return GetEntry(cert) != nullptr;
}

bool TrustStoreInMemory::ContainsMTCAnchor(const MTCAnchor *anchor) const {
  return GetMTCAnchorEntry(anchor->NormalizedSubject()) != nullptr;
}

void TrustStoreInMemory::AddCertificate(
    std::shared_ptr<const ParsedCertificate> cert,
    const CertificateTrust &trust) {
  Entry entry;
  entry.cert = std::move(cert);
  entry.trust = trust;

  // TODO(mattm): should this check for duplicate certificates?
  entries_.emplace(BytesAsStringView(entry.cert->normalized_subject()), entry);
}

const TrustStoreInMemory::Entry *TrustStoreInMemory::GetEntry(
    const ParsedCertificate *cert) const {
  auto range =
      entries_.equal_range(BytesAsStringView(cert->normalized_subject()));
  for (auto it = range.first; it != range.second; ++it) {
    if (cert == it->second.cert.get() ||
        cert->der_cert() == it->second.cert->der_cert()) {
      // NOTE: ambiguity when there are duplicate entries.
      return &it->second;
    }
  }
  return nullptr;
}

const TrustStoreInMemory::Entry* TrustStoreInMemory::GetMTCAnchorEntry(
    der::Input subject) const {
  auto range = entries_.equal_range(BytesAsStringView(subject));
  for (auto it = range.first; it != range.second; ++it) {
    if (it->second.cert->mtc_ca_info() && it->second.trust.IsTrustAnchor()) {
      return &it->second;
    }
  }
  return nullptr;
}

BSSL_NAMESPACE_END
