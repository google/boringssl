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

#include <openssl/asn1.h>
#include <openssl/base.h>
#include <openssl/evp.h>
#include <openssl/mldsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <iostream>

using namespace bssl;

// Copied from crypto/x509/x509_test.cc
static UniquePtr<X509_NAME> MakeTestName(std::string_view common_name) {
  auto bytes = StringAsBytes(common_name);
  UniquePtr<X509_NAME> name(X509_NAME_new());
  if (name == nullptr ||
      !X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_UTF8, bytes.data(),
                                  bytes.size(), -1, 0)) {
    return nullptr;
  }
  return name;
}

// Copied from crypto/x509/x509_test.cc, with some modifications.
static UniquePtr<X509> MakeTestCert(std::string_view issuer,
                                    std::string_view subject, EVP_PKEY *key,
                                    int64_t reference_time, bool is_ca) {
  UniquePtr<X509_NAME> issuer_name = MakeTestName(issuer);
  UniquePtr<X509_NAME> subject_name = MakeTestName(subject);
  UniquePtr<X509> cert(X509_new());
  UniquePtr<ASN1_INTEGER> serial(ASN1_INTEGER_new());
  if (issuer_name == nullptr || subject_name == nullptr || cert == nullptr ||
      serial == nullptr ||  //
      !X509_set_version(cert.get(), X509_VERSION_3) ||
      !ASN1_INTEGER_set_uint64(serial.get(), 42) ||
      !X509_set_serialNumber(cert.get(), serial.get()) ||
      !X509_set_issuer_name(cert.get(), issuer_name.get()) ||
      !X509_set_subject_name(cert.get(), subject_name.get()) ||
      !X509_set_pubkey(cert.get(), key) ||
      !ASN1_TIME_adj(X509_getm_notBefore(cert.get()), reference_time, -1, 0) ||
      !ASN1_TIME_adj(X509_getm_notAfter(cert.get()), reference_time, 1, 0)) {
    return nullptr;
  }
  UniquePtr<BASIC_CONSTRAINTS> bc(BASIC_CONSTRAINTS_new());
  if (!bc) {
    return nullptr;
  }
  bc->ca = is_ca ? ASN1_BOOLEAN_TRUE : ASN1_BOOLEAN_FALSE;
  if (!X509_add1_ext_i2d(cert.get(), NID_basic_constraints, bc.get(),
                         /*crit=*/1, /*flags=*/0)) {
    return nullptr;
  }
  return cert;
}

static bool PrintCert(X509 *cert) {
  UniquePtr<BIO> bio(BIO_new_fp(stdout, BIO_NOCLOSE));
  return PEM_write_bio_X509(bio.get(), cert);
}

// This tool is used to generate mldsa-root.pem, mldsa-intermediate.pem, and
// mldsa-leaf.pem.
int main() {
  // Generate keys
  UniquePtr<EVP_PKEY> root_key(
      EVP_PKEY_generate_from_alg(EVP_pkey_ml_dsa_87()));
  UniquePtr<EVP_PKEY> int_key(EVP_PKEY_generate_from_alg(EVP_pkey_ml_dsa_65()));
  UniquePtr<EVP_PKEY> leaf_key(
      EVP_PKEY_generate_from_alg(EVP_pkey_ml_dsa_44()));

  if (!root_key || !int_key || !leaf_key) {
    std::cerr << "Failed to generate keys" << std::endl;
    return 1;
  }

  static const int64_t reference_time = 1775458800;  // April 6, 2026
  // Root CA (self-signed)
  UniquePtr<X509> root(
      MakeTestCert("Root", "Root", root_key.get(), reference_time, true));
  if (!root || !X509_sign(root.get(), root_key.get(), nullptr)) {
    std::cerr << "Failed to create root cert" << std::endl;
    return 1;
  }

  // Intermediate CA (signed by Root)
  UniquePtr<X509> intermediate(MakeTestCert(
      "Root", "Intermediate", int_key.get(), reference_time, true));
  if (!intermediate ||
      !X509_sign(intermediate.get(), root_key.get(), nullptr)) {
    std::cerr << "Failed to create intermediate cert" << std::endl;
    return 1;
  }

  // Leaf (signed by Intermediate)
  UniquePtr<X509> leaf(MakeTestCert("Intermediate", "Leaf", leaf_key.get(),
                                    reference_time, false));
  if (!leaf || !X509_sign(leaf.get(), int_key.get(), nullptr)) {
    std::cerr << "Failed to create leaf cert" << std::endl;
    return 1;
  }

  if (!PrintCert(root.get()) || !PrintCert(intermediate.get()) ||
      !PrintCert(leaf.get())) {
    std::cerr << "Failed to print certs" << std::endl;
    return 1;
  }

  return 0;
}
