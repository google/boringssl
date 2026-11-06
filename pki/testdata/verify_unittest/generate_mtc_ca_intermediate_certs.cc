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
#include <openssl/bio.h>
#include <openssl/digest.h>
#include <openssl/evp.h>
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

static UniquePtr<X509> ReadCert(const char *path) {
  UniquePtr<BIO> bio(BIO_new_file(path, "r"));
  if (!bio) {
    return nullptr;
  }
  return UniquePtr<X509>(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

static bool WriteCert(const char *path, X509 *cert) {
  UniquePtr<BIO> bio(BIO_new_file(path, "w"));
  return bio && PEM_write_bio_X509(bio.get(), cert);
}

// This tool is used to generate:
// - mtc-ca-intermediate-root.pem (root): a conventional, self-signed root;
// - mtc-ca-intermediate.pem (intermediate): an MTC CA certificate, modeled on
//   crypto/x509/test/mtc/ca_cert.pem but issued by the root.
int main(int argc, char **argv) {
  if (argc != 4) {
    std::cerr << "Usage: " << argv[0]
              << " MTC_CA_CERT ROOT_OUT INTERMEDIATE_OUT" << std::endl;
    return 1;
  }

  UniquePtr<EVP_PKEY> root_key(EVP_PKEY_generate_from_alg(EVP_pkey_ec_p256()));
  if (!root_key) {
    std::cerr << "Failed to generate key" << std::endl;
    return 1;
  }

  // The time at which the crypto/x509 MTC test certificates are verified.
  static const int64_t reference_time = 1735689600;  // Jan 1st, 2025
  UniquePtr<X509_NAME> root_name = MakeTestName("Root");
  UniquePtr<X509> root(X509_new());
  UniquePtr<ASN1_INTEGER> serial(ASN1_INTEGER_new());
  UniquePtr<BASIC_CONSTRAINTS> bc(BASIC_CONSTRAINTS_new());
  if (!root_name || !root || !serial || !bc ||
      !X509_set_version(root.get(), X509_VERSION_3) ||
      !ASN1_INTEGER_set_uint64(serial.get(), 42) ||
      !X509_set_serialNumber(root.get(), serial.get()) ||
      !X509_set_issuer_name(root.get(), root_name.get()) ||
      !X509_set_subject_name(root.get(), root_name.get()) ||
      !X509_set_pubkey(root.get(), root_key.get()) ||
      !ASN1_TIME_adj(X509_getm_notBefore(root.get()), reference_time, -1, 0) ||
      !ASN1_TIME_adj(X509_getm_notAfter(root.get()), reference_time, 1, 0)) {
    std::cerr << "Failed to create root cert" << std::endl;
    return 1;
  }
  bc->ca = ASN1_BOOLEAN_TRUE;
  if (!X509_add1_ext_i2d(root.get(), NID_basic_constraints, bc.get(),
                         /*crit=*/1, /*flags=*/0) ||
      !X509_sign(root.get(), root_key.get(), EVP_sha256())) {
    std::cerr << "Failed to create root cert" << std::endl;
    return 1;
  }

  UniquePtr<X509> intermediate = ReadCert(argv[1]);
  if (!intermediate ||
      !X509_set_issuer_name(intermediate.get(), root_name.get()) ||
      !X509_sign(intermediate.get(), root_key.get(), EVP_sha256())) {
    std::cerr << "Failed to re-issue MTC CA cert" << std::endl;
    return 1;
  }

  if (!WriteCert(argv[2], root.get()) ||
      !WriteCert(argv[3], intermediate.get())) {
    std::cerr << "Failed to write certs" << std::endl;
    return 1;
  }

  return 0;
}
