// Copyright 2020 The BoringSSL Authors
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

#ifndef OPENSSL_HEADER_CRYPTO_DSA_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_DSA_INTERNAL_H

#include <openssl/dsa.h>

#include "../internal.h"
#include "../mem_internal.h"


DECLARE_OPAQUE_STRUCT(dsa_st, DSAImpl)

BSSL_NAMESPACE_BEGIN

class DSAImpl : public dsa_st, public RefCounted<DSAImpl> {
 public:
  DSAImpl();

  BIGNUM *p = nullptr;
  BIGNUM *q = nullptr;
  BIGNUM *g = nullptr;

  BIGNUM *pub_key = nullptr;
  BIGNUM *priv_key = nullptr;

  // Normally used to cache montgomery values
  bssl::CRYPTO_MUTEX method_mont_lock;
  BN_MONT_CTX *method_mont_p = nullptr;
  BN_MONT_CTX *method_mont_q = nullptr;
  CRYPTO_EX_DATA ex_data;

 private:
  friend RefCounted;
  ~DSAImpl();
};

// dsa_check_key performs cheap self-checks on |dsa|, and ensures it is within
// DoS bounds. It returns one on success and zero on error.
int dsa_check_key(const DSAImpl *dsa);

BSSL_NAMESPACE_END

#endif  // OPENSSL_HEADER_CRYPTO_DSA_INTERNAL_H
