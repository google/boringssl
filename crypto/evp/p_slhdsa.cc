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

#include <openssl/evp.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/sha2.h>
#include <openssl/slhdsa.h>
#include <openssl/span.h>

#include "../mem_internal.h"
#include "internal.h"

using namespace bssl;

namespace {

constexpr uint8_t kSLHDSASHA2_128SOID[] = {OBJ_ENC_SLH_DSA_SHA2_128s};
constexpr uint8_t kSLHDSASHAKE_256FOID[] = {OBJ_ENC_SLH_DSA_SHAKE_256f};
constexpr uint8_t kSLHDSASHA2_128SWithSHA256OID[] = {
    OBJ_ENC_SLH_DSA_SHA2_128s_WITH_SHA256};

constexpr size_t kMaxContextLength = 255;

struct SLHDSASHA2_128STraits {
  static constexpr size_t kPublicKeyBytes = SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES;
  static constexpr size_t kPrivateKeyBytes = SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES;
  static constexpr size_t kSignatureBytes = SLHDSA_SHA2_128S_SIGNATURE_BYTES;
  static constexpr int kType = EVP_PKEY_SLH_DSA_SHA2_128S;
  static constexpr Span<const uint8_t> kOID = kSLHDSASHA2_128SOID;
  static constexpr bool kPrehash = false;

  static constexpr auto GenerateKey = &SLHDSA_SHA2_128S_generate_key;
  static constexpr auto Sign = &SLHDSA_SHA2_128S_sign;
  static constexpr auto Verify = &SLHDSA_SHA2_128S_verify;
};

struct SLHDSASHAKE_256FTraits {
  static constexpr size_t kPublicKeyBytes = SLHDSA_SHAKE_256F_PUBLIC_KEY_BYTES;
  static constexpr size_t kPrivateKeyBytes =
      SLHDSA_SHAKE_256F_PRIVATE_KEY_BYTES;
  static constexpr size_t kSignatureBytes = SLHDSA_SHAKE_256F_SIGNATURE_BYTES;
  static constexpr int kType = EVP_PKEY_SLH_DSA_SHAKE_256F;
  static constexpr Span<const uint8_t> kOID = kSLHDSASHAKE_256FOID;
  static constexpr bool kPrehash = false;

  static constexpr auto GenerateKey = &SLHDSA_SHAKE_256F_generate_key;
  static constexpr auto Sign = &SLHDSA_SHAKE_256F_sign;
  static constexpr auto Verify = &SLHDSA_SHAKE_256F_verify;
};

struct SLHDSASHA2_128SWithSHA256Traits {
  static constexpr size_t kPublicKeyBytes = SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES;
  static constexpr size_t kPrivateKeyBytes = SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES;
  static constexpr size_t kSignatureBytes = SLHDSA_SHA2_128S_SIGNATURE_BYTES;
  static constexpr int kType = EVP_PKEY_SLH_DSA_SHA2_128S_WITH_SHA256;
  static constexpr Span<const uint8_t> kOID = kSLHDSASHA2_128SWithSHA256OID;
  static constexpr bool kPrehash = true;
  static constexpr size_t kDigestLength = SHA256_DIGEST_LENGTH;
  static constexpr int kDigestNID = NID_sha256;

  static constexpr auto GenerateKey = &SLHDSA_SHA2_128S_generate_key;
  static constexpr auto PrehashSign = &SLHDSA_SHA2_128S_prehash_sign;
  static constexpr auto PrehashVerify = &SLHDSA_SHA2_128S_prehash_verify;
};

template <typename Traits>
struct SLHDSA_KEY {
  enum { kAllowUniquePtr = true };

  // key is the 4n-byte SLH-DSA private key (SK.seed || SK.prf || PK.seed ||
  // PK.root). If `has_private` is false, the first 2n bytes are uninitialized
  // and the 2n-byte public key (PK.seed || PK.root) is in the last 2n bytes.
  uint8_t key[Traits::kPrivateKeyBytes];
  bool has_private;

  Span<uint8_t, Traits::kPublicKeyBytes> public_key() {
    return MakeSpan(key).template last<Traits::kPublicKeyBytes>();
  }
  Span<const uint8_t, Traits::kPublicKeyBytes> public_key() const {
    return MakeConstSpan(key).template last<Traits::kPublicKeyBytes>();
  }
};

struct SlhdsaPkeyCtx {
  bssl::Array<uint8_t> context;
};

template <typename Traits>
struct SLHDSAImplementation {
  static SLHDSA_KEY<Traits> *GetKeyData(EvpPkey *pkey) {
    assert(pkey->ameth == &asn1_method);
    return static_cast<SLHDSA_KEY<Traits> *>(pkey->pkey);
  }

  static const SLHDSA_KEY<Traits> *GetKeyData(const EvpPkey *pkey) {
    return GetKeyData(const_cast<EvpPkey *>(pkey));
  }

  static void PkeyFree(EvpPkey *pkey) {
    Delete(GetKeyData(pkey));
    pkey->pkey = nullptr;
  }

  static int SetRawPrivate(EvpPkey *pkey, const uint8_t *in, size_t len) {
    if (len != Traits::kPrivateKeyBytes) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
      return 0;
    }
    UniquePtr<SLHDSA_KEY<Traits>> key = MakeUnique<SLHDSA_KEY<Traits>>();
    if (key == nullptr) {
      return 0;
    }
    OPENSSL_memcpy(key->key, in, Traits::kPrivateKeyBytes);
    key->has_private = true;
    evp_pkey_set0(pkey, &asn1_method, key.release());
    return 1;
  }

  static int SetRawPublic(EvpPkey *pkey, const uint8_t *in, size_t len) {
    if (len != Traits::kPublicKeyBytes) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
      return 0;
    }
    UniquePtr<SLHDSA_KEY<Traits>> key = MakeUnique<SLHDSA_KEY<Traits>>();
    if (key == nullptr) {
      return 0;
    }
    OPENSSL_memcpy(key->public_key().data(), in, Traits::kPublicKeyBytes);
    key->has_private = false;
    evp_pkey_set0(pkey, &asn1_method, key.release());
    return 1;
  }

  static int GetRawPrivate(const EvpPkey *pkey, uint8_t *out, size_t *out_len) {
    const SLHDSA_KEY<Traits> *key = GetKeyData(pkey);
    if (!key->has_private) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);
      return 0;
    }
    if (out == nullptr) {
      *out_len = Traits::kPrivateKeyBytes;
      return 1;
    }
    if (*out_len < Traits::kPrivateKeyBytes) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
      return 0;
    }
    OPENSSL_memcpy(out, key->key, Traits::kPrivateKeyBytes);
    *out_len = Traits::kPrivateKeyBytes;
    return 1;
  }

  static int GetRawPublic(const EvpPkey *pkey, uint8_t *out, size_t *out_len) {
    const SLHDSA_KEY<Traits> *key = GetKeyData(pkey);
    if (out == nullptr) {
      *out_len = Traits::kPublicKeyBytes;
      return 1;
    }
    if (*out_len < Traits::kPublicKeyBytes) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
      return 0;
    }
    OPENSSL_memcpy(out, key->public_key().data(), Traits::kPublicKeyBytes);
    *out_len = Traits::kPublicKeyBytes;
    return 1;
  }

  static evp_decode_result_t DecodePublic(const EVP_PKEY_ALG *alg, EvpPkey *out,
                                          CBS *params, CBS *key) {
    // The parameters must be omitted. See RFC 9909, Sections 3 and 4.
    if (CBS_len(params) != 0) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
      return evp_decode_error;
    }
    return SetRawPublic(out, CBS_data(key), CBS_len(key)) ? evp_decode_ok
                                                          : evp_decode_error;
  }

  static int EncodePublic(CBB *out, const EvpPkey *pkey) {
    const SLHDSA_KEY<Traits> *key = GetKeyData(pkey);
    // See RFC 9909, Sections 3 and 4.
    CBB spki, algorithm, key_bitstring;
    if (!CBB_add_asn1(out, &spki, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1_element(&algorithm, CBS_ASN1_OBJECT, Traits::kOID.data(),
                              Traits::kOID.size()) ||
        !CBB_add_asn1(&spki, &key_bitstring, CBS_ASN1_BITSTRING) ||
        !CBB_add_u8(&key_bitstring, 0 /* no unused bits */) ||
        !CBB_add_bytes(&key_bitstring, key->public_key().data(),
                       key->public_key().size()) ||
        !CBB_flush(out)) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
      return 0;
    }
    return 1;
  }

  static bool EqualPublic(const EvpPkey *a, const EvpPkey *b) {
    const SLHDSA_KEY<Traits> *a_key = GetKeyData(a);
    const SLHDSA_KEY<Traits> *b_key = GetKeyData(b);
    return OPENSSL_memcmp(a_key->public_key().data(),
                          b_key->public_key().data(),
                          Traits::kPublicKeyBytes) == 0;
  }

  static bool HasPublic(const EvpPkey *pk) { return true; }

  static bool CopyPublic(EvpPkey *out, const EvpPkey *pk) {
    const SLHDSA_KEY<Traits> *key = GetKeyData(pk);
    UniquePtr<SLHDSA_KEY<Traits>> public_copy = MakeUnique<SLHDSA_KEY<Traits>>();
    if (public_copy == nullptr) {
      return false;
    }
    OPENSSL_memcpy(public_copy->public_key().data(), key->public_key().data(),
                   Traits::kPublicKeyBytes);
    public_copy->has_private = false;
    evp_pkey_set0(out, &asn1_method, public_copy.release());
    return true;
  }

  static evp_decode_result_t DecodePrivate(const EVP_PKEY_ALG *alg,
                                           EvpPkey *out, CBS *params,
                                           CBS *key) {
    // The parameters must be omitted. See RFC 9909, Sections 3 and 5.
    if (CBS_len(params) != 0) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
      return evp_decode_error;
    }
    return SetRawPrivate(out, CBS_data(key), CBS_len(key)) ? evp_decode_ok
                                                           : evp_decode_error;
  }

  static int EncodePrivate(CBB *out, const EvpPkey *pkey) {
    const SLHDSA_KEY<Traits> *key = GetKeyData(pkey);
    if (!key->has_private) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);
      return 0;
    }
    // See RFC 9909, Sections 3 and 5.
    CBB pkcs8, algorithm, private_key;
    if (!CBB_add_asn1(out, &pkcs8, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1_uint64(&pkcs8, 0 /* version */) ||
        !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1_element(&algorithm, CBS_ASN1_OBJECT, Traits::kOID.data(),
                              Traits::kOID.size()) ||
        !CBB_add_asn1(&pkcs8, &private_key, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&private_key, key->key, Traits::kPrivateKeyBytes) ||
        !CBB_flush(out)) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
      return 0;
    }
    return 1;
  }

  static bool HasPrivate(const EvpPkey *pk) {
    return GetKeyData(pk)->has_private;
  }

  static int PkeySize(const EvpPkey *pkey) { return Traits::kSignatureBytes; }
  static int PkeyBits(const EvpPkey *pkey) {
    // OpenSSL counts the bits in the public key serialization.
    return Traits::kPublicKeyBytes * 8;
  }

  static int Init(EvpPkeyCtx *ctx, const EVP_PKEY_ALG *) {
    SlhdsaPkeyCtx *sctx = New<SlhdsaPkeyCtx>();
    if (sctx == nullptr) {
      return 0;
    }
    ctx->data = sctx;
    return 1;
  }

  static void Cleanup(EvpPkeyCtx *ctx) {
    Delete(static_cast<SlhdsaPkeyCtx *>(ctx->data));
  }

  static int CopyContext(EvpPkeyCtx *dst, EvpPkeyCtx *src) {
    if (!Init(dst, nullptr)) {
      return 0;
    }
    SlhdsaPkeyCtx *sctx = static_cast<SlhdsaPkeyCtx *>(src->data);
    SlhdsaPkeyCtx *dctx = static_cast<SlhdsaPkeyCtx *>(dst->data);
    if (!dctx->context.CopyFrom(sctx->context)) {
      return 0;
    }
    return 1;
  }

  static int KeyGen(EvpPkeyCtx *ctx, EvpPkey *pkey) {
    UniquePtr<SLHDSA_KEY<Traits>> key = MakeUnique<SLHDSA_KEY<Traits>>();
    if (key == nullptr) {
      return 0;
    }
    uint8_t unused_public[Traits::kPublicKeyBytes];
    Traits::GenerateKey(unused_public, key->key);
    key->has_private = true;
    evp_pkey_set0(pkey, &asn1_method, key.release());
    return 1;
  }

  static int SignMessage(EvpPkeyCtx *ctx, uint8_t *sig, size_t *siglen,
                         const uint8_t *tbs, size_t tbslen) {
    const SLHDSA_KEY<Traits> *key = GetKeyData(ctx->pkey.get());
    if (!key->has_private) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);
      return 0;
    }
    if (sig == nullptr) {
      *siglen = Traits::kSignatureBytes;
      return 1;
    }
    if (*siglen < Traits::kSignatureBytes) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
      return 0;
    }
    SlhdsaPkeyCtx *sctx = static_cast<SlhdsaPkeyCtx *>(ctx->data);
    if (!Traits::Sign(sig, key->key, tbs, tbslen, sctx->context.data(),
                      sctx->context.size())) {
      return 0;
    }
    *siglen = Traits::kSignatureBytes;
    return 1;
  }

  static int VerifyMessage(EvpPkeyCtx *ctx, const uint8_t *sig, size_t siglen,
                           const uint8_t *tbs, size_t tbslen) {
    const SLHDSA_KEY<Traits> *key = GetKeyData(ctx->pkey.get());
    SlhdsaPkeyCtx *sctx = static_cast<SlhdsaPkeyCtx *>(ctx->data);
    if (!Traits::Verify(sig, siglen, key->public_key().data(), tbs, tbslen,
                        sctx->context.data(), sctx->context.size())) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_SIGNATURE);
      return 0;
    }
    return 1;
  }

  static int SignDigest(EvpPkeyCtx *ctx, uint8_t *sig, size_t *siglen,
                        const uint8_t *tbs, size_t tbslen) {
    const SLHDSA_KEY<Traits> *key = GetKeyData(ctx->pkey.get());
    if (!key->has_private) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);
      return 0;
    }
    if (sig == nullptr) {
      *siglen = Traits::kSignatureBytes;
      return 1;
    }
    if (*siglen < Traits::kSignatureBytes) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
      return 0;
    }
    if (tbslen != Traits::kDigestLength) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_DIGEST_LENGTH);
      return 0;
    }
    SlhdsaPkeyCtx *sctx = static_cast<SlhdsaPkeyCtx *>(ctx->data);
    if (!Traits::PrehashSign(sig, key->key, tbs, tbslen, Traits::kDigestNID,
                             sctx->context.data(), sctx->context.size())) {
      return 0;
    }
    *siglen = Traits::kSignatureBytes;
    return 1;
  }

  static int VerifyDigest(EvpPkeyCtx *ctx, const uint8_t *sig, size_t siglen,
                          const uint8_t *tbs, size_t tbslen) {
    const SLHDSA_KEY<Traits> *key = GetKeyData(ctx->pkey.get());
    if (tbslen != Traits::kDigestLength) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_DIGEST_LENGTH);
      return 0;
    }
    SlhdsaPkeyCtx *sctx = static_cast<SlhdsaPkeyCtx *>(ctx->data);
    if (!Traits::PrehashVerify(sig, siglen, key->public_key().data(), tbs,
                               tbslen, Traits::kDigestNID,
                               sctx->context.data(), sctx->context.size())) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_SIGNATURE);
      return 0;
    }
    return 1;
  }

  static int Ctrl(EvpPkeyCtx *ctx, int type, int p1, void *p2) {
    SlhdsaPkeyCtx *sctx = static_cast<SlhdsaPkeyCtx *>(ctx->data);
    switch (type) {
      case EVP_PKEY_CTRL_SIGNATURE_CONTEXT_STRING: {
        const auto *context_string =
            reinterpret_cast<const Span<const uint8_t> *>(p2);
        if (context_string == nullptr ||
            context_string->size() > kMaxContextLength) {
          OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_PARAMETERS);
          return 0;
        }
        return sctx->context.CopyFrom(*context_string);
      }

      case EVP_PKEY_CTRL_MD: {
        if constexpr (!Traits::kPrehash) {
          OPENSSL_PUT_ERROR(EVP, EVP_R_COMMAND_NOT_SUPPORTED);
          return 0;
        } else {
          const auto *md = reinterpret_cast<const EVP_MD *>(p2);
          if (md == nullptr || EVP_MD_type(md) != Traits::kDigestNID) {
            OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_DIGEST_TYPE);
            return 0;
          }
          return 1;
        }
      }

      case EVP_PKEY_CTRL_GET_MD: {
        if constexpr (!Traits::kPrehash) {
          OPENSSL_PUT_ERROR(EVP, EVP_R_COMMAND_NOT_SUPPORTED);
          return 0;
        } else {
          // Add a `Digest()` hook to the traits if other algorithms supported.
          static_assert(Traits::kDigestNID == NID_sha256);
          *reinterpret_cast<const EVP_MD **>(p2) = EVP_sha256();
          return 1;
        }
      }

      default:
        OPENSSL_PUT_ERROR(EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        return 0;
    }
  }

  static constexpr EVP_PKEY_CTX_METHOD BuildPkeyMethod() {
    EVP_PKEY_CTX_METHOD ret = {
        Traits::kType,
        &Init,
        &CopyContext,
        &Cleanup,
        &KeyGen,
        /*sign=*/nullptr,
        /*sign_message=*/nullptr,
        /*verify=*/nullptr,
        /*verify_message=*/nullptr,
        /*verify_recover=*/nullptr,
        /*encrypt=*/nullptr,
        /*decrypt=*/nullptr,
        /*derive=*/nullptr,
        /*paramgen=*/nullptr,
        /*encap=*/nullptr,
        /*decap=*/nullptr,
        &Ctrl,
    };
    if constexpr (Traits::kPrehash) {
      ret.sign = &SignDigest;
      ret.verify = &VerifyDigest;
    } else {
      ret.sign_message = &SignMessage;
      ret.verify_message = &VerifyMessage;
    }
    return ret;
  }

  static constexpr EVP_PKEY_CTX_METHOD pkey_method = BuildPkeyMethod();

  static constexpr EVP_PKEY_ASN1_METHOD BuildASN1Method() {
    EVP_PKEY_ASN1_METHOD ret = {
        Traits::kType,
        // The OID is filled in below.
        /*oid=*/{},
        /*oid_len=*/0,
        &pkey_method,
        &DecodePublic,
        &EncodePublic,
        &EqualPublic,
        &HasPublic,
        &CopyPublic,
        &DecodePrivate,
        &EncodePrivate,
        &HasPrivate,
        &SetRawPrivate,
        /*set_priv_seed=*/nullptr,
        &SetRawPublic,
        &GetRawPrivate,
        /*get_priv_seed=*/nullptr,
        &GetRawPublic,
        /*set1_tls_encodedpoint=*/nullptr,
        /*get1_tls_encodedpoint=*/nullptr,
        /*pkey_opaque=*/nullptr,
        &PkeySize,
        &PkeyBits,
        /*param_missing=*/nullptr,
        /*param_copy=*/nullptr,
        /*param_equal=*/nullptr,
        &PkeyFree,
    };
    constexpr auto oid = Traits::kOID;
    static_assert(oid.size() <= sizeof(ret.oid));
    for (size_t i = 0; i < oid.size(); i++) {
      ret.oid[i] = oid[i];
    }
    ret.oid_len = oid.size();
    return ret;
  }

  static constexpr EVP_PKEY_ASN1_METHOD asn1_method = BuildASN1Method();
  static constexpr EVP_PKEY_ALG pkey_alg = {&asn1_method, &pkey_method};
};

}  // namespace

const EVP_PKEY_ALG *EVP_pkey_slh_dsa_sha2_128s() {
  return &SLHDSAImplementation<SLHDSASHA2_128STraits>::pkey_alg;
}

const EVP_PKEY_ALG *EVP_pkey_slh_dsa_shake_256f() {
  return &SLHDSAImplementation<SLHDSASHAKE_256FTraits>::pkey_alg;
}

const EVP_PKEY_ALG *EVP_pkey_slh_dsa_sha2_128s_with_sha256() {
  return &SLHDSAImplementation<SLHDSASHA2_128SWithSHA256Traits>::pkey_alg;
}
