/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>

#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/dsa.h>
#include <openssl/ec_key.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "internal.h"
#include "../bytestring/internal.h"
#include "../internal.h"


// We intentionally omit |dh_asn1_meth| from this list. It is not serializable.
static const EVP_PKEY_ASN1_METHOD *const kASN1Methods[] = {
    &rsa_asn1_meth,
    &ec_asn1_meth,
    &dsa_asn1_meth,
    &ed25519_asn1_meth,
    &x25519_asn1_meth,
};

static const EVP_PKEY_ASN1_METHOD *parse_key_type(CBS *cbs) {
  CBS oid;
  if (!CBS_get_asn1(cbs, &oid, CBS_ASN1_OBJECT)) {
    return NULL;
  }

  for (unsigned i = 0; i < OPENSSL_ARRAY_SIZE(kASN1Methods); i++) {
    const EVP_PKEY_ASN1_METHOD *method = kASN1Methods[i];
    if (CBS_len(&oid) == method->oid_len &&
        OPENSSL_memcmp(CBS_data(&oid), method->oid, method->oid_len) == 0) {
      return method;
    }
  }

  return NULL;
}

EVP_PKEY *EVP_parse_public_key(CBS *cbs) {
  // Parse the SubjectPublicKeyInfo.
  CBS spki, algorithm, key;
  uint8_t padding;
  if (!CBS_get_asn1(cbs, &spki, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&spki, &key, CBS_ASN1_BITSTRING) ||
      CBS_len(&spki) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return NULL;
  }
  const EVP_PKEY_ASN1_METHOD *method = parse_key_type(&algorithm);
  if (method == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    return NULL;
  }
  if (// Every key type defined encodes the key as a byte string with the same
      // conversion to BIT STRING.
      !CBS_get_u8(&key, &padding) ||
      padding != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return NULL;
  }

  // Set up an |EVP_PKEY| of the appropriate type.
  EVP_PKEY *ret = EVP_PKEY_new();
  if (ret == NULL) {
    goto err;
  }
  evp_pkey_set_method(ret, method);

  // Call into the type-specific SPKI decoding function.
  if (ret->ameth->pub_decode == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    goto err;
  }
  if (!ret->ameth->pub_decode(ret, &algorithm, &key)) {
    goto err;
  }

  return ret;

err:
  EVP_PKEY_free(ret);
  return NULL;
}

int EVP_marshal_public_key(CBB *cbb, const EVP_PKEY *key) {
  if (key->ameth == NULL || key->ameth->pub_encode == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    return 0;
  }

  return key->ameth->pub_encode(cbb, key);
}

EVP_PKEY *EVP_parse_private_key(CBS *cbs) {
  // Parse the PrivateKeyInfo.
  CBS pkcs8, algorithm, key;
  uint64_t version;
  if (!CBS_get_asn1(cbs, &pkcs8, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1_uint64(&pkcs8, &version) ||
      version != 0 ||
      !CBS_get_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&pkcs8, &key, CBS_ASN1_OCTETSTRING)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return NULL;
  }
  const EVP_PKEY_ASN1_METHOD *method = parse_key_type(&algorithm);
  if (method == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    return NULL;
  }

  // A PrivateKeyInfo ends with a SET of Attributes which we ignore.

  // Set up an |EVP_PKEY| of the appropriate type.
  EVP_PKEY *ret = EVP_PKEY_new();
  if (ret == NULL) {
    goto err;
  }
  evp_pkey_set_method(ret, method);

  // Call into the type-specific PrivateKeyInfo decoding function.
  if (ret->ameth->priv_decode == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    goto err;
  }
  if (!ret->ameth->priv_decode(ret, &algorithm, &key)) {
    goto err;
  }

  return ret;

err:
  EVP_PKEY_free(ret);
  return NULL;
}

int EVP_marshal_private_key(CBB *cbb, const EVP_PKEY *key) {
  if (key->ameth == NULL || key->ameth->priv_encode == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    return 0;
  }

  return key->ameth->priv_encode(cbb, key);
}

static EVP_PKEY *old_priv_decode(CBS *cbs, int type) {
  EVP_PKEY *ret = EVP_PKEY_new();
  if (ret == NULL) {
    return NULL;
  }

  switch (type) {
    case EVP_PKEY_EC: {
      EC_KEY *ec_key = EC_KEY_parse_private_key(cbs, NULL);
      if (ec_key == NULL || !EVP_PKEY_assign_EC_KEY(ret, ec_key)) {
        EC_KEY_free(ec_key);
        goto err;
      }
      return ret;
    }
    case EVP_PKEY_DSA: {
      DSA *dsa = DSA_parse_private_key(cbs);
      if (dsa == NULL || !EVP_PKEY_assign_DSA(ret, dsa)) {
        DSA_free(dsa);
        goto err;
      }
      return ret;
    }
    case EVP_PKEY_RSA: {
      RSA *rsa = RSA_parse_private_key(cbs);
      if (rsa == NULL || !EVP_PKEY_assign_RSA(ret, rsa)) {
        RSA_free(rsa);
        goto err;
      }
      return ret;
    }
    default:
      OPENSSL_PUT_ERROR(EVP, EVP_R_UNKNOWN_PUBLIC_KEY_TYPE);
      goto err;
  }

err:
  EVP_PKEY_free(ret);
  return NULL;
}

EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **out, const uint8_t **inp,
                         long len) {
  if (len < 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return NULL;
  }

  // Parse with the legacy format.
  CBS cbs;
  CBS_init(&cbs, *inp, (size_t)len);
  EVP_PKEY *ret = old_priv_decode(&cbs, type);
  if (ret == NULL) {
    // Try again with PKCS#8.
    ERR_clear_error();
    CBS_init(&cbs, *inp, (size_t)len);
    ret = EVP_parse_private_key(&cbs);
    if (ret == NULL) {
      return NULL;
    }
    if (ret->type != type) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_DIFFERENT_KEY_TYPES);
      EVP_PKEY_free(ret);
      return NULL;
    }
  }

  if (out != NULL) {
    EVP_PKEY_free(*out);
    *out = ret;
  }
  *inp = CBS_data(&cbs);
  return ret;
}

// num_elements parses one SEQUENCE from |in| and returns the number of elements
// in it. On parse error, it returns zero.
static size_t num_elements(const uint8_t *in, size_t in_len) {
  CBS cbs, sequence;
  CBS_init(&cbs, in, (size_t)in_len);

  if (!CBS_get_asn1(&cbs, &sequence, CBS_ASN1_SEQUENCE)) {
    return 0;
  }

  size_t count = 0;
  while (CBS_len(&sequence) > 0) {
    if (!CBS_get_any_asn1_element(&sequence, NULL, NULL, NULL)) {
      return 0;
    }

    count++;
  }

  return count;
}

EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **out, const uint8_t **inp, long len) {
  if (len < 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return NULL;
  }

  // Parse the input as a PKCS#8 PrivateKeyInfo.
  CBS cbs;
  CBS_init(&cbs, *inp, (size_t)len);
  EVP_PKEY *ret = EVP_parse_private_key(&cbs);
  if (ret != NULL) {
    if (out != NULL) {
      EVP_PKEY_free(*out);
      *out = ret;
    }
    *inp = CBS_data(&cbs);
    return ret;
  }
  ERR_clear_error();

  // Count the elements to determine the legacy key format.
  switch (num_elements(*inp, (size_t)len)) {
    case 4:
      return d2i_PrivateKey(EVP_PKEY_EC, out, inp, len);

    case 6:
      return d2i_PrivateKey(EVP_PKEY_DSA, out, inp, len);

    default:
      return d2i_PrivateKey(EVP_PKEY_RSA, out, inp, len);
  }
}

int i2d_PublicKey(const EVP_PKEY *key, uint8_t **outp) {
  switch (key->type) {
    case EVP_PKEY_RSA:
      return i2d_RSAPublicKey(EVP_PKEY_get0_RSA(key), outp);
    case EVP_PKEY_DSA:
      return i2d_DSAPublicKey(EVP_PKEY_get0_DSA(key), outp);
    case EVP_PKEY_EC:
      return i2o_ECPublicKey(EVP_PKEY_get0_EC_KEY(key), outp);
    default:
      OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
      return -1;
  }
}

EVP_PKEY *d2i_PublicKey(int type, EVP_PKEY **out, const uint8_t **inp,
                        long len) {
  EVP_PKEY *ret = EVP_PKEY_new();
  if (ret == NULL) {
    return NULL;
  }

  CBS cbs;
  CBS_init(&cbs, *inp, len < 0 ? 0 : (size_t)len);
  switch (type) {
    case EVP_PKEY_RSA: {
      RSA *rsa = RSA_parse_public_key(&cbs);
      if (rsa == NULL || !EVP_PKEY_assign_RSA(ret, rsa)) {
        RSA_free(rsa);
        goto err;
      }
      break;
    }

    // Unlike OpenSSL, we do not support EC keys with this API. The raw EC
    // public key serialization requires knowing the group. In OpenSSL, calling
    // this function with |EVP_PKEY_EC| and setting |out| to NULL does not work.
    // It requires |*out| to include a partially-initialized |EVP_PKEY| to
    // extract the group.
    default:
      OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
      goto err;
  }

  *inp = CBS_data(&cbs);
  if (out != NULL) {
    EVP_PKEY_free(*out);
    *out = ret;
  }
  return ret;

err:
  EVP_PKEY_free(ret);
  return NULL;
}

EVP_PKEY *d2i_PUBKEY(EVP_PKEY **out, const uint8_t **inp, long len) {
  if (len < 0) {
    return NULL;
  }
  CBS cbs;
  CBS_init(&cbs, *inp, (size_t)len);
  EVP_PKEY *ret = EVP_parse_public_key(&cbs);
  if (ret == NULL) {
    return NULL;
  }
  if (out != NULL) {
    EVP_PKEY_free(*out);
    *out = ret;
  }
  *inp = CBS_data(&cbs);
  return ret;
}

int i2d_PUBKEY(const EVP_PKEY *pkey, uint8_t **outp) {
  if (pkey == NULL) {
    return 0;
  }

  CBB cbb;
  if (!CBB_init(&cbb, 128) ||
      !EVP_marshal_public_key(&cbb, pkey)) {
    CBB_cleanup(&cbb);
    return -1;
  }
  return CBB_finish_i2d(&cbb, outp);
}

RSA *d2i_RSA_PUBKEY(RSA **out, const uint8_t **inp, long len) {
  if (len < 0) {
    return NULL;
  }
  CBS cbs;
  CBS_init(&cbs, *inp, (size_t)len);
  EVP_PKEY *pkey = EVP_parse_public_key(&cbs);
  if (pkey == NULL) {
    return NULL;
  }
  RSA *rsa = EVP_PKEY_get1_RSA(pkey);
  EVP_PKEY_free(pkey);
  if (rsa == NULL) {
    return NULL;
  }
  if (out != NULL) {
    RSA_free(*out);
    *out = rsa;
  }
  *inp = CBS_data(&cbs);
  return rsa;
}

int i2d_RSA_PUBKEY(const RSA *rsa, uint8_t **outp) {
  if (rsa == NULL) {
    return 0;
  }

  int ret = -1;
  EVP_PKEY *pkey = EVP_PKEY_new();
  if (pkey == NULL ||
      !EVP_PKEY_set1_RSA(pkey, (RSA *)rsa)) {
    goto err;
  }

  ret = i2d_PUBKEY(pkey, outp);

err:
  EVP_PKEY_free(pkey);
  return ret;
}

DSA *d2i_DSA_PUBKEY(DSA **out, const uint8_t **inp, long len) {
  if (len < 0) {
    return NULL;
  }
  CBS cbs;
  CBS_init(&cbs, *inp, (size_t)len);
  EVP_PKEY *pkey = EVP_parse_public_key(&cbs);
  if (pkey == NULL) {
    return NULL;
  }
  DSA *dsa = EVP_PKEY_get1_DSA(pkey);
  EVP_PKEY_free(pkey);
  if (dsa == NULL) {
    return NULL;
  }
  if (out != NULL) {
    DSA_free(*out);
    *out = dsa;
  }
  *inp = CBS_data(&cbs);
  return dsa;
}

int i2d_DSA_PUBKEY(const DSA *dsa, uint8_t **outp) {
  if (dsa == NULL) {
    return 0;
  }

  int ret = -1;
  EVP_PKEY *pkey = EVP_PKEY_new();
  if (pkey == NULL ||
      !EVP_PKEY_set1_DSA(pkey, (DSA *)dsa)) {
    goto err;
  }

  ret = i2d_PUBKEY(pkey, outp);

err:
  EVP_PKEY_free(pkey);
  return ret;
}

EC_KEY *d2i_EC_PUBKEY(EC_KEY **out, const uint8_t **inp, long len) {
  if (len < 0) {
    return NULL;
  }
  CBS cbs;
  CBS_init(&cbs, *inp, (size_t)len);
  EVP_PKEY *pkey = EVP_parse_public_key(&cbs);
  if (pkey == NULL) {
    return NULL;
  }
  EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
  EVP_PKEY_free(pkey);
  if (ec_key == NULL) {
    return NULL;
  }
  if (out != NULL) {
    EC_KEY_free(*out);
    *out = ec_key;
  }
  *inp = CBS_data(&cbs);
  return ec_key;
}

int i2d_EC_PUBKEY(const EC_KEY *ec_key, uint8_t **outp) {
  if (ec_key == NULL) {
    return 0;
  }

  int ret = -1;
  EVP_PKEY *pkey = EVP_PKEY_new();
  if (pkey == NULL ||
      !EVP_PKEY_set1_EC_KEY(pkey, (EC_KEY *)ec_key)) {
    goto err;
  }

  ret = i2d_PUBKEY(pkey, outp);

err:
  EVP_PKEY_free(pkey);
  return ret;
}