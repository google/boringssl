// Copyright 2016 The BoringSSL Authors
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

#include <openssl/pool.h>

#include <assert.h>
#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/siphash.h>

#include "../internal.h"
#include "../mem_internal.h"
#include "internal.h"


using namespace bssl;

static uint32_t CRYPTO_BUFFER_hash(const CRYPTO_BUFFER *buf) {
  const auto *impl = FromOpaque(buf);
  return (uint32_t)SIPHASH_24(impl->pool->hash_key, impl->data, impl->len);
}

static int CRYPTO_BUFFER_cmp(const CRYPTO_BUFFER *a, const CRYPTO_BUFFER *b) {
  const auto *a_impl = FromOpaque(a);
  const auto *b_impl = FromOpaque(b);
  // Only |CRYPTO_BUFFER|s from the same pool have compatible hashes.
  assert(a_impl->pool != nullptr);
  assert(a_impl->pool == b_impl->pool);
  if (a_impl->len != b_impl->len) {
    return 1;
  }
  return OPENSSL_memcmp(a_impl->data, b_impl->data, a_impl->len);
}

CRYPTO_BUFFER_POOL *CRYPTO_BUFFER_POOL_new() {
  CRYPTO_BUFFER_POOL *pool = NewZeroed<CRYPTO_BUFFER_POOL>();
  if (pool == nullptr) {
    return nullptr;
  }

  pool->bufs = lh_CRYPTO_BUFFER_new(CRYPTO_BUFFER_hash, CRYPTO_BUFFER_cmp);
  if (pool->bufs == nullptr) {
    OPENSSL_free(pool);
    return nullptr;
  }

  CRYPTO_MUTEX_init(&pool->lock);
  RAND_bytes((uint8_t *)&pool->hash_key, sizeof(pool->hash_key));

  return pool;
}

void CRYPTO_BUFFER_POOL_free(CRYPTO_BUFFER_POOL *pool) {
  if (pool == nullptr) {
    return;
  }

#if !defined(NDEBUG)
  CRYPTO_MUTEX_lock_write(&pool->lock);
  assert(lh_CRYPTO_BUFFER_num_items(pool->bufs) == 0);
  CRYPTO_MUTEX_unlock_write(&pool->lock);
#endif

  lh_CRYPTO_BUFFER_free(pool->bufs);
  CRYPTO_MUTEX_cleanup(&pool->lock);
  OPENSSL_free(pool);
}

static void crypto_buffer_free_object(CryptoBuffer *buf) {
  if (!buf->data_is_static) {
    OPENSSL_free(buf->data);
  }
  OPENSSL_free(buf);
}

static CRYPTO_BUFFER *crypto_buffer_new(const uint8_t *data, size_t len,
                                        int data_is_static,
                                        CRYPTO_BUFFER_POOL *pool) {
  if (pool != nullptr) {
    CryptoBuffer tmp;
    tmp.data = (uint8_t *)data;
    tmp.len = len;
    tmp.pool = pool;

    CRYPTO_MUTEX_lock_read(&pool->lock);
    CRYPTO_BUFFER *duplicate = lh_CRYPTO_BUFFER_retrieve(pool->bufs, &tmp);
    if (data_is_static && duplicate != nullptr &&
        !FromOpaque(duplicate)->data_is_static) {
      // If the new |CRYPTO_BUFFER| would have static data, but the duplicate
      // does not, we replace the old one with the new static version.
      duplicate = nullptr;
    }
    if (duplicate != nullptr) {
      CRYPTO_refcount_inc(&FromOpaque(duplicate)->references);
    }
    CRYPTO_MUTEX_unlock_read(&pool->lock);

    if (duplicate != nullptr) {
      return duplicate;
    }
  }

  CryptoBuffer *const buf = NewZeroed<CryptoBuffer>();
  if (buf == nullptr) {
    return nullptr;
  }

  if (data_is_static) {
    buf->data = (uint8_t *)data;
    buf->data_is_static = 1;
  } else {
    buf->data = reinterpret_cast<uint8_t *>(OPENSSL_memdup(data, len));
    if (len != 0 && buf->data == nullptr) {
      OPENSSL_free(buf);
      return nullptr;
    }
  }

  buf->len = len;
  buf->references = 1;

  if (pool == nullptr) {
    return buf;
  }

  buf->pool = pool;

  CRYPTO_MUTEX_lock_write(&pool->lock);
  CRYPTO_BUFFER *duplicate = lh_CRYPTO_BUFFER_retrieve(pool->bufs, buf);
  if (data_is_static && duplicate != nullptr &&
      !FromOpaque(duplicate)->data_is_static) {
    // If the new |CRYPTO_BUFFER| would have static data, but the duplicate does
    // not, we replace the old one with the new static version.
    duplicate = nullptr;
  }
  int inserted = 0;
  if (duplicate == nullptr) {
    CRYPTO_BUFFER *old = nullptr;
    inserted = lh_CRYPTO_BUFFER_insert(pool->bufs, &old, buf);
    // |old| may be non-NULL if a match was found but ignored. |pool->bufs| does
    // not increment refcounts, so there is no need to clean up after the
    // replacement.
  } else {
    CRYPTO_refcount_inc(&FromOpaque(duplicate)->references);
  }
  CRYPTO_MUTEX_unlock_write(&pool->lock);

  if (!inserted) {
    // We raced to insert |buf| into the pool and lost, or else there was an
    // error inserting.
    crypto_buffer_free_object(buf);
    return duplicate;
  }

  return buf;
}

CRYPTO_BUFFER *CRYPTO_BUFFER_new(const uint8_t *data, size_t len,
                                 CRYPTO_BUFFER_POOL *pool) {
  return crypto_buffer_new(data, len, /*data_is_static=*/0, pool);
}

CRYPTO_BUFFER *CRYPTO_BUFFER_alloc(uint8_t **out_data, size_t len) {
  CryptoBuffer *const buf = NewZeroed<CryptoBuffer>();
  if (buf == nullptr) {
    return nullptr;
  }

  buf->data = reinterpret_cast<uint8_t *>(OPENSSL_malloc(len));
  if (len != 0 && buf->data == nullptr) {
    OPENSSL_free(buf);
    return nullptr;
  }
  buf->len = len;
  buf->references = 1;

  *out_data = buf->data;
  return buf;
}

CRYPTO_BUFFER *CRYPTO_BUFFER_new_from_CBS(const CBS *cbs,
                                          CRYPTO_BUFFER_POOL *pool) {
  return CRYPTO_BUFFER_new(CBS_data(cbs), CBS_len(cbs), pool);
}

CRYPTO_BUFFER *CRYPTO_BUFFER_new_from_static_data_unsafe(
    const uint8_t *data, size_t len, CRYPTO_BUFFER_POOL *pool) {
  return crypto_buffer_new(data, len, /*data_is_static=*/1, pool);
}

void CRYPTO_BUFFER_free(CRYPTO_BUFFER *buf) {
  if (buf == nullptr) {
    return;
  }
  auto *impl = FromOpaque(buf);

  CRYPTO_BUFFER_POOL *const pool = impl->pool;
  if (pool == nullptr) {
    if (CRYPTO_refcount_dec_and_test_zero(&impl->references)) {
      // If a reference count of zero is observed, there cannot be a reference
      // from any pool to this buffer and thus we are able to free this
      // buffer.
      crypto_buffer_free_object(impl);
    }

    return;
  }

  CRYPTO_MUTEX_lock_write(&pool->lock);
  if (!CRYPTO_refcount_dec_and_test_zero(&impl->references)) {
    CRYPTO_MUTEX_unlock_write(&impl->pool->lock);
    return;
  }

  // We have an exclusive lock on the pool, therefore no concurrent lookups can
  // find this buffer and increment the reference count. Thus, if the count is
  // zero there are and can never be any more references and thus we can free
  // this buffer.
  //
  // Note it is possible |buf| is no longer in the pool, if it was replaced by a
  // static version. If that static version was since removed, it is even
  // possible for |found| to be NULL.
  CRYPTO_BUFFER *found = lh_CRYPTO_BUFFER_retrieve(pool->bufs, impl);
  if (found == impl) {
    found = lh_CRYPTO_BUFFER_delete(pool->bufs, impl);
    assert(found == impl);
    (void)found;
  }

  CRYPTO_MUTEX_unlock_write(&impl->pool->lock);
  crypto_buffer_free_object(impl);
}

int CRYPTO_BUFFER_up_ref(CRYPTO_BUFFER *buf) {
  auto *impl = FromOpaque(buf);
  // This is safe in the case that |buf->pool| is NULL because it's just
  // standard reference counting in that case.
  //
  // This is also safe if |buf->pool| is non-NULL because, if it were racing
  // with |CRYPTO_BUFFER_free| then the two callers must have independent
  // references already and so the reference count will never hit zero.
  CRYPTO_refcount_inc(&impl->references);
  return 1;
}

const uint8_t *CRYPTO_BUFFER_data(const CRYPTO_BUFFER *buf) {
  auto *impl = FromOpaque(buf);
  return impl->data;
}

size_t CRYPTO_BUFFER_len(const CRYPTO_BUFFER *buf) {
  auto *impl = FromOpaque(buf);
  return impl->len;
}

void CRYPTO_BUFFER_init_CBS(const CRYPTO_BUFFER *buf, CBS *out) {
  auto *impl = FromOpaque(buf);
  CBS_init(out, impl->data, impl->len);
}
