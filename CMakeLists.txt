# Copyright 2015 The BoringSSL Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file is created by generate_build_files.py. Do not edit manually.

cmake_minimum_required(VERSION 3.16)

project(BoringSSL LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fno-common -fno-exceptions -fno-rtti")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -fno-common")
endif()

# pthread_rwlock_t requires a feature flag on glibc.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_XOPEN_SOURCE=700")
endif()

if(WIN32)
  add_definitions(-D_HAS_EXCEPTIONS=0)
  add_definitions(-DWIN32_LEAN_AND_MEAN)
  add_definitions(-DNOMINMAX)
  # Allow use of fopen.
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

add_definitions(-DBORINGSSL_IMPLEMENTATION)

if(OPENSSL_NO_ASM)
  add_definitions(-DOPENSSL_NO_ASM)
else()
  # On x86 and x86_64 Windows, we use the NASM output.
  if(WIN32 AND CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64|amd64|x86|i[3-6]86")
    enable_language(ASM_NASM)
    set(OPENSSL_NASM TRUE)
    set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -gcv8")
  else()
    enable_language(ASM)
    set(OPENSSL_ASM TRUE)
    # Work around https://gitlab.kitware.com/cmake/cmake/-/issues/20771 in older
    # CMake versions.
    if(APPLE AND CMAKE_VERSION VERSION_LESS 3.19)
      if(CMAKE_OSX_SYSROOT)
        set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -isysroot \"${CMAKE_OSX_SYSROOT}\"")
      endif()
      foreach(arch ${CMAKE_OSX_ARCHITECTURES})
        set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch ${arch}")
      endforeach()
    endif()
    if(NOT WIN32)
      set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -Wa,--noexecstack")
    endif()
    # Clang's integerated assembler does not support debug symbols.
    if(NOT CMAKE_ASM_COMPILER_ID MATCHES "Clang")
      set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -Wa,-g")
    endif()
  endif()
endif()

if(BUILD_SHARED_LIBS)
  add_definitions(-DBORINGSSL_SHARED_LIBRARY)
  # Enable position-independent code globally. This is needed because
  # some library targets are OBJECT libraries.
  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
endif()

set(
  CRYPTO_SOURCES_ASM

  src/crypto/curve25519/asm/x25519-asm-arm.S
  src/crypto/hrss/asm/poly_rq_mul.S
  src/crypto/poly1305/poly1305_arm_asm.S
  src/gen/bcm/aes-gcm-avx2-x86_64-apple.S
  src/gen/bcm/aes-gcm-avx2-x86_64-linux.S
  src/gen/bcm/aes-gcm-avx512-x86_64-apple.S
  src/gen/bcm/aes-gcm-avx512-x86_64-linux.S
  src/gen/bcm/aesni-gcm-x86_64-apple.S
  src/gen/bcm/aesni-gcm-x86_64-linux.S
  src/gen/bcm/aesni-x86-apple.S
  src/gen/bcm/aesni-x86-linux.S
  src/gen/bcm/aesni-x86_64-apple.S
  src/gen/bcm/aesni-x86_64-linux.S
  src/gen/bcm/aesv8-armv7-linux.S
  src/gen/bcm/aesv8-armv8-apple.S
  src/gen/bcm/aesv8-armv8-linux.S
  src/gen/bcm/aesv8-armv8-win.S
  src/gen/bcm/aesv8-gcm-armv8-apple.S
  src/gen/bcm/aesv8-gcm-armv8-linux.S
  src/gen/bcm/aesv8-gcm-armv8-win.S
  src/gen/bcm/armv4-mont-linux.S
  src/gen/bcm/armv8-mont-apple.S
  src/gen/bcm/armv8-mont-linux.S
  src/gen/bcm/armv8-mont-win.S
  src/gen/bcm/bn-586-apple.S
  src/gen/bcm/bn-586-linux.S
  src/gen/bcm/bn-armv8-apple.S
  src/gen/bcm/bn-armv8-linux.S
  src/gen/bcm/bn-armv8-win.S
  src/gen/bcm/bsaes-armv7-linux.S
  src/gen/bcm/co-586-apple.S
  src/gen/bcm/co-586-linux.S
  src/gen/bcm/ghash-armv4-linux.S
  src/gen/bcm/ghash-neon-armv8-apple.S
  src/gen/bcm/ghash-neon-armv8-linux.S
  src/gen/bcm/ghash-neon-armv8-win.S
  src/gen/bcm/ghash-ssse3-x86-apple.S
  src/gen/bcm/ghash-ssse3-x86-linux.S
  src/gen/bcm/ghash-ssse3-x86_64-apple.S
  src/gen/bcm/ghash-ssse3-x86_64-linux.S
  src/gen/bcm/ghash-x86-apple.S
  src/gen/bcm/ghash-x86-linux.S
  src/gen/bcm/ghash-x86_64-apple.S
  src/gen/bcm/ghash-x86_64-linux.S
  src/gen/bcm/ghashv8-armv7-linux.S
  src/gen/bcm/ghashv8-armv8-apple.S
  src/gen/bcm/ghashv8-armv8-linux.S
  src/gen/bcm/ghashv8-armv8-win.S
  src/gen/bcm/p256-armv8-asm-apple.S
  src/gen/bcm/p256-armv8-asm-linux.S
  src/gen/bcm/p256-armv8-asm-win.S
  src/gen/bcm/p256-x86_64-asm-apple.S
  src/gen/bcm/p256-x86_64-asm-linux.S
  src/gen/bcm/p256_beeu-armv8-asm-apple.S
  src/gen/bcm/p256_beeu-armv8-asm-linux.S
  src/gen/bcm/p256_beeu-armv8-asm-win.S
  src/gen/bcm/p256_beeu-x86_64-asm-apple.S
  src/gen/bcm/p256_beeu-x86_64-asm-linux.S
  src/gen/bcm/rdrand-x86_64-apple.S
  src/gen/bcm/rdrand-x86_64-linux.S
  src/gen/bcm/rsaz-avx2-apple.S
  src/gen/bcm/rsaz-avx2-linux.S
  src/gen/bcm/sha1-586-apple.S
  src/gen/bcm/sha1-586-linux.S
  src/gen/bcm/sha1-armv4-large-linux.S
  src/gen/bcm/sha1-armv8-apple.S
  src/gen/bcm/sha1-armv8-linux.S
  src/gen/bcm/sha1-armv8-win.S
  src/gen/bcm/sha1-x86_64-apple.S
  src/gen/bcm/sha1-x86_64-linux.S
  src/gen/bcm/sha256-586-apple.S
  src/gen/bcm/sha256-586-linux.S
  src/gen/bcm/sha256-armv4-linux.S
  src/gen/bcm/sha256-armv8-apple.S
  src/gen/bcm/sha256-armv8-linux.S
  src/gen/bcm/sha256-armv8-win.S
  src/gen/bcm/sha256-x86_64-apple.S
  src/gen/bcm/sha256-x86_64-linux.S
  src/gen/bcm/sha512-586-apple.S
  src/gen/bcm/sha512-586-linux.S
  src/gen/bcm/sha512-armv4-linux.S
  src/gen/bcm/sha512-armv8-apple.S
  src/gen/bcm/sha512-armv8-linux.S
  src/gen/bcm/sha512-armv8-win.S
  src/gen/bcm/sha512-x86_64-apple.S
  src/gen/bcm/sha512-x86_64-linux.S
  src/gen/bcm/vpaes-armv7-linux.S
  src/gen/bcm/vpaes-armv8-apple.S
  src/gen/bcm/vpaes-armv8-linux.S
  src/gen/bcm/vpaes-armv8-win.S
  src/gen/bcm/vpaes-x86-apple.S
  src/gen/bcm/vpaes-x86-linux.S
  src/gen/bcm/vpaes-x86_64-apple.S
  src/gen/bcm/vpaes-x86_64-linux.S
  src/gen/bcm/x86-mont-apple.S
  src/gen/bcm/x86-mont-linux.S
  src/gen/bcm/x86_64-mont-apple.S
  src/gen/bcm/x86_64-mont-linux.S
  src/gen/bcm/x86_64-mont5-apple.S
  src/gen/bcm/x86_64-mont5-linux.S
  src/gen/crypto/aes128gcmsiv-x86_64-apple.S
  src/gen/crypto/aes128gcmsiv-x86_64-linux.S
  src/gen/crypto/chacha-armv4-linux.S
  src/gen/crypto/chacha-armv8-apple.S
  src/gen/crypto/chacha-armv8-linux.S
  src/gen/crypto/chacha-armv8-win.S
  src/gen/crypto/chacha-x86-apple.S
  src/gen/crypto/chacha-x86-linux.S
  src/gen/crypto/chacha-x86_64-apple.S
  src/gen/crypto/chacha-x86_64-linux.S
  src/gen/crypto/chacha20_poly1305_armv8-apple.S
  src/gen/crypto/chacha20_poly1305_armv8-linux.S
  src/gen/crypto/chacha20_poly1305_armv8-win.S
  src/gen/crypto/chacha20_poly1305_x86_64-apple.S
  src/gen/crypto/chacha20_poly1305_x86_64-linux.S
  src/gen/crypto/md5-586-apple.S
  src/gen/crypto/md5-586-linux.S
  src/gen/crypto/md5-x86_64-apple.S
  src/gen/crypto/md5-x86_64-linux.S
  src/gen/test_support/trampoline-armv4-linux.S
  src/gen/test_support/trampoline-armv8-apple.S
  src/gen/test_support/trampoline-armv8-linux.S
  src/gen/test_support/trampoline-armv8-win.S
  src/gen/test_support/trampoline-x86-apple.S
  src/gen/test_support/trampoline-x86-linux.S
  src/gen/test_support/trampoline-x86_64-apple.S
  src/gen/test_support/trampoline-x86_64-linux.S
  src/third_party/fiat/asm/fiat_curve25519_adx_mul.S
  src/third_party/fiat/asm/fiat_curve25519_adx_square.S
  src/third_party/fiat/asm/fiat_p256_adx_mul.S
  src/third_party/fiat/asm/fiat_p256_adx_sqr.S
)

set(
  CRYPTO_SOURCES_NASM

  src/gen/bcm/aes-gcm-avx2-x86_64-win.asm
  src/gen/bcm/aes-gcm-avx512-x86_64-win.asm
  src/gen/bcm/aesni-gcm-x86_64-win.asm
  src/gen/bcm/aesni-x86-win.asm
  src/gen/bcm/aesni-x86_64-win.asm
  src/gen/bcm/bn-586-win.asm
  src/gen/bcm/co-586-win.asm
  src/gen/bcm/ghash-ssse3-x86-win.asm
  src/gen/bcm/ghash-ssse3-x86_64-win.asm
  src/gen/bcm/ghash-x86-win.asm
  src/gen/bcm/ghash-x86_64-win.asm
  src/gen/bcm/p256-x86_64-asm-win.asm
  src/gen/bcm/p256_beeu-x86_64-asm-win.asm
  src/gen/bcm/rdrand-x86_64-win.asm
  src/gen/bcm/rsaz-avx2-win.asm
  src/gen/bcm/sha1-586-win.asm
  src/gen/bcm/sha1-x86_64-win.asm
  src/gen/bcm/sha256-586-win.asm
  src/gen/bcm/sha256-x86_64-win.asm
  src/gen/bcm/sha512-586-win.asm
  src/gen/bcm/sha512-x86_64-win.asm
  src/gen/bcm/vpaes-x86-win.asm
  src/gen/bcm/vpaes-x86_64-win.asm
  src/gen/bcm/x86-mont-win.asm
  src/gen/bcm/x86_64-mont-win.asm
  src/gen/bcm/x86_64-mont5-win.asm
  src/gen/crypto/aes128gcmsiv-x86_64-win.asm
  src/gen/crypto/chacha-x86-win.asm
  src/gen/crypto/chacha-x86_64-win.asm
  src/gen/crypto/chacha20_poly1305_x86_64-win.asm
  src/gen/crypto/md5-586-win.asm
  src/gen/crypto/md5-x86_64-win.asm
  src/gen/test_support/trampoline-x86-win.asm
  src/gen/test_support/trampoline-x86_64-win.asm
)

if(OPENSSL_ASM)
  list(APPEND CRYPTO_SOURCES_ASM_USED ${CRYPTO_SOURCES_ASM})
endif()
if(OPENSSL_NASM)
  list(APPEND CRYPTO_SOURCES_ASM_USED ${CRYPTO_SOURCES_NASM})
endif()

add_library(
  crypto

  ${CRYPTO_SOURCES_ASM_USED}
  src/crypto/aes/aes.cc
  src/crypto/asn1/a_bitstr.cc
  src/crypto/asn1/a_bool.cc
  src/crypto/asn1/a_d2i_fp.cc
  src/crypto/asn1/a_dup.cc
  src/crypto/asn1/a_gentm.cc
  src/crypto/asn1/a_i2d_fp.cc
  src/crypto/asn1/a_int.cc
  src/crypto/asn1/a_mbstr.cc
  src/crypto/asn1/a_object.cc
  src/crypto/asn1/a_octet.cc
  src/crypto/asn1/a_strex.cc
  src/crypto/asn1/a_strnid.cc
  src/crypto/asn1/a_time.cc
  src/crypto/asn1/a_type.cc
  src/crypto/asn1/a_utctm.cc
  src/crypto/asn1/asn1_lib.cc
  src/crypto/asn1/asn1_par.cc
  src/crypto/asn1/asn_pack.cc
  src/crypto/asn1/f_int.cc
  src/crypto/asn1/f_string.cc
  src/crypto/asn1/posix_time.cc
  src/crypto/asn1/tasn_dec.cc
  src/crypto/asn1/tasn_enc.cc
  src/crypto/asn1/tasn_fre.cc
  src/crypto/asn1/tasn_new.cc
  src/crypto/asn1/tasn_typ.cc
  src/crypto/asn1/tasn_utl.cc
  src/crypto/base64/base64.cc
  src/crypto/bio/bio.cc
  src/crypto/bio/bio_mem.cc
  src/crypto/bio/connect.cc
  src/crypto/bio/errno.cc
  src/crypto/bio/fd.cc
  src/crypto/bio/file.cc
  src/crypto/bio/hexdump.cc
  src/crypto/bio/pair.cc
  src/crypto/bio/printf.cc
  src/crypto/bio/socket.cc
  src/crypto/bio/socket_helper.cc
  src/crypto/blake2/blake2.cc
  src/crypto/bn/bn_asn1.cc
  src/crypto/bn/convert.cc
  src/crypto/bn/div.cc
  src/crypto/bn/exponentiation.cc
  src/crypto/bn/sqrt.cc
  src/crypto/buf/buf.cc
  src/crypto/bytestring/asn1_compat.cc
  src/crypto/bytestring/ber.cc
  src/crypto/bytestring/cbb.cc
  src/crypto/bytestring/cbs.cc
  src/crypto/bytestring/unicode.cc
  src/crypto/chacha/chacha.cc
  src/crypto/cipher/derive_key.cc
  src/crypto/cipher/e_aesctrhmac.cc
  src/crypto/cipher/e_aeseax.cc
  src/crypto/cipher/e_aesgcmsiv.cc
  src/crypto/cipher/e_chacha20poly1305.cc
  src/crypto/cipher/e_des.cc
  src/crypto/cipher/e_null.cc
  src/crypto/cipher/e_rc2.cc
  src/crypto/cipher/e_rc4.cc
  src/crypto/cipher/e_tls.cc
  src/crypto/cipher/get_cipher.cc
  src/crypto/cipher/tls_cbc.cc
  src/crypto/cms/cms.cc
  src/crypto/conf/conf.cc
  src/crypto/cpu_aarch64_apple.cc
  src/crypto/cpu_aarch64_fuchsia.cc
  src/crypto/cpu_aarch64_linux.cc
  src/crypto/cpu_aarch64_openbsd.cc
  src/crypto/cpu_aarch64_sysreg.cc
  src/crypto/cpu_aarch64_win.cc
  src/crypto/cpu_arm_freebsd.cc
  src/crypto/cpu_arm_linux.cc
  src/crypto/cpu_intel.cc
  src/crypto/crypto.cc
  src/crypto/curve25519/curve25519.cc
  src/crypto/curve25519/curve25519_64_adx.cc
  src/crypto/curve25519/spake25519.cc
  src/crypto/des/des.cc
  src/crypto/dh/dh_asn1.cc
  src/crypto/dh/params.cc
  src/crypto/digest/digest_extra.cc
  src/crypto/dsa/dsa.cc
  src/crypto/dsa/dsa_asn1.cc
  src/crypto/ec/ec_asn1.cc
  src/crypto/ec/ec_derive.cc
  src/crypto/ec/hash_to_curve.cc
  src/crypto/ecdh/ecdh.cc
  src/crypto/ecdsa/ecdsa_asn1.cc
  src/crypto/engine/engine.cc
  src/crypto/err/err.cc
  src/crypto/evp/evp.cc
  src/crypto/evp/evp_asn1.cc
  src/crypto/evp/evp_ctx.cc
  src/crypto/evp/p_dh.cc
  src/crypto/evp/p_dh_asn1.cc
  src/crypto/evp/p_dsa_asn1.cc
  src/crypto/evp/p_ec.cc
  src/crypto/evp/p_ec_asn1.cc
  src/crypto/evp/p_ed25519.cc
  src/crypto/evp/p_ed25519_asn1.cc
  src/crypto/evp/p_hkdf.cc
  src/crypto/evp/p_rsa.cc
  src/crypto/evp/p_rsa_asn1.cc
  src/crypto/evp/p_x25519.cc
  src/crypto/evp/p_x25519_asn1.cc
  src/crypto/evp/pbkdf.cc
  src/crypto/evp/print.cc
  src/crypto/evp/scrypt.cc
  src/crypto/evp/sign.cc
  src/crypto/ex_data.cc
  src/crypto/fipsmodule/bcm.cc
  src/crypto/fipsmodule/fips_shared_support.cc
  src/crypto/fuzzer_mode.cc
  src/crypto/hpke/hpke.cc
  src/crypto/hrss/hrss.cc
  src/crypto/kyber/kyber.cc
  src/crypto/lhash/lhash.cc
  src/crypto/md4/md4.cc
  src/crypto/md5/md5.cc
  src/crypto/mem.cc
  src/crypto/mldsa/mldsa.cc
  src/crypto/mlkem/mlkem.cc
  src/crypto/obj/obj.cc
  src/crypto/obj/obj_xref.cc
  src/crypto/pem/pem_all.cc
  src/crypto/pem/pem_info.cc
  src/crypto/pem/pem_lib.cc
  src/crypto/pem/pem_oth.cc
  src/crypto/pem/pem_pk8.cc
  src/crypto/pem/pem_pkey.cc
  src/crypto/pem/pem_x509.cc
  src/crypto/pem/pem_xaux.cc
  src/crypto/pkcs7/pkcs7.cc
  src/crypto/pkcs7/pkcs7_x509.cc
  src/crypto/pkcs8/p5_pbev2.cc
  src/crypto/pkcs8/pkcs8.cc
  src/crypto/pkcs8/pkcs8_x509.cc
  src/crypto/poly1305/poly1305.cc
  src/crypto/poly1305/poly1305_arm.cc
  src/crypto/poly1305/poly1305_vec.cc
  src/crypto/pool/pool.cc
  src/crypto/rand/deterministic.cc
  src/crypto/rand/fork_detect.cc
  src/crypto/rand/forkunsafe.cc
  src/crypto/rand/getentropy.cc
  src/crypto/rand/ios.cc
  src/crypto/rand/passive.cc
  src/crypto/rand/rand.cc
  src/crypto/rand/trusty.cc
  src/crypto/rand/urandom.cc
  src/crypto/rand/windows.cc
  src/crypto/rc4/rc4.cc
  src/crypto/refcount.cc
  src/crypto/rsa/rsa_asn1.cc
  src/crypto/rsa/rsa_crypt.cc
  src/crypto/rsa/rsa_extra.cc
  src/crypto/rsa/rsa_print.cc
  src/crypto/sha/sha1.cc
  src/crypto/sha/sha256.cc
  src/crypto/sha/sha512.cc
  src/crypto/siphash/siphash.cc
  src/crypto/slhdsa/slhdsa.cc
  src/crypto/spake2plus/spake2plus.cc
  src/crypto/stack/stack.cc
  src/crypto/thread.cc
  src/crypto/thread_none.cc
  src/crypto/thread_pthread.cc
  src/crypto/thread_win.cc
  src/crypto/trust_token/pmbtoken.cc
  src/crypto/trust_token/trust_token.cc
  src/crypto/trust_token/voprf.cc
  src/crypto/x509/a_digest.cc
  src/crypto/x509/a_sign.cc
  src/crypto/x509/a_verify.cc
  src/crypto/x509/algorithm.cc
  src/crypto/x509/asn1_gen.cc
  src/crypto/x509/by_dir.cc
  src/crypto/x509/by_file.cc
  src/crypto/x509/i2d_pr.cc
  src/crypto/x509/name_print.cc
  src/crypto/x509/policy.cc
  src/crypto/x509/rsa_pss.cc
  src/crypto/x509/t_crl.cc
  src/crypto/x509/t_req.cc
  src/crypto/x509/t_x509.cc
  src/crypto/x509/t_x509a.cc
  src/crypto/x509/v3_akey.cc
  src/crypto/x509/v3_akeya.cc
  src/crypto/x509/v3_alt.cc
  src/crypto/x509/v3_bcons.cc
  src/crypto/x509/v3_bitst.cc
  src/crypto/x509/v3_conf.cc
  src/crypto/x509/v3_cpols.cc
  src/crypto/x509/v3_crld.cc
  src/crypto/x509/v3_enum.cc
  src/crypto/x509/v3_extku.cc
  src/crypto/x509/v3_genn.cc
  src/crypto/x509/v3_ia5.cc
  src/crypto/x509/v3_info.cc
  src/crypto/x509/v3_int.cc
  src/crypto/x509/v3_lib.cc
  src/crypto/x509/v3_ncons.cc
  src/crypto/x509/v3_ocsp.cc
  src/crypto/x509/v3_pcons.cc
  src/crypto/x509/v3_pmaps.cc
  src/crypto/x509/v3_prn.cc
  src/crypto/x509/v3_purp.cc
  src/crypto/x509/v3_skey.cc
  src/crypto/x509/v3_utl.cc
  src/crypto/x509/x509.cc
  src/crypto/x509/x509_att.cc
  src/crypto/x509/x509_cmp.cc
  src/crypto/x509/x509_d2.cc
  src/crypto/x509/x509_def.cc
  src/crypto/x509/x509_ext.cc
  src/crypto/x509/x509_lu.cc
  src/crypto/x509/x509_obj.cc
  src/crypto/x509/x509_req.cc
  src/crypto/x509/x509_set.cc
  src/crypto/x509/x509_trs.cc
  src/crypto/x509/x509_txt.cc
  src/crypto/x509/x509_v3.cc
  src/crypto/x509/x509_vfy.cc
  src/crypto/x509/x509_vpm.cc
  src/crypto/x509/x509cset.cc
  src/crypto/x509/x509name.cc
  src/crypto/x509/x509rset.cc
  src/crypto/x509/x509spki.cc
  src/crypto/x509/x_algor.cc
  src/crypto/x509/x_all.cc
  src/crypto/x509/x_attrib.cc
  src/crypto/x509/x_crl.cc
  src/crypto/x509/x_exten.cc
  src/crypto/x509/x_name.cc
  src/crypto/x509/x_pubkey.cc
  src/crypto/x509/x_req.cc
  src/crypto/x509/x_sig.cc
  src/crypto/x509/x_spki.cc
  src/crypto/x509/x_val.cc
  src/crypto/x509/x_x509.cc
  src/crypto/x509/x_x509a.cc
  src/gen/crypto/err_data.cc
)

target_include_directories(crypto PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/include>)

add_library(
  ssl

  src/ssl/bio_ssl.cc
  src/ssl/d1_both.cc
  src/ssl/d1_lib.cc
  src/ssl/d1_pkt.cc
  src/ssl/d1_srtp.cc
  src/ssl/dtls_method.cc
  src/ssl/dtls_record.cc
  src/ssl/encrypted_client_hello.cc
  src/ssl/extensions.cc
  src/ssl/handoff.cc
  src/ssl/handshake.cc
  src/ssl/handshake_client.cc
  src/ssl/handshake_server.cc
  src/ssl/s3_both.cc
  src/ssl/s3_lib.cc
  src/ssl/s3_pkt.cc
  src/ssl/ssl_aead_ctx.cc
  src/ssl/ssl_asn1.cc
  src/ssl/ssl_buffer.cc
  src/ssl/ssl_cert.cc
  src/ssl/ssl_cipher.cc
  src/ssl/ssl_credential.cc
  src/ssl/ssl_file.cc
  src/ssl/ssl_key_share.cc
  src/ssl/ssl_lib.cc
  src/ssl/ssl_privkey.cc
  src/ssl/ssl_session.cc
  src/ssl/ssl_stat.cc
  src/ssl/ssl_transcript.cc
  src/ssl/ssl_versions.cc
  src/ssl/ssl_x509.cc
  src/ssl/t1_enc.cc
  src/ssl/tls13_both.cc
  src/ssl/tls13_client.cc
  src/ssl/tls13_enc.cc
  src/ssl/tls13_server.cc
  src/ssl/tls_method.cc
  src/ssl/tls_record.cc
)

target_link_libraries(ssl crypto)

add_executable(
  bssl

  src/tool/args.cc
  src/tool/ciphers.cc
  src/tool/client.cc
  src/tool/const.cc
  src/tool/digest.cc
  src/tool/fd.cc
  src/tool/file.cc
  src/tool/generate_ech.cc
  src/tool/generate_ed25519.cc
  src/tool/genrsa.cc
  src/tool/pkcs12.cc
  src/tool/rand.cc
  src/tool/server.cc
  src/tool/sign.cc
  src/tool/speed.cc
  src/tool/tool.cc
  src/tool/transport_common.cc
)

target_link_libraries(bssl ssl crypto)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
  find_package(Threads REQUIRED)
  target_link_libraries(crypto Threads::Threads)
endif()

if(WIN32)
  target_link_libraries(crypto ws2_32)
endif()

