#!/bin/bash
# Copyright 2016 The BoringSSL Authors
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

set -ex

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 fuzzer_mode_build_dir no_fuzzer_mode_build_dir"
  exit 1
fi

fuzzer_mode_build_dir=$1
no_fuzzer_mode_build_dir=$2


# Sanity-check the build directories.

if ! grep -q '^FUZZ:' "$fuzzer_mode_build_dir/CMakeCache.txt"; then
  echo "$fuzzer_mode_build_dir was not built with -DFUZZ=1"
  exit 1
fi

if grep -q '^NO_FUZZER_MODE:' "$fuzzer_mode_build_dir/CMakeCache.txt"; then
  echo "$fuzzer_mode_build_dir was built with -DNO_FUZZER_MODE=1"
  exit 1
fi

if ! grep -q '^FUZZ:' "$no_fuzzer_mode_build_dir/CMakeCache.txt"; then
  echo "$no_fuzzer_mode_build_dir was not built with -DFUZZ=1"
  exit 1
fi

if ! grep -q '^NO_FUZZER_MODE:' "$no_fuzzer_mode_build_dir/CMakeCache.txt"; then
  echo "$no_fuzzer_mode_build_dir was not built with -DNO_FUZZER_MODE=1"
  exit 1
fi


# Sanity-check the current working directory.

assert_directory() {
  if [[ ! -d $1 ]]; then
    echo "$1 not found."
    exit 1
  fi
}

assert_directory client_corpus
assert_directory client_corpus_no_fuzzer_mode
assert_directory server_corpus
assert_directory server_corpus_no_fuzzer_mode
assert_directory dtls_client_corpus
assert_directory dtls_server_corpus


# Gather new transcripts. Ignore errors in running the tests.

fuzzer_mode_shim=$(readlink -f "$fuzzer_mode_build_dir/ssl/test/bssl_shim")
no_fuzzer_mode_shim=$(readlink -f \
    "$no_fuzzer_mode_build_dir/ssl/test/bssl_shim")

fuzzer_mode_handshaker=$(readlink -f \
    "$fuzzer_mode_build_dir/ssl/test/handshaker")
no_fuzzer_mode_handshaker=$(readlink -f \
    "$no_fuzzer_mode_build_dir/ssl/test/handshaker")

fuzzer_mode_transcripts=$(mktemp -d '/tmp/boringssl-transcript-fuzzer-mode.XXXXXX')
no_fuzzer_mode_transcripts=$(mktemp -d '/tmp/boringssl-transcript-no-fuzzer-mode.XXXXXX')

echo Recording fuzzer-mode transcripts
(cd ../ssl/test/runner/ && go test \
    -shim-path "$fuzzer_mode_shim" \
    -handshaker-path "$fuzzer_mode_handshaker" \
    -transcript-dir "$fuzzer_mode_transcripts" \
    -fuzzer \
    -deterministic) || true

echo Recording non-fuzzer-mode transcripts
(cd ../ssl/test/runner/ && go test \
    -shim-path "$no_fuzzer_mode_shim" \
    -handshaker-path "$no_fuzzer_mode_handshaker" \
    -transcript-dir "$no_fuzzer_mode_transcripts" \
    -deterministic)


# Minimize the existing corpora.

minimize_corpus() {
  local fuzzer="$1"
  local corpus="$2"

  echo "Minimizing ${corpus}"
  mv "$corpus" "${corpus}_old"
  mkdir "$corpus"
  "$fuzzer" -max_len=50000 -merge=1 "$corpus" "${corpus}_old"
  rm -Rf "${corpus}_old"
}

minimize_corpus "$fuzzer_mode_build_dir/fuzz/client" client_corpus
minimize_corpus "$fuzzer_mode_build_dir/fuzz/server" server_corpus
minimize_corpus "$no_fuzzer_mode_build_dir/fuzz/client" client_corpus_no_fuzzer_mode
minimize_corpus "$no_fuzzer_mode_build_dir/fuzz/server" server_corpus_no_fuzzer_mode
minimize_corpus "$fuzzer_mode_build_dir/fuzz/dtls_client" dtls_client_corpus
minimize_corpus "$fuzzer_mode_build_dir/fuzz/dtls_server" dtls_server_corpus
minimize_corpus "$fuzzer_mode_build_dir/fuzz/decode_client_hello_inner" decode_client_hello_inner_corpus


# Incorporate the new transcripts.

"$fuzzer_mode_build_dir/fuzz/client" -max_len=50000 -merge=1 client_corpus "${fuzzer_mode_transcripts}/tls/client"
"$fuzzer_mode_build_dir/fuzz/server" -max_len=50000 -merge=1 server_corpus "${fuzzer_mode_transcripts}/tls/server"
"$no_fuzzer_mode_build_dir/fuzz/client" -max_len=50000 -merge=1 client_corpus_no_fuzzer_mode "${no_fuzzer_mode_transcripts}/tls/client"
"$no_fuzzer_mode_build_dir/fuzz/server" -max_len=50000 -merge=1 server_corpus_no_fuzzer_mode "${no_fuzzer_mode_transcripts}/tls/server"
"$fuzzer_mode_build_dir/fuzz/dtls_client" -max_len=50000 -merge=1 dtls_client_corpus "${fuzzer_mode_transcripts}/dtls/client"
"$fuzzer_mode_build_dir/fuzz/dtls_server" -max_len=50000 -merge=1 dtls_server_corpus "${fuzzer_mode_transcripts}/dtls/server"
"$fuzzer_mode_build_dir/fuzz/decode_client_hello_inner" -max_len=50000 -merge=1 decode_client_hello_inner_corpus "${fuzzer_mode_transcripts}/decode_client_hello_inner"
