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

#include <openssl/bio.h>

#include <string>
#include <string_view>

#include <gtest/gtest.h>


BSSL_NAMESPACE_BEGIN
namespace {

TEST(Base64BIOTest, Decode) {
  const struct {
    bool no_nl;
    const char *in;
    const char *out;
  } kTests[] = {
      {true, "QUJD", "ABC"},
      {true, "QQ==", "A"},
      {true, "QUJDRA==", "ABCD"},
      // Trailing whitespace does not affect padding.
      {true, "QQ==    ", "A"},
      {true, "QQ==\t\t\r\n", "A"},
      // Interior whitespace is ignored.
      {true, "QUJD QUJD", "ABCABC"},
      // Default mode (without NO_NL) requires input to be newline delimited.
      {false, "QQ==\n", "A"},
      {false, "QQ==    \n", "A"},
      {false, "QUJD\nRA==\n", "ABCD"},
      {false, "QU\nJD\nRA==\n", "ABCD"},
  };
  for (const auto &t : kTests) {
    SCOPED_TRACE(t.in);
    SCOPED_TRACE(t.no_nl);
    UniquePtr<BIO> b64(BIO_new(BIO_f_base64()));
    ASSERT_TRUE(b64);
    if (t.no_nl) {
      BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    }
    std::string_view in(t.in);
    BIO *mem = BIO_new_mem_buf(in.data(), in.size());
    ASSERT_TRUE(mem);
    BIO_push(b64.get(), mem);

    std::string out;
    char buf[1024];
    int ret;
    while ((ret = BIO_read(b64.get(), buf, sizeof(buf))) > 0) {
      out.append(buf, ret);
    }
    EXPECT_EQ(out, t.out);
  }
}

}  // namespace
BSSL_NAMESPACE_END
