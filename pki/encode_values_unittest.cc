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

#include "encode_values.h"

#include <string_view>

#include <gtest/gtest.h>

#include <openssl/bytestring.h>
#include <openssl/nid.h>
#include <openssl/span.h>

#include "../crypto/bytestring/internal.h"
#include "parse_values.h"

BSSL_NAMESPACE_BEGIN
namespace der::test {

TEST(EncodeValuesTest, EncodePosixTimeAsGeneralizedTime) {
  // Fri, 24 Jun 2016 17:04:54 GMT
  int64_t time = 1466787894;
  GeneralizedTime generalized_time;
  ASSERT_TRUE(EncodePosixTimeAsGeneralizedTime(time, &generalized_time));
  EXPECT_EQ(2016, generalized_time.year);
  EXPECT_EQ(6, generalized_time.month);
  EXPECT_EQ(24, generalized_time.day);
  EXPECT_EQ(17, generalized_time.hours);
  EXPECT_EQ(4, generalized_time.minutes);
  EXPECT_EQ(54, generalized_time.seconds);
}

TEST(EncodeValuesTest, GeneralizedTimeToPosixTime) {
  GeneralizedTime generalized_time;
  generalized_time.year = 2016;
  generalized_time.month = 6;
  generalized_time.day = 24;
  generalized_time.hours = 17;
  generalized_time.minutes = 4;
  generalized_time.seconds = 54;
  int64_t time;
  ASSERT_TRUE(GeneralizedTimeToPosixTime(generalized_time, &time));
  EXPECT_EQ(1466787894, time);
}

// As Posix times use BoringSSL's POSIX time routines underneath the covers
// these should not have any issues on 32 bit platforms.
TEST(EncodeValuesTest, GeneralizedTimeToPosixTimeAfter32BitPosixMaxYear) {
  GeneralizedTime generalized_time;
  generalized_time.year = 2039;
  generalized_time.month = 1;
  generalized_time.day = 1;
  generalized_time.hours = 0;
  generalized_time.minutes = 0;
  generalized_time.seconds = 0;
  int64_t time;
  ASSERT_TRUE(GeneralizedTimeToPosixTime(generalized_time, &time));

  generalized_time.day = 0;  // Invalid day of month should fail.
  EXPECT_FALSE(GeneralizedTimeToPosixTime(generalized_time, &time));
}

TEST(EncodeValuesTest, EncodeGeneralizedTime) {
  GeneralizedTime time;
  time.year = 2014;
  time.month = 12;
  time.day = 18;
  time.hours = 16;
  time.minutes = 12;
  time.seconds = 59;

  // Encode a time where no components have leading zeros.
  uint8_t out[kGeneralizedTimeLength];
  ASSERT_TRUE(EncodeGeneralizedTime(time, out));
  EXPECT_EQ("20141218161259Z", bssl::BytesAsStringView(out));

  // Test bounds on all components. Note the encoding function does not validate
  // the input is a valid time, only that it is encodable.
  time.year = 0;
  time.month = 0;
  time.day = 0;
  time.hours = 0;
  time.minutes = 0;
  time.seconds = 0;
  ASSERT_TRUE(EncodeGeneralizedTime(time, out));
  EXPECT_EQ("00000000000000Z", bssl::BytesAsStringView(out));

  time.year = 9999;
  time.month = 99;
  time.day = 99;
  time.hours = 99;
  time.minutes = 99;
  time.seconds = 99;
  ASSERT_TRUE(EncodeGeneralizedTime(time, out));
  EXPECT_EQ("99999999999999Z", bssl::BytesAsStringView(out));

  time.year = 10000;
  EXPECT_FALSE(EncodeGeneralizedTime(time, out));

  time.year = 2000;
  time.month = 100;
  EXPECT_FALSE(EncodeGeneralizedTime(time, out));
}

TEST(EncodeValuesTest, EncodeUTCTime) {
  GeneralizedTime time;
  time.year = 2014;
  time.month = 12;
  time.day = 18;
  time.hours = 16;
  time.minutes = 12;
  time.seconds = 59;

  // Encode a time where no components have leading zeros.
  uint8_t out[kUTCTimeLength];
  ASSERT_TRUE(EncodeUTCTime(time, out));
  EXPECT_EQ("141218161259Z", bssl::BytesAsStringView(out));

  time.year = 2049;
  ASSERT_TRUE(EncodeUTCTime(time, out));
  EXPECT_EQ("491218161259Z", bssl::BytesAsStringView(out));

  time.year = 2000;
  ASSERT_TRUE(EncodeUTCTime(time, out));
  EXPECT_EQ("001218161259Z", bssl::BytesAsStringView(out));

  time.year = 1999;
  ASSERT_TRUE(EncodeUTCTime(time, out));
  EXPECT_EQ("991218161259Z", bssl::BytesAsStringView(out));

  time.year = 1950;
  ASSERT_TRUE(EncodeUTCTime(time, out));
  EXPECT_EQ("501218161259Z", bssl::BytesAsStringView(out));

  time.year = 2050;
  EXPECT_FALSE(EncodeUTCTime(time, out));

  time.year = 1949;
  EXPECT_FALSE(EncodeUTCTime(time, out));

  // Test bounds on all components. Note the encoding function does not validate
  // the input is a valid time, only that it is encodable.
  time.year = 2000;
  time.month = 0;
  time.day = 0;
  time.hours = 0;
  time.minutes = 0;
  time.seconds = 0;
  ASSERT_TRUE(EncodeUTCTime(time, out));
  EXPECT_EQ("000000000000Z", bssl::BytesAsStringView(out));

  time.year = 1999;
  time.month = 99;
  time.day = 99;
  time.hours = 99;
  time.minutes = 99;
  time.seconds = 99;
  ASSERT_TRUE(EncodeUTCTime(time, out));
  EXPECT_EQ("999999999999Z", bssl::BytesAsStringView(out));

  time.year = 2000;
  time.month = 100;
  EXPECT_FALSE(EncodeUTCTime(time, out));
}

TEST(EncodeValuesTest, EncodeUnsignedAlgorithmIdentifier) {
  ScopedCBB cbb;
  ASSERT_TRUE(CBB_init(cbb.get(), 0));
  ASSERT_TRUE(EncodeUnsignedAlgorithmIdentifier(cbb.get()));
  // SEQUENCE { OBJECT IDENTIFIER 1.3.6.1.5.5.7.6.36 }
  static const uint8_t kExpected[] = {0x30, 0x0a, 0x06, 0x08,
                                      OBJ_ENC_alg_unsigned};
  EXPECT_EQ(CBBAsSpan(cbb.get()), Span(kExpected));
}

TEST(EncodeValuesTest, EncodeUnsignedIssuerName) {
  ScopedCBB cbb;
  ASSERT_TRUE(CBB_init(cbb.get(), 0));
  ASSERT_TRUE(EncodeUnsignedIssuerName(cbb.get()));
  // SEQUENCE { SET { SEQUENCE {
  //   OBJECT IDENTIFIER 1.3.6.1.5.5.7.25.1, UTF8String "" } } }
  static const uint8_t kExpected[] = {
      0x30, 0x10, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x08, OBJ_ENC_rdna_unsigned,
      0x0c, 0x00};
  EXPECT_EQ(CBBAsSpan(cbb.get()), Span(kExpected));
}

TEST(EncodeValuesTest, EncodeExtension) {
  static const uint8_t kOid[] = {OBJ_ENC_basic_constraints};
  static const uint8_t kValue[] = {0x30, 0x00};

  ScopedCBB cbb;
  ASSERT_TRUE(CBB_init(cbb.get(), 0));
  ASSERT_TRUE(EncodeExtension(cbb.get(), kOid, /*critical=*/false, kValue));
  // SEQUENCE { OBJECT IDENTIFIER, OCTET STRING { SEQUENCE {} } }
  static const uint8_t kNonCritical[] = {
      0x30, 0x09, 0x06, 0x03, OBJ_ENC_basic_constraints,
      0x04, 0x02, 0x30, 0x00};
  EXPECT_EQ(CBBAsSpan(cbb.get()), Span(kNonCritical));

  cbb.Reset();
  ASSERT_TRUE(CBB_init(cbb.get(), 0));
  ASSERT_TRUE(EncodeExtension(cbb.get(), kOid, /*critical=*/true, kValue));
  // SEQUENCE { OBJECT IDENTIFIER, BOOLEAN TRUE, OCTET STRING { SEQUENCE {} } }
  static const uint8_t kCritical[] = {
      0x30, 0x0c, 0x06, 0x03, OBJ_ENC_basic_constraints, 0x01, 0x01, 0xff,
      0x04, 0x02, 0x30, 0x00};
  EXPECT_EQ(CBBAsSpan(cbb.get()), Span(kCritical));
}

}  // namespace der::test
BSSL_NAMESPACE_END
