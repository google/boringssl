// Copyright 2014 The BoringSSL Authors
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <iterator>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/asn1.h>
#include <openssl/base.h>
#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/nid.h>
#include <openssl/obj.h>
#include <openssl/sha.h>

#include "../internal.h"
#include "../test/test_util.h"


BSSL_NAMESPACE_BEGIN
namespace {

struct MD {
  // name is the name of the digest.
  const char *name;
  // md_func is the digest to test.
  const EVP_MD *(*func)();
  // one_shot_func is the convenience one-shot version of the
  // digest.
  uint8_t *(*one_shot_func)(const uint8_t *, size_t, uint8_t *);
  // is_xof is whether the hash function is a XOF.
  bool is_xof = false;
};

const MD md4 = {"MD4", &EVP_md4, nullptr};
const MD md5 = {"MD5", &EVP_md5, &MD5};
const MD sha1 = {"SHA1", &EVP_sha1, &SHA1};
const MD sha224 = {"SHA224", &EVP_sha224, &SHA224};
const MD sha256 = {"SHA256", &EVP_sha256, &SHA256};
const MD sha384 = {"SHA384", &EVP_sha384, &SHA384};
const MD sha512 = {"SHA512", &EVP_sha512, &SHA512};
const MD sha512_256 = {"SHA512-256", &EVP_sha512_256, &SHA512_256};
const MD md5_sha1 = {"MD5-SHA1", &EVP_md5_sha1, nullptr};
const MD blake2b256 = {"BLAKE2b-256", &EVP_blake2b256, nullptr};
const MD sha3_256 = {"SHA3-256", &EVP_sha3_256, nullptr};
const MD sha3_384 = {"SHA3-384", &EVP_sha3_384, nullptr};
const MD sha3_512 = {"SHA3-512", &EVP_sha3_512, nullptr};
const MD shake128 = {"SHAKE128", &EVP_shake128, nullptr, /*is_xof=*/true};
const MD shake256 = {"SHAKE256", &EVP_shake256, nullptr, /*is_xof=*/true};
const MD turboshake128 = {"TurboSHAKE128", &EVP_turboshake128, nullptr,
                          /*is_xof=*/true};
const MD turboshake256 = {"TurboSHAKE256", &EVP_turboshake256, nullptr,
                          /*is_xof=*/true};

struct DigestTestVector {
  // md is the digest to test.
  const MD &md;
  // input is a NUL-terminated string to hash.
  const char *input;
  // repeat is the number of times to repeat input.
  size_t repeat;
  // expected_hex is the expected digest in hexadecimal.
  const char *expected_hex;
};

const DigestTestVector kTestVectors[] = {
    // MD4 tests, from RFC 1320. (crypto/md4 does not provide a
    // one-shot MD4 function.)
    {md4, "", 1, "31d6cfe0d16ae931b73c59d7e0c089c0"},
    {md4, "a", 1, "bde52cb31de33e46245e05fbdbd6fb24"},
    {md4, "abc", 1, "a448017aaf21d8525fc10ae87aa6729d"},
    {md4, "message digest", 1, "d9130a8164549fe818874806e1c7014b"},
    {md4, "abcdefghijklmnopqrstuvwxyz", 1, "d79e1c308aa5bbcdeea8ed63df412da9"},
    {md4, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1,
     "043f8582f241db351ce627e153e7f0e4"},
    {md4, "1234567890", 8, "e33b4ddc9c38f2199c3e7b164fcc0536"},

    // MD5 tests, from RFC 1321.
    {md5, "", 1, "d41d8cd98f00b204e9800998ecf8427e"},
    {md5, "a", 1, "0cc175b9c0f1b6a831c399e269772661"},
    {md5, "abc", 1, "900150983cd24fb0d6963f7d28e17f72"},
    {md5, "message digest", 1, "f96b697d7cb7938d525a2f31aaf161d0"},
    {md5, "abcdefghijklmnopqrstuvwxyz", 1, "c3fcd3d76192e4007dfb496cca67e13b"},
    {md5, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1,
     "d174ab98d277d9f5a5611c2c9f419d9f"},
    {md5, "1234567890", 8, "57edf4a22be3c955ac49da2e2107b67a"},

    // SHA-1 tests, from RFC 3174.
    {sha1, "abc", 1, "a9993e364706816aba3e25717850c26c9cd0d89d"},
    {sha1, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
     "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
    {sha1, "a", 1000000, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"},
    {sha1, "0123456701234567012345670123456701234567012345670123456701234567",
     10, "dea356a2cddd90c7a7ecedc5ebb563934f460452"},

    // SHA-224 tests, from RFC 3874.
    {sha224, "abc", 1,
     "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
    {sha224, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
     "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"},
    {sha224, "a", 1000000,
     "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"},

    // SHA-256 tests, from NIST.
    {sha256, "abc", 1,
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {sha256, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},

    // SHA-384 tests, from NIST.
    {sha384, "abc", 1,
     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
     "8086072ba1e7cc2358baeca134c825a7"},
    {sha384,
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
     "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     1,
     "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
     "fcc7c71a557e2db966c3e9fa91746039"},

    // SHA-512 tests, from NIST.
    {sha512, "abc", 1,
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
    {sha512,
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
     "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     1,
     "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
     "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},

    // SHA-512-256 tests, from
    // https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha512_256.pdf
    {sha512_256, "abc", 1,
     "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"},
    {sha512_256,
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopj"
     "klmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     1, "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a"},

    // MD5-SHA1 tests.
    {md5_sha1, "abc", 1,
     "900150983cd24fb0d6963f7d28e17f72a9993e364706816aba3e25717850c26c9cd0d89"
     "d"},

    // BLAKE2b-256 tests.
    {blake2b256, "abc", 1,
     "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"},

    // SHA3-256 tests, from
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg0.pdf
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_1600.pdf
    {sha3_256, "", 1,
     "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
    {sha3_256, "\xa3", 200,
     "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"},

    // SHA3-384 tests, from
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_Msg0.pdf
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_1600.pdf
    {sha3_384, "", 1,
     "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
     "c3713831264adb47fb6bd1e058d5f004"},
    {sha3_384, "\xa3", 200,
     "1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd"
     "76197a31fd55ee989f2d7050dd473e8f"},

    // SHA3-512 tests, from
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg0.pdf
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_1600.pdf
    {sha3_512, "", 1,
     "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
     "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"},
    {sha3_512, "\xa3", 200,
     "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca8"
     "1b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00"},

    // SHAKE128 tests, from
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg0.pdf
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg1600.pdf
    {shake128, "", 1,
     "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea98"
     "8004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8"
     "d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b5"
     "9d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007"
     "cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348"
     "b196691abaeb580b32def58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4c"
     "ee8cc0d4c922a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d861"
     "9f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b1de33fd7"
     "5081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f1368ec2967fc84ef2"
     "ae9aff268e0b1700affc6820b523a3d917135f2dff2ee06bfe72b3124721d4a26c04e53a7"
     "5e30e73a7a9c4a95d91c55d495e9f51dd0b5e9d83c6d5e8ce803aa62b8d654db53d09b8dc"
     "ff273cdfeb573fad8bcd45578bec2e770d01efde86e721a3f7c6cce275dabe6e2143f1af1"
     "8da7efddc4c7b70b5e345db93cc936bea323491ccb38a388f546a9ff00dd4e1300b9b2153"
     "d2041d205b443e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b"
     "6f"},
    {shake128, "\xa3", 200,
     "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037cf232ef71"
     "64a6d1eb448c8908186ad852d3f85a5cf28da1ab6fe3438171978467f1c05d58c7ef38c28"
     "4c41f6c2221a76f12ab1c04082660250802294fb87180213fdef5b0ecb7df50ca1f8555be"
     "14d32e10f6edcde892c09424b29f597afc270c904556bfcb47a7d40778d390923642b3cbd"
     "0579e60908d5a000c1d08b98ef933f806445bf87f8b009ba9e94f7266122ed7ac24e5e266"
     "c42a82fa1bbefb7b8db0066e16a85e0493f07df4809aec084a593748ac3dde5a6d7aae1e8"
     "b6e5352b2d71efbb47d4caeed5e6d633805d2d323e6fd81b4684b93a2677d45e7421c2c6a"
     "ea259b855a698fd7d13477a1fe53e5a4a6197dbec5ce95f505b520bcd9570c4a8265a7e01"
     "f89c0c002c59bfec6cd4a5c109258953ee5ee70cd577ee217af21fa70178f0946c9bf6ca8"
     "751793479f6b537737e40b6ed28511d8a2d7e73eb75f8daac912ff906e0ab955b083bac45"
     "a8e5e9b744c8506f37e9b4e749a184b30f43eb188d855f1b70d71ff3e50c537ac1b0f8974"
     "f0fe1a6ad295ba42f6aec74d123a7abedde6e2c0711cab36be5acb1a5a11a4b1db08ba698"
     "2efccd716929a7741cfc63aa4435e0b69a9063e880795c3dc5ef3272e11c497a91acf699f"
     "efee206227a44c9fb359fd56ac0a9a75a743cff6862f17d7259ab075216c0699511643b64"
     "39"},

    // SHAKE256 tests, from
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg0.pdf
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg1600.pdf
    {shake256, "", 1,
     "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd"
     "8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb1395769"
     "2cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462"
     "c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c"
     "06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b"
     "9a46cbe854713672f5caaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53f"
     "b8e9eb2ea203bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7"
     "f5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390bf9a66d13"
     "68b208e21f7c10d04a3dbd4e360633e5db4b602601c14cea737db3dcf722632cc77851cbd"
     "de2aaf0a33a07b373445df490cc8fc1e4160ff118378f11f0477de055a81a9eda57a4a2cf"
     "b0c83929d310912f729ec6cfa36c6ac6a75837143045d791cc85eff5b21932f23861bcf23"
     "a52b5da67eaf7baae0f5fb1369db78f3ac45f8c4ac5671d85735cdddb09d2b1e34a1fc066"
     "ff4a162cb263d6541274ae2fcc865f618abe27c124cd8b074ccd516301b91875824d09958"
     "f341ef274bdab0bae316339894304e35877b0c28a9b1fd166c796b9cc258a064a8f57e27f"
     "2a"},
    {shake256, "\xa3", 200,
     "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d2d700caae"
     "7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b1048a7f64e1074cd62"
     "9e85ad7566048efc4fb500b486a3309a8f26724c0ed628001a1099422468de726f1061d99"
     "eb9e93604d5aa7467d4b1bd6484582a384317d7f47d750b8f5499512bb85a226c4243556e"
     "696f6bd072c5aa2d9b69730244b56853d16970ad817e213e470618178001c9fb56c54fefa"
     "5fee67d2da524bb3b0b61ef0e9114a92cdbb6cccb98615cfe76e3510dd88d1cc28ff99287"
     "512f24bfafa1a76877b6f37198e3a641c68a7c42d45fa7acc10dae5f3cefb7b735f12d4e5"
     "89f7a456e78c0f5e4c4471fffa5e4fa0514ae974d8c2648513b5db494cea847156d277ad0"
     "e141c24c7839064cd08851bc2e7ca109fd4e251c35bb0a04fb05b364ff8c4d8b59bc303e2"
     "5328c09a882e952518e1a8ae0ff265d61c465896973d7490499dc639fb8502b39456791b1"
     "b6ec5bcc5d9ac36a6df622a070d43fed781f5f149f7b62675e7d1a4d6dec48c1c7164586e"
     "ae06a51208c0b791244d307726505c3ad4b26b6822377257aa152037560a739714a3ca79b"
     "d605547c9b78dd1f596f2d4f1791bc689a0e9b799a37339c04275733740143ef5d2b58b96"
     "a363d4e08076a1a9d7846436e4dca5728b6f760eef0ca92bf0be5615e96959d767197a0be"
     "eb"},

    // TurboSHAKE tests, from
    // https://www.rfc-editor.org/rfc/rfc9861.html#section-5, but extended with
    // more bytes.
    {turboshake128, "", 1,
     "1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c3e8ccae2a"
     "4dae56c84a04c2385c03c15e8193bdf58737363321691c05462c8dfdbdf137ce385dc5164"
     "0ac13897b9078b56b752345f19ee63011fb016abd57cf2a5ca9bf410aee71044042719e1c"
     "3ebea94c398909bd8ec9b443e62b0cc0fd7c6b79519f0c470ebd12a0a423e74e845baf888"
     "e5d635b534049fe87b2528159ac3b5b69ad78425efe13728a261f2a4be2d4ea83a3b8c3be"
     "12fed74555f2410f0d0aa56d0d63967f8e92c662a351386d6d42cd771f88e7b63b350ee50"
     "139980f278cba458e85e82948963c3979ea0a809e12b1b266d8f98b8eb3acf190e1f94bd5"
     "69832cce1e2516f477e26e3d51de3f93ae018693db399ff5792f407353add0c72abb1af7e"
     "160400522a9d2452477f384c46a6c199147266544fe66cb1669e52f6e31aa72fd9a86a671"
     "2a188e7c60da8ef0b8e5b2b1346731a2f28503c99ce5cfb374b451ff92a862458101ff970"
     "c8875ac5b036eb1374c685db404a234bc63148b34ba9bc614872b3835ac11723af11f8158"
     "b330b2ad5ea7d2936f0856e8beb5c76484063894e6bcff3c08bd22de965eea5e62c42c93a"
     "0cdeb749a3c7e7fba389d80ac91da65c7dd15860c43bcaf4b49f70d4adfa170e20a1a68c3"
     "72ef70e50b26525849b6d16358fd3f9e5dcafa4e06f6f402ad21afac154a1b5006e348930"
     "20"},
    {turboshake256, "", 1,
     "367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db11edc0e12"
     "e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db06c0618043e89afee80"
     "f552390fdd09f45c51953be5f0904ac669c6ab50b885c9f5717c743a7a78bf0b72ed4b9a7"
     "f51c7a0a06876f0d0526b68b8368ce563c770641b1a67b28d4f5942483a0ae3a996a45075"
     "741bd9d4ef0f254f13cc0c9818bd8205758c04ccd6ccefcd12d07bf2cddf38e8b575096e5"
     "d5f74117f29db7c70d842b49d9d812a1b7b29a26e303c5219c7fa16242111c924ec9d9948"
     "f8cc71152679e6b4b0ec59e7b203b4a771ce491a3c4bf567442fd2f1a1232110351675e56"
     "e3797fed8738abbef7f9a7ed3d161efa4b68b8362be0be43f58819e94712d1b2e26a7dbd7"
     "7a01443cd5c603b36045f5b969a56218251d6cafe7cd9987e70ccc664184837ff0b4bd284"
     "bee073bba98da65c83727fbea28dd57c5dd46ca5ccd431dcda802094e8b7e7c991eec1ea6"
     "e7ccf869405f41a960381fb2febe1ae6d39ee4692d99f9658cc2652e34bf39df5a2e6eb6b"
     "cbf5ea71369e8bf1feeed7b86c0ef171bbe0a9e2b4faf9a46b0c2ebd3c9a141983d4a5ecf"
     "58dac6a51c7dc2a8c852223604a99930f1be1b9d1fbc135342993fff098231531efc3f446"
     "e4d5ca960f3c8512203af1961f64de0a3d4b277d2d8e6f96719412625d3c13daee7cee499"
     "8f"},
};

void TestDigest(const DigestTestVector *test, std::string_view expected_hex,
                bool test_xof) {
  size_t md_size = expected_hex.size() / 2;
  auto final = [&](EVP_MD_CTX *ctx, uint8_t *out, unsigned *out_len) -> int {
    if (!test_xof) {
      return EVP_DigestFinal_ex(ctx, out, out_len);
    }
    if (!EVP_DigestFinalXOF(ctx, out, md_size)) {
      return 0;
    }
    *out_len = static_cast<unsigned>(md_size);
    return 1;
  };

  ScopedEVP_MD_CTX ctx;

  // Test the input provided.
  {
    auto digest = std::make_unique<uint8_t[]>(md_size);
    ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
    for (size_t i = 0; i < test->repeat; i++) {
      ASSERT_TRUE(
          EVP_DigestUpdate(ctx.get(), test->input, strlen(test->input)));
    }
    unsigned digest_len;
    ASSERT_TRUE(final(ctx.get(), digest.get(), &digest_len));
    EXPECT_EQ(expected_hex, EncodeHex(Span(digest.get(), digest_len)));
  }

  // Test the input one character at a time.
  {
    auto digest = std::make_unique<uint8_t[]>(md_size);
    ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
    ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), nullptr, 0));
    for (size_t i = 0; i < test->repeat; i++) {
      for (const char *p = test->input; *p; p++) {
        ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), p, 1));
      }
    }
    unsigned digest_len;
    ASSERT_TRUE(final(ctx.get(), digest.get(), &digest_len));
    EXPECT_EQ(md_size, digest_len);
    EXPECT_EQ(expected_hex, EncodeHex(Span(digest.get(), digest_len)));
  }

  if (test_xof) {
    // Squeeze the output one character at a time.
    auto digest = std::make_unique<uint8_t[]>(md_size);
    ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
    ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), nullptr, 0));
    for (size_t i = 0; i < test->repeat; i++) {
      ASSERT_TRUE(
          EVP_DigestUpdate(ctx.get(), test->input, strlen(test->input)));
    }
    for (size_t i = 0; i < md_size; i++) {
      ASSERT_TRUE(EVP_DigestSqueeze(ctx.get(), &digest[i], 1));
    }
    EXPECT_EQ(expected_hex, EncodeHex(Span(digest.get(), md_size)));
  }

  // Test with unaligned input.
  {
    auto digest = std::make_unique<uint8_t[]>(md_size);
    ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
    std::vector<char> unaligned(strlen(test->input) + 1);
    char *ptr = unaligned.data();
    if ((reinterpret_cast<uintptr_t>(ptr) & 1) == 0) {
      ptr++;
    }
    OPENSSL_memcpy(ptr, test->input, strlen(test->input));
    for (size_t i = 0; i < test->repeat; i++) {
      ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), ptr, strlen(test->input)));
    }
    unsigned digest_len;
    ASSERT_TRUE(final(ctx.get(), digest.get(), &digest_len));
    EXPECT_EQ(expected_hex, EncodeHex(Span(digest.get(), digest_len)));
  }

  // Make a copy of the digest in the initial state.
  {
    auto digest = std::make_unique<uint8_t[]>(md_size);
    ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
    ScopedEVP_MD_CTX copy;
    ASSERT_TRUE(EVP_MD_CTX_copy_ex(copy.get(), ctx.get()));
    for (size_t i = 0; i < test->repeat; i++) {
      ASSERT_TRUE(
          EVP_DigestUpdate(copy.get(), test->input, strlen(test->input)));
    }
    unsigned digest_len;
    ASSERT_TRUE(final(copy.get(), digest.get(), &digest_len));
    EXPECT_EQ(expected_hex, EncodeHex(Span(digest.get(), digest_len)));
  }

  // Make a copy of the digest with half the input provided.
  {
    auto digest = std::make_unique<uint8_t[]>(md_size);
    size_t half = strlen(test->input) / 2;
    ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), test->input, half));
    ScopedEVP_MD_CTX copy;
    ASSERT_TRUE(EVP_MD_CTX_copy_ex(copy.get(), ctx.get()));
    ASSERT_TRUE(EVP_DigestUpdate(copy.get(), test->input + half,
                                 strlen(test->input) - half));
    for (size_t i = 1; i < test->repeat; i++) {
      ASSERT_TRUE(
          EVP_DigestUpdate(copy.get(), test->input, strlen(test->input)));
    }
    unsigned digest_len;
    ASSERT_TRUE(final(copy.get(), digest.get(), &digest_len));
    EXPECT_EQ(expected_hex, EncodeHex(Span(digest.get(), digest_len)));
  }

  // Make a copy of the digest with half the output squeezed.
  if (test_xof) {
    auto digest = std::make_unique<uint8_t[]>(md_size);
    ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
    ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), nullptr, 0));
    for (size_t i = 0; i < test->repeat; i++) {
      ASSERT_TRUE(
          EVP_DigestUpdate(ctx.get(), test->input, strlen(test->input)));
    }
    size_t half_out = md_size / 2;
    ASSERT_TRUE(EVP_DigestSqueeze(ctx.get(), digest.get(), half_out));
    ScopedEVP_MD_CTX copy;
    ASSERT_TRUE(EVP_MD_CTX_copy_ex(copy.get(), ctx.get()));
    ASSERT_TRUE(EVP_DigestSqueeze(copy.get(), digest.get() + half_out,
                                  md_size - half_out));
    EXPECT_EQ(expected_hex, EncodeHex(Span(digest.get(), md_size)));
  }

  // Move the digest from the initial state.
  {
    auto digest = std::make_unique<uint8_t[]>(md_size);
    ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
    ScopedEVP_MD_CTX copy = std::move(ctx);
    for (size_t i = 0; i < test->repeat; i++) {
      ASSERT_TRUE(
          EVP_DigestUpdate(copy.get(), test->input, strlen(test->input)));
    }
    unsigned digest_len;
    ASSERT_TRUE(final(copy.get(), digest.get(), &digest_len));
    EXPECT_EQ(expected_hex, EncodeHex(Span(digest.get(), digest_len)));
  }

  // Move the digest with half the input provided.
  {
    auto digest = std::make_unique<uint8_t[]>(md_size);
    size_t half = strlen(test->input) / 2;
    ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
    ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), test->input, half));
    ScopedEVP_MD_CTX copy = std::move(ctx);
    ASSERT_TRUE(EVP_DigestUpdate(copy.get(), test->input + half,
                                 strlen(test->input) - half));
    for (size_t i = 1; i < test->repeat; i++) {
      ASSERT_TRUE(
          EVP_DigestUpdate(copy.get(), test->input, strlen(test->input)));
    }
    unsigned digest_len;
    ASSERT_TRUE(final(copy.get(), digest.get(), &digest_len));
    EXPECT_EQ(expected_hex, EncodeHex(Span(digest.get(), digest_len)));
  }

  // Move the digest with half the output squeezed.
  if (test_xof) {
    auto digest = std::make_unique<uint8_t[]>(md_size);
    ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
    ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), nullptr, 0));
    for (size_t i = 0; i < test->repeat; i++) {
      ASSERT_TRUE(
          EVP_DigestUpdate(ctx.get(), test->input, strlen(test->input)));
    }
    size_t half_out = md_size / 2;
    ASSERT_TRUE(EVP_DigestSqueeze(ctx.get(), digest.get(), half_out));
    ScopedEVP_MD_CTX copy = std::move(ctx);
    ASSERT_TRUE(EVP_DigestSqueeze(copy.get(), digest.get() + half_out,
                                  md_size - half_out));
    EXPECT_EQ(expected_hex, EncodeHex(Span(digest.get(), md_size)));
  }

  // Test the one-shot function.
  if (test->md.one_shot_func && test->repeat == 1 && !test_xof) {
    auto digest = std::make_unique<uint8_t[]>(md_size);
    uint8_t *out = test->md.one_shot_func((const uint8_t *)test->input,
                                          strlen(test->input), digest.get());
    // One-shot functions return their supplied buffers.
    EXPECT_EQ(digest.get(), out);
    EXPECT_EQ(expected_hex, EncodeHex(Span(digest.get(), md_size)));
  }
}

TEST(DigestTest, TestVectors) {
  for (size_t i = 0; i < std::size(kTestVectors); i++) {
    SCOPED_TRACE(i);
    const auto &t = kTestVectors[i];
    if (t.md.is_xof) {
      TestDigest(&t,
                 std::string_view(t.expected_hex)
                     .substr(0, 2 * EVP_MD_size(t.md.func())),
                 /*test_xof=*/false);
      TestDigest(&t, t.expected_hex, /*test_xof=*/true);
    } else {
      TestDigest(&t, t.expected_hex, /*test_xof=*/false);
    }
  }
}

TEST(DigestTest, Getters) {
  EXPECT_EQ(EVP_sha512(), EVP_get_digestbyname("RSA-SHA512"));
  EXPECT_EQ(EVP_sha512(), EVP_get_digestbyname("sha512WithRSAEncryption"));
  EXPECT_EQ(nullptr, EVP_get_digestbyname("nonsense"));
  EXPECT_EQ(EVP_sha512(), EVP_get_digestbyname("SHA512"));
  EXPECT_EQ(EVP_sha512(), EVP_get_digestbyname("sha512"));

  EXPECT_EQ(EVP_sha512(), EVP_get_digestbynid(NID_sha512));
  EXPECT_EQ(nullptr, EVP_get_digestbynid(NID_sha512WithRSAEncryption));
  EXPECT_EQ(nullptr, EVP_get_digestbynid(NID_undef));

  UniquePtr<ASN1_OBJECT> obj(OBJ_txt2obj("1.3.14.3.2.26", 0));
  ASSERT_TRUE(obj);
  EXPECT_EQ(EVP_sha1(), EVP_get_digestbyobj(obj.get()));
  EXPECT_EQ(EVP_md5_sha1(), EVP_get_digestbyobj(OBJ_nid2obj(NID_md5_sha1)));
  EXPECT_EQ(EVP_sha1(), EVP_get_digestbyobj(OBJ_nid2obj(NID_sha1)));
}

TEST(DigestTest, ASN1) {
  ScopedCBB cbb;
  ASSERT_TRUE(CBB_init(cbb.get(), 0));
  EXPECT_FALSE(EVP_marshal_digest_algorithm(cbb.get(), EVP_md5_sha1()));
  EXPECT_TRUE(ErrorsAreAndClear({{ERR_LIB_DIGEST, DIGEST_R_UNKNOWN_HASH}}));

  static const uint8_t kSHA256NullParam[] = {0x30, 0x0d, 0x06, 0x09, 0x60,
                                             0x86, 0x48, 0x01, 0x65, 0x03,
                                             0x04, 0x02, 0x01, 0x05, 0x00};
  static const uint8_t kSHA256NoParam[] = {0x30, 0x0b, 0x06, 0x09, 0x60,
                                           0x86, 0x48, 0x01, 0x65, 0x03,
                                           0x04, 0x02, 0x01};
  static const uint8_t kSHA256GarbageParam[] = {
      0x30, 0x0e, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
      0x65, 0x03, 0x04, 0x02, 0x01, 0x02, 0x01, 0x2a};

  // Serialize SHA-256, with and without NULL.
  cbb.Reset();
  ASSERT_TRUE(CBB_init(cbb.get(), 0));
  ASSERT_TRUE(EVP_marshal_digest_algorithm(cbb.get(), EVP_sha256()));
  EXPECT_EQ(Bytes(kSHA256NullParam),
            Bytes(CBB_data(cbb.get()), CBB_len(cbb.get())));
  cbb.Reset();
  ASSERT_TRUE(CBB_init(cbb.get(), 0));
  ASSERT_TRUE(EVP_marshal_digest_algorithm_no_params(cbb.get(), EVP_sha256()));
  EXPECT_EQ(Bytes(kSHA256NoParam),
            Bytes(CBB_data(cbb.get()), CBB_len(cbb.get())));

  // Parse SHA-256. Either absent or NULL parameters are tolerated for
  // compatibility.
  CBS cbs;
  CBS_init(&cbs, kSHA256NullParam, sizeof(kSHA256NullParam));
  EXPECT_EQ(EVP_sha256(), EVP_parse_digest_algorithm(&cbs));
  EXPECT_EQ(0u, CBS_len(&cbs));
  CBS_init(&cbs, kSHA256NoParam, sizeof(kSHA256NoParam));
  EXPECT_EQ(EVP_sha256(), EVP_parse_digest_algorithm(&cbs));
  EXPECT_EQ(0u, CBS_len(&cbs));

  // Garbage parameters are not.
  CBS_init(&cbs, kSHA256GarbageParam, sizeof(kSHA256GarbageParam));
  EXPECT_FALSE(EVP_parse_digest_algorithm(&cbs));
  EXPECT_TRUE(ErrorsAreAndClear({{ERR_LIB_DIGEST, DIGEST_R_DECODE_ERROR}}));
}

TEST(DigestTest, TransformBlocks) {
  uint8_t blocks[SHA256_CBLOCK * 10];
  for (size_t i = 0; i < sizeof(blocks); i++) {
    blocks[i] = i * 3;
  }

  SHA256_CTX ctx1;
  SHA256_Init(&ctx1);
  SHA256_Update(&ctx1, blocks, sizeof(blocks));

  SHA256_CTX ctx2;
  SHA256_Init(&ctx2);
  SHA256_TransformBlocks(ctx2.h, blocks, sizeof(blocks) / SHA256_CBLOCK);
  SHA256_TransformBlocks(ctx2.h, nullptr, 0);

  EXPECT_TRUE(0 == OPENSSL_memcmp(ctx1.h, ctx2.h, sizeof(ctx1.h)));
}

// |EVP_MD_CTX| is a caller-allocatable C struct. Some APIs are required to work
// when the struct is uninitialized.
TEST(DigestTest, Uninitialized) {
  // |EVP_MD_CTX_init| initializes its input from an arbitrary state.
  {
    EVP_MD_CTX ctx;
    EVP_MD_CTX_init(&ctx);
    EVP_DigestInit_ex(&ctx, EVP_sha256(), nullptr);
    EVP_MD_CTX_cleanup(&ctx);
  }

  // |EVP_DigestInit| internally calls |EVP_MD_CTX_init| and thus initializes it
  // from an arbitrary state.
  {
    EVP_MD_CTX ctx;
    EVP_DigestInit(&ctx, EVP_sha256());
    EVP_MD_CTX_cleanup(&ctx);
  }
}

TEST(DigestTest, NonXOF) {
  // Non-XOF digests should fail `EVP_DigestSqueeze`.
  ScopedEVP_MD_CTX ctx;
  ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr));
  uint8_t out[64];
  EXPECT_FALSE(EVP_DigestSqueeze(ctx.get(), out, sizeof(out)));
}

struct XOFTestVector {
  const char *name;
  const EVP_MD *(*md)();
  const std::string_view input_hex;
  const std::string_view expected_hex;
};

class XOFSqueeze : public testing::TestWithParam<XOFTestVector> {};

TEST_P(XOFSqueeze, Squeeze) {
  const auto &test = GetParam();

  ScopedEVP_MD_CTX ctx;
  std::vector<uint8_t> input;
  ASSERT_TRUE(DecodeHex(&input, test.input_hex));
  std::vector<uint8_t> expected;
  ASSERT_TRUE(DecodeHex(&expected, test.expected_hex));
  std::vector<uint8_t> out(expected.size());

  // One shot
  ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test.md(), nullptr));
  ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), input.data(), input.size()));
  ASSERT_TRUE(EVP_DigestSqueeze(ctx.get(), out.data(), out.size()));
  EXPECT_EQ(Bytes(out), Bytes(expected));

  // Absorb one at a time
  out.assign(expected.size(), 0);
  ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test.md(), nullptr));
  for (const auto &byte : input) {
    ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), &byte, 1));
  }
  ASSERT_TRUE(EVP_DigestSqueeze(ctx.get(), out.data(), out.size()));
  EXPECT_EQ(Bytes(out), Bytes(expected));

  // Squeeze one at a time
  out.assign(expected.size(), 0);
  ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test.md(), nullptr));
  ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), input.data(), input.size()));
  for (auto &byte : out) {
    ASSERT_TRUE(EVP_DigestSqueeze(ctx.get(), &byte, 1));
  }
  EXPECT_EQ(Bytes(out), Bytes(expected));
}

const XOFTestVector kSqueezeVectors[] = {
    {"SHAKE256_MSG", EVP_shake256,
     "e4baace59e93f0a59db1e7a9a3e6ba9de6be97e6ada3e8bc89e6a5b5e68192e6"
     "b2b3e6b299e998bfe583a7e7a587e982a3e794b1e4bb96e4b88de58fafe6809d"
     "e8adb0",
     "64feb2a33554eb5f27246625c20969bc2fb62e1f57b4a5426ea38ac9de186e96"
     "e28ec780c3869eca3f43d7d33d46d4582ff57a378733a0af272e7da58ec385c1"
     "93609d5a3a95d07819e3eb868b263321e248ff3bcc9bed506a1e8c507c8f953d"
     "acbe9911c261ab378dd08ccb6a9cee43fdd637a324dc37b8366fa692b9ea0e3e"
     "439bb85202c6b0141c6956604f5758ff3b1cd73977afe98c53d2352d987f2d48"
     "71e02afd919d39b72fba2bae479b8871b75a98c0bf8ec802f29ab88133a8379e"
     "3b8e4a70fd3bf5c4"},
    {"TURBOSHAKE256_MSG", EVP_turboshake256,
     "e58886e58e98e6af9be7b3b8e5bfbde5beaee7b98ae6b299e5a1b5e59f83e6b8"
     "bae6bca0e6a8a1e7b38ae980a1e5b7a1e9a088e887bee79eace681af",
     "3311577e7908dded934b818db25d18b578513e04199071f9b4f7b37761326fab"
     "15edbd103627c7cbcfbd32bba069488d7257f6c652831679ee050d6e0ad7807c"
     "cc746ccd6a3124696bd21d224d3cd588fb7c52637c5ae448a16eb156d5000482"
     "be97e26d6429e252f43e3f18fda98af2ad748f2814e7473b96e2bdc7252027be"
     "3310a49106e5eccedf9d08efc1172f25595a3624addd65c943cab15a5ab7059f"
     "929e6d7f8d3b938da5811ce385268c5a30f35d131fd96db6ab363cd681e1453b"
     "d237e182969d2376"}};
INSTANTIATE_TEST_SUITE_P(All, XOFSqueeze, testing::ValuesIn(kSqueezeVectors),
                         [](const testing::TestParamInfo<XOFTestVector> &v) {
                           return v.param.name;
                         });

}  // namespace
BSSL_NAMESPACE_END
