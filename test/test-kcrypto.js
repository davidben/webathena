"use strict";

module("kcrypto");

function hexDigit(h) {
    var c = h.toLowerCase().charCodeAt(0);
    if ('a'.charCodeAt(0) <= c && c <= 'f'.charCodeAt(0))
        return c - 'a'.charCodeAt(0) + 10;
    return c - '0'.charCodeAt(0);
}

function hexToBytes(h) {
    var ret = "";
    h = h.replace(/ /g, '');
    for (var i = 0; i < h.length; i += 2) {
        var byte = (hexDigit(h[i]) << 4) | hexDigit(h[i + 1]);
        ret += String.fromCharCode(byte);
    }
    return ret;
}

test("RFC 3961 n-fold test vectors", function() {
    equal(kcrypto.nFold(64, "012345"), hexToBytes("be072631276b1955"));
    equal(kcrypto.nFold(56, "password"), hexToBytes("78a07b6caf85fa"));
    equal(kcrypto.nFold(64, "Rough Consensus, and Running Code"),
          hexToBytes("bb6ed30870b7f0e0"));
    equal(kcrypto.nFold(168, "password"),
          hexToBytes("59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"));
    equal(kcrypto.nFold(192, "MASSACHVSETTS INSTITVTE OF TECHNOLOGY"),
          hexToBytes("db3b0d8f0b061e603282b308a50841229ad798fab9540c1b"));
    equal(kcrypto.nFold(168, "Q"),
          hexToBytes("518a54a2 15a8452a 518a54a2 15a8452a 518a54a2 15"))
    equal(kcrypto.nFold(168, "ba"),
          hexToBytes("fb25d531 ae897449 9f52fd92 ea9857c4 ba24cf29 7e"));
    equal(kcrypto.nFold(64, "kerberos"), hexToBytes("6b657262 65726f73"));
    equal(kcrypto.nFold(128, "kerberos"),
          hexToBytes("6b657262 65726f73 7b9b5b2b 93132b93"));
    equal(kcrypto.nFold(168, "kerberos"),
          hexToBytes("8372c236 344e5f15 50cd0747 e15d62ca 7a5a3bce a4"));
    equal(kcrypto.nFold(256, "kerberos"),
          hexToBytes("6b657262 65726f73 7b9b5b2b 93132b93" +
                     "5c9bdcda d95c9899 c4cae4de e6d6cae4"));
});

test("RFC 3961 mit_des_string_to_key test vectors", function() {
    var mit_des_string_to_key =
        kcrypto.DesCbcCrcProfile.stringToKey.bind(kcrypto.DesCbcCrcProfile);
    equal(mit_des_string_to_key("password", "ATHENA.MIT.EDUraeburn"),
          hexToBytes("cbc22fae235298e3"));
    equal(mit_des_string_to_key("potatoe", "WHITEHOUSE.GOVdanny"),
          hexToBytes("df3d32a74fd92a01"));
    // U+1D11E in UTF-16.
    equal(mit_des_string_to_key("\uD834\uDD1E", "EXAMPLE.COMpianist"),
          hexToBytes("4ffb26bab0cd9413"));
    equal(mit_des_string_to_key("\u00DF", "ATHENA.MIT.EDUJuri\u0161i\u0107"),
          hexToBytes("62c81a5232b5e69d"));
    equal(mit_des_string_to_key("11119999", "AAAAAAAA"),
          hexToBytes("984054d0f1a73e31"));
    equal(mit_des_string_to_key("NNNN6666", "FFFFAAAA"),
          hexToBytes("c4bf6b25adf7a4f8"));
});

test("RFC 3961 mod-crc-32 test vectors", function() {
    equal(kcrypto.Crc32Checksum.getMIC("", "foo"),
          hexToBytes("33 bc 32 73"));
    equal(kcrypto.Crc32Checksum.getMIC("", "test0123456789"),
          hexToBytes("d6 88 3e b8"));
    equal(kcrypto.Crc32Checksum.getMIC(
        "", "MASSACHVSETTS INSTITVTE OF TECHNOLOGY"),
          hexToBytes("f7 80 41 e3"));
    equal(kcrypto.Crc32Checksum.getMIC("", hexToBytes("8000")),
          hexToBytes("4b 98 83 3b"));
    equal(kcrypto.Crc32Checksum.getMIC("", hexToBytes("0008")),
          hexToBytes("32 88 db 0e"));
    equal(kcrypto.Crc32Checksum.getMIC("", hexToBytes("0080")),
          hexToBytes("20 83 b8 ed"));
    equal(kcrypto.Crc32Checksum.getMIC("", hexToBytes("80")),
          hexToBytes("20 83 b8 ed"));
    equal(kcrypto.Crc32Checksum.getMIC("", hexToBytes("80000000")),
          hexToBytes("3b b6 59 ed"));
    equal(kcrypto.Crc32Checksum.getMIC("", hexToBytes("00000001")),
          hexToBytes("96 30 07 77"));
});

test("RFC 3962 PBKDF2 test vectors", function() {
    function testStringToKey(password, salt, iters, expected128, expected256) {
        var param = String.fromCharCode(
            iters >> 24,
            (iters >> 16) & 0xff,
            (iters >> 8) & 0xff,
            iters & 0xff);
        equal(kcrypto.Aes128CtsHmacShaOne96.stringToKey(password, salt, param),
              hexToBytes(expected128));
        equal(kcrypto.Aes256CtsHmacShaOne96.stringToKey(password, salt, param),
              hexToBytes(expected256));
    }
    testStringToKey("password", "ATHENA.MIT.EDUraeburn", 1,
                    "42 26 3c 6e 89 f4 fc 28 b8 df 68 ee 09 79 9f 15",

                    "fe 69 7b 52 bc 0d 3c e1 44 32 ba 03 6a 92 e6 5b" +
                    "bb 52 28 09 90 a2 fa 27 88 39 98 d7 2a f3 01 61");

    testStringToKey("password", "ATHENA.MIT.EDUraeburn", 2,
                    "c6 51 bf 29 e2 30 0a c2 7f a4 69 d6 93 bd da 13",

                    "a2 e1 6d 16 b3 60 69 c1 35 d5 e9 d2 e2 5f 89 61" +
                    "02 68 56 18 b9 59 14 b4 67 c6 76 22 22 58 24 ff");

    testStringToKey("password", "ATHENA.MIT.EDUraeburn", 1200,
                    "4c 01 cd 46 d6 32 d0 1e 6d be 23 0a 01 ed 64 2a",

                    "55 a6 ac 74 0a d1 7b 48 46 94 10 51 e1 e8 b0 a7" +
                    "54 8d 93 b0 ab 30 a8 bc 3f f1 62 80 38 2b 8c 2a");

    // XXX: This test does pass, but we're actually expecting UTF-8
    // input... it just happens that all of these are in
    // ASCII. stringToKey really should take a byte array.
    testStringToKey("password", hexToBytes("1234567878563412"), 5,
                    "e9 b2 3d 52 27 37 47 dd 5c 35 cb 55 be 61 9d 8e",

                    "97 a4 e7 86 be 20 d8 1a 38 2d 5e bc 96 d5 90 9c" +
                    "ab cd ad c8 7c a4 8f 57 45 04 15 9f 16 c3 6e 31");

    testStringToKey(
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase equals block size", 1200,
        "59 d1 bb 78 9a 82 8b 1a a5 4e f9 c2 88 3f 69 ed",

        "89 ad ee 36 08 db 8b c7 1f 1b fb fe 45 94 86 b0" +
        "56 18 b7 0c ba e2 20 92 53 4e 56 c5 53 ba 4b 34");

    testStringToKey(
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase exceeds block size", 1200,
        "cb 80 05 dc 5f 90 17 9a 7f 02 10 4c 00 18 75 1d",

        "d7 8c 5c 9c b8 72 a8 c9 da d4 69 7f 0b b5 b2 d2" +
        "14 96 c8 2b eb 2c ae da 21 12 fc ee a0 57 40 1b");

    testStringToKey("\uD834\uDD1E", "EXAMPLE.COMpianist", 50,
                    "f1 49 c1 f2 e1 54 a7 34 52 d4 3e 7f e6 2a 56 e5",

                    "4b 6d 98 39 f8 44 06 df 1f 09 cc 16 6d b4 b8 3c" +
                    "57 18 48 b7 84 a3 d6 bd c3 46 58 9a 3e 39 3f 9e");
});

test("RFC 3962 AES-CBC-CTS test vectors", function() {
    function testCipher(key, iv, input, output, nextIv) {
        // Test both directions.
        var r = kcrypto.aesCtsEncrypt(key, iv, input);
        equal(r[0], nextIv);
        equal(r[1], output);
        var r = kcrypto.aesCtsDecrypt(key, iv, output);
        equal(r[0], nextIv);
        equal(r[1], input);
    }

    var key = hexToBytes("63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69");
    var zeros = hexToBytes("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

    testCipher(key, zeros,
               hexToBytes("49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65" +
                          "20"),
               hexToBytes("c6 35 35 68 f2 bf 8c b4 d8 a5 80 36 2d a7 ff 7f" +
                          "97"),
               hexToBytes("c6 35 35 68 f2 bf 8c b4 d8 a5 80 36 2d a7 ff 7f"));

    testCipher(key, zeros,
               hexToBytes("49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65" +
                          "20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20"),
               hexToBytes("fc 00 78 3e 0e fd b2 c1 d4 45 d4 c8 ef f7 ed 22" +
                          "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5"),
               hexToBytes("fc 00 78 3e 0e fd b2 c1 d4 45 d4 c8 ef f7 ed 22"));

    testCipher(key, zeros,
               hexToBytes("49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65" +
                          "20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43"),
               hexToBytes("39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8" +
                          "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84"),
               hexToBytes("39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8"));

    testCipher(key, zeros,
               hexToBytes("49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65" +
                          "20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43" +
                          "68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c"),
               hexToBytes("97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84" +
                          "b3 ff fd 94 0c 16 a1 8c 1b 55 49 d2 f8 38 02 9e" +
                          "39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5"),
               hexToBytes("b3 ff fd 94 0c 16 a1 8c 1b 55 49 d2 f8 38 02 9e"));

    testCipher(key, zeros,
               hexToBytes("49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65" +
                          "20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43" +
                          "68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c 20"),
               hexToBytes("97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84" +
                          "9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8" +
                          "39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8"),
               hexToBytes("9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8"));

    testCipher(key, zeros,
               hexToBytes("49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65" +
                          "20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43" +
                          "68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c 20" +
                          "61 6e 64 20 77 6f 6e 74 6f 6e 20 73 6f 75 70 2e"),
               hexToBytes("97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84" +
                          "39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8" +
                          "48 07 ef e8 36 ee 89 a5 26 73 0d bc 2f 7b c8 40" +
                          "9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8"),
               hexToBytes("48 07 ef e8 36 ee 89 a5 26 73 0d bc 2f 7b c8 40"));
});
