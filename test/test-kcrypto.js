"use strict";

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
    equal(kcrypto.mit_des_string_to_key("password", "ATHENA.MIT.EDUraeburn"),
          hexToBytes("cbc22fae235298e3"));
    equal(kcrypto.mit_des_string_to_key("potatoe", "WHITEHOUSE.GOVdanny"),
          hexToBytes("df3d32a74fd92a01"));
    // U+1D11E in UTF-16.
    equal(kcrypto.mit_des_string_to_key("\uD834\uDD1E", "EXAMPLE.COMpianist"),
          hexToBytes("4ffb26bab0cd9413"));
    equal(kcrypto.mit_des_string_to_key("\u00DF", "ATHENA.MIT.EDUJuri\u0161i\u0107"),
          hexToBytes("62c81a5232b5e69d"));
    equal(kcrypto.mit_des_string_to_key("11119999", "AAAAAAAA"),
          hexToBytes("984054d0f1a73e31"));
    equal(kcrypto.mit_des_string_to_key("NNNN6666", "FFFFAAAA"),
          hexToBytes("c4bf6b25adf7a4f8"));
});
