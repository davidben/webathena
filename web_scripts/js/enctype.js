"use strict";

// 3.  Encryption Algorithm Profile
//
// An encryption profile includes the following methods:
// 
//  var encryptionProfile = {
//    checksum: <a checksum profile>,
//    keyGenerationSeedLength: <Number K>,
//    stringToKey: function (pass, salt, opaque) -> protocolKey,
//    randomToKey: function (bitstring[K) -> protocolKey,
//    deriveKey: function (protocolKey, Number) -> specificKey,
//    defaultStringToKeyParameters: <octet string>,
//    initialCipherState: function (specificKey, direction) -> state,
//    encrypt: function (specificKey, state, string) -> [state, string],
//    decrypt: function (specificKey, state, string) -> [state, string],
//    pseudoRandom: function (protocolKey, string) -> string
//  };
//
//  var checksumProfile = {
//    getMic: function (?) -> ?,
//    verifyMic: function (?) -> ?
//  };
//
// Stuff to deal with: these strings are UTF-8 strings and octet
// strings.

// 5.2.  Simplified Profile Parameters
//
//  var simplifiedProfile = {
//    stringToKey: function (pass, salt, opaque) -> protocolKey,
//    defaultStringToKeyParameters: <octet string>,
//    keyGenerationSeedLength: <Number K>,
//    randomToKey: function (bitstring[K) -> protocolKey,
//    unkeyedHash: function (?) -> ?,
//    hmacOutputSize: <Number h>,
//    messageBlockSize: <Number m>,
//    encrypt: function (?) -> ?,
//    decrypt: function (?) -> ?,
//    cipherBlockSize: <Number c>
//  };
//

// 8.  Assigned Numbers
krb.enctype = {};
krb.enctype.des_cbc_crc                     =  1;
krb.enctype.des_cbc_md4                     =  2;
krb.enctype.des_cbc_md5                     =  3;
krb.enctype.des3_cbc_md5                    =  5;
krb.enctype.des3_cbc_sha1                   =  7;
krb.enctype.dsaWithSHA1_CmsOID              =  9;
krb.enctype.md5WithRSAEncryption_CmsOID     = 10;
krb.enctype.sha1WithRSAEncryption_CmsOID    = 11;
krb.enctype.rc2CBC_EnvOID                   = 12;
krb.enctype.rsaEncryption_EnvOID            = 13;
krb.enctype.rsaES_OAEP_ENV_OID              = 14;
krb.enctype.des_ede3_cbc_Env_OID            = 15;
krb.enctype.des3_cbc_sha1_kd                = 16;
krb.enctype.aes128_cts_hmac_sha1_96         = 17;
krb.enctype.aes256_cts_hmac_sha1_96         = 18;
krb.enctype.rc4_hmac                        = 23;
krb.enctype.rc4_hmac_exp                    = 24;
krb.enctype.subkey_keymaterial              = 65;

krb.sumtype = {};
krb.sumtype.CRC32                         =  1;
krb.sumtype.rsa_md4                       =  2;
krb.sumtype.rsa_md4_des                   =  3;
krb.sumtype.des_mac                       =  4;
krb.sumtype.des_mac_k                     =  5;
krb.sumtype.rsa_md4_des_k                 =  6;
krb.sumtype.rsa_md5                       =  7;
krb.sumtype.rsa_md5_des                   =  8;
krb.sumtype.rsa_md5_des3                  =  9;
krb.sumtype.sha1                          = 10;
krb.sumtype.hmac_sha1_des3_kd             = 12;
krb.sumtype.hmac_sha1_des3                = 13;
krb.sumtype.sha1_2                        = 14;
krb.sumtype.hmac_sha1_96_aes128           = 15;
krb.sumtype.hmac_sha1_96_aes256           = 16;

// 6.1.3.  CRC-32 Checksum
krb.Crc32Checksum = {
    sumtype: krb.sumtype.CRC32,
    checksumBytes: 4,
    getMic: function (key, msg) {
        // The CRC-32 checksum used in the des-cbc-crc encryption mode
        // is identical to the 32-bit FCS described in ISO 3309 with
        // two exceptions: The sum with the all-ones polynomial times
        // x**k is omitted, and the final remainder is not
        // ones-complemented.

        // This seems to be correct. (It's also what pykrb5 does.)
        var checksum = crc32(msg, 0xffffffff) ^ 0xffffffff;
        // Get it into a string, little-endian.
        return String.fromCharCode(checksum & 0xff,
                                   (checksum >>> 8) & 0xff,
                                   (checksum >>> 16) & 0xff,
                                   (checksum >>> 24) & 0xff);
    },
    verifyMic: function (key, msg, token) {
        return token == this.getMic(key, msg);
    }
};

// 6.2.  DES-Based Encryption and Checksum Types
krb._7bitReverseTable = [
    0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120, 4, 68,
    36, 100, 20, 84, 52, 116, 12, 76, 44, 108, 28, 92, 60, 124, 2, 66, 34,
    98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122, 6, 70, 38, 102,
    22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126, 1, 65, 33, 97, 17,
    81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121, 5, 69, 37, 101, 21, 85,
    53, 117, 13, 77, 45, 109, 29, 93, 61, 125, 3, 67, 35, 99, 19, 83, 51,
    115, 11, 75, 43, 107, 27, 91, 59, 123, 7, 71, 39, 103, 23, 87, 55, 119,
    15, 79, 47, 111, 31, 95, 63, 127
];

krb._desParityBitTable = [
    1, 2, 4, 7, 8, 11, 13, 14, 16, 19, 
    21, 22, 25, 26, 28, 31, 32, 35, 37, 38, 
    41, 42, 44, 47, 49, 50, 52, 55, 56, 59, 
    61, 62, 64, 67, 69, 70, 73, 74, 76, 79, 
    81, 82, 84, 87, 88, 91, 93, 94, 97, 98, 
    100, 103, 104, 107, 109, 110, 112, 115, 117, 118, 
    121, 122, 124, 127, 128, 131, 133, 134, 137, 138, 
    140, 143, 145, 146, 148, 151, 152, 155, 157, 158, 
    161, 162, 164, 167, 168, 171, 173, 174, 176, 179, 
    181, 182, 185, 186, 188, 191, 193, 194, 196, 199, 
    200, 203, 205, 206, 208, 211, 213, 214, 217, 218, 
    220, 223, 224, 227, 229, 230, 233, 234, 236, 239, 
    241, 242, 244, 247, 248, 251, 253, 254, 
];

krb._desWeakKeys = {
    "0101010101010101": 1,
    "fefefefefefefefe": 1,
    "e0e0e0e0f1f1f1f1": 1,
    "1f1f1f1f0e0e0e0e": 1,
    "011f011f010e010e": 1,
    "1f011f010e010e01": 1,      
    "01e001e001f101f1": 1,
    "e001e001f101f101": 1,
    "01fe01fe01fe01fe": 1,
    "fe01fe01fe01fe01": 1,
    "1fe01fe00ef10ef1": 1,                                         
    "e01fe01ff10ef10e": 1,
    "1ffe1ffe0efe0efe": 1,
    "fe1ffe1ffe0efe0e": 1,
    "e0fee0fef1fef1fe": 1,
    "fee0fee0fef1fef1": 1
};

krb._mit_des_string_to_key = function (password, salt) {
    function removeMSBits(block) {
        // Clears the MSB of each octet. Now we have a 8 octets, but
        // the MSB of each is uninteresting.
        for (var i = 0; i < block.words.length; i++) {
            block.words[i] = block.words[i] & 0x7f7f7f7f;
        }
    }

    function reverse56Bits(block) {
        block.words.reverse();
        for (var i = 0; i < block.words.length; i++) {
            var word = block.words[i];
            // Just reverse bytes by lookup table.
            word = ((krb._7bitReverseTable[word & 0xff] << 24) |
                    (krb._7bitReverseTable[(word >>> 8) & 0xff] << 16) |
                    (krb._7bitReverseTable[(word >>> 16) & 0xff] << 8) |
                    (krb._7bitReverseTable[(word >>> 24) & 0xff]));
            block.words[i] = word;
        }
    }

    function add_parity_bits(block) {
        for (var i = 0; i < block.words.length; i++) {
            var word = block.words[i];
            word = ((krb._desParityBitTable[word & 0xff]) |
                    (krb._desParityBitTable[(word >>> 8) & 0xff] << 8) |
                    (krb._desParityBitTable[(word >>> 16) & 0xff] << 16) |
                    (krb._desParityBitTable[(word >>> 24) & 0xff] << 24));
            block.words[i] = word;
         }
    }

    function shift_bits(block) {
        for (var i = 0; i < block.words.length; i++) {
            var word = block.words[i];
            word = word >> 1;
            block.words[i] = word;
         }
    }

    function key_correction(block) {
        var hex = CryptoJS.enc.Hex.stringify(block);
        if (hex in krb._desWeakKeys) {
            block.words[1] = block.words[1] ^ 0xf0;
        }
    }

    // "parse" is a funny name. Apparently the input here is
    // JavaScript (UTF-16) string interpreted as UTF-8.
    var passwordUtf8 = CryptoJS.enc.Utf8.parse(password);
    var saltUtf8 = CryptoJS.enc.Utf8.parse(salt);

    var s = passwordUtf8.clone();
    s.concat(saltUtf8);

    // Pad NULs to 8-byte boundary.
    var remainder = 8 - (s.sigBytes % 8);
    if (remainder == 8) remainder = 0;
    if (remainder > 4) {
        s.concat(CryptoJS.lib.WordArray.create([0, 0], remainder));
    } else if (remainder > 0) {
        s.concat(CryptoJS.lib.WordArray.create([0], remainder));
    }

    var tempString = CryptoJS.lib.WordArray.create([0, 0]);

    // For each 8-byte-block in s...
    var odd = false;
    for (var i = 0; i < s.sigBytes; i += 8) {
        var word1 = s.words[i >> 2];
        var word2 = s.words[(i >> 2) + 1];
        var block = CryptoJS.lib.WordArray.create([word1, word2]);
        removeMSBits(block);
        if (odd) {
            reverse56Bits(block);
        }
        odd = !odd;

        // XOR block into tempString
        for (var j = 0; j < 2; j++) {
            tempString.words[j] = tempString.words[j] ^ block.words[j];
        }
    }
    add_parity_bits(tempString);
    key_correction(tempString);
    var enc = CryptoJS.DES.encrypt(s, tempString,
                                   { iv: tempString,
                                     padding: CryptoJS.pad.NoPadding });
    // We want the DES-CBC checksum, which is the last hunk of
    // ciphertext.
    var keyWord1 = enc.ciphertext.words[enc.ciphertext.words.length - 2];
    var keyWord2 = enc.ciphertext.words[enc.ciphertext.words.length - 1];
    // Remove the last bit and align for parity bits.
    var key = CryptoJS.lib.WordArray.create([(keyWord1 & 0xfefefefe) >>> 1,
                                             (keyWord2 & 0xfefefefe) >>> 1]);
    add_parity_bits(key);
    key_correction(key);
    // These guys get serialized to/from ASN.1, so we need to end with
    // strings.

    // TODO: Add functions to the encryption profile to convert
    // between a key's OCTET STRING form and the native one. This is a
    // little silly.
    return CryptoJS.enc.Latin1.stringify(key);
};

krb._des_string_to_key = function (password, salt, params) {
    if (params === undefined) params = "";

    var type;
    if (params.length == 0) {
        type = 0;
    } else if (params.length == 1) {
        type = params.charCodeAt(0);
    } else {
        throw "Invalid params";
    }

    if (type == 0) {
        return krb._mit_des_string_to_key(password, salt);
    } else {
        throw "Invalid params";
    }
};

krb._makeDesEncryptionProfile = function (checksum) {
    if (checksum.checksumBytes % 4 != 0)
        throw "Checksum not an integer number of words";
    var checksumWords = checksum.checksumBytes / 4;

    var profile = {};
    profile.stringToKey = krb._des_string_to_key;
    profile.deriveKey = function (key, usage) {
        return key;
    };
    // profile.initialCipherState varies.
    profile.checksum = checksum;
    profile.decrypt = function (key, state, data) {
        key = CryptoJS.enc.Latin1.parse(key);
        state = CryptoJS.enc.Latin1.parse(state);

        // data is a String where only the last byte matters.
        data = CryptoJS.enc.Latin1.parse(data);
        var cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: data
        });

        var decrypted = CryptoJS.DES.decrypt(
            cipherParams, key, { iv: state, padding: CryptoJS.pad.NoPadding });
        if (decrypted.sigBytes < 12)
            throw "Bad format";

        // First 2 words (8 bytes) are the confounder.

        // Next checksumWords words are a checksum.
        var checksum = CryptoJS.lib.WordArray.create(
            decrypted.words.slice(2, 2 + checksumWords));

        // Rest are the message (plus padding).
        var message = CryptoJS.lib.WordArray.create(
            decrypted.words.slice(2 + checksumWords),
            decrypted.sigBytes - 12);

        // Check the checksum.
        var checksumData = decrypted.clone();
        for (var i = 0; i < checksumWords; i++) {
            checksumData.words[2 + i] = 0;
        }
        if (!this.checksum.verifyMic(
            key, CryptoJS.enc.Latin1.stringify(checksumData),
            CryptoJS.enc.Latin1.stringify(checksum)))
            throw "Checksum mismatch!";

        // New cipher state is the last block of the ciphertext.
        state = CryptoJS.lib.WordArray.create(
            [data.words[data.words.length - 2],
             data.words[data.words.length - 1]]);
        return [
            CryptoJS.enc.Latin1.stringify(state),
            CryptoJS.enc.Latin1.stringify(message)
        ];
    };
    profile.encrypt = function (key, state, data) {
        key = CryptoJS.enc.Latin1.parse(key);
        state = CryptoJS.enc.Latin1.parse(state);

        // First, add a confounder and space for the checksum.
        var words = sjcl.random.randomWords(2);
        for (var i = 0; i < checksumWords; i++) {
            words.push(0);
        }

        var plaintext = CryptoJS.lib.WordArray.create(words);
        // Now the message. It's our usual String-as-byte-array.
        plaintext.concat(CryptoJS.enc.Latin1.parse(data));

        // Pad with random gunk to 8 octets.
        var remainder = 8 - (plaintext.sigBytes % 8);
        if (remainder == 8)
            remainder = 0;
        var remainderWords = remainder + 3;
        remainderWords -= (remainderWords % 4);
        remainderWords /= 4;
        plaintext.concat(CryptoJS.lib.WordArray.create(
            sjcl.random.randomWords(remainderWords),
            remainder));

        // Compute a checksum of the message, and stick it in the
        // plaintext.
        // FIXME: This converts between string and WordArray a
        // lot. Perhaps we should just standardize on the latter, much
        // of a pain as it is to use sometimes.
        var cksum = CryptoJS.enc.Latin1.parse(
            this.checksum.getMic(
                key, CryptoJS.enc.Latin1.stringify(plaintext)));
        for (var i = 0; i < checksumWords; i++) {
            plaintext.words[2 + i] = cksum.words[i];
        }

        // Finally, encrypt the checksummed plaintext.
        var encrypted = CryptoJS.DES.encrypt(
            plaintext, key, { iv: state, padding: CryptoJS.pad.NoPadding });

        // New cipher state is the last block of the ciphertext.
        state = CryptoJS.lib.WordArray.create(
            [encrypted.ciphertext[encrypted.ciphertext.words.length - 2],
             encrypted.ciphertext[encrypted.ciphertext.words.length - 1]]);
        return [
            CryptoJS.enc.Latin1.stringify(state),
            CryptoJS.enc.Latin1.stringify(encrypted.ciphertext)
        ];
    };
    return profile;
};

// 6.2.3.  DES with CRC
krb.DesCbcCrcProfile = krb._makeDesEncryptionProfile(krb.Crc32Checksum);
krb.DesCbcCrcProfile.enctype = krb.enctype.des_cbc_crc;
krb.DesCbcCrcProfile.initialCipherState = function (key, isEncrypt) {
    return key;
};

// The supported encryption types.
krb.encProfiles = { };
krb.encProfiles[krb.DesCbcCrcProfile.enctype] = krb.DesCbcCrcProfile;

krb.checksumProfiles = { };
krb.checksumProfiles[krb.Crc32Checksum.sumtype] = krb.Crc32Checksum;
