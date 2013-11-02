var kcrypto = (function() {
    "use strict";

    var kcrypto = { };

    kcrypto.DecryptionError = function(message) {
        this.message = message;
    };
    kcrypto.DecryptionError.prototype.toString = function() {
        return "DecryptionError: " + this.message;
    };
    kcrypto.InvalidParameters = function(message) {
        this.message = message;
    };
    kcrypto.InvalidParameters.prototype.toString = function() {
        return "InvalidParameters: " + this.message;
    };

    /** @const */ kcrypto.DECRYPT = 0;
    /** @const */ kcrypto.ENCRYPT = 1;

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
    //    pseudoRandom: function (protocolKey, string) -> string,
    //    paddingBytes: function(number) -> number
    //  };
    //
    //  var checksumProfile = {
    //    getMIC: function (?) -> ?,
    //    verifyMIC: function (?) -> ?
    //  };
    //
    // Stuff to deal with: these strings are UTF-8 strings and octet
    // strings.

    // 5.2.  Simplified Profile Parameters
    //
    //  var simplifiedProfile = {
    //    stringToKey: function (pass, salt, opaque) -> protocolKey,
    //    defaultStringToKeyParam: <octet string>,
    //    keyGenerationSeedLength: <Number K>,
    //    randomToKey: function (bitstring[K] -> protocolKey,
    //    unkeyedHash: instance of sjcl.hash.something for now
    //    hmacOutputSize: <Number h>,
    //    messageBlockSize: <Number m>,
    //    encrypt: function (key, state, string) -> [state, string],
    //    decrypt: function (key, state, string) -> [state, string],
    //    cipherBlockSize: <Number c>
    //  };
    //
    // Each function is also passed the resulting profile as the last
    // argument since AES refers to things computed by the full
    // profile in terms of the simple profile. It's annoying.

    // 8.  Assigned Numbers
    kcrypto.enctype = {};
    /** @const */ kcrypto.enctype.des_cbc_crc                     =  1;
    /** @const */ kcrypto.enctype.des_cbc_md4                     =  2;
    /** @const */ kcrypto.enctype.des_cbc_md5                     =  3;
    /** @const */ kcrypto.enctype.des3_cbc_md5                    =  5;
    /** @const */ kcrypto.enctype.des3_cbc_sha1                   =  7;
    /** @const */ kcrypto.enctype.dsaWithSHA1_CmsOID              =  9;
    /** @const */ kcrypto.enctype.md5WithRSAEncryption_CmsOID     = 10;
    /** @const */ kcrypto.enctype.sha1WithRSAEncryption_CmsOID    = 11;
    /** @const */ kcrypto.enctype.rc2CBC_EnvOID                   = 12;
    /** @const */ kcrypto.enctype.rsaEncryption_EnvOID            = 13;
    /** @const */ kcrypto.enctype.rsaES_OAEP_ENV_OID              = 14;
    /** @const */ kcrypto.enctype.des_ede3_cbc_Env_OID            = 15;
    /** @const */ kcrypto.enctype.des3_cbc_sha1_kd                = 16;
    /** @const */ kcrypto.enctype.aes128_cts_hmac_sha1_96         = 17;
    /** @const */ kcrypto.enctype.aes256_cts_hmac_sha1_96         = 18;
    /** @const */ kcrypto.enctype.rc4_hmac                        = 23;
    /** @const */ kcrypto.enctype.rc4_hmac_exp                    = 24;
    /** @const */ kcrypto.enctype.subkey_keymaterial              = 65;

    kcrypto.sumtype = {};
    /** @const */ kcrypto.sumtype.CRC32                         =  1;
    /** @const */ kcrypto.sumtype.rsa_md4                       =  2;
    /** @const */ kcrypto.sumtype.rsa_md4_des                   =  3;
    /** @const */ kcrypto.sumtype.des_mac                       =  4;
    /** @const */ kcrypto.sumtype.des_mac_k                     =  5;
    /** @const */ kcrypto.sumtype.rsa_md4_des_k                 =  6;
    /** @const */ kcrypto.sumtype.rsa_md5                       =  7;
    /** @const */ kcrypto.sumtype.rsa_md5_des                   =  8;
    /** @const */ kcrypto.sumtype.rsa_md5_des3                  =  9;
    /** @const */ kcrypto.sumtype.sha1                          = 10;
    /** @const */ kcrypto.sumtype.hmac_sha1_des3_kd             = 12;
    /** @const */ kcrypto.sumtype.hmac_sha1_des3                = 13;
    /** @const */ kcrypto.sumtype.sha1_2                        = 14;
    /** @const */ kcrypto.sumtype.hmac_sha1_96_aes128           = 15;
    /** @const */ kcrypto.sumtype.hmac_sha1_96_aes256           = 16;

    // CBC-CTS encryption mode for SJCL. Adapted from sjcl.mode.cbc.
    function pad128(l) {
        l[l.length - 1] >>>= 0;
        while (l.length < 4)
            l.push(0);
    }
    function xor4(x,y) {
        return [x[0]^y[0],x[1]^y[1],x[2]^y[2],x[3]^y[3]];
    }
    var cbcCtsMode = {
        encrypt: function(prp, plaintext, iv, adata) {
            if (adata && adata.length) {
                throw new sjcl.exception.invalid("cbc can't authenticate data");
            }
            if (sjcl.bitArray.bitLength(iv) !== 128) {
                throw new sjcl.exception.invalid("cbc iv must be 128 bits");
            }
            var i,
            w = sjcl.bitArray,
            bl = w.bitLength(plaintext),
            output = [];

            /* CTS can't handle short plaintexts. Caller checks for this. */
            if (bl <= 128) {
                throw new sjcl.exception.invalid(
                    "plaintext must be more than 128 bits");
            }

            /* Encrypt all but the last two blocks as in CBC. */
            for (i=0; i+8 < plaintext.length; i+=4) {
                iv = prp.encrypt(xor4(iv, plaintext.slice(i,i+4)));
                output.splice(i,0,iv[0],iv[1],iv[2],iv[3]);
            }
            /* Encrypt the second-to-last block. */
            iv = prp.encrypt(xor4(iv, plaintext.slice(i,i+4)));
            /* Pad the last block with zeros. */
            var last = plaintext.slice(i+4, i+8);
            var lastLen = w.bitLength(last);
            pad128(last);
            /* Second-to-last cipher block is E(iv|last) */
            var lastc = prp.encrypt(xor4(iv, last));
            output.push(lastc[0], lastc[1], lastc[2], lastc[3]);
            /* Last cipher-block is iv truncated. */
            var ivTrunc = w.clamp(iv, lastLen);
            for (i = 0; i < ivTrunc.length; i++)
                output.push(ivTrunc[i]);
            return output;
        },
        decrypt: function(prp, ciphertext, iv, adata) {
            if (adata && adata.length) {
                throw new sjcl.exception.invalid("cbc can't authenticate data");
            }
            if (sjcl.bitArray.bitLength(iv) !== 128) {
                throw new sjcl.exception.invalid("cbc iv must be 128 bits");
            }
            var cl = sjcl.bitArray.bitLength(ciphertext);
            if (cl <= 128) {
                throw new sjcl.exception.corrupt(
                    "cbc-cts ciphertext must be at least two blocks");
            }
            var i,
            w = sjcl.bitArray,
            bi, bo,
            output = [];

            /* Decrypt all but the last two blocks. */
            for (i=0; i+8 < ciphertext.length; i+=4) {
                bi = ciphertext.slice(i,i+4);
                bo = xor4(iv,prp.decrypt(bi));
                output.splice(i,0,bo[0],bo[1],bo[2],bo[3]);
                iv = bi;
            }
            /* Decrypt the second to last block with IV 0. */
            var d = prp.decrypt(ciphertext.slice(i,i+4));
            /* Pad the last ciphertext block with zeros. */
            var c = ciphertext.slice(i+4, i+8);
            var cLength = w.bitLength(c);
            pad128(c);
            /* C xor D is Pn* | {Cn's truncated bits} */
            var x = xor4(c, d);
            var pn = w.clamp(x, cLength);
            /* Recover the original Cn. */
            var pnPad = pn.slice(0);
            pad128(pnPad);
            var cn = xor4(c, xor4(pnPad, x));
            /* Decrypt with iv to get Pn-1 */
            var pn1 = xor4(iv, prp.decrypt(cn));

            /* Assemble the output. */
            output.push(pn1[0], pn1[1], pn1[2], pn1[3]);
            for (i = 0; i < pn.length; i++)
                output.push(pn[i]);
            return output;
        }
    };

    function gcd(a, b) {
        var tmp;
        if (b < a) {
            tmp = a;
            a = b;
            b = tmp;
        }
        while (a != 0) {
            tmp = b % a;
            b = a;
            a = tmp;
        }
        return b;
    }
    // both parameters are always well-known constants, so n-fold
    // needn't be constant-time or anything. Really we could just
    // precompute all the n-folds we need.
    function onesComplementAdd(a, b) {
        if (sjcl.bitArray.bitLength(a) != sjcl.bitArray.bitLength(b))
            throw "Lengths must match";
        if (a.length == 0)
            return [];

        var lastPartial = sjcl.bitArray.getPartial(a[a.length - 1]);
        var word = 0;
        var ret = a.slice(0);
        word += (ret[ret.length - 1] >>> 0) + (b[ret.length - 1] >>> 0);
        ret[ret.length - 1] = sjcl.bitArray.partial(lastPartial, word >>> 0, 1);
        word = (word > 0x100000000) ? 1 : 0;
        for (var i = ret.length - 2; i >= 0; i--) {
            word += (ret[i] >>> 0) + (b[i] >>> 0);
            ret[i] = word >>> 0;
            word = (word >= 0x100000000) ? 1 : 0;
        }
        // Carry.
        if (word > 0) {
            word = (1 << (32 - lastPartial)) + (ret[ret.length - 1] >>> 0);
            ret[ret.length - 1] =
                sjcl.bitArray.partial(lastPartial, word >>> 0, 1);
            if (word >= 0x100000000) {
                for (var i = ret.length - 2; i >= 0; i--) {
                    word = 1 + (ret[i] >>> 0);
                    ret[i] = word >>> 0;
                    if (word < 0x100000000)
                        break;
                }
            }
        }
        return ret;
    }
    function nFold(n, input) {
        var inBits = arrayutils.toSJCL(input);
        var inLength = sjcl.bitArray.bitLength(inBits);
        var numCopies = n / gcd(n, inLength);
        var shift = 13 % inLength;

        var ret = arrayutils.toSJCL(new Uint8Array(n / 8));
        var chunk = []; var chunkLength = 0;
        var lastCopy = inBits;
        for (var i = 0; i < numCopies; i++) {
            // Append the chunk.
            chunk = sjcl.bitArray.concat(chunk, lastCopy);
            chunkLength += inLength;
            // Rotate the next one by 13 bits.
            lastCopy = sjcl.bitArray.concat(
                sjcl.bitArray.bitSlice(lastCopy, inLength - shift),
                sjcl.bitArray.bitSlice(lastCopy, 0, inLength - shift));
            // If we have a completed chunk, add and remove it.
            while (chunkLength >= n) {
                ret = onesComplementAdd(
                    ret, sjcl.bitArray.bitSlice(chunk, 0, n));
                chunk = sjcl.bitArray.bitSlice(chunk, n);
                chunkLength -= n;
            }
        }
        if (sjcl.bitArray.bitLength(chunk) != 0)
            throw "Bits left over!";
        return arrayutils.fromSJCL(ret);
    }
    kcrypto.nFold = nFold;

    // 5.3.  Cryptosystem Profile Based on Simple Profile
    function profilesFromSimpleProfile(simpleProfile) {
        if (simpleProfile.keyGenerationSeedLength % 8 != 0)
            throw "Bad simple profile";

        function truncatedHmac(hmac, msg) {
            // Round-tripping between Uint8Array and sjcl.bitArray is
            // a pain.
            var h1 = hmac.encrypt(arrayutils.toSJCL(msg));
            h1 = sjcl.bitArray.bitSlice(
                h1, 0, 8 * simpleProfile.hmacOutputSize);
            return arrayutils.fromSJCL(h1);
        }

        var enc = { };
        enc.enctype = simpleProfile.enctype;
        var initialCipherState = new Uint8Array(simpleProfile.cipherBlockSize);
        enc.initialCipherState = function() {
            return initialCipherState;
        };
        enc.keyGenerationSeedLength = simpleProfile.keyGenerationSeedLength;
        enc.randomToKey = function(random) {
            return simpleProfile.randomToKey(random);
        };
        enc.stringToKey = function(pass, salt, param) {
            return simpleProfile.stringToKey(pass, salt, param, this);
        };
        enc.encrypt = function(derivedKey, iv, plaintext) {
            plaintext = arrayutils.asUint8Array(plaintext);
            // conf = Random string of length c
            var conf = arrayutils.fromSJCL(
                sjcl.bitArray.clamp(
                    sjcl.random.randomWords(
                        Math.ceil(simpleProfile.cipherBlockSize / 4)),
                    simpleProfile.cipherBlockSize * 8));
            // pad = Shortest string to bring confounder and plaintext
            // to a length that's a multiple of m.
            var padLength = (simpleProfile.cipherBlockSize + plaintext.length) %
                simpleProfile.messageBlockSize;
            padLength = simpleProfile.messageBlockSize - padLength;
            if (padLength == simpleProfile.messageBlockSize)
                padLength = 0;
            // (C1, newIV) = E(Ke, conf | plaintext | pad, oldstate.ivec)
            var data = new Uint8Array(
                conf.length + plaintext.length + padLength);
            data.set(conf);
            data.set(plaintext, conf.length);
            // pad is already zero'd
            var t = simpleProfile.encrypt(derivedKey.E, iv, data, this);
            var newIV = t[0], c1 = t[1];
            // H1 = HMAC(Ki, conf | plaintext | pad)
            var h1 = truncatedHmac(derivedKey.I, data);
            // ciphertext =  C1 | H1[1..h]
            var ciphertext = new Uint8Array(c1.length + h1.length);
            ciphertext.set(c1); ciphertext.set(h1, c1.length);
            // newstate.ivec = newIV
            return [newIV, ciphertext];
        };
        enc.decrypt = function(derivedKey, iv, ciphertext) {
            ciphertext = arrayutils.asUint8Array(ciphertext);
            // (C1,H1) = ciphertext
            var c1 = ciphertext.subarray(
                0, ciphertext.length - simpleProfile.hmacOutputSize);
            var h1 = ciphertext.subarray(
                ciphertext.length - simpleProfile.hmacOutputSize);
            // (P1, newIV) = D(Ke, C1, oldstate.ivec)
            var t = simpleProfile.decrypt(derivedKey.E, iv, c1, this);
            var newIV = t[0], p1 = t[1];
            // if (H1 != HMAC(Ki, P1)[1..h]) report error
            if (!arrayutils.equals(h1, truncatedHmac(derivedKey.I, p1)))
                throw new kcrypto.DecryptionError('Checksum mismatch!');
            // Strip off confounder.
            p1 = p1.subarray(simpleProfile.cipherBlockSize);
            return [newIV, p1];
        };
        enc.DK = function(key, constant) {
            // If the Constant is smaller than the cipher block size
            // of E, then it must be expanded with n-fold() so it can
            // be encrypted.
            // FIXME: smaller? What about equal?
            if (constant.length < simpleProfile.cipherBlockSize) {
                constant = nFold(simpleProfile.cipherBlockSize * 8, constant);
            }
            var truncateLength = simpleProfile.keyGenerationSeedLength / 8;
            var DR = new Uint8Array(truncateLength);
            var len = 0;
            var state = constant;
            // If the output of E is shorter than k bits, it is fed
            // back into the encryption as many times as necessary.
            while (len < truncateLength) {
                state = simpleProfile.encrypt(
                    key, initialCipherState, state)[1];
                DR.set(state.subarray(0, Math.min(state.byteLength,
                                                  truncateLength - len)),
                       len);
                len += state.byteLength;
            }
            return this.randomToKey(DR);
        };
        enc.deriveKey = function(key, usage) {
            // The "well-known constant" used for the DK function is
            // the key usage number, expressed as four octets in
            // big-endian order, followed by one octet indicated
            // below.
            var constant = new Uint8Array(5);
            new DataView(constant.buffer).setUint32(0, usage);
            // Kc = DK(base-key, usage | 0x99);
            constant[4] = 0x99;
            var Kc = this.DK(key, constant);
            // Ke = DK(base-key, usage | 0xAA);
            constant[4] = 0xAA;
            var Ke = this.DK(key, constant);
            // Ki = DK(base-key, usage | 0x55);
            constant[4] = 0x55;
            var Ki = this.DK(key, constant);
            return {
                C: new sjcl.misc.hmac(arrayutils.toSJCL(Kc),
                                      simpleProfile.unkeyedHash),
                // FIXME: Cache the profile-specific key object
                // here. AES does a fair amount of precomputation. Not
                // quite as easy as putting it in randomToKey as
                // that's called to make an HMAC key too.
                E: Ke,
                I: new sjcl.misc.hmac(arrayutils.toSJCL(Ki),
                                      simpleProfile.unkeyedHash)
            };
        };
        enc.paddingBytes = function(len) {
            len %= simpleProfile.messageBlockSize;
            if (len != 0)
                return simpleProfile.messageBlockSize - len;
            return 0;
        };

        var checksum = { };
        checksum.sumtype = simpleProfile.sumtype;
        checksum.checksumBytes = simpleProfile.hmacOutputSize;
        checksum.getMIC = function(key, msg) {
            return truncatedHmac(key.C, msg);
        };
        checksum.verifyMIC = function(key, msg, token) {
            return arrayutils.equals(token, this.getMIC(key, msg));
        };

        enc.checksum = checksum;

        return [enc, checksum];
    }

    // RFC 3962  Advanced Encryption Standard (AES) Encryption for Kerberos 5
    function aesStringToKey(pass, salt, param, profile) {
        if (param == undefined) param = new Uint8Array([0x00,0x00,0x10,0x00]);
        if (param.length != 4)
            throw new kcrypto.InvalidParameters("Bad string-to-key parameter");
        // Parameter is iteration count.
        var iterCount = new DataView(param.buffer,
                                     param.byteOffset,
                                     param.byteLength).getUint32(0);
        if (iterCount == 0)
            iterCount = 4294967296;
        // Pass SHA-1 instead of SHA-256 into hmac constructor.
        function sha1Hmac(pass) {
            sjcl.misc.hmac.call(this, pass, sjcl.hash.sha1);
        }
        sha1Hmac.prototype = sjcl.misc.hmac.prototype;
        var tkey = this.randomToKey(
            arrayutils.fromSJCL(
                sjcl.misc.pbkdf2(
                    sjcl.codec.utf8String.toBits(pass),
                    arrayutils.toSJCL(salt),
                    iterCount, this.keyGenerationSeedLength, sha1Hmac)));
        return profile.DK(tkey, arrayutils.fromByteString("kerberos"));
    }
    function aesCtsEncrypt(key, state, plaintext) {
        var aes = new sjcl.cipher.aes(arrayutils.toSJCL(key));
        var stateBits = arrayutils.toSJCL(state);
        var plaintextBits = arrayutils.toSJCL(plaintext);
        if (plaintextBits.length <= 4) {
            // Can't do CBC-CTS. Just pad arbitrarily and encrypt
            // plain. Apparently you don't even xor the iv.
            pad128(plaintextBits);
            var output = arrayutils.fromSJCL(aes.encrypt(plaintextBits));
            return [output, output];
        } else {
            var outputBits = cbcCtsMode.encrypt(aes, plaintextBits, stateBits);
            // State is second-to-last chunk.
            var outLength = outputBits.length;
            if (outLength % 4 != 0)
                outLength += 4 - (outLength % 4);
            var newState = outputBits.slice(outLength - 8, outLength - 4);
            return [
                arrayutils.fromSJCL(newState),
                arrayutils.fromSJCL(outputBits)
            ];
        }
    }
    kcrypto.aesCtsEncrypt = aesCtsEncrypt;  // Exported for tests.
    function aesCtsDecrypt(key, state, ciphertext) {
        var aes = new sjcl.cipher.aes(arrayutils.toSJCL(key));
        var stateBits = arrayutils.toSJCL(state);
        var ciphertextBits = arrayutils.toSJCL(ciphertext);
        if (ciphertextBits.length <= 4) {
            if (sjcl.bitArray.bitLength(ciphertextBits) != 128)
                throw new kcrypto.DecryptionError("Bad length");
            try {
                return [
                    ciphertext,
                    arrayutils.fromSJCL(aes.decrypt(ciphertextBits))
                ];
            } catch (e) {
                if (e instanceof sjcl.exception.corrupt)
                    throw new kcrypto.DecryptionError(e.message);
                throw e;
            }
        } else {
            var output = cbcCtsMode.decrypt(aes, ciphertextBits, stateBits);
            // State is second-to-last chunk.
            var outLength = ciphertextBits.length;
            if (outLength % 4 != 0)
                outLength += 4 - (outLength % 4);
            var newState = ciphertextBits.slice(outLength - 8, outLength - 4);
            return [
                arrayutils.fromSJCL(newState),
                arrayutils.fromSJCL(output)
            ];
        }
    }
    kcrypto.aesCtsDecrypt = aesCtsDecrypt;  // Exported for tests.
    function aesRandomToKey(x) {
        // Just copy.
        return new Uint8Array(arrayutils.asUint8Array(x));
    }
    var aes128 = profilesFromSimpleProfile({
        enctype: kcrypto.enctype.aes128_cts_hmac_sha1_96,
        sumtype: kcrypto.sumtype.hmac_sha1_96_aes128,
        stringToKey: aesStringToKey,
        keyGenerationSeedLength: 128,
        randomToKey: aesRandomToKey,
        unkeyedHash: sjcl.hash.sha1,
        hmacOutputSize: 12,
        messageBlockSize: 1,
        encrypt: aesCtsEncrypt,
        decrypt: aesCtsDecrypt,
        cipherBlockSize: 16
    });
    kcrypto.Aes128CtsHmacShaOne96 = aes128[0];
    kcrypto.ShaOne96Aes128Checksum = aes128[1];

    var aes256 = profilesFromSimpleProfile({
        enctype: kcrypto.enctype.aes256_cts_hmac_sha1_96,
        sumtype: kcrypto.sumtype.hmac_sha1_96_aes256,
        stringToKey: aesStringToKey,
        keyGenerationSeedLength: 256,
        randomToKey: aesRandomToKey,
        unkeyedHash: sjcl.hash.sha1,
        hmacOutputSize: 12,
        messageBlockSize: 1,
        encrypt: aesCtsEncrypt,
        decrypt: aesCtsDecrypt,
        cipherBlockSize: 16
    });
    kcrypto.Aes256CtsHmacShaOne96 = aes256[0];
    kcrypto.ShaOne96Aes256Checksum = aes256[1];

    // The supported encryption types.
    kcrypto.encProfiles = { };
    kcrypto.encProfiles[kcrypto.Aes128CtsHmacShaOne96.enctype] =
        kcrypto.Aes128CtsHmacShaOne96;
    kcrypto.encProfiles[kcrypto.Aes256CtsHmacShaOne96.enctype] =
        kcrypto.Aes256CtsHmacShaOne96;

    kcrypto.sumProfiles = { };
    kcrypto.sumProfiles[kcrypto.ShaOne96Aes128Checksum.sumtype] =
        kcrypto.ShaOne96Aes128Checksum;
    kcrypto.sumProfiles[kcrypto.ShaOne96Aes256Checksum.sumtype] =
        kcrypto.ShaOne96Aes256Checksum;

    return kcrypto;
}());
