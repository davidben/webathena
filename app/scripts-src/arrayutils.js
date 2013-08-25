var arrayutils = (function() {
    "use strict";
    var arrayutils = { };

    /**
     * Wraps any ArrayBufferView as a Uint8Array. The ctor actually
     * makes a copy, and doesn't work on DataView.
     *
     * @param {ArrayBufferView}
     * @returns {Uint8Array}
     */
    arrayutils.asUint8Array = function(abv) {
        if (abv instanceof Uint8Array)
            return abv;
        return new Uint8Array(abv.buffer, abv.byteOffset, abv.byteLength);
    };

    /**
     * @param {string} bs
     * @returns {Uint8Array}
     */
    arrayutils.fromByteString = function(bs) {
        var ret = new Uint8Array(bs.length);
        for (var i = 0; i < bs.length; i++) {
            ret[i] = bs.charCodeAt(i);
        }
        return ret;
    };

    if (Uint8Array.prototype._getter) {
        /**
         * @param {ArrayBufferView} arr
         * @returns {string}
         */
        arrayutils.toByteString = function(arr) {
            // Apparently the polyfill and Function.prototype.apply on
            // old Android don't like each other. (Do we care? We
            // require SNI anyway. Meh.)
            arr = arrayutils.asUint8Array(arr);
            var ret = "";
            for (var i = 0; i < arr.length; i++) {
                ret += String.fromCharCode(arr._getter(i));
            }
            return ret;
        };
    } else {
        // Detect if we can Function#apply a Uint8Array. It seems
        // PhantomJS (sigh) can't deal.
        try {
            String.fromCharCode.apply(String, new Uint8Array([1,2,3]));

            /**
             * @param {ArrayBufferView} arr
             * @returns {string}
             */
            arrayutils.toByteString = function(arr) {
                return String.fromCharCode.apply(
                    String, arrayutils.asUint8Array(arr));
            };
        } catch (e) {
            /**
             * @param {ArrayBufferView} arr
             * @returns {string}
             */
            arrayutils.toByteString = function(arr) {
                arr = arrayutils.asUint8Array(arr);
                var ret = "";
                for (var i = 0; i < arr.length; i++) {
                    ret += String.fromCharCode(arr[i]);
                }
                return ret;
            };
        }
    }

    /**
     * Encodes as UTF-8.
     * @param {string} str
     * @returns {Uint8Array}
     */
    arrayutils.fromString = function(str) {
        // That this is the best way to convert UTF-16 to UTF-8 on the
        // web platform is ridiculous. We going to get TextEncoder
        // implemented any time soon?
        return arrayutils.fromByteString(unescape(encodeURIComponent(str)));
    };

    /**
     * Decodes from UTF-8.
     * @param {ArrayBufferView} arr
     * @returns {string}
     */
    arrayutils.toString = function(arr) {
        return decodeURIComponent(escape(arrayutils.toByteString(arr)));
    };

    /**
     * @param {string} str
     * @returns {Uint8Array}
     */
    arrayutils.fromBase64 = function(str) {
        return arrayutils.fromByteString(atob(str));
    };

    /**
     * @param {ArrayBufferView} arr
     * @returns {string}
     */
    arrayutils.toBase64 = function(arr) {
        return btoa(arrayutils.toByteString(arr));
    };


    /**
     * Adapted from sjcl.codec.utf8String.
     * @param {Array.<number>}
     * @returns {Uint8Array}
     */
    arrayutils.fromSJCL = function(arr) {
        var bl = sjcl.bitArray.bitLength(arr), i, tmp;
        var out = new Uint8Array(bl >>> 3);
        for (i=0; i<bl/8; i++) {
            if ((i&3) === 0) {
                tmp = arr[i/4];
            }
            out[i] = tmp >>> 24;
            tmp <<= 8;
        }
        return out;
    };

    /**
     * Adapted from sjcl.codec.utf8String.
     * @param {ArrayBufferView}
     * @returns {Array.<number>}
     */
    arrayutils.toSJCL = function(arr) {
        arr = arrayutils.asUint8Array(arr);
        var out = [], i, tmp=0;
        for (i=0; i<arr.length; i++) {
            tmp = tmp << 8 | arr[i];
            if ((i&3) === 3) {
                out.push(tmp);
                tmp = 0;
            }
        }
        if (i&3) {
            out.push(sjcl.bitArray.partial(8*(i&3), tmp));
        }
        return out;
    };

    /**
     * Adapted from CryptoJS.enc.Latin1.
     * @param {CryptoJS.lib.WordArray}
     * @returns {Uint8Array}
     */
    arrayutils.fromCryptoJS = function(wordArray) {
        // Shortcuts
        var words = wordArray.words;
        var sigBytes = wordArray.sigBytes;

        // Convert
        var out = new Uint8Array(sigBytes);
        for (var i = 0; i < sigBytes; i++) {
            var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            out[i] = bite;
        }

        return out;
    };

    /**
     * Adapted from CryptoJS.enc.Latin1.
     * @param {ArrayBufferView}
     * @returns {CryptoJS.lib.WordArray}
     */
    arrayutils.toCryptoJS = function(arr) {
        arr = arrayutils.asUint8Array(arr);
        // Shortcut
        var arrLength = arr.length;

        // Convert
        var words = [];
        for (var i = 0; i < arrLength; i++) {
            words[i >>> 2] |= arr[i] << (24 - (i % 4) * 8);
        }

        return new CryptoJS.lib.WordArray.init(words, arrLength);
    };

    /**
     * @param {ArrayBufferView}
     * @param {ArrayBufferView}
     * @returns {boolean}
     */
    arrayutils.equals = function(a, b) {
        a = arrayutils.asUint8Array(a);
        b = arrayutils.asUint8Array(b);
        if (a.length !== b.length)
            return false;
        for (var i = 0; i < a.length; i++) {
            if (a[i] !== b[i])
                return false;
        }
        return true;
    };

    return arrayutils;
})();
