/**
 * @preserve Copyright (c) 2013 David Benjamin and Alan Huang
 * Use of this source code is governed by an MIT-style license that
 * can be found at
 * https://github.com/davidben/webathena
 */
// Only place in first file of each bundle.

function log(arg) {
    if (typeof console != "undefined" && console.log)
        console.log(arg);
}

if (!window.atob || !window.btoa) {
    (function() {
        // Bleh. At least there's no other need for this thing.
        var sjcl_byteString = {
            /** Convert from a bitArray to a byte string. */
            fromBits: function (arr) {
                var out = "", bl = sjcl.bitArray.bitLength(arr), i, tmp;
                for (i=0; i<bl/8; i++) {
                    if ((i&3) === 0) {
                        tmp = arr[i/4];
                    }
                    out += String.fromCharCode(tmp >>> 24);
                    tmp <<= 8;
                }
                return out;
            },

            /** Convert from a byte string to a bitArray. */
            toBits: function (str) {
                var out = [], i, tmp=0;
                for (i=0; i<str.length; i++) {
                    tmp = tmp << 8 | str.charCodeAt(i);
                    if ((i&3) === 3) {
                        out.push(tmp);
                        tmp = 0;
                    }
                }
                if (i&3) {
                    out.push(sjcl.bitArray.partial(8*(i&3), tmp));
                }
                return out;
            }
        };

        window.atob = function(a) {
            return sjcl_byteString.fromBits(sjcl.codec.base64.toBits(a));
        };
        window.btoa = function(b) {
            return sjcl.codec.base64.fromBits(sjcl_byteString.toBits(b));
        };
    })();
}

// Internet Explorer 10 has a broken Typed Array
// implementation. subarray doesn't work correctly when slicing a
// zero-length subarray at the end of the array. Monkey-patch in a
// working version, adapted from the typed array polyfill.
//
// It was reported back in November, but they seem to have WONTFIXed
// the bug.
// https://connect.microsoft.com/IE/feedback/details/771452/typed-array-subarray-issue
if (window.Uint8Array && new Uint8Array(1).subarray(1).byteLength !== 0) {
    (function() {
        var subarray = function(start, end) {
            function clamp(v, min, max) {
                return v < min ? min : v > max ? max : v;
            }

            start = start|0;
            end = end|0;

            if (arguments.length < 1) { start = 0; }
            if (arguments.length < 2) { end = this.length; }

            if (start < 0) { start = this.length + start; }
            if (end < 0) { end = this.length + end; }

            start = clamp(start, 0, this.length);
            end = clamp(end, 0, this.length);

            var len = end - start;
            if (len < 0) {
                len = 0;
            }

            return new this.constructor(
                this.buffer,
                this.byteOffset + start * this.BYTES_PER_ELEMENT,
                len);
        };
        var types = ['Int8Array', 'Uint8Array', 'Uint8ClampedArray',
                     'Int16Array', 'Uint16Array',
                     'Int32Array', 'Uint32Array',
                     'Float32Array', 'Float64Array'];
        for (var i = 0; i < types.length; i++) {
            if (window[types[i]])
                window[types[i]].prototype.subarray = subarray;
        }
    })();
}

if (!String.prototype.startsWith) {
  // We can use Object.defineProperty; typedarray.js polyfills that
  // in. (Ugh, so much random polyfilling.)
  Object.defineProperty(String.prototype, 'startsWith', {
    enumerable: false,
    configurable: false,
    writable: false,
    value: function (searchString, position) {
      position = position || 0;
      return this.substr(position, searchString.length) === searchString;
    }
  });
}
