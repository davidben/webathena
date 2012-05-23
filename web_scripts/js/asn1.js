/**
 * @fileOverview An implementation of the subset ASN.1 and DER
 * encoding needed for Keberos.
 * @author davidben@mit.edu (David Benjamin)
 */

/** @namespace Functionality related to ASN.1 */
var asn1 = { };

/**
 * Creates a substring object, so we can do the Java thing with cheap
 * substrings.
 *
 * @param {String|asn1.SubString} str The string to substring
 * @param {Number} start The character index to start taking characters
 *     from.
 * @param {Number} length The number of characters to take.
 * @class 
 */
asn1.SubString = function (str, start, length) {
    if (start === undefined) start = 0;
    if (length === undefined) length = str.length;

    start = Math.min(start, str.length);
    length = Math.min(length, str.length - start);

    if (str instanceof asn1.SubString) {
        start += str.start;
        str = str.str;
    }
    this.str = str;
    this.start = start;
    this.length = length;
};

/**
 * Returns a character code from the substring. Returns NaN if out of
 * bounds.
 *
 * @param {Number} i The character to return
 * @return {Number} a character code.
 */
asn1.SubString.prototype.charCodeAt = function (i) {
    if (i < 0 || i >= this.length)
        return NaN;  // Apparently this is what String does.
    return this.str.charCodeAt(i + this.start);
};

/**
 * Returns a substring.
 *
 * @param {Number} start The character index to start taking characters
 *     from.
 * @param {Number} length The number of characters to take.
 * @return {asn1.SubString} a substring.
 */
asn1.SubString.prototype.substr = function (start, length) {
    return new asn1.SubString(this, start, length);
};

asn1.SubString.prototype.toString = function () {
    return this.str.substr(this.start, this.length);
};


/** @const */ asn1.TAG_UNIVERSAL   = 0x0 << 6;
/** @const */ asn1.TAG_APPLICATION = 0x1 << 6;
/** @const */ asn1.TAG_CONTEXT     = 0x2 << 6;
/** @const */ asn1.TAG_PRIVATE     = 0x3 << 6;

/** @const */ asn1.TAG_PRIMITIVE   = 0x0 << 5;
/** @const */ asn1.TAG_CONSTRUCTED = 0x1 << 5;

/**
 * Returns an ASN.1 tag.
 *
 * @param {Number} number The number of the tag.
 * @param {Number} pc TAG_PRIMITIVE or TAG_CONSTRUCTED. Defaults to
 *     TAG_CONSTRUCTED.
 * @param {Number} cls The class of the tag. Defaults to
 *     TAG_CONTEXT.
 * @return {Number} A tag number representing the tag.
 */
asn1.tag = function (number, pc, cls) {
    if (pc === undefined)
        pc = asn1.TAG_CONSTRUCTED;
    if (cls === undefined)
        cls = asn1.TAG_CONTEXT;
    // We'll implement this if we ever have to deal with it.
    if (number >= 31)
        throw "High-tag-number form not implemented!";
    return (cls | pc | number);
};


/**
 * DER-encodes an ASN.1 tag.
 *
 * @param {Number} tag The tag to encode.
 * @return {String} The DER-encoded tag.
 */
asn1.encodeTagDER = function (tag) {
    return String.fromCharCode(tag);
};

/**
 * Encodes a length in a DER TLV tuple.
 *
 * @param {Number} length The length to encode.
 * @return {String} The DER-encoded length.
 */
asn1.encodeLengthDER = function (length) {
    if (length <= 127) {
        // Short form must be used when possible.
        return String.fromCharCode(length);
    }
    // First, encode in base 256.
    var ret = "";
    while (length > 0) {
        ret = String.fromCharCode(length & 0xff) + ret;
        length = length >> 8;
    }
    // Prepend the number of bytes used.
    ret = String.fromCharCode(ret.length | 0x80) + ret;
    return ret;
};

/**
 * Decodes an ASN.1 TLV tuple.
 *
 * @param {String|asn1.SubString} data The data to decode.
 * @return {Array} A tuple [tag, value, rest] containing the tag as a
 *    Number, the value as an asn1.SubString, and the unread data as
 *    an asn1.SubString.
 */
asn1.decodeTagLengthValueDER = function (data) {
    var off = 0;

    // First octet describes the tag.
    var tagOctet = data.charCodeAt(off);
    var tagNumber = tagOctet & 0x1f;
    var tagPc = tagOctet & (0x1 << 5);
    var tagCls = tagOctet & (0x3 << 6);
    if (tagNumber == 0x1f)
        throw "High-tag-number form not implemented!";
    var tag = asn1.tag(tagNumber, tagPc, tagCls);
    off++;

    // Now decode the length.
    var lengthOctet = data.charCodeAt(off);
    var length = 0;
    off++;
    if ((lengthOctet & 0x80) == 0) {
        // Yay, short form.
        length = lengthOctet;
    } else if (lengthOctet == 0x80) {
        // You're not supposed to use this in DER anyway.
        throw "Indefinite-length method unsupported!";
    } else {
        // Long form. Mask off top bit to charCodeAt number of octets in
        // length expressed in base 256, big-endian.
        var numOctets = lengthOctet & 0x7f;
        for (var i = 0; i < numOctets; i++, off++) {
            length *= 256;
            length += data.charCodeAt(off);
        }
    }

    // And return everything.
    if (off + length > data.length)
        throw "Length too large!";
    return [tag, data.substr(off, length), data.substr(off + length)];
}


/**
 * Base class for all ASN.1 types. Types are supposed to provide
 * encodeDERValue and decodeDERValue implementations.
 *
 * @param {Number} tag The tag of this type.
 * @class
 */
asn1.Type = function (tag) {
    if (tag !== undefined)
        this.tag = tag;
};

/**
 * DER-encodes an object according to this type.
 *
 * @param {Object} object The object to encode.
 * @return {String} The encoding of the object.
 */
asn1.Type.prototype.encodeDER = function (object) {
    var value = this.encodeDERValue(object);

    var out = []
    out.push(asn1.encodeTagDER(this.tag));
    out.push(asn1.encodeLengthDER(value.length));
    out.push(value);
    return out.join("");
};

/**
 * Decodes DER-encoded data according to this type. Throws an
 * exception if the entire data isn't read.
 *
 * @param {String|asn1.SubString} data The data to decode.
 * @return {Object} The decoded object.
 */
asn1.Type.prototype.decodeDER = function (data) {
    var objRest = this.decodeDERPrefix(data);
    if (objRest[1].length != 0)
        throw "Excess data!";
    return objRest[0];
};

/**
 * Decodes DER-encoded data according to this type.
 *
 * @param {String|asn1.SubString} data The data to decode.
 * @return {Array} A tuple of the decoded object and the unread data.
 */
asn1.Type.prototype.decodeDERPrefix = function (data) {
    var tvr = asn1.decodeTagLengthValueDER(data);
    if (tvr[0] != this.tag)
        throw "Tag mismatch!";
    return [this.decodeDERValue(tvr[1]), tvr[2]];
};

/**
 * Creates an explicitly-tagged version of this type.
 *
 * @param {Number} tag The value to tag with.
 * @return {asn1.ExplicitlyTagged} An explicitly tagged version of
 *     this.
 */
asn1.Type.prototype.tagged = function (tag) {
    return new asn1.ExplicitlyTagged(tag, this);
};

/**
 * Creates an constrained version of this type.
 *
 * @param {Function} checkValue A function which those an exception if
 *     a value is invalid.
 * @return {asn1.Type} An constrained version of this.
 */
asn1.Type.prototype.constrained = function (checkValue) {
    function TempCtor() {
    }
    TempCtor.prototype = this;
    var newType = new TempCtor();
    var self = this;

    newType.encodeDERValue = function (object) {
        checkValue.call(this, object);
        return self.encodeDERValue(object);
    }
    newType.decodeDERValue = function (data) {
        var object = self.decodeDERValue(data);
        checkValue.call(this, object);
        return object;
    }
    return newType;
};


/**
 * An explicitly-tagged type.
 *
 * @param {Number} tag The tag of this type.
 * @param {asn1.Type} baseType The type to tag.
 * @class
 */
asn1.ExplicitlyTagged = function (tag, baseType) {
    this.tag = tag;
    this.baseType = baseType;
};
asn1.ExplicitlyTagged.prototype = new asn1.Type();

asn1.ExplicitlyTagged.prototype.encodeDERValue = function (object) {
    return this.baseType.encodeDER(object);
};

asn1.ExplicitlyTagged.prototype.decodeDERValue = function (data) {
    return this.baseType.decodeDER(data);
};


/**
 * An implicitly-tagged type.
 *
 * @param {Number} tag The tag of this type.
 * @param {asn1.Type} baseType The type to tag.
 * @class
 */
asn1.ImplicitlyTagged = function (tag, baseType) {
    this.tag = tag;
    this.baseType = baseType;
};
asn1.ImplicitlyTagged.prototype = new asn1.Type();

asn1.ImplicitlyTagged.prototype.encodeDERValue = function (object) {
    return this.baseType.encodeDERValue(object);
};

asn1.ImplicitlyTagged.prototype.decodeDERValue = function (data) {
    return this.baseType.decodeDERValue(data);
};


/** ASN.1 INTEGER type. */
asn1.INTEGER = new asn1.Type(
    asn1.tag(0x02, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.INTEGER.encodeDERValue = function (object) {
    var ret = [];
    var sign = 0;
    // Encode in two's-complement, base 256, most sigificant bit
    // first, with the minimum number of bytes needed.
    while ((object >= 0 && (sign != 1 || object > 0)) ||
           (object <= -1 && (sign != -1 || object < -1))) {
        var digit = object & 0xff;
        ret.push(String.fromCharCode(digit));
        sign = (digit & 0x80) ? -1 : 1;
        object = object >> 8;
    }
    ret.reverse();
    return ret.join('');
};

asn1.INTEGER.decodeDERValue = function (data) {
    var ret = data.charCodeAt(i);
    if (ret > 127)
        ret = ret - 256;
    for (var i = 1; i < data.length; i++) {
        ret *= 256;
        ret += data.charCodeAt(i);
    }
    return ret;
};

asn1.INTEGER.valueConstrained = function () {
    var allowed = [];
    for (var i = 0; i < arguments.length; i++) {
        allowed.push(arguments[i]);
    }

    return this.constrained(function (v) {
        if (allowed.indexOf(v) == -1)
            throw "Invalid value: " + v;
    });
}

asn1.INTEGER.rangeConstrained = function (lo, hi) {
    return this.constrained(function (v) {
        if (v < lo || v > hi)
            throw "Invalid value: " + v;
    });
}


/**
 * ASN.1 BIT STRING type. We'll represent it as an Array of 0s and 1s,
 * though a bitmask works fine for Kerberos.
 */
asn1.BIT_STRING = new asn1.Type(
    asn1.tag(0x03, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.BIT_STRING.encodeDERValue = function (object) {
    var remainder = 8 - (object.length % 8);
    if (remainder == 8) remainder = 0;

    var ret = [];
    ret.push(String.fromCharCode(remainder));
    for (var i = 0; i < object.length; i += 8) {
        var octet = 0;
        // Bit zero ends up in the high-order bit of the first octet.
        for (var j = 0; j < 8; j++) {
            octet |= (object[i + j] || 0) << (7-j);
        }
        ret.push(String.fromCharCode(octet));
    }
    return ret.join("");
};

asn1.BIT_STRING.decodeDERValue = function (data) {
    var remainder = data.charCodeAt(0);
    var ret = [];
    for (var i = 1; i < data.length; i++) {
        var octet = data.charCodeAt(i);
        for (var j = 7; j >= 0; j--) {
            ret.push((octet & (1 << j)) ? 1 : 0);
        }
    }
    // Chop off the extra bits.
    for (var i = 0; i < remainder; i++)
        ret.pop();
    return ret;
};


/** ASN.1 OCTET STRING type. */
asn1.OCTET_STRING = new asn1.Type(
    asn1.tag(0x04, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.OCTET_STRING.encodeDERValue = function (object) {
    return String(object);
};

asn1.OCTET_STRING.decodeDERValue = function (data) {
    return String(data);
};


/** ASN.1 NULL type. */
asn1.NULL = new asn1.Type(
    asn1.tag(0x05, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.NULL.encodeDERValue = function (object) {
    if (object !== null)
        throw "Bad value";
    return "";
};

asn1.NULL.decodeDERValue = function (data) {
    if (data.length > 0)
        throw "Bad encoding";
    return null;
};


/** ASN.1 GeneralString type. */
asn1.GeneralString = new asn1.Type(
    asn1.tag(0x1b, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.GeneralString.encodeDERValue = function (object) {
    // TODO: Is this correct? Do we need to check anything? Not that
    // it matters a whole lot since KerberosString is limited to
    // IA5String's characters for compatibility.
    return String(object);
};

asn1.GeneralString.decodeDERValue = function (data) {
    return String(data);
};


/** ASN.1 GeneralizedTime type. */
asn1.GeneralizedTime = new asn1.Type(
    asn1.tag(0x18, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.GeneralizedTime.encodeDERValue = function (object) {
    // Date.toISOString exists, but we have to be more careful about
    // stripping off trailing zeros on the fractional part in
    // DER. (Not that KerberosTime supports fractional seconds
    // anyway...)

    function pad(number, len) {
        if (len == undefined) len = 2;
        var r = String(number);
        while (r.length < len) {
            r = '0' + r;
        }
        return r;
    }
    var ret = (object.getUTCFullYear() + '-'
               + pad(object.getUTCMonth() + 1) + '-'
               + pad(object.getUTCDate()) + 'T'
               + pad(object.getUTCHours()) + ':'
               + pad(object.getUTCMinutes()) + ':'
               + pad(object.getUTCSeconds()));
    if (object.getUTCMilliseconds() != 0) {
        var ms = pad(object.getUTCMilliseconds(), 3);
        while (ms[ms.length - 1] == '0') {
            ms = ms.substr(0, ms.length - 1);
        }
        ret += "." + ms;
    }
    ret += "Z";
    return ret;
};

asn1.GeneralizedTime.decodeDERValue = function (data) {
    // The Internet claims new Date(iso8601Str) isn't implemented
    // everywhere?
    var re = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.(\d{1,3}))?Z$/;
    var match = String(data).match(re);
    if (!match)
        throw "Bad date format";
    var date = new Date(Number(match[1]),
                        Number(match[2]) - 1,
                        Number(match[3]),
                        Number(match[4]),
                        Number(match[5]),
                        Number(match[6]));
    console.log(match);
    if (match[8]) {
        var ms = match[8];
        while (ms.length < 3)
            ms = ms + "0";
        date.setMilliseconds(Number(ms));
    }
    return date;
};


/**
 * ASN.1 SEQUENCE OF type.
 *
 * @param {asn1.Type} componentType The type we are sequencing.
 * @class
 */
asn1.SEQUENCE_OF = function (componentType) {
    this.tag = asn1.tag(0x10, asn1.TAG_CONSTRUCTED, asn1.TAG_UNIVERSAL);
    this.componentType = componentType;
};
asn1.SEQUENCE_OF.prototype = new asn1.Type();

asn1.SEQUENCE_OF.prototype.encodeDERValue = function (object) {
    var out = [];
    for (var i = 0; i < object.length; i++) {
        out.push(this.componentType.encodeDER(object[i]));
    }
    return out.join("");
};

asn1.SEQUENCE_OF.prototype.decodeDERValue = function (data) {
    var off = 0;
    var ret = [];
    while (data.length) {
        var objRest = this.componentType.decodeDERPrefix(data);
        ret.push(objRest[0]);
        data = objRest[1];
    }
    return ret;
};
