/**
 * An implementation of the subset ASN.1 and DER encoding needed for
 * Kerberos.
 * @author davidben@mit.edu (David Benjamin)
 */

"use strict";

/** @namespace Functionality related to ASN.1 */
var asn1 = { };

/** @const */ asn1.TAG_UNIVERSAL   = 0x0 << 6;
/** @const */ asn1.TAG_APPLICATION = 0x1 << 6;
/** @const */ asn1.TAG_CONTEXT     = 0x2 << 6;
/** @const */ asn1.TAG_PRIVATE     = 0x3 << 6;

/** @const */ asn1.TAG_PRIMITIVE   = 0x0 << 5;
/** @const */ asn1.TAG_CONSTRUCTED = 0x1 << 5;

/** @constructor */
asn1.Error = function(message) {
    this.message = message;
};
asn1.Error.prototype.toString = function() {
    return "ASN.1 error: " + this.message;
};

/**
 * Returns an ASN.1 tag.
 *
 * @param {number} number The number of the tag.
 * @param {number} pc TAG_PRIMITIVE or TAG_CONSTRUCTED. Defaults to
 *     TAG_CONSTRUCTED.
 * @param {number} cls The class of the tag. Defaults to
 *     TAG_CONTEXT.
 * @return {number} A tag number representing the tag.
 */
asn1.tag = function (number, pc, cls) {
    if (pc === undefined)
        pc = asn1.TAG_CONSTRUCTED;
    if (cls === undefined)
        cls = asn1.TAG_CONTEXT;
    // We'll implement this if we ever have to deal with it.
    if (number >= 31)
        throw new asn1.Error("High-tag-number form not implemented!");
    return (cls | pc | number);
};


/**
 * DER-encodes an ASN.1 tag.
 *
 * @param {number} tag The tag to encode.
 * @return {string} The DER-encoded tag.
 */
asn1.encodeTagDER = function (tag) {
    return String.fromCharCode(tag);
};

/**
 * Encodes a length in a DER TLV tuple.
 *
 * @param {number} length The length to encode.
 * @return {string} The DER-encoded length.
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
 * @param {string} data The data to decode.
 * @return {Array} A tuple [tag, value, rest] containing the tag as a
 *    Number, the value as a String, and the unread data as a String.
 */
asn1.decodeTagLengthValueDER = function (data) {
    var off = 0;

    // First octet describes the tag.
    var tagOctet = data.charCodeAt(off);
    var tagNumber = tagOctet & 0x1f;
    var tagPc = tagOctet & (0x1 << 5);
    var tagCls = tagOctet & (0x3 << 6);
    if (tagNumber == 0x1f)
        throw new asn1.Error("High-tag-number form not implemented!");
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
        throw new asn1.Error("Indefinite-length method unsupported!");
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
        throw new asn1.Error("Length too large!");
    return [tag, data.substr(off, length), data.substr(off + length)];
}


/**
 * Base class for all ASN.1 types. Types are supposed to provide
 * encodeDERValue and decodeDERValue implementations.
 *
 * @param {number} tag The tag of this type.
 * @constructor
 */
asn1.Type = function (tag) {
    this.tag = tag;
};

/**
 * DER-encodes an object according to this type.
 *
 * @param {Object} object The object to encode.
 * @return {string} The encoding of the object.
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
 * @param {string} data The data to decode.
 * @return {Object} The decoded object.
 */
asn1.Type.prototype.decodeDER = function (data) {
    var objRest = this.decodeDERPrefix(data);
    var obj = objRest[0], rest = objRest[1];
    if (rest.length != 0)
        throw new asn1.Error("Excess data!");
    return obj;
};

/**
 * Decodes DER-encoded data according to this type.
 *
 * @param {string} data The data to decode.
 * @return {Array} A tuple of the decoded object and the unread data.
 */
asn1.Type.prototype.decodeDERPrefix = function (data) {
    var tvr = asn1.decodeTagLengthValueDER(data);
    var tag = tvr[0], value = tvr[1], rest = tvr[2];
    if (tag != this.tag)
        throw new asn1.Error("Tag mismatch!");
    return [this.decodeDERValue(value), rest];
};

/**
 * Creates an explicitly-tagged version of this type.
 *
 * @param {number} tag The value to tag with.
 * @return {asn1.ExplicitlyTagged} An explicitly tagged version of
 *     this.
 */
asn1.Type.prototype.tagged = function (tag) {
    return new asn1.ExplicitlyTagged(tag, this);
};

/**
 * Creates an implicitly-tagged version of this type.
 *
 * @param {number} tag The value to tag with.
 * @return {asn1.ImplicitlyTagged} An implicitly tagged version of
 *     this.
 */
asn1.Type.prototype.implicitlyTagged = function (tag) {
    return new asn1.ImplicitlyTagged(tag, this);
};

/**
 * Creates an constrained version of this type.
 *
 * @param {Function} checkValue A function which those an exception if
 *     a value is invalid.
 * @return {asn1.Type} An constrained version of this.
 */
asn1.Type.prototype.constrained = function (checkValue) {
    var newType = this.subtype();
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
 * Creates a new version of this type.
 *
 * @return {asn1.Type} A subtype of this type.
 */
asn1.Type.prototype.subtype = function () {
    return Object.create(this);
};


/**
 * An explicitly-tagged type.
 *
 * @param {number} tag The tag of this type.
 * @param {asn1.Type} baseType The type to tag.
 * @constructor
 */
asn1.ExplicitlyTagged = function (tag, baseType) {
    this.tag = tag;
    this.baseType = baseType;
};
asn1.ExplicitlyTagged.prototype = Object.create(asn1.Type.prototype);

asn1.ExplicitlyTagged.prototype.encodeDERValue = function (object) {
    return this.baseType.encodeDER(object);
};

asn1.ExplicitlyTagged.prototype.decodeDERValue = function (data) {
    return this.baseType.decodeDER(data);
};


/**
 * An implicitly-tagged type.
 *
 * @param {number} tag The tag of this type.
 * @param {asn1.Type} baseType The type to tag.
 * @constructor
 */
asn1.ImplicitlyTagged = function (tag, baseType) {
    this.tag = tag;
    this.baseType = baseType;
};
asn1.ImplicitlyTagged.prototype = Object.create(asn1.Type.prototype);

asn1.ImplicitlyTagged.prototype.encodeDERValue = function (object) {
    return this.baseType.encodeDERValue(object);
};

asn1.ImplicitlyTagged.prototype.decodeDERValue = function (data) {
    return this.baseType.decodeDERValue(data);
};


/** ASN.1 BOOLEAN type. */
asn1.BOOLEAN = new asn1.Type(
    asn1.tag(0x01, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.BOOLEAN.encodeDERValue = function(object) {
    if (typeof object != "boolean")
        throw new TypeError("boolean");
    return object ? "\xFF" : "\x00";
}

asn1.BOOLEAN.decodeDERValue = function(data) {
    return data !== "\x00";
}


/** ASN.1 INTEGER type. */
asn1.INTEGER = new asn1.Type(
    asn1.tag(0x02, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.INTEGER.encodeDERValue = function (object) {
    var ret = [];
    var sign = 0;
    if (typeof object != "number")
        throw new TypeError("Not a number");
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
    var ret = data.charCodeAt(0);
    if (ret > 127)
        ret = ret - 256;
    for (var i = 1; i < data.length; i++) {
        ret *= 256;
        ret += data.charCodeAt(i);
    }
    return ret;
};

/**
 * @this {asn1.Type}
 * @return {asn1.Type}
 */
asn1.INTEGER.valueConstrained = function () {
    var allowed = [];
    for (var i = 0; i < arguments.length; i++) {
        allowed.push(arguments[i]);
    }

    return this.constrained(function (v) {
        if (allowed.indexOf(v) == -1)
            throw new RangeError("Invalid value: " + v);
    });
};

/**
 * @this {asn1.Type}
 * @return {asn1.Type}
 */
asn1.INTEGER.rangeConstrained = function (lo, hi) {
    return this.constrained(function (v) {
        if (v < lo || v > hi)
            throw new RangeError("Invalid value: " + v);
    });
};


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
    return ret.slice(0, ret.length - remainder);
};


/** ASN.1 OCTET STRING type. */
asn1.OCTET_STRING = new asn1.Type(
    asn1.tag(0x04, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.OCTET_STRING.encodeDERValue = function (object) {
    if (typeof object != "string")
        throw new TypeError("Not a string");
    return object;
};

asn1.OCTET_STRING.decodeDERValue = function (data) {
    return String(data);
};


/** ASN.1 NULL type. */
asn1.NULL = new asn1.Type(
    asn1.tag(0x05, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.NULL.encodeDERValue = function (object) {
    if (object !== null)
        throw new TypeError("Bad value");
    return "";
};

asn1.NULL.decodeDERValue = function (data) {
    if (data.length > 0)
        throw new asn1.Error("Bad encoding");
    return null;
};


/** ASN.1 OBJECT IDENTIFIER type. For sanity, just make the JS
 * representation a string. We can do something more complex if
 * there's a need. */
asn1.OBJECT_IDENTIFIER = new asn1.Type(
    asn1.tag(0x06, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.OBJECT_IDENTIFIER.encodeDERValue = function(object) {
    if (typeof object !== "string")
        throw new TypeError("Not a string");
    var components = object.split(".");
    if (components.length < 2) // ??
        throw new TypeError("Too few components");
    // The first subidentifier is special.
    var subidentifiers = [40 * Number(components[0]) + Number(components[1])];
    for (var i = 2; i < components.length; i++) {
        subidentifiers.push(Number(components[i]));
    }
    var ret = [];
    // Subidentifiers are encoded big-endian. Encode the whole thing
    // in reverse and flip at the end.
    for (var i = subidentifiers.length - 1; i >= 0; i--) {
        // Base 128, big endian. All but last octet has MSB 1.
        var c = subidentifiers[i];
        ret.push(String.fromCharCode(c & 0x7f));
        c >>>= 7;
        while (c > 0) {
            ret.push(String.fromCharCode((c & 0x7f) | 0x80));
            c >>>= 7;
        }
    }
    ret.reverse();
    return ret.join("");
};

asn1.OBJECT_IDENTIFIER.decodeDERValue = function(data) {
    var c = 0;
    var subidentifiers = [];
    for (var i = 0; i < data.length; i++) {
        var octet = data.charCodeAt(i);
        c *= 128;
        c += (octet & 0x7f);
        if (!(octet & 0x80)) {
            // MSB 0 means new component.
            subidentifiers.push(c);
            c = 0;
        }
    }

    if (subidentifiers.length === 0)
        throw new asn1.Error("Bad format");

    var oid = [];
    // First two components are special.
    var value1 = Math.min((subidentifiers[0] / 40) >>> 0, 2);
    var oid = [value1, subidentifiers[0] - (40 * value1)];
    oid = oid.concat(subidentifiers.slice(1));

    return oid.join(".");
};


/** ASN.1 GeneralString type. */
asn1.GeneralString = new asn1.Type(
    asn1.tag(0x1b, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.GeneralString.encodeDERValue = function (object) {
    // TODO: Is this correct? Do we need to check anything? Not that
    // it matters a whole lot since KerberosString is limited to
    // IA5String's characters for compatibility.
    if (typeof object != "string")
        throw new TypeError("Not a string");
    return object;
};

asn1.GeneralString.decodeDERValue = function (data) {
    return String(data);
};


/** ASN.1 GeneralizedTime type. */
asn1.GeneralizedTime = new asn1.Type(
    asn1.tag(0x18, asn1.TAG_PRIMITIVE, asn1.TAG_UNIVERSAL));

asn1.GeneralizedTime.encodeDERValue = function (object) {
    function pad(number, len) {
        if (len == undefined) len = 2;
        var r = String(number);
        while (r.length < len) {
            r = '0' + r;
        }
        return r;
    }
    var ret = (object.getUTCFullYear()
               + pad(object.getUTCMonth() + 1)
               + pad(object.getUTCDate())
               + pad(object.getUTCHours())
               + pad(object.getUTCMinutes())
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
    var re = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.(\d{1,3}))?Z$/;
    var match = String(data).match(re);
    if (!match)
        throw new Error("Bad date format");
    var date = new Date(Date.UTC(Number(match[1]),
                                 Number(match[2]) - 1,
                                 Number(match[3]),
                                 Number(match[4]),
                                 Number(match[5]),
                                 Number(match[6])));
    if (match[8]) {
        var ms = match[8];
        while (ms.length < 3)
            ms = ms + "0";
        date.setUTCMilliseconds(Number(ms));
    }
    return date;
};


/**
 * ASN.1 SEQUENCE OF type.
 *
 * @param {asn1.Type} componentType The type we are sequencing.
 * @constructor
 */
asn1.SEQUENCE_OF = function (componentType) {
    this.tag = asn1.tag(0x10, asn1.TAG_CONSTRUCTED, asn1.TAG_UNIVERSAL);
    this.componentType = componentType;
};
asn1.SEQUENCE_OF.prototype = Object.create(asn1.Type.prototype);

asn1.SEQUENCE_OF.prototype.encodeDERValue = function (object) {
    var out = [];
    for (var i = 0; i < object.length; i++) {
        out.push(this.componentType.encodeDER(object[i]));
    }
    return out.join("");
};

asn1.SEQUENCE_OF.prototype.decodeDERValue = function (data) {
    var ret = [];
    while (data.length) {
        var objRest = this.componentType.decodeDERPrefix(data);
        ret.push(objRest[0]);
        data = objRest[1];
    }
    return ret;
};


/**
 * ASN.1 SEQUENCE type.
 *
 * Takes in a compontentSpec of the form:
 * [ { 'id': 'patimestamp',
 *     'type': krb.KerberosTime.tagged(asn1.tag(0)) },
 *   { 'id': 'pausec',
 *     'type': krb.Microseconds.tagged(asn1.tag(1)),
 *     'optional': true } ]
 *
 * This deviates from the proper ASN.1 sequence somewhat in that the
 * JavaScript representation of a SEQUENCE is Object, not Array. All
 * components are required to have unique identifiers. This is mostly
 * for API convenience.
 *
 * Optional types are supported. Defaults are not for now.
 *
 * @param {Object} componentSpec A specification of the sequence's
 *     components, as described above.
 * @constructor
 */
asn1.SEQUENCE = function (componentSpec) {
    this.tag = asn1.tag(0x10, asn1.TAG_CONSTRUCTED, asn1.TAG_UNIVERSAL);
    this.componentSpec = componentSpec;
};
asn1.SEQUENCE.prototype = Object.create(asn1.Type.prototype);

asn1.SEQUENCE.prototype.encodeDERValue = function (object) {
    var out = [];
    for (var i = 0; i < this.componentSpec.length; i++) {
        var id = this.componentSpec[i].id;
        if (id in object) {
            out.push(this.componentSpec[i].type.encodeDER(object[id]));
        } else if (!this.componentSpec[i].optional) {
            throw new TypeError("Field " + id + " missing!");
        }
    }
    return out.join("");
};

asn1.SEQUENCE.prototype.decodeDERValue = function (data) {
    var ret = {};
    var nextSpec = 0;
    while (data.length) {
        // Peek ahead at the tag.
        var tvr = asn1.decodeTagLengthValueDER(data);
        var tag = tvr[0], value = tvr[1], rest = tvr[2];

        // See which field this corresponds to.
        while (nextSpec < this.componentSpec.length &&
               this.componentSpec[nextSpec].type.tag != tag) {
            // Skip this one, if we can.
            if (!this.componentSpec[nextSpec].optional)
                throw new asn1.Error("Missing required field " +
                                     this.componentSpec[nextSpec].id);
            nextSpec++;
        }
        if (nextSpec >= this.componentSpec.length)
            throw new asn1.Error("Unexpected tag " + tag);

        // Tag matches. Go use this one.
        ret[this.componentSpec[nextSpec].id] =
            this.componentSpec[nextSpec].type.decodeDERValue(value);
        data = rest;
        nextSpec++;
    }

    // Make sure we didn't miss any non-optional fields.
    while (nextSpec < this.componentSpec.length) {
        if (!this.componentSpec[nextSpec].optional)
            throw new asn1.Error("Missing required field " +
                                 this.componentSpec[nextSpec].id);
        nextSpec++;
    }

    return ret;
};


/**
 * ASN.1 CHOICE type. This is going to be a little funny. It exists
 * only so that we can do things like distinguish between AS_REQ or
 * KRB_ERROR. JavaScript representation is a pair of [type,
 * object]. It almost certainly doesn't work outside the top level
 * since it has no TLV and everything expects one. If we really need
 * it, passing the tag to decodeDERValue might do the trick?
 *
 * @param {Array.<asn1.Type>} choices A list of possible types.
 * @constructor
 */
asn1.CHOICE = function (choices) {
    this.choices = choices;
};
asn1.CHOICE.prototype = Object.create(asn1.Type.prototype);

asn1.CHOICE.prototype.encodeDER = function (object) {
    var type = object[0], realObj = object[1];
    if (this.choices.indexOf(type) == -1)
	throw new TypeError("Invalid type");
    return type.encodeDER(realObj);
};

asn1.CHOICE.prototype.decodeDERPrefix = function (data) {
    // Peek ahead at the tag.
    var tvr = asn1.decodeTagLengthValueDER(data);
    var tag = tvr[0], value = tvr[1], rest = tvr[2];

    for (var i = 0; i < this.choices.length; i++) {
	if (tag == this.choices[i].tag) {
	    // Found it!
	    return [[this.choices[i],
		     this.choices[i].decodeDERValue(value)], rest];
	}
    }
    throw new asn1.Error("Unexpected tag " + tag);
};
