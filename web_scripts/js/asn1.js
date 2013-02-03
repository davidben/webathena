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
 * @param {number} cls The class of the tag. Defaults to
 *     TAG_CONTEXT.
 * @param {number} pc TAG_PRIMITIVE or TAG_CONSTRUCTED. Defaults to
 *     TAG_PRIMITIVE.
 * @return {number} A tag number representing the tag.
 */
asn1.tag = function(number, cls, pc) {
    if (cls === undefined)
        cls = asn1.TAG_CONTEXT;
    if (pc === undefined)
        pc = asn1.TAG_PRIMITIVE;
    // We'll implement this if we ever have to deal with it.
    if (number >= 31)
        throw new asn1.Error("High-tag-number form not implemented!");
    return (number | cls | pc);
};

/**
 * A growable array, like std::vector. But you prepend to the array
 * instead of append because DER is most naturally encoded in reverse.
 *
 * @constructor
 */
asn1.Buffer = function() {
    this.buffer = new Uint8Array(10);
    this.start = 10;
};
asn1.Buffer.prototype.reserve = function(size) {
    if (this.start >= size)
        return;
    // Double the size until there's room.
    var targetSize = size - this.start + this.buffer.byteLength;
    var newSize = this.buffer.byteLength;
    while (newSize < targetSize) {
        newSize *= 2;
    }
    // Allocate a new buffer and copy the old contents.
    var newBuffer = new Uint8Array(newSize);
    newBuffer.set(this.buffer, newSize - this.buffer.byteLength);
    this.start += newSize - this.buffer.byteLength;
    this.buffer = newBuffer;
};
asn1.Buffer.prototype.prependUint8 = function(octet) {
    this.reserve(1);
    this.start -= 1;
    this.buffer[this.start] = octet;
    return 1;
};
asn1.Buffer.prototype.prependUint32 = function(value, littleEndian) {
    if (littleEndian) {
        return this.prependBytes([value & 0xff,
                                  (value >>> 8) & 0xff,
                                  (value >>> 16) & 0xff,
                                  value >>> 24]);
    } else {
        return this.prependBytes([value >>> 24,
                                  (value >>> 16) & 0xff,
                                  (value >>> 8) & 0xff,
                                  value & 0xff]);
    }
};
asn1.Buffer.prototype.prependUint16 = function(value, littleEndian) {
    if (littleEndian) {
        return this.prependBytes([value & 0xff, value >>> 8]);
    } else {
        return this.prependBytes([value >>> 8, value & 0xff]);
    }
};
asn1.Buffer.prototype.prependBytes = function(buffer) {
    if (!(buffer instanceof Array))
        buffer = arrayutils.asUint8Array(buffer);
    this.reserve(buffer.length);
    this.start -= buffer.length;
    this.buffer.set(buffer, this.start);
    return buffer.length;
};
asn1.Buffer.prototype.contents = function() {
    return this.buffer.subarray(this.start);
};

/**
 * DER-encodes an ASN.1 tag.
 *
 * @param {number} tag The tag to encode.
 * @param {asn1.Buffer} buffer The buffer to prepend into.
 * @return {number} The bytes prepended.
 */
asn1.encodeTagDER = function(tag, buffer) {
    return buffer.prependUint8(tag);
};

/**
 * Encodes a length in a DER TLV tuple.
 *
 * @param {number} length The length to encode.
 * @param {asn1.Buffer} buffer The buffer to prepend into.
 * @return {number} The bytes prepended.
 */
asn1.encodeLengthDER = function(length, buffer) {
    if (length <= 127) {
        // Short form must be used when possible.
        return buffer.prependUint8(length);
    }
    // First, encode in base 256, big-endian.
    var bytes = 0;
    while (length > 0) {
        buffer.prependUint8(length & 0xff);
        length = length >> 8;
        bytes++;
    }
    // Prepend the number of bytes used.
    buffer.prependUint8(bytes | 0x80);
    return bytes + 1;
};

/**
 * Decodes an ASN.1 TLV tuple.
 *
 * @param {ArrayBufferView} data The data to decode.
 * @return {Array} A tuple [tag, value, rest] containing the tag as a
 *    Number, the value as a String, and the unread data as a String.
 */
asn1.decodeTagLengthValueDER = function(data) {
    var off = 0;

    // First octet describes the tag.
    var tagOctet = data[off];
    var tagNumber = tagOctet & 0x1f;
    var tagPc = tagOctet & (0x1 << 5);
    var tagCls = tagOctet & (0x3 << 6);
    if (tagNumber == 0x1f)
        throw new asn1.Error("High-tag-number form not implemented!");
    var tag = asn1.tag(tagNumber, tagCls, tagPc);
    off++;

    // Now decode the length.
    var lengthOctet = data[off];
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
            length += data[off];
        }
    }

    // And return everything.
    if (off + length > data.length)
        throw new asn1.Error("Length too large!");
    return [tag, data.subarray(off, off + length),
            data.subarray(off + length)];
}


/**
 * Base class for all ASN.1 types. Types are supposed to provide
 * encodeDERValue and decodeDERValue implementations.
 *
 * @param {number} tag The tag of this type. Primitive/constructed bit
 *     may be omitted.
 * @param {boolean=} primitive If the type is primitive.
 * @constructor
 */
asn1.Type = function(tag, primitive) {
    this.primitive = primitive ? true : false;
    if (!this.primitive)
        tag |= asn1.TAG_CONSTRUCTED;
    this.tag = tag;
};

/**
 * DER-encodes an object according to this type.
 *
 * @param {*} object The object to encode.
 * @return {string} The encoding of the object.
 */
asn1.Type.prototype.encodeDER = function(object) {
    var buffer = new asn1.Buffer();
    this.encodeDERTriple(object, buffer);
    return buffer.contents();
};

/**
 * DER-encodes an object according to this type.
 *
 * @param {*} object The object to encode.
 * @param {asn1.Buffer} buffer The buffer to prepend into.
 * @return {number} The bytes prepended.
 */
asn1.Type.prototype.encodeDERTriple = function(object, buffer) {
    var bytes = this.encodeDERValue(object, buffer);
    bytes += asn1.encodeLengthDER(bytes, buffer);
    bytes += asn1.encodeTagDER(this.tag, buffer);
    return bytes;
};

/**
 * Decodes DER-encoded data according to this type. Throws an
 * exception if the entire data isn't read.
 *
 * @param {string} data The data to decode.
 * @return {*} The decoded object.
 */
asn1.Type.prototype.decodeDER = function(data) {
    var objRest = this.decodeDERPrefix(data);
    var obj = objRest[0], rest = objRest[1];
    if (rest.byteLength != 0)
        throw new asn1.Error("Excess data!");
    return obj;
};

/**
 * Decodes DER-encoded data according to this type.
 *
 * @param {ArrayBufferView} data The data to decode.
 * @return {Array} A tuple of the decoded object and the unread data.
 */
asn1.Type.prototype.decodeDERPrefix = function(data) {
    // Only cast to Uint8Array here. The other entry points aren't
    // really public, so they'll assume Uint8Array.
    data = new Uint8Array(data);
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
asn1.Type.prototype.tagged = function(tag) {
    return new asn1.ExplicitlyTagged(tag, this);
};

/**
 * Creates an implicitly-tagged version of this type.
 *
 * @param {number} tag The value to tag with.
 * @return {asn1.ImplicitlyTagged} An implicitly tagged version of
 *     this.
 */
asn1.Type.prototype.implicitlyTagged = function(tag) {
    return new asn1.ImplicitlyTagged(tag, this);
};

/**
 * Creates an constrained version of this type.
 *
 * @param {Function} checkValue A function which those an exception if
 *     a value is invalid.
 * @return {asn1.Type} An constrained version of this.
 */
asn1.Type.prototype.constrained = function(checkValue) {
    var newType = this.subtype();
    var self = this;

    newType.encodeDERValue = function(object, buffer) {
        checkValue.call(this, object);
        return self.encodeDERValue(object, buffer);
    }
    newType.decodeDERValue = function(data) {
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
asn1.Type.prototype.subtype = function() {
    return Object.create(this);
};


/**
 * An explicitly-tagged type.
 *
 * @param {number} tag The tag of this type.
 * @param {asn1.Type} baseType The type to tag.
 * @constructor
 */
asn1.ExplicitlyTagged = function(tag, baseType) {
    asn1.Type.call(this, tag, false);
    this.baseType = baseType;
};
asn1.ExplicitlyTagged.prototype = Object.create(asn1.Type.prototype);

asn1.ExplicitlyTagged.prototype.encodeDERValue = function(object, buffer) {
    return this.baseType.encodeDERTriple(object, buffer);
};

asn1.ExplicitlyTagged.prototype.decodeDERValue = function(data) {
    return this.baseType.decodeDER(data);
};


/**
 * An implicitly-tagged type.
 *
 * @param {number} tag The tag of this type.
 * @param {asn1.Type} baseType The type to tag.
 * @constructor
 */
asn1.ImplicitlyTagged = function(tag, baseType) {
    asn1.Type.call(this, tag, baseType.primitive);
    this.baseType = baseType;
};
asn1.ImplicitlyTagged.prototype = Object.create(asn1.Type.prototype);

asn1.ImplicitlyTagged.prototype.encodeDERValue = function(object, buffer) {
    return this.baseType.encodeDERValue(object, buffer);
};

asn1.ImplicitlyTagged.prototype.decodeDERValue = function(data) {
    return this.baseType.decodeDERValue(data);
};


/** ASN.1 BOOLEAN type. */
asn1.BOOLEAN = new asn1.Type(asn1.tag(0x01, asn1.TAG_UNIVERSAL), true);

asn1.BOOLEAN.encodeDERValue = function(object, buffer) {
    if (typeof object != "boolean")
        throw new TypeError("boolean");
    return buffer.prependUint8(object ? 0xff : 0x00);
};

asn1.BOOLEAN.decodeDERValue = function(data) {
    return data[0] !== 0x00;
};


/** ASN.1 INTEGER type. */
asn1.INTEGER = new asn1.Type(asn1.tag(0x02, asn1.TAG_UNIVERSAL), true);

asn1.INTEGER.encodeDERValue = function(object, buffer) {
    var bytes = 0;
    var sign = 0;
    if (typeof object != "number")
        throw new TypeError("Not a number");
    // Encode in two's-complement, base 256, most sigificant bit
    // first, with the minimum number of bytes needed.
    while ((object >= 0 && (sign != 1 || object > 0)) ||
           (object <= -1 && (sign != -1 || object < -1))) {
        var digit = object & 0xff;
        bytes += buffer.prependUint8(digit);
        sign = (digit & 0x80) ? -1 : 1;
        object = object >> 8;
    }
    return bytes;
};

asn1.INTEGER.decodeDERValue = function(data) {
    var ret = data[0];
    if (ret > 127)
        ret = ret - 256;
    for (var i = 1; i < data.length; i++) {
        ret *= 256;
        ret += data[i];
    }
    return ret;
};

/**
 * @this {asn1.Type}
 * @return {asn1.Type}
 */
asn1.INTEGER.valueConstrained = function() {
    var allowed = [];
    for (var i = 0; i < arguments.length; i++) {
        allowed.push(arguments[i]);
    }

    return this.constrained(function(v) {
        if (allowed.indexOf(v) == -1)
            throw new RangeError("Invalid value: " + v);
    });
};

/**
 * @this {asn1.Type}
 * @return {asn1.Type}
 */
asn1.INTEGER.rangeConstrained = function(lo, hi) {
    return this.constrained(function(v) {
        if (v < lo || v > hi)
            throw new RangeError("Invalid value: " + v);
    });
};


/**
 * ASN.1 BIT STRING type. We'll represent it as an Array of 0s and 1s,
 * though a bitmask works fine for Kerberos.
 */
asn1.BIT_STRING = new asn1.Type(asn1.tag(0x03, asn1.TAG_UNIVERSAL), true);

asn1.BIT_STRING.encodeDERValue = function(object, buffer) {
    var remainder = 8 - (object.length % 8);
    if (remainder == 8) remainder = 0;

    var bytes = 0;
    for (var i = object.length + remainder - 8; i >= 0; i -= 8) {
        var octet = 0;
        // Bit zero ends up in the high-order bit of the first octet.
        for (var j = 0; j < 8; j++) {
            octet |= (object[i + j] || 0) << (7-j);
        }
        bytes += buffer.prependUint8(octet);
    }
    bytes += buffer.prependUint8(remainder);
    return bytes;
};

asn1.BIT_STRING.decodeDERValue = function(data) {
    var remainder = data[0];
    var ret = [];
    for (var i = 1; i < data.length; i++) {
        var octet = data[i];
        for (var j = 7; j >= 0; j--) {
            ret.push((octet & (1 << j)) ? 1 : 0);
        }
    }
    // Chop off the extra bits.
    return ret.slice(0, ret.length - remainder);
};


/** ASN.1 OCTET STRING type. */
asn1.OCTET_STRING = new asn1.Type(asn1.tag(0x04, asn1.TAG_UNIVERSAL), true);

asn1.OCTET_STRING.encodeDERValue = function(object, buffer) {
    // Apparently this isn't exposed everywhere. Sigh.
    if (window.ArrayBufferView && !object instanceof ArrayBufferView)
        throw new TypeError("Not an array buffer");
    return buffer.prependBytes(object);
};

asn1.OCTET_STRING.decodeDERValue = function(data) {
    return new Uint8Array(data);
};


/** ASN.1 NULL type. */
asn1.NULL = new asn1.Type(asn1.tag(0x05, asn1.TAG_UNIVERSAL), true);

asn1.NULL.encodeDERValue = function(object, buffer) {
    if (object !== null)
        throw new TypeError("Bad value");
    return 0;
};

asn1.NULL.decodeDERValue = function(data) {
    if (data.length > 0)
        throw new asn1.Error("Bad encoding");
    return null;
};


/** ASN.1 OBJECT IDENTIFIER type. For sanity, just make the JS
 * representation a string. We can do something more complex if
 * there's a need. */
asn1.OBJECT_IDENTIFIER = new asn1.Type(asn1.tag(0x06, asn1.TAG_UNIVERSAL),
                                       true);

asn1.OBJECT_IDENTIFIER.encodeDERValue = function(object, buffer) {
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
    // Subidentifiers are encoded big-endian, but we encode in
    // reverse.
    var bytes = 0;
    for (var i = subidentifiers.length - 1; i >= 0; i--) {
        // Base 128, big endian. All but last octet has MSB 1.
        var c = subidentifiers[i];
        bytes += buffer.prependUint8(c & 0x7f);
        c >>>= 7;
        while (c > 0) {
            bytes += buffer.prependUint8((c & 0x7f) | 0x80);
            c >>>= 7;
        }
    }
    return bytes;
};

asn1.OBJECT_IDENTIFIER.decodeDERValue = function(data) {
    var c = 0;
    var subidentifiers = [];
    for (var i = 0; i < data.length; i++) {
        var octet = data[i];
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


/** ASN.1 GeneralString type.
 *
 * Stuffing UTF-8 in an ASN.1 GeneralString would make ITU-T sad, but
 * apparently this is what Microsoft does, although they also do
 * case-folding. MIT Kerberos just forwards the string it gets from
 * the caller, which is locale-specific. Given that, the most
 * reasonable thing for us to do is probably assume UTF-8.
 */
asn1.GeneralString = new asn1.Type(asn1.tag(0x1b, asn1.TAG_UNIVERSAL), true);

asn1.GeneralString.encodeDERValue = function(object, buffer) {
    if (typeof object != "string")
        throw new TypeError("Not a string");
    return buffer.prependBytes(arrayutils.fromUTF16(object));
};

asn1.GeneralString.decodeDERValue = function(data) {
    try {
        return arrayutils.toUTF16(data);
    } catch (e) {
        if (e instanceof URIError)
            throw new asn1.Error("Invalid UTF-8 string");
        throw e;
    }
};


/** ASN.1 GeneralizedTime type. */
asn1.GeneralizedTime = new asn1.Type(asn1.tag(0x18, asn1.TAG_UNIVERSAL), true);

asn1.GeneralizedTime.encodeDERValue = function(object, buffer) {
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
    return buffer.prependBytes(arrayutils.fromByteString(ret));
};

asn1.GeneralizedTime.decodeDERValue = function(data) {
    var re = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.(\d{1,3}))?Z$/;
    var match = arrayutils.toByteString(data).match(re);
    if (!match)
        throw new asn1.Error("Bad date format");
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
asn1.SEQUENCE_OF = function(componentType) {
    asn1.Type.call(this, asn1.tag(0x10, asn1.TAG_UNIVERSAL), false);
    this.componentType = componentType;
};
asn1.SEQUENCE_OF.prototype = Object.create(asn1.Type.prototype);

asn1.SEQUENCE_OF.prototype.encodeDERValue = function(object, buffer) {
    var bytes = 0;
    for (var i = object.length - 1; i >= 0; i--) {
        bytes += this.componentType.encodeDERTriple(object[i], buffer);
    }
    return bytes;
};

asn1.SEQUENCE_OF.prototype.decodeDERValue = function(data) {
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
 * @param {Array.<Object>} componentSpec A specification of the sequence's
 *     components, as described above.
 * @constructor
 */
asn1.SEQUENCE = function(componentSpec) {
    asn1.Type.call(this, asn1.tag(0x10, asn1.TAG_UNIVERSAL), false);
    this.componentSpec = componentSpec;
};
asn1.SEQUENCE.prototype = Object.create(asn1.Type.prototype);

asn1.SEQUENCE.prototype.encodeDERValue = function(object, buffer) {
    var bytes = 0;
    for (var i = this.componentSpec.length - 1; i >= 0; i--) {
        var id = this.componentSpec[i].id;
        if (id in object) {
            bytes += this.componentSpec[i].type.encodeDERTriple(object[id],
                                                                buffer);
        } else if (!this.componentSpec[i].optional) {
            throw new TypeError("Field " + id + " missing!");
        }
    }
    return bytes;
};

asn1.SEQUENCE.prototype.decodeDERValue = function(data) {
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
asn1.CHOICE = function(choices) {
    // This thing is a hack, so it doesn't call the ctor.
    this.choices = choices;
};
asn1.CHOICE.prototype = Object.create(asn1.Type.prototype);

asn1.CHOICE.prototype.encodeDERTriple = function(object, buffer) {
    var type = object[0], realObj = object[1];
    if (this.choices.indexOf(type) == -1)
	throw new TypeError("Invalid type");
    return type.encodeDERTriple(realObj, buffer);
};

asn1.CHOICE.prototype.decodeDERPrefix = function(data) {
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
