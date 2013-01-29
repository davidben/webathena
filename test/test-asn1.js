"use strict";

module("asn1");

// Our bitstrings are arrays.
function bytesToBitString(b, remainder) {
    var bits = [];
    for (var i = 0; i < b.length; i++) {
        var octet = b.charCodeAt(i);
        for (var m = (1 << 7); m > 0; m >>= 1) {
            bits.push((octet & m) ? 1 : 0);
        }
    }
    return bits.slice(0, bits.length - remainder);
}

function isEncoding(type, input, output, msg) {
    deepEqual(type.encodeDER(input), output, msg + " - encode");
    deepEqual(type.decodeDER(output), input, msg + " - decode");
}

test("X.690 examples", function() {
    equal(asn1.encodeLengthDER(38), "\x26", "Length - short form");
    equal(asn1.encodeLengthDER(201), "\x81\xc9", "Length - long form");

    isEncoding(asn1.BOOLEAN, true, "\x01\x01\xff", "BOOLEAN");
    isEncoding(asn1.BIT_STRING,
               bytesToBitString("\x0a\x3b\x5f\x29\x1c\xd0", 4),
               "\x03\x07\x04\x0a\x3b\x5f\x29\x1c\xd0",
               "BIT STRING");
    isEncoding(asn1.NULL, null, "\x05\x00", "NULL");
    // IA5String changed to GeneralString.
    isEncoding(new asn1.SEQUENCE([{id: "name", type: asn1.GeneralString},
                                  {id: "ok", type: asn1.BOOLEAN}]),
               {name: "Smith", ok: true},
               "\x30\x0a\x1b\x05Smith\x01\x01\xff");

    // VisibleString changed to GeneralString.

    // Okay, this is kind of annoying. We shouldn't have to manually
    // specify tags as primitive or constructed; it's a property of
    // the type.
    var Type1 = asn1.GeneralString;
    var Type2 = Type1.implicitlyTagged(
        asn1.tag(3, asn1.TAG_PRIMITIVE, asn1.TAG_APPLICATION));
    var Type3 = Type2.tagged(asn1.tag(2));
    var Type4 = Type3.implicitlyTagged(
        asn1.tag(7, asn1.TAG_CONSTRUCTED, asn1.TAG_APPLICATION));
    var Type5 = Type2.implicitlyTagged(
        asn1.tag(2, asn1.TAG_PRIMITIVE));
    isEncoding(Type1, "Jones", "\x1b\x05\x4a\x6f\x6e\x65\x73",
               "Prefixed Type1");
    isEncoding(Type2, "Jones", "\x43\x05\x4a\x6f\x6e\x65\x73",
               "Prefixed Type2");
    isEncoding(Type3, "Jones", "\xa2\x07\x43\x05\x4a\x6f\x6e\x65\x73",
               "Prefixed Type3");
    isEncoding(Type4, "Jones", "\x67\x07\x43\x05\x4a\x6f\x6e\x65\x73",
               "Prefixed Type4");
    isEncoding(Type5, "Jones", "\x82\x05\x4a\x6f\x6e\x65\x73",
               "Prefixed Type5");

    isEncoding(asn1.OBJECT_IDENTIFIER, "2.100.3", "\x06\x03\x81\x34\x03",
               "OBJECT IDENTIFIER");

    // VisibleString changed to GeneralString.
    isEncoding(asn1.GeneralString, "Jones", "\x1b\x05\x4a\x6f\x6e\x65\x73",
               "GeneralString");
});

// TODO: Transcribe X.690 Annex A example. But it uses SET. Can that
// be a SEQUENCE OF?
