"use strict";

module("kdc");

test("Basic principal serialization/deserialization", function() {
    var principal = KDC.Principal.fromString("davidben/extra@ATHENA.MIT.EDU");

    equal(principal.realm, "ATHENA.MIT.EDU");
    equal(principal.principalName.nameType, krb.KRB_NT_PRINCIPAL);
    ok(principal.principalName.nameString.length === 2 &&
       principal.principalName.nameString[0] === "davidben" &&
       principal.principalName.nameString[1] === "extra");

    equal(principal.toString(), "davidben/extra@ATHENA.MIT.EDU");
    equal(principal.toStringShort(), "davidben/extra");
    equal(principal.nameToString(), "davidben/extra");
});

test("Escaping characters in principals", function() {
    var principal = KDC.Principal.fromString("davidben\\/extra\\@\\z@ATHENA.MI\\t.EDU");

    equal(principal.realm, "ATHENA.MI\t.EDU");
    equal(principal.principalName.nameType, krb.KRB_NT_PRINCIPAL);
    ok(principal.principalName.nameString.length === 1 &&
       principal.principalName.nameString[0] === "davidben/extra@z");

    equal(principal.toString(), "davidben\\/extra\\@z@ATHENA.MI\\t.EDU");
    equal(principal.toStringShort(), "davidben\\/extra\\@z@ATHENA.MI\\t.EDU");
    equal(principal.nameToString(), "davidben\\/extra\\@z");
});

test("Principal parsing, default realm", function() {
    var principal = KDC.Principal.fromString("davidben");

    equal(principal.realm, "ATHENA.MIT.EDU");
    equal(principal.principalName.nameType, krb.KRB_NT_PRINCIPAL);
    ok(principal.principalName.nameString.length === 1 &&
       principal.principalName.nameString[0] === "davidben");

    equal(principal.toString(), "davidben@ATHENA.MIT.EDU");
    equal(principal.toStringShort(), "davidben");
    equal(principal.nameToString(), "davidben");

    principal = KDC.Principal.fromString("davidben@EXAMPLE.COM");
    equal(principal.toString(), "davidben@EXAMPLE.COM");
    equal(principal.toStringShort(), "davidben@EXAMPLE.COM");
    equal(principal.nameToString(), "davidben");    
});

test("Principal parsing, malformed principals", function() {
    throws(function() { KDC.Principal.fromString("davidben\\"); });
    throws(function() { KDC.Principal.fromString("davidben@FOO@BAR"); });
});
