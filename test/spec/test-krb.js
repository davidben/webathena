"use strict";

describe("kdc", function() {

  it("should handle basic principal serialization/deserialization", function() {
    var principal = krb.Principal.fromString("davidben/extra@ATHENA.MIT.EDU");

    assert.equal(principal.realm, "ATHENA.MIT.EDU");
    assert.equal(principal.principalName.nameType, krb.KRB_NT_PRINCIPAL);
    assert.ok(principal.principalName.nameString.length === 2 &&
              principal.principalName.nameString[0] === "davidben" &&
              principal.principalName.nameString[1] === "extra");

    assert.equal(principal.toString(), "davidben/extra@ATHENA.MIT.EDU");
    assert.equal(principal.toStringShort(), "davidben/extra");
    assert.equal(principal.nameToString(), "davidben/extra");
  });

  it("should correctly escape characters in principals", function() {
    var principal = krb.Principal.fromString("davidben\\/extra\\@\\z@ATHENA.MI\\t.EDU");

    assert.equal(principal.realm, "ATHENA.MI\t.EDU");
    assert.equal(principal.principalName.nameType, krb.KRB_NT_PRINCIPAL);
    assert.ok(principal.principalName.nameString.length === 1 &&
              principal.principalName.nameString[0] === "davidben/extra@z");

    assert.equal(principal.toString(), "davidben\\/extra\\@z@ATHENA.MI\\t.EDU");
    assert.equal(principal.toStringShort(), "davidben\\/extra\\@z@ATHENA.MI\\t.EDU");
    assert.equal(principal.nameToString(), "davidben\\/extra\\@z");
  });

  it("should handle the default realm", function() {
    var principal = krb.Principal.fromString("davidben");

    assert.equal(principal.realm, "ATHENA.MIT.EDU");
    assert.equal(principal.principalName.nameType, krb.KRB_NT_PRINCIPAL);
    assert.ok(principal.principalName.nameString.length === 1 &&
              principal.principalName.nameString[0] === "davidben");

    assert.equal(principal.toString(), "davidben@ATHENA.MIT.EDU");
    assert.equal(principal.toStringShort(), "davidben");
    assert.equal(principal.nameToString(), "davidben");

    principal = krb.Principal.fromString("davidben@EXAMPLE.COM");
    assert.equal(principal.toString(), "davidben@EXAMPLE.COM");
    assert.equal(principal.toStringShort(), "davidben@EXAMPLE.COM");
    assert.equal(principal.nameToString(), "davidben");
  });

  it("should throw on malformed principals", function() {
    assert.throws(function() { krb.Principal.fromString("davidben\\"); });
    assert.throws(function() { krb.Principal.fromString("davidben@FOO@BAR"); });
  });
});
