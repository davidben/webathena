(function() {
    /** @const */ krb.realm = "ATHENA.MIT.EDU"; // XXX

    /** @constructor */
    krb.Principal = function(principalName, realm) {
	this.principalName = principalName;
	this.realm = realm;
    };
    function krbEscape(str) {
	// From src/lib/krb5/krb/unparse.c. Escape \0, \n, \t, \b, \\, \/,
	// and \@.  Other characters as-is.
	return str.replace("\\", "\\\\")
            .replace("\0", "\\0")
            .replace("\n", "\\n")
            .replace("\t", "\\t")
            .replace("\b", "\\b")
            .replace("/", "\\/")
            .replace("@", "\\@");
    };
    krb.Principal.prototype.nameToString = function() {
	var escaped = [];
	for (var i = 0; i < this.principalName.nameString.length; i++) {
            escaped.push(krbEscape(this.principalName.nameString[i]));
	}
	return escaped.join("/");
    };
    krb.Principal.prototype.toString = function() {
	return this.nameToString() + "@" + krbEscape(this.realm);
    };
    krb.Principal.prototype.toStringShort = function() {
        // Ugh, circular dependency between modules.
	if (this.realm == krb.realm)
            return this.nameToString();
	return this.toString();
    }
    krb.Principal.fromString = function(str) {
	var components = [];
	var component = "";
	var seenAt = false;
	for (var i = 0; i < str.length; i++) {
            if (str[i] == "\\") {
		i++;
		if (i >= str.length)
                    throw "Malformed principal";
		switch (str[i]) {
		case "n": component += "\n"; break;
		case "t": component += "\t"; break;
		case "b": component += "\b"; break;
		case "0": component += "\0"; break;
		default: component += str[i];
		}
            } else if (str[i] == "/") {
		if (seenAt)
                    throw "Malformed principal";
		components.push(component);
		component = "";
            } else if (str[i] == "@") {
		if (seenAt)
                    throw "Malformed principal";
		components.push(component);
		component = "";
		seenAt = true;
            } else {
		component += str[i];
            }
	}
	if (!seenAt) {
            components.push(component);
            // If no realm, use the default.
            component = krb.realm;
	}
	return new krb.Principal({
            nameType: krb.KRB_NT_PRINCIPAL,
            nameString: components
	}, component);
    }

    /** @constructor */
    krb.Key = function (keytype, keyvalue) {
	this.keytype = keytype;
	this.keyvalue = keyvalue;
    };
    krb.Key.prototype.getEncProfile = function () {
	var encProfile = kcrypto.encProfiles[this.keytype];
	if (encProfile === undefined)
            throw new Err(Err.Context.KEY, 0x00,
			  'Unsupported enctype ' + this.keytype);
	return encProfile;
    };
    krb.Key.prototype.decrypt = function (usage, data) {
	if (data.etype != this.keytype)
            throw new Err(Err.Context.KEY, 0x01, 'Key types do not match');
	var encProfile = this.getEncProfile();
	// TODO: cache the derived key? This'll let us also cache things
	// computed from the derived key.
	var derivedKey = encProfile.deriveKey(this.keyvalue, usage);
	return encProfile.decrypt(
            derivedKey,
            encProfile.initialCipherState(derivedKey, kcrypto.DECRYPT),
            data.cipher)[1];
    };
    krb.Key.prototype.decryptAs = function (asn1Type, usage, data) {
	// Some ciphers add padding, so we can't abort if there is data
	// left over.
	return asn1Type.decodeDERPrefix(this.decrypt(usage, data))[0];
    };
    krb.Key.prototype.encrypt = function (usage, data) {
	var encProfile = this.getEncProfile();
	var derivedKey = encProfile.deriveKey(this.keyvalue, usage);
	return {
            etype: this.keytype,
            // kvno??
            cipher: encProfile.encrypt(
		derivedKey,
		encProfile.initialCipherState(derivedKey, kcrypto.ENCRYPT),
		data)[1]
	};
    };
    krb.Key.prototype.encryptAs = function (asn1Type, usage, obj) {
	return this.encrypt(usage, asn1Type.encodeDER(obj));
    }
    krb.Key.prototype.checksum = function (usage, data) {
	var encProfile = this.getEncProfile();
	var derivedKey = encProfile.deriveKey(this.keyvalue, usage);
	return {
            cksumtype: encProfile.checksum.sumtype,
            checksum: encProfile.checksum.getMIC(derivedKey, data)
	};
    };
    krb.Key.prototype.toDict = function() {
        // You can postMessage a typed array, but so that we can
        // persist as JSON or not require polyfills, all IPCs transfer
        // buffers as byte strings.
        return {
            keytype: this.keytype,
            keyvalue: arrayutils.toByteString(this.keyvalue)
        };
    };

    krb.Key.fromDict = function(key) {
	return new krb.Key(key.keytype,
                           arrayutils.fromByteString(key.keyvalue));
    };
    krb.Key.fromPassword = function (keytype, password, salt, params) {
	var encProfile = kcrypto.encProfiles[keytype];
	if (encProfile === undefined)
            throw new Err(Err.Context.KEY, 0x02,
			  'Unsupported enctype ' + keytype);
	return new krb.Key(keytype,
			   encProfile.stringToKey(password, salt, params));
    };

})();
