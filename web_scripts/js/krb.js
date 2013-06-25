(function() {
    "use strict";

    /** @const */ krb.realm = "ATHENA.MIT.EDU"; // XXX
    /** @const */ krb.supportedEnctypes = [
	kcrypto.enctype.aes256_cts_hmac_sha1_96,
	kcrypto.enctype.aes128_cts_hmac_sha1_96,
	kcrypto.enctype.des_cbc_crc,
	kcrypto.enctype.des_cbc_md5
    ];

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
    krb.Key = function(keytype, keyvalue) {
	this.keytype = keytype;
	this.keyvalue = keyvalue;
        this.profile = kcrypto.encProfiles[keytype];
        if (this.profile === undefined)
            throw new Err(Err.Context.KEY, 0x00,
                          'Unsupported enctype ' + this.keytype);
    };
    krb.Key.makeRandomKey = function(keytype) {
	var encProfile = kcrypto.encProfiles[keytype];
	if (encProfile === undefined)
            throw new Err(Err.Context.KEY, 0x00,
			  'Unsupported enctype ' + keytype);
        // Generate the appropriate number of random bytes.
        var words = sjcl.random.randomWords(
            (encProfile.keyGenerationSeedLength + 31) >>> 5);
        var arr = arrayutils.fromSJCL(words).subarray(
            0, (encProfile.keyGenerationSeedLength + 7) >>> 3);
        return new krb.Key(keytype, encProfile.randomToKey(arr));
    };
    krb.Key.prototype.decrypt = function(usage, data) {
	if (data.etype != this.keytype)
            throw new Err(Err.Context.KEY, 0x01, 'Key types do not match');
	// TODO: cache the derived key? This'll let us also cache things
	// computed from the derived key.
	var derivedKey = this.profile.deriveKey(this.keyvalue, usage);
	return this.profile.decrypt(
            derivedKey,
            this.profile.initialCipherState(derivedKey, kcrypto.DECRYPT),
            data.cipher)[1];
    };
    krb.Key.prototype.decryptAs = function(asn1Type, usage, data) {
	// Some ciphers add padding, so we can't abort if there is data
	// left over.
	return asn1Type.decodeDERPrefix(this.decrypt(usage, data))[0];
    };
    krb.Key.prototype.encrypt = function(usage, data) {
	var derivedKey = this.profile.deriveKey(this.keyvalue, usage);
	return {
            etype: this.keytype,
            // kvno??
            cipher: this.profile.encrypt(
		derivedKey,
		this.profile.initialCipherState(derivedKey, kcrypto.ENCRYPT),
		data)[1]
	};
    };
    krb.Key.prototype.encryptAs = function(asn1Type, usage, obj) {
	return this.encrypt(usage, asn1Type.encodeDER(obj));
    }
    krb.Key.prototype.checksum = function(usage, data) {
	var derivedKey = this.profile.deriveKey(this.keyvalue, usage);
	return {
            cksumtype: this.profile.checksum.sumtype,
            checksum: this.profile.checksum.getMIC(derivedKey, data)
	};
    };
    krb.Key.prototype.toDict = function() {
        // You can postMessage a typed array, but so that we can
        // persist as JSON or not require polyfills, all IPCs transfer
        // buffers as byte strings.
        return {
            keytype: this.keytype,
            keyvalue: arrayutils.toBase64(this.keyvalue)
        };
    };

    krb.Key.fromDict = function(key) {
	return new krb.Key(key.keytype,
                           arrayutils.fromBase64(key.keyvalue));
    };
    krb.Key.fromPassword = function(keytype, password, salt, params) {
	var encProfile = kcrypto.encProfiles[keytype];
	if (encProfile === undefined)
            throw new Err(Err.Context.KEY, 0x02,
			  'Unsupported enctype ' + keytype);
	return new krb.Key(keytype,
			   encProfile.stringToKey(password, salt, params));
    };

    /** @constructor */
    krb.Session = function(asRep, encRepPart) {
        // Just store everything. Whatever.
        this.client = new krb.Principal(asRep.cname, asRep.crealm);
        this.ticket = asRep.ticket;

        this.key = new krb.Key(encRepPart.key.keytype, encRepPart.key.keyvalue);
        this.flags = encRepPart.flags;
        this.authtime = encRepPart.authtime;
        this.starttime = encRepPart.starttime;
        this.endtime = encRepPart.endtime;
        this.renewTill = encRepPart.renewTill;
        this.service = new krb.Principal(encRepPart.sname, encRepPart.srealm);
        this.caddr = encRepPart.caddr;
    };

    krb.Session.fromDict = function(dict) {
        function dateOrUndef(d) {
            return (d == null) ? undefined : new Date(d);
        }
	return new krb.Session({
            crealm: dict.crealm,
            cname: dict.cname,
            ticket: {
                tktVno: dict.ticket.tktVno,
                realm: dict.ticket.realm,
                sname: dict.ticket.sname,
                encPart: {
                    kvno: dict.ticket.encPart.kvno,
                    etype: dict.ticket.encPart.etype,
                    cipher: arrayutils.fromBase64(
                        dict.ticket.encPart.cipher)
                }
            }
        }, {
            // Ugh. This really should use Key.fromDict. Need a
            // different ctor for krb.Session to avoid type confusion.
            key: {
                keytype: dict.key.keytype,
                keyvalue: arrayutils.fromBase64(dict.key.keyvalue)
            },
            lastReq: dict.lastReq,
            nonce: dict.nonce,
            keyExpiration: dict.keyExpiration,
            flags: dict.flags,
            authtime: new Date(dict.authtime),
            starttime: dateOrUndef(dict.starttime),
            endtime: new Date(dict.endtime),
            renewTill: dateOrUndef(dict.renewTill),
            srealm: dict.srealm,
            sname: dict.sname,
            caddr: dict.caddr
        });
    };

    krb.Session.prototype.toDict = function() {
        function getTimeOrUndef(d) {
            return (d == null) ? undefined : d.getTime();
        }
        return {
            crealm: this.client.realm,
            cname: this.client.principalName,
            ticket: {
                tktVno: this.ticket.tktVno,
                realm: this.ticket.realm,
                sname: this.ticket.sname,
                encPart: {
                    kvno: this.ticket.encPart.kvno,
                    etype: this.ticket.encPart.etype,
                    cipher: arrayutils.toBase64(this.ticket.encPart.cipher)
                }
            },
            key: this.key.toDict(),
            flags: this.flags,
            authtime: this.authtime.getTime(),
            starttime: getTimeOrUndef(this.starttime),
            endtime: this.endtime.getTime(),
            renewTill: getTimeOrUndef(this.renewTill),
            srealm: this.service.realm,
            sname: this.service.principalName,
            caddr: this.caddr
        };
    };

    krb.Session.prototype.timeRemaining = function() {
        return this.endtime.getTime() - (new Date()).getTime();
    };

    krb.Session.prototype.isExpired = function() {
	return this.timeRemaining() < 0;
    };

    krb.Session.prototype.makeAPReq = function(keyUsage,
                                               cksum,
                                               opts) {
        opts = opts || { };

	var apReq = { };
	apReq.pvno = krb.pvno;
	apReq.msgType = krb.KRB_MT_AP_REQ;
	apReq.apOptions = opts.apOptions || krb.APOptions.make();
	apReq.ticket = this.ticket;

	var auth = { };
	auth.authenticatorVno = krb.pvno;
	auth.crealm = this.client.realm;
	auth.cname = this.client.principalName;
	if (cksum !== undefined) auth.cksum = cksum;
	auth.ctime = new Date();
	auth.cusec = auth.ctime.getUTCMilliseconds() * 1000;
	auth.ctime.setUTCMilliseconds(0);

        // Stuff the key into the entropy pool; it comes from a
        // trusted third party (the KDC). This matches the MIT
        // Kerberos code. This should have a good amount of entropy as
        // it's a session key generated by the KDC.
        sjcl.random.addEntropy(
            arrayutils.toSJCL(this.key.keyvalue),
            this.key.keyvalue.length * 8, "key");

        var subkey;
        if (opts.useSubkey) {
            subkey = krb.Key.makeRandomKey(this.key.keytype);
            auth.subkey = {
                keytype: subkey.keytype,
                keyvalue: subkey.keyvalue
            };
        }
        var seqNumber;
	if (opts.useSeqNumber) {
            seqNumber = sjcl.random.randomWords(1)[0] & 0x3ffffff;
            auth.seqNumber = seqNumber;
        }

        if (apReq.apOptions[krb.APOptions.mutual_required] &&
            opts.etypeNegotiation &&
            this.key.keytype !== krb.supportedEnctypes[0]) {
            // RFC 4537, Kerberos Cryptosystem Negotiation Extension
            var adIfRelevant = [{
                adType: krb.AD_ETYPE_NEGOTIATION,
                adData: krb.EtypeList.encodeDER(krb.supportedEnctypes)
            }];
            var adEntry = {
                adType: krb.AD_IF_RELEVANT_TYPE,
                adData: krb.AD_IF_RELEVANT.encodeDER(adIfRelevant)
            };
            auth.authorizationData = [adEntry];
        }

	// Encode the authenticator.
        apReq.authenticator = this.key.encryptAs(krb.Authenticator,
                                                 keyUsage, auth);
        return {
            apReq: apReq,
            subkey: subkey,
            seqNumber: seqNumber,
            authenticator: auth
        };
    };

})();
