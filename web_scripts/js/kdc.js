"use strict";

var Err = function(ctx, code, msg) {
    this.ctx = ctx;
    this.code = code;
    this.msg = msg;
};

Err.Context = {};
Err.Context.KEY = 0x02;
Err.Context.NET = 0x03;
Err.Context.UNK = 0x0f;

var Crypto = {};

Crypto.toBase64 = function(str) {
    return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Latin1.parse(str));
};

Crypto.fromBase64 = function(str) {
    return CryptoJS.enc.Latin1.stringify(CryptoJS.enc.Base64.parse(str));
};

Crypto.randomNonce = function() {
    var word = sjcl.random.randomWords(1)[0];
    // Twos-complement it if negative.
    if (word < 0)
        word += 0x80000000;
    return word;
};

Crypto.retryForEntropy = function (action) {
    var deferred = Q.defer();
    // We can maybe be more awesome and note that SJCL never needs to
    // re-seed its PRNG once its been seeded initially.
    var retry = function() {
        sjcl.random.removeEventListener("seeded", retry);
	try {
            deferred.resolve(action());
	} catch (e) {
            if (e instanceof sjcl.exception.notReady) {
		// Retry when we have more entropy.
		// TODO: Notify the UI in case we want to retry later.
		log("Not enough entropy!");
		sjcl.random.addEventListener("seeded", retry);
            } else {
		deferred.reject(e);
            }
	}
    };
    retry();
    return deferred.promise;
};

var KDC = (function() {
    var KDC = {};

    KDC.urlBase = '/kdc/v1/';
    KDC.realm = 'ATHENA.MIT.EDU'; // XXX
    KDC.supportedEnctypes = [
	kcrypto.enctype.aes256_cts_hmac_sha1_96,
	kcrypto.enctype.aes128_cts_hmac_sha1_96,
	kcrypto.enctype.des_cbc_crc,
	kcrypto.enctype.des_cbc_md5
    ];

    KDC.Error = function(code, message) {
	this.code = code;
	this.message = message;
    };
    KDC.Error.prototype.toString = function() {
	return "KDC Error " + this.code + ": " + this.message;
    };

    KDC.Principal = function(principalName, realm) {
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
    KDC.Principal.prototype.nameToString = function() {
	var escaped = [];
	for (var i = 0; i < this.principalName.nameString.length; i++) {
            escaped.push(krbEscape(this.principalName.nameString[i]));
	}
	return escaped.join("/");
    };
    KDC.Principal.prototype.toString = function() {
	return this.nameToString() + "@" + krbEscape(this.realm);
    };
    KDC.Principal.prototype.toStringShort = function() {
	if (this.realm == KDC.realm)
            return this.nameToString();
	return this.toString();
    }
    KDC.Principal.fromString = function(str) {
	var components = [];
	var component = "";
	var seenAt = false;
	for (var i = 0; i < str.length; i++) {
            if (str[i] == "\\") {
		i++;
		if (i >= str.length)
                    throw "Malformed principal";
		switch (str[i]) {
		case "n": component += "\n";
		case "t": component += "\t";
		case "b": component += "\b";
		case "0": component += "\0";
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
            component = KDC.realm;
	}
	return new KDC.Principal({
            nameType: krb.KRB_NT_PRINCIPAL,
            nameString: components
	}, component);
    }

    KDC.Key = function (keytype, keyvalue) {
	this.keytype = keytype;
	this.keyvalue = keyvalue;
    };
    KDC.Key.prototype.getEncProfile = function () {
	var encProfile = kcrypto.encProfiles[this.keytype];
	if (encProfile === undefined)
            throw new Err(Err.Context.KEY, 0x00,
			  'Unsupported enctype ' + this.keytype);
	return encProfile;
    };
    KDC.Key.prototype.decrypt = function (usage, data) {
	if (data.etype != this.keytype)
            throw new Err(Err.Context.KEY, 0x01, 'Key types do not match');
	var encProfile = this.getEncProfile();
	// TODO: cache the derived key? This'll let us also cache things
	// computed from the derived key.
	var derivedKey = encProfile.deriveKey(this.keyvalue, usage);
	return encProfile.decrypt(
            derivedKey,
            encProfile.initialCipherState(derivedKey, false),
            data.cipher)[1];
    };
    KDC.Key.prototype.decryptAs = function (asn1Type, usage, data) {
	// Some ciphers add padding, so we can't abort if there is data
	// left over.
	return asn1Type.decodeDERPrefix(this.decrypt(usage, data))[0];
    };
    KDC.Key.prototype.encrypt = function (usage, data) {
	var encProfile = this.getEncProfile();
	var derivedKey = encProfile.deriveKey(this.keyvalue, usage);
	return {
            etype: this.keytype,
            // kvno??
            cipher: encProfile.encrypt(
		derivedKey,
		encProfile.initialCipherState(derivedKey, true),
		data)[1]
	};
    };
    KDC.Key.prototype.encryptAs = function (asn1Type, usage, obj) {
	return this.encrypt(usage, asn1Type.encodeDER(obj));
    }
    KDC.Key.prototype.checksum = function (usage, data) {
	var encProfile = this.getEncProfile();
	var derivedKey = encProfile.deriveKey(this.keyvalue, usage);
	return {
            cksumtype: encProfile.checksum.sumtype,
            checksum: encProfile.checksum.getMic(derivedKey, data)
	};
    };

    KDC.Key.fromDict = function (key) {
	return new KDC.Key(key.keytype, key.keyvalue);
    };
    KDC.Key.fromPassword = function (keytype, password, salt, params) {
	var encProfile = kcrypto.encProfiles[keytype];
	if (encProfile === undefined)
            throw new Err(Err.Context.KEY, 0x02,
			  'Unsupported enctype ' + keytype);
	return new KDC.Key(keytype,
			   encProfile.stringToKey(password, salt, params));
    };

    KDC.kdcProxyRequest = function (data, target, outputType) {
	var deferred = Q.defer();
	var xhr = new XMLHttpRequest();
	xhr.open('POST', KDC.urlBase + target);
	xhr.setRequestHeader('X-WebKDC-Request', 'OK');
	xhr.setRequestHeader('Content-Type', 'text/plain');
	xhr.onreadystatechange = function (e) {
            if (this.readyState != 4)
		return;
            if (this.status == 200) {
		var data = JSON.parse(this.responseText);
		switch(data.status) {
		case 'ERROR':
                    deferred.reject(new Err(Err.Context.NET, 'proxy',
					    data.msg));
                    break;
		case 'TIMEOUT':
                    deferred.reject(new Err(Err.Context.NET, 'timeout',
                                            'KDC connection timed out'));
                    break;
		case 'OK':
                    var der = Crypto.fromBase64(data.reply);
                    var reply = outputType.decodeDER(der)[1];
                    deferred.resolve(reply);
                    break;
		}
            } else {
		deferred.reject(new Err(Err.Context.NET, 'error', xhr.status));
            }
	};
	xhr.send(Crypto.toBase64(data));
	return deferred.promise;
    };

    KDC.asReq = function(principal, padata) {
	return Crypto.retryForEntropy(function () {
            var asReq = {};
            asReq.pvno = krb.pvno;
            asReq.msgType = krb.KRB_MT_AS_REQ;
            // TODO: padata will likely want to be a more interesting
            // callback for ones which depend on, say, the reqBody.
            if (padata !== undefined)
		asReq.padata = padata;

            // FIXME: This is obnoxious. Also constants.
            asReq.reqBody = {};
            // TODO: Pick a reasonable set of flags. These are just
            // taken from a wireshark trace.
            asReq.reqBody.kdcOptions = krb.KDCOptions.make(
		krb.KDCOptions.forwardable,
		krb.KDCOptions.proxiable,
		krb.KDCOptions.renewable_ok);

            if (principal.realm != KDC.realm)
		throw "Cross-realm not supported!";
            asReq.reqBody.principalName = principal.principalName;

            asReq.reqBody.realm = KDC.realm;

            asReq.reqBody.sname = {};
            asReq.reqBody.sname.nameType = krb.KRB_NT_SRV_INST;
            asReq.reqBody.sname.nameString = [ 'krbtgt', KDC.realm ];

            asReq.reqBody.till = new Date(0);
            asReq.reqBody.nonce = Crypto.randomNonce();
            asReq.reqBody.etype = KDC.supportedEnctypes;

            return KDC.kdcProxyRequest(krb.AS_REQ.encodeDER(asReq),
                                       'AS_REQ', krb.AS_REP_OR_ERROR)
		.then(function (asRep) {
		    return { asReq: asReq, asRep: asRep };
		});
	});
    };

    KDC.extractPreAuthHint = function (methodData) {
	// The preferred ordering of the "hint" pre-authentication data
	// that affect client key selection is: ETYPE-INFO2, followed by
	// ETYPE-INFO, followed by PW-SALT.  As noted in Section 3.1.3, a
	// KDC MUST NOT send ETYPE-INFO or PW-SALT when the client's
	// AS-REQ includes at least one "newer" etype.
	for (var i = 0; i < methodData.length; i++) {
            if (methodData[i].padataType == krb.PA_ETYPE_INFO2)
		return krb.ETYPE_INFO2.decodeDER(methodData[i].padataValue);
	}
	for (var i = 0; i < methodData.length; i++) {
            if (methodData[i].padataType == krb.PA_ETYPE_INFO)
		return krb.ETYPE_INFO.decodeDER(methodData[i].padataValue);
	}
	for (var i = 0; i < methodData.length; i++) {
            if (methodData[i].padataType == krb.PA_PW_SALT)
		return [ { salt: methodData[i].padataValue } ];
	}
	return [];
    }

    KDC.getTGTSession = function (principal, password) {
	return KDC.asReq(principal).then(function (ret) {
            var asReq = ret.asReq, asRep = ret.asRep;
            // Handle pre-authentication.
            if (asRep.msgType == krb.KRB_MT_ERROR &&
		asRep.errorCode == krb.KDC_ERR_PREAUTH_REQUIRED) {
		// Got a pre-auth request. Retry with pre-auth. Pick the
		// first PA-DATA we can handle.
		// TODO: Implement other types of PA-DATA.
		// TODO: Implement RFC 6113.
		var methodData = krb.METHOD_DATA.decodeDER(asRep.eData);
		for (var i = 0; i < methodData.length; i++) {
                    if (methodData[i].padataType == krb.PA_ENC_TIMESTAMP) {
			var etypeInfos = KDC.extractPreAuthHint(methodData);
			var etypeInfo = null;
			// Find an enctype we support.
			for (var j = 0; j < etypeInfos.length; j++) {
                            if (etypeInfos[j].etype in kcrypto.encProfiles) {
				etypeInfo = etypeInfos[j];
				break;
                            }
			}
			if (etypeInfo === null)
                            throw new Err(Err.Context.KEY, 0x03,
					  'No supported enctypes');

			// Derive a key.
			var salt = principal.realm +
                            principal.principalName.nameString.join("");
			if ("salt" in etypeInfo)
                            salt = etypeInfo.salt;
			var key = KDC.Key.fromPassword(etypeInfo.etype, password,
                                                       salt, etypeInfo.s2kparams);

			// Encrypt a timestamp.
			return Crypto.retryForEntropy(function () {
                            var ts = { };
                            ts.patimestamp = new Date();
                            ts.pausec = ts.patimestamp.getUTCMilliseconds() * 1000;
                            ts.patimestamp.setUTCMilliseconds(0);
                            var encTs = key.encryptAs(
				krb.ENC_TS_ENC, krb.KU_AS_REQ_PA_ENC_TIMESTAMP, ts);
                            return {
				padataType: krb.PA_ENC_TIMESTAMP,
				padataValue: krb.ENC_TIMESTAMP.encodeDER(encTs)
                            };
			}).then(function (padata) {
                            // Make a new AS-REQ with our PA-DATA and process that.
                            return KDC.asReq(principal, [padata]);
			});
                    }
		}
            }
            // Not a request for pre-auth. Process whatever we got.
            return ret;
	}).then(function (ret) {
            var asReq = ret.asReq, asRep = ret.asRep;

            // Handle errors.
            if (asRep.msgType == krb.KRB_MT_ERROR)
		throw new KDC.Error(asRep.errorCode, asRep.eText);

            // The default salt string, if none is provided via
            // pre-authentication data, is the concatenation of the
            // principal's realm and name components, in order, with
            // no separators.
            //
            // If any padata fields are present, they may be used to
            // derive the proper secret key to decrypt the message.
            var salt = principal.realm +
		principal.principalName.nameString.join("");
            var s2kparams = undefined;
            if (asRep.padata) {
		// Is this right?
		var etypeInfos = KDC.extractPreAuthHint(asRep.padata);
		if (etypeInfos.length != 1)
                    throw "Bad pre-auth hint";
		if ("etype" in etypeInfos[0] &&
                    etypeInfos[0].etype != asRep.encPart.etype)
                    throw "Bad pre-auth hint";
		if ("salt" in etypeInfos[0])
                    salt = etypeInfos[0].salt;
		s2kparams = etypeInfos[0].s2kparams;
            }
            var key = KDC.Key.fromPassword(asRep.encPart.etype, password, salt,
					   s2kparams);

            // The key usage value for encrypting this field is 3 in
            // an AS-REP message, using the client's long-term key or
            // another key selected via pre-authentication mechanisms.
            return KDC.sessionFromKDCRep(key, krb.KU_AS_REQ_ENC_PART,
					 asReq, asRep);
	});
    };

    KDC.sessionFromKDCRep = function (key, keyUsage, kdcReq, kdcRep) {
	// 3.1.5.  Receipt of KRB_AS_REP Message

	// If the reply message type is KRB_AS_REP, then the
	// client verifies that the cname and crealm fields in the
	// cleartext portion of the reply match what it requested.
	if (kdcReq.reqBody.principalName) {
            // If we didn't send principalName (because it was a TGS_REQ)
            // do we still check stuff?
            if(kdcRep.crealm != kdcReq.reqBody.realm)
		throw new Err(Err.Context.KEY, 0x10, 'crealm does not match');
            if(!krb.principalNamesEqual(kdcReq.reqBody.principalName,
					kdcRep.cname))
		throw new Err(Err.Context.KEY, 0x11, 'cname does not match');
	}

	// The client decrypts the encrypted part of the response
	// using its secret key...
	var encRepPart = key.decryptAs(krb.EncASorTGSRepPart,
                                       keyUsage, kdcRep.encPart)[1];

	// ...and verifies that the nonce in the encrypted part
	// matches the nonce it supplied in its request (to detect
	// replays).
	if (kdcReq.reqBody.nonce != encRepPart.nonce)
            throw new Err(Err.Context.KEY, 0x12, 'nonce does not match');

	// It also verifies that the sname and srealm in the
	// response match those in the request (or are otherwise
	// expected values), and that the host address field is
	// also correct.
	if (!krb.principalNamesEqual(kdcReq.reqBody.sname, encRepPart.sname))
            throw new Err(Err.Context.KEY, 0x13, 'sname does not match');

	// It then stores the ticket, session key, start and
	// expiration times, and other information for later use.
	return new KDC.Session(kdcRep, encRepPart);

	// TODO: Do we want to do anything with last-req and
	// authtime?
    };

    KDC.Session = function (asRep, encRepPart) {
	// Make sure this thing is trivial JSON-able.
	function dateToInt(d) {
            if (d instanceof Date)
		return d.getTime();
            return d;
	}

	// Just store everything. Whatever.
	this.crealm = asRep.crealm;
	this.cname = asRep.cname;
	this.ticket = asRep.ticket;

	this.key = KDC.Key.fromDict(encRepPart.key);
	this.flags = encRepPart.flags;
	this.starttime = dateToInt(encRepPart.starttime);
	this.endtime = dateToInt(encRepPart.endtime);
	this.renewTill = dateToInt(encRepPart.renewTill);
	this.srealm = encRepPart.srealm;
	this.sname = encRepPart.sname;
	this.caddr = encRepPart.caddr;
    };

    KDC.Session.fromDict = function (dict) {
	return new KDC.Session(dict, dict);
    };

    KDC.Session.prototype.makeAPReq = function (keyUsage,
						cksum,
						subkey,
						seqNumber) {
	var apReq = { };
	apReq.pvno = krb.pvno;
	apReq.msgType = krb.KRB_MT_AP_REQ;
	apReq.apOptions = krb.APOptions.make();
	apReq.ticket = this.ticket;

	var auth = { };
	auth.authenticatorVno = krb.pvno;
	auth.crealm = this.crealm;
	auth.cname = this.cname;
	if (cksum !== undefined) auth.cksum = cksum;
	auth.ctime = new Date();
	auth.cusec = auth.ctime.getUTCMilliseconds() * 1000;
	auth.ctime.setUTCMilliseconds(0);
	if (subkey !== undefined) auth.subkey = subkey;
	if (seqNumber !== undefined) auth.seqNumber = seqNumber;

	// Encode the authenticator.
	apReq.authenticator = this.key.encryptAs(krb.Authenticator, keyUsage, auth);
	return apReq;
    };

    KDC.Session.prototype.getServiceSession = function (service) {
	var self = this;
	return Crypto.retryForEntropy(function () {
            var tgsReq = { };
            tgsReq.pvno = krb.pvno;
            tgsReq.msgType = krb.KRB_MT_TGS_REQ;

            tgsReq.reqBody = { };
            // TODO: What flags?
            tgsReq.reqBody.kdcOptions = krb.KDCOptions.make();
            tgsReq.reqBody.sname = service.principalName;
            tgsReq.reqBody.realm = service.realm;

            // TODO: Do we want to request the maximum end time? Seems a
            // reasonable default I guess.
            tgsReq.reqBody.till = new Date(0);
            tgsReq.reqBody.nonce = Crypto.randomNonce();
            tgsReq.reqBody.etype = KDC.supportedEnctypes;

            // Checksum the reqBody. Note: if our DER encoder isn't completely
            // correct, the proxy will re-encode it and possibly mess up the
            // checksum. This is probably a little poor.
            var checksum = self.key.checksum(
		krb.KU_TGS_REQ_PA_TGS_REQ_CKSUM,
		krb.KDC_REQ_BODY.encodeDER(tgsReq.reqBody));

            // Requests for additional tickets (KRB_TGS_REQ) MUST contain a
            // padata of PA-TGS-REQ.
            var apReq = self.makeAPReq(krb.KU_TGS_REQ_PA_TGS_REQ, checksum);
            tgsReq.padata = [{ padataType: krb.PA_TGS_REQ,
                               padataValue: krb.AP_REQ.encodeDER(apReq) }];

            return KDC.kdcProxyRequest(krb.TGS_REQ.encodeDER(tgsReq),
                                       'TGS_REQ', krb.TGS_REP_OR_ERROR)
		.then(function (tgsRep) {
                    if(tgsRep.msgType == krb.KRB_MT_ERROR)
			throw new KDC.Error(tgsRep.errorCode, tgsRep.eText);

                    // When the KRB_TGS_REP is received by the client, it
                    // is processed in the same manner as the KRB_AS_REP
                    // processing described above.  The primary difference
                    // is that the ciphertext part of the response must be
                    // decrypted using the sub-session key from the
                    // Authenticator, if it was specified in the request,
                    // or the session key from the TGT, rather than the
                    // client's secret key.
                    //
                    // If we use a subkey, the usage might change I think.
                    return KDC.sessionFromKDCRep(
			self.key, krb.KU_TGS_REQ_ENC_PART, tgsReq, tgsRep);
		});
	});
    };

    KDC.Session.prototype.isExpired = function () {
	return new Date(this.endtime) <= new Date();
    };

    return KDC;
}());
