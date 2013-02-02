"use strict";

/** @constructor */
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
		// FIXME: NO. Just... no.
		alert("Not enough entropy! Please jiggle the mouse a bunch.");
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
    KDC.supportedEnctypes = [
	kcrypto.enctype.aes256_cts_hmac_sha1_96,
	kcrypto.enctype.aes128_cts_hmac_sha1_96,
	kcrypto.enctype.des_cbc_crc,
	kcrypto.enctype.des_cbc_md5
    ];

    /** @constructor */
    KDC.Error = function(code, message) {
	this.code = code;
	this.message = message;
    };
    KDC.Error.prototype.toString = function() {
	return "KDC Error " + this.code + ": " + this.message;
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
                    var der = arrayutils.fromByteString(atob(data.reply));
                    var reply = outputType.decodeDER(der)[1];
                    deferred.resolve(reply);
                    break;
		}
            } else {
		deferred.reject(new Err(Err.Context.NET, 'error', xhr.status));
            }
	};
	xhr.send(btoa(arrayutils.toByteString(data)));
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

            if (principal.realm != krb.realm)
		throw "Cross-realm not supported!";
            asReq.reqBody.principalName = principal.principalName;

            asReq.reqBody.realm = krb.realm;

            asReq.reqBody.sname = {};
            asReq.reqBody.sname.nameType = krb.KRB_NT_SRV_INST;
            asReq.reqBody.sname.nameString = [ 'krbtgt', krb.realm ];

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

    function extractPreAuthHint(methodData) {
	// The preferred ordering of the "hint" pre-authentication data
	// that affect client key selection is: ETYPE-INFO2, followed by
	// ETYPE-INFO, followed by PW-SALT.  As noted in Section 3.1.3, a
	// KDC MUST NOT send ETYPE-INFO or PW-SALT when the client's
	// AS-REQ includes at least one "newer" etype.
	for (var i = 0; i < methodData.length; i++) {
            // The type of the salt changed from OCTET STRING to
            // GeneralString between PA-ETYPE-INFO and
            // PA-ETYPE-INFO2. Arbitrarily declare that typed array is
            // the representation.
            if (methodData[i].padataType == krb.PA_ETYPE_INFO2) {
		var info = krb.ETYPE_INFO2.decodeDER(methodData[i].padataValue);
                if (info.salt !== undefined)
                    info.salt = arrayutils.fromUTF16(info.salt);
                return info;
            }
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
    function defaultSaltForPrincipal(principal) {
        // The default salt string, if none is provided via
        // pre-authentication data, is the concatenation of the
        // principal's realm and name components, in order, with no
        // separators.
	return arrayutils.fromUTF16(
            principal.realm + principal.principalName.nameString.join(""));
    }
    function keyFromPassword(etypeInfo, principal, password) {
	var salt;
	if ("salt" in etypeInfo)
	    salt = etypeInfo.salt;
	else
	    salt = defaultSaltForPrincipal(principal);
	return krb.Key.fromPassword(etypeInfo.etype,
				    password, salt, etypeInfo.s2kparams);
    }

    var padataHandlers = { };
    // TODO: Implement other types of PA-DATA.
    padataHandlers[krb.PA_ENC_TIMESTAMP] = function(asReq, asRep, methodData,
                                                    paData, principal, password) {
        var etypeInfos = extractPreAuthHint(methodData);
	var etypeInfo = null;
	// Find an enctype we support.
	for (var j = 0; j < etypeInfos.length; j++) {
            if (etypeInfos[j].etype in kcrypto.encProfiles) {
		etypeInfo = etypeInfos[j];
		break;
            }
	}
	if (etypeInfo === null)
            throw new Err(Err.Context.KEY, 0x03, 'No supported enctypes');

	// Derive a key.
	var key = keyFromPassword(etypeInfo, principal, password);

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
	});
    };

    KDC.getTGTSession = function (principal, password) {
	return KDC.asReq(principal).then(function (ret) {
            var asReq = ret.asReq, asRep = ret.asRep;
            // Handle pre-authentication.
            if (asRep.msgType == krb.KRB_MT_ERROR &&
		asRep.errorCode == krb.KDC_ERR_PREAUTH_REQUIRED) {
		// Got a pre-auth request. Retry with pre-auth. Pick the
		// first PA-DATA we can handle.
		// TODO: Implement RFC 6113.
		var methodData = krb.METHOD_DATA.decodeDER(asRep.eData);
		for (var i = 0; i < methodData.length; i++) {
                    if (methodData[i].padataType in padataHandlers) {
                        // Found one we have a handler for. Pre-auth
                        // and redo the request.
                        return padataHandlers[methodData[i].padataType](
                            asReq, asRep, methodData, methodData[i],
                            principal, password
                        ).then(function(padata) {
                            // Make a new AS-REQ with our PA-DATA and
                            // process that.
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

            // If any padata fields are present, they may be used to
            // derive the proper secret key to decrypt the message.
	    var etypeInfo = { };
	    if (asRep.padata) {
		var etypeInfos = extractPreAuthHint(asRep.padata);
		if (etypeInfos) {
		    if (etypeInfos.length != 1)
			throw "Bad pre-auth hint";
		    etypeInfo = etypeInfos[0];
		    if ("etype" in etypeInfo &&
			etypeInfo.etype != asRep.encPart.etype)
			throw "Bad pre-auth hint";
		}
	    }
	    etypeInfo.etype = asRep.encPart.etype;
	    var key = keyFromPassword(etypeInfo, principal, password);

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

    /** @constructor */
    KDC.Session = function (asRep, encRepPart) {
        // Just store everything. Whatever.
        this.client = new krb.Principal(asRep.cname, asRep.crealm);
        this.ticket = asRep.ticket;

        this.key = new krb.Key(encRepPart.key.keytype, encRepPart.key.keyvalue);
        this.flags = encRepPart.flags;
        this.starttime = encRepPart.starttime;
        this.endtime = encRepPart.endtime;
        this.renewTill = encRepPart.renewTill;
        this.service = new krb.Principal(encRepPart.sname, encRepPart.srealm);
        this.caddr = encRepPart.caddr;
    };

    KDC.Session.fromDict = function (dict) {
        function dateOrUndef(d) {
            return (d == null) ? undefined : new Date(d);
        }
	return new KDC.Session({
            crealm: dict.crealm,
            cname: dict.cname,
            ticket: {
                tktVno: dict.ticket.tktVno,
                realm: dict.ticket.realm,
                sname: dict.ticket.sname,
                encPart: {
                    kvno: dict.ticket.encPart.kvno,
                    etype: dict.ticket.encPart.etype,
                    cipher: arrayutils.fromByteString(
                        dict.ticket.encPart.cipher)
                }
            }
        }, {
            // Ugh. This really should use Key.fromDict. Need a
            // different ctor for KDC.Session to avoid type confusion.
            key: {
                keytype: dict.key.keytype,
                keyvalue: arrayutils.fromByteString(dict.key.keyvalue)
            },
            lastReq: dict.lastReq,
            nonce: dict.nonce,
            keyExpiration: dict.keyExpiration,
            flags: dict.flags,
            starttime: dateOrUndef(dict.starttime),
            endtime: new Date(dict.endtime),
            renewTill: dateOrUndef(dict.renewTill),
            srealm: dict.srealm,
            sname: dict.sname,
            caddr: dict.caddr
        });
    };

    KDC.Session.prototype.toDict = function() {
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
                    cipher: arrayutils.toByteString(this.ticket.encPart.cipher)
                }
            },
            key: this.key.toDict(),
            flags: this.flags,
            starttime: getTimeOrUndef(this.starttime),
            endtime: this.endtime.getTime(),
            renewTill: getTimeOrUndef(this.renewTill),
            srealm: this.service.realm,
            sname: this.service.principalName,
            caddr: this.caddr
        };
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
	auth.crealm = this.client.realm;
	auth.cname = this.client.principalName;
	if (cksum !== undefined) auth.cksum = cksum;
	auth.ctime = new Date();
	auth.cusec = auth.ctime.getUTCMilliseconds() * 1000;
	auth.ctime.setUTCMilliseconds(0);
	if (subkey !== undefined) auth.subkey = subkey;
	if (seqNumber !== undefined) auth.seqNumber = seqNumber;

	// Encode the authenticator.
	apReq.authenticator = this.key.encryptAs(krb.Authenticator,
						 keyUsage, auth);
	return apReq;
    };

    KDC.Session.prototype.getServiceSession = function(service) {
	return Crypto.retryForEntropy(function() {
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
            var checksum = this.key.checksum(
		krb.KU_TGS_REQ_PA_TGS_REQ_CKSUM,
		krb.KDC_REQ_BODY.encodeDER(tgsReq.reqBody));

            // Requests for additional tickets (KRB_TGS_REQ) MUST contain a
            // padata of PA-TGS-REQ.
            var apReq = this.makeAPReq(krb.KU_TGS_REQ_PA_TGS_REQ, checksum);
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
			this.key, krb.KU_TGS_REQ_ENC_PART, tgsReq, tgsRep);
		}.bind(this));
	}.bind(this));
    };

    KDC.Session.prototype.isExpired = function () {
	return this.endtime <= new Date();
    };

    return KDC;
}());
