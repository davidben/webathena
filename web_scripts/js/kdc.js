"use strict";

var Err = function(ctx, code, msg) {
    this.ctx = ctx;
    this.code = code;
    this.msg = msg;
};

Err.Context = {};
Err.Context.KEY = 0x02;
Err.Context.NET = 0x03;
Err.Context.KDC = 0x04;
Err.Context.ENC = 0x05;
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
    try {
        deferred.resolve(action());
    } catch (e) {
        if (e instanceof sjcl.exception.notReady) {
            // Retry when we have more entropy.

            // TODO: Notify the UI in case we want to retry later.
            log("Not enough entropy!");
            var retry = function () {
                sjcl.random.removeEventListener("seeded", retry);
                Crypto.retryForEntropy(action);
            };
            sjcl.random.addEventListener("seeded", retry);
        } else {
            deferred.reject(e);
        }
    }
    return deferred.promise;
};

var KDC = {};

KDC.urlBase = '/kdc/v1/';
KDC.realm = 'ATHENA.MIT.EDU'; // XXX

KDC.Key = function (keytype, keyvalue) {
    this.keytype = keytype;
    this.keyvalue = keyvalue;
};
KDC.Key.prototype.getEncProfile = function () {
    var encProfile = krb.encProfiles[this.keytype];
    if (encProfile === undefined)
        throw new Err(Err.Context.KEY, 0x00, 'Unsupported enctype ' + this.keytype);
    return encProfile;
};
KDC.Key.prototype.decrypt = function (usage, data) {
    if (data.etype != this.keytype)
        throw new Err(Err.Context.KEY, 0x01, 'Key types do not match');
    var encProfile = this.getEncProfile();
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
    var encProfile = krb.encProfiles[keytype];
    if (encProfile === undefined)
        throw new Err(Err.Context.KEY, 0x02, 'Unsupported enctype ' + keytype);
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
                deferred.reject(new Err(Err.Context.NET, 'proxy', data.msg));
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

KDC.asReq = function(username) {
    return Crypto.retryForEntropy(function () {
        var asReq = {};
        asReq.pvno = krb.pvno;
        asReq.msgType = krb.KRB_MT_AS_REQ;
        // TODO: Implement pre-authentication and everything.
        // asReq.padata = []; // Omit if empty.

        // FIXME: This is obnoxious. Also constants.
        asReq.reqBody = {};
        // TODO: Pick a reasonable set of flags. These are just taken from
        // a wireshark trace.
        asReq.reqBody.kdcOptions = krb.KDCOptions.make(
            krb.KDCOptions.forwardable,
            krb.KDCOptions.proxiable,
            krb.KDCOptions.renewable_ok);

        asReq.reqBody.principalName = {};
        asReq.reqBody.principalName.nameType = krb.KRB_NT_PRINCIPAL;
        // FIXME: proper parsing of principals.
        asReq.reqBody.principalName.nameString = username.split('/');

        asReq.reqBody.realm = KDC.realm;

        asReq.reqBody.sname = {};
        asReq.reqBody.sname.nameType = krb.KRB_NT_SRV_INST;
        asReq.reqBody.sname.nameString = [ 'krbtgt', KDC.realm ];

        asReq.reqBody.till = new Date(0);
        asReq.reqBody.nonce = Crypto.randomNonce();
        asReq.reqBody.etype = [krb.enctype.des_cbc_crc,
                               krb.enctype.des_cbc_md5];

        return KDC.kdcProxyRequest(krb.AS_REQ.encodeDER(asReq),
                                   'AS_REQ', krb.AS_REP_OR_ERROR)
            .then(function (asRep) {
                return { asReq: asReq, asRep: asRep };
            });
    });
};

KDC.getTGTSession = function (username, password) {
    return KDC.asReq(username).then(function (ret) {
        var asReq = ret.asReq, asRep = ret.asRep;

        // TODO: Rearrange this code to interpret this error and
        // stuff. We may get a request for pre-authentication, in
        // which case we retry with pre-auth after prompting for
        // the password. (We already have the password, but I
        // believe in theory this could be written so that we
        // prompt on demand.)
        if (asRep.msgType == krb.KRB_MT_ERROR)
            throw new Err(Err.Context.KDC, asRep.errorCode, asRep.eText);

        // The default salt string, if none is provided via
        // pre-authentication data, is the concatenation of the
        // principal's realm and name components, in order, with
        // no separators.
        var salt = asReq.reqBody.realm + username;
        var key = KDC.Key.fromPassword(asRep.encPart.etype, password, salt);

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

    // If any padata fields are present, they may be used to
    // derive the proper secret key to decrypt the message.
    if (kdcRep.padata) {
        // TODO: Do something about this one.
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
    apReq.authenticator = this.key.encrypt(keyUsage,
                                           krb.Authenticator.encodeDER(auth));
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
        // For now just pass service in a pair of [PrincipalName,
        // Realm]. We need to be able to parse these things though.
        tgsReq.reqBody.sname = service[0];
        tgsReq.reqBody.realm = service[1];

        // TODO: Do we want to request the maximum end time? Seems a
        // reasonable default I guess.
        tgsReq.reqBody.till = new Date(0);
        tgsReq.reqBody.nonce = Crypto.randomNonce();
        tgsReq.reqBody.etype = [krb.enctype.des_cbc_crc,
                                krb.enctype.des_cbc_md5];

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
                                   'TGS_REQ', krb.TGS_REP_OR_ERROR);
    }).then(function (tgsRep) {
        // TODO: Rearrange this code to interpret this error and
        // stuff. We may get a request for pre-authentication, in
        // which case we retry with pre-auth after prompting for
        // the password. (We already have the password, but I
        // believe in theory this could be written so that we
        // prompt on demand.)
        if(tgsRep.msgType == krb.KRB_MT_ERROR)
            throw new Err(Err.Context.KDC, tgsRep.errorCode, tgsRep.eText);

        // When the KRB_TGS_REP is received by the client, it is
        // processed in the same manner as the KRB_AS_REP
        // processing described above.  The primary difference is
        // that the ciphertext part of the response must be
        // decrypted using the sub-session key from the
        // Authenticator, if it was specified in the request, or
        // the session key from the TGT, rather than the client's
        // secret key.
        //
        // If we use a subkey, the usage might change I think.
        return KDC.sessionFromKDCRep(
            self.key, krb.KU_TGS_REQ_ENC_PART, tgsReq, tgsRep);
    });
};

KDC.Session.prototype.isExpired = function () {
    return new Date(this.endtime) <= new Date();
};
