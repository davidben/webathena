"use strict";

$.ajaxSetup({
    cache: false,
    contentType: 'text/plain',
    dataType: 'json',
    headers: { 'X-WebKDC-Request' : 'OK' },
    type: 'POST',
});

var Crypto = {};

Crypto.toBase64 = function(str) {
    return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Latin1.parse(str));
};

Crypto.fromBase64 = function(str) {
    return CryptoJS.enc.Latin1.stringify(CryptoJS.enc.Base64.parse(str));
};

Crypto.randomNonce = function() {
    try {
        var word = sjcl.random.randomWords(1)[0];
	// Twos-complement it if negative.
	if (word < 0)
	    word += 0x80000000;
	return word;
    } catch (e) {
        if (e instanceof sjcl.exception.notReady) {
            // TODO: We should retry a little later. We can also
            // adjust the paranoia argument.
            window.setTimeout(function () { error(String(e)); });
            return;
        }
        throw e;
    }
};

var KDC = {};

KDC.urlBase = '/kdc/v1/';
KDC.realm = 'ATHENA.MIT.EDU'; // XXX

KDC.asReq = function(username, success, error) {
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
    asReq.reqBody.principalName.nameString = [ username ];

    asReq.reqBody.realm = KDC.realm;

    asReq.reqBody.sname = {};
    asReq.reqBody.sname.nameType = krb.KRB_NT_SRV_INST;
    asReq.reqBody.sname.nameString = [ 'krbtgt', KDC.realm ];

    var now = new Date();
    now.setUTCMilliseconds(0);
    var later = new Date(Date.UTC(now.getUTCFullYear(),
                                  now.getUTCMonth(),
                                  now.getUTCDate() + 1,
                                  now.getUTCHours(),
                                  now.getUTCMinutes(),
                                  now.getUTCSeconds()));
    asReq.reqBody.from = now;
    asReq.reqBody.till = later;
    asReq.reqBody.nonce = Crypto.randomNonce();
    asReq.reqBody.etype = [krb.enctype.des_cbc_crc];
    
    $.ajax(KDC.urlBase + 'AS_REQ', {
        data: Crypto.toBase64(krb.AS_REQ.encodeDER(asReq)),
        error: function(xhr, status, error) {
            var msg = status || 'unknown error';
            if(error)
                msg += ': ' + error;
            error(msg);
        },
        success: function(data, status, xhr) {
            switch(data.status) {
                case 'ERROR':
                    error(data.msg);
                    break;
                case 'TIMEOUT':
                    error('KDC connection timed out');
                    break;
                case 'OK':
                    var der = Crypto.fromBase64(data.reply);
                    success(asReq, krb.AS_REP_OR_ERROR.decodeDER(der)[1]);
                    break;
            }
        },
    });
};

KDC.getTGTSession = function (username, password, success, error) {
    KDC.asReq(username, function (asReq, asRep) {
        var validate = KDC.validateAsRep(username, asRep);
        if (validate) {
            error(validate);
            return;
        }

        // 3.1.5.  Receipt of KRB_AS_REP Message

        // If any padata fields are present, they may be used to
        // derive the proper secret key to decrypt the message.
        if (asRep.padata) {
            // TODO: Do something about this one.
        }

        // The default salt string, if none is provided via
        // pre-authentication data, is the concatenation of the
        // principal's realm and name components, in order, with
        // no separators.
        var salt = KDC.realm + username;
        var encProfile = krb.encProfiles[asRep.encPart.etype];
        if (encProfile === undefined) {
            error('Unsupported enctype ' + asRep.encPart.etype);
            return;
        }

        var key = encProfile.stringToKey(password, salt);
        // The key usage value for encrypting this field is 3 in
        // an AS-REP message, using the client's long-term key or
        // another key selected via pre-authentication mechanisms.
        var derivedKey = encProfile.deriveKey(key, krb.KU_AS_REQ_ENC_PART);

        // The client decrypts the encrypted part of the response
        // using its secret key...
        try {
            var t = encProfile.decrypt(
                derivedKey,
                encProfile.initialCipherState(derivedKey, false),
                asRep.encPart.cipher);
        } catch(e) {
            error(e);
            return;
        }
        // Some ciphers add padding, so we can't abort if there is
        // data left over. Also allow an EncTGSRepPart because the
        // MIT KDC is screwy.
        var encRepPart = krb.EncASorTGSRepPart.decodeDERPrefix(t[1])[0][1];

	// ...and verifies that the nonce in the encrypted part
	// matches the nonce it supplied in its request (to detect
	// replays).
        console.log(asReq);
        console.log(encRepPart);
	if (asReq.reqBody.nonce != encRepPart.nonce) {
	    error('Bad nonce');
	    return;
	}

	// It also verifies that the sname and srealm in the
	// response match those in the request (or are otherwise
	// expected values), and that the host address field is
	// also correct.
	if (!krb.principalNamesEqual(asReq.reqBody.sname, encRepPart.sname)) {
	    error('Bad sname');
	    return;
	}

	// It then stores the ticket, session key, start and
	// expiration times, and other information for later use.
	success(new KDC.Session(asRep, encRepPart));

	// TODO: Do we want to do anything with last-req and
	// authtime?
    }, error);
};

KDC.validateAsRep = function(username, reply) {
    // TODO: Rearrange this code to interpret this error and stuff. We
    // may get a request for pre-authentication, in which case we
    // retry with pre-auth after prompting for the password. (We
    // already have the password, but I believe in theory this could
    // be written so that we prompt on demand.)
    if(reply.msgType == krb.KRB_MT_ERROR)
        return reply.eText + ' (' + reply.errorCode + ')';

    // 3.1.5.  Receipt of KRB_AS_REP Message

    // If the reply message type is KRB_AS_REP, then the
    // client verifies that the cname and crealm fields in the
    // cleartext portion of the reply match what it requested.
    if(reply.crealm != KDC.realm)
        return 'crealm does not match';
    if(reply.cname.nameType != krb.KRB_NT_PRINCIPAL ||
       reply.cname.nameString.length != 1 ||
       reply.cname.nameString[0] != username)
        return 'cname does not match';
};


KDC.Session = function (asRep, encRepPart) {
    // Just store everything. Whatever.
    this.crealm = asRep.crealm;
    this.cname = asRep.cname;
    this.ticket = asRep.ticket;

    this.key = encRepPart.key;
    this.flags = encRepPart.flags;
    this.starttime = encRepPart.starttime;
    this.endtime = encRepPart.endtime;
    this.renewTill = encRepPart.renewTill;
    this.srealm = encRepPart.srealm;
    this.sname = encRepPart.sname;
    this.caddr = encRepPart.caddr;
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
    auth.seqNumber = seqNumber;

    // Encode the authenticator.
    // FIXME: This is kinda tedious.
    var encProfile = krb.encProfiles[this.key.keytype];
    if (encProfile === undefined)
        throw "Unknown enctype " + this.key.keytype;
    var derivedKey = encProfile.deriveKey(this.key.keyvalue, keyUsage);
    apReq.authenticator = encProfile.encrypt(
        derivedKey,
        encProfile.initialCipherState(derivedKey, true),
        krb.Authenticator.encodeDER(auth))[1];

    return apReq;
};

KDC.Session.prototype.getServiceSession = function (blah, success, error) {
    var tgsReq = { };
    tgsReq.pvno = krb.pvno;
    tgsReq.msgType = krb.KRB_MT_TGS_REQ;

    // Requests for additional tickets (KRB_TGS_REQ) MUST contain a
    // padata of PA-TGS-REQ.

    // FIXME: Do we need a subkey and stuff? We can't forward the TGT
    // session key to the random server. I'm still unclear on whether
    // we have to do anything interesting to achieve that.
    // TODO: Checksum the reqBody and pass it in.
    var apReq = this.makeAPReq(krb.KU_TGS_REQ_PA_TGS_REQ);
    tgsReq.padata = [{ padataType: krb.PA_TGS_REQ,
                       padataValue: krb.AP_REQ.encodeDER(apReq) }];

    tgsReq.reqBody = { };
    // TODO: Flags?
    tgsReq.reqBody.kdcOptions = krb.KDCOptions.make();
    // TODO: The rest of this function.
    tgsReq.reqBody.nonce = Crypto.randomNonce();
};
