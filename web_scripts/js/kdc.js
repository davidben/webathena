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
    asReq.reqBody.kdcOptions = [];
    for(var i = 0; i < 32; i++)
        asReq.reqBody.kdcOptions.push(0);
    // TODO: Pick a reasonable set of keys. These are just taken from
    // a wireshark trace.
    asReq.reqBody.kdcOptions[krb.KDCOptions.forwardable] = 1;
    asReq.reqBody.kdcOptions[krb.KDCOptions.proxiable] = 1;
    asReq.reqBody.kdcOptions[krb.KDCOptions.renewable_ok] = 1;

    asReq.reqBody.principalName = {};
    asReq.reqBody.principalName.nameType = krb.KRB_NT_PRINCIPAL;
    asReq.reqBody.principalName.nameString = [ username ];

    asReq.reqBody.realm = KDC.realm;

    asReq.reqBody.sname = {};
    asReq.reqBody.sname.nameType = krb.KRB_NT_SRV_INST;
    asReq.reqBody.sname.nameString = [ 'krbtgt', KDC.realm ];

    var now = new Date();
    now.setUTCMilliseconds(0);
    var later = new Date(now.getUTCFullYear(),
                         now.getUTCMonth(),
                         now.getUTCDay() + 1,
                         now.getUTCHours(),
                         now.getUTCMinutes(),
                         now.getUTCSeconds());
    asReq.reqBody.from = now;
    asReq.reqBody.till = later;
    try {
	// Avoid negative numbers... ASN.1 errors and stuff.
	asReq.reqBody.nonce = sjcl.random.randomWords(1)[0] & 0x7fffffff;
    } catch (e) {
	if (e instanceof sjcl.exception.notReady) {
	    // TODO: We should retry a little later. We can also
	    // adjust the paranoia argument.
	    window.setTimeout(function () { error(String(e)); });
	    return;
	}
    }
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
                    var reply = krb.AS_REP_OR_ERROR.decodeDER(der)[1];
                    var validate = KDC.validateAsReq(username, reply);
                    if(validate)
                        error(validate);
                    else
                        success(reply);
                    break;
            }
        },
    });
};

KDC.validateAsReq = function(username, reply) {
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
