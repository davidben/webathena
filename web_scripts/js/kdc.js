$.ajaxSetup({
    cache: false,
    contentType: 'text/plain',
    dataType: 'json',
    headers: { 'X-WebKDC-Request' : 'OK' },
    type: 'POST',
});

KDC = {};

KDC.urlBase = '/kdc/v1/';
KDC.realm = 'ATHENA.MIT.EDU'; // XXX

KDC.toBase64 = function(str) {
    return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Latin1.parse(str));
};

KDC.fromBase64 = function(str) {
    return CryptoJS.enc.Latin1.stringify(CryptoJS.enc.Base64.parse(str));
};

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
    // FIXME: Cryptographically secure nonce.
    asReq.reqBody.nonce = Math.floor(Math.random() * (1<<32));
    asReq.reqBody.etype = [18, 17, 16, 23, 1, 3, 2];
    
    $.ajax(KDC.urlBase + 'AS_REQ', {
        data: KDC.toBase64(krb.AS_REQ.encodeDER(asReq)),
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
                    var der = KDC.fromBase64(data.reply);
                    success(krb.AS_REP_OR_ERROR.decodeDER(der)[1]);
                    break;
            }
        },
    });
};
