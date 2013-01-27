"use strict";

var krb = { };

// 5.2.1.  KerberosString
krb.KerberosString = asn1.GeneralString;  // TODO: IA5String restriction

// 5.2.4.  Constrained Integer Types
krb.Int32 = asn1.INTEGER.rangeConstrained(-2147483648, 2147483647);
krb.UInt32 = asn1.INTEGER.rangeConstrained(0, 4294967295);
krb.Microseconds = asn1.INTEGER.rangeConstrained(0, 999999);

// 5.2.2.  Realm and PrincipalName
krb.Realm = krb.KerberosString;
krb.PrincipalName = new asn1.SEQUENCE(
    [{id: 'nameType', type: krb.Int32.tagged(asn1.tag(0))},
     {id: 'nameString',
      type: new asn1.SEQUENCE_OF(krb.KerberosString).tagged(asn1.tag(1))}]);
krb.principalNamesEqual = function (a, b) {
    if (a.nameString.length != b.nameString.length)
        return false;
    for (var i = 0; i < a.nameString.length; i++) {
        if (a.nameString[i] != b.nameString[i])
            return false;
    }
    return true;
};

// 5.2.3.  KerberosTime
krb.KerberosTime = asn1.GeneralizedTime.constrained(function (date) {
    if (date.getUTCMilliseconds() != 0)
        throw "Milliseconds not allowed in KerberosTime";
});

// 5.2.5.  HostAddress and HostAddresses
krb.HostAddress = new asn1.SEQUENCE(
    [{id: 'addrType', type: krb.Int32.tagged(asn1.tag(0))},
     {id: 'address', type: asn1.OCTET_STRING.tagged(asn1.tag(1))}]);
krb.HostAddresses = new asn1.SEQUENCE_OF(krb.HostAddress);

// 5.2.6.  AuthorizationData
krb.AuthorizationData = new asn1.SEQUENCE_OF(
    new asn1.SEQUENCE(
        [{id: 'adType', type: krb.Int32.tagged(asn1.tag(0))},
         {id: 'adData', type: asn1.OCTET_STRING.tagged(asn1.tag(1))}]));

// 5.2.6.1.  IF-RELEVANT
krb.AD_IF_RELEVANT = krb.AuthorizationData;

// 5.2.9.  Cryptosystem-Related Types
krb.EncryptedData = new asn1.SEQUENCE(
    [{id: 'etype', type: krb.Int32.tagged(asn1.tag(0))},
     {id: 'kvno', type: krb.UInt32.tagged(asn1.tag(1)), optional: true},
     {id: 'cipher', type: asn1.OCTET_STRING.tagged(asn1.tag(2))}]);
krb.EncryptionKey = new asn1.SEQUENCE(
    [{id: 'keytype', type: krb.Int32.tagged(asn1.tag(0))},
     {id: 'keyvalue', type: asn1.OCTET_STRING.tagged(asn1.tag(1))}]);
krb.Checksum = new asn1.SEQUENCE(
    [{id: 'cksumtype', type: krb.Int32.tagged(asn1.tag(0))},
     {id: 'checksum', type: asn1.OCTET_STRING.tagged(asn1.tag(1))}]);

// 5.2.6.2.  KDCIssued
krb.AD_KDCIssued = new asn1.SEQUENCE( 
    [{id: 'adChecksum', type: krb.Checksum.tagged(asn1.tag(0))},
     {id: 'iRealm', type: krb.Realm.tagged(asn1.tag(1)), optional: true},
     {id: 'iSname', type: krb.PrincipalName.tagged(asn1.tag(2)),
      optional: true},
     {id: 'elements', type: krb.AuthorizationData.tagged(asn1.tag(3))}]);

// 5.2.6.3.  AND-OR
krb.AD_AND_OR = new asn1.SEQUENCE(
    [{id: 'conditionCount', type: krb.Int32.tagged(asn1.tag(0))},
     {id: 'elements', type: krb.AuthorizationData.tagged(asn1.tag(1))}]);

// 5.2.6.4.  MANDATORY-FOR-KDC
krb.AD_MANDATORY_FOR_KDC = krb.AuthorizationData;

// 5.2.7.  PA-DATA
krb.PA_DATA = new asn1.SEQUENCE(
    [{id: 'padataType', type: krb.Int32.tagged(asn1.tag(1))},
     {id: 'padataValue', type: asn1.OCTET_STRING.tagged(asn1.tag(2))}]);

// 5.2.7.2.  Encrypted Timestamp Pre-authentication
krb.ENC_TIMESTAMP = krb.EncryptedData;
krb.ENC_TS_ENC = new asn1.SEQUENCE(
    [{id: 'patimestamp', type: krb.KerberosTime.tagged(asn1.tag(0))},
     {id: 'pausec', type: krb.Microseconds.tagged(asn1.tag(1)),
      optional: true}]);

// 5.2.7.4.  PA-ETYPE-INFO
krb.ETYPE_INFO_ENTRY = new asn1.SEQUENCE(
    [{id: 'etype', type: krb.Int32.tagged(asn1.tag(0))},
     {id: 'salt', type: asn1.OCTET_STRING.tagged(asn1.tag(1)),
      optional: true}]);
krb.ETYPE_INFO = new asn1.SEQUENCE_OF(krb.ETYPE_INFO_ENTRY);

// 5.2.7.5.  PA-ETYPE-INFO2
krb.ETYPE_INFO2_ENTRY = new asn1.SEQUENCE(
    [{id: 'etype', type: krb.Int32.tagged(asn1.tag(0))},
     {id: 'salt', type: krb.KerberosString.tagged(asn1.tag(1)),
      optional: true},
     {id: 's2kparams', type: asn1.OCTET_STRING.tagged(asn1.tag(2)),
      optional: true}]);
krb.ETYPE_INFO2 = new asn1.SEQUENCE_OF(krb.ETYPE_INFO2_ENTRY);

// 5.2.8.  KerberosFlags
krb.KerberosFlags = asn1.BIT_STRING.constrained(function (bs) {
    if (bs.length < 32)
        throw "Invalid KerberosFlags";
});
krb.KerberosFlags.makeZeroFlags = function (num) {
    num = num || 32;
    var bits = [];
    for (var i = 0; i < num; i++) {
        bits.push(0);
    }
    return bits;
};
/**
 * @this {asn1.Type}
 * @return {Array.<number>}
 */
krb.KerberosFlags.make = function () {
    var num = 32;
    for (var i = 0; i < arguments.length; i++) {
        num = Math.max(num, arguments[i]);
    }
    var bits = this.makeZeroFlags(num);
    for (var i = 0; i < arguments.length; i++) {
        bits[arguments[i]] = 1;
    }
    return bits;
};

// 5.3.  Tickets
krb.Ticket = new asn1.SEQUENCE(
    [{id: 'tktVno', type: asn1.INTEGER.valueConstrained(5).tagged(asn1.tag(0))},
     {id: 'realm', type: krb.Realm.tagged(asn1.tag(1))},
     {id: 'sname', type: krb.PrincipalName.tagged(asn1.tag(2))},
     {id: 'encPart', type: krb.EncryptedData.tagged(asn1.tag(3))}]
).tagged(asn1.tag(1, asn1.TAG_CONSTRUCTED, asn1.TAG_APPLICATION));

krb.TicketFlags = krb.KerberosFlags.subtype();
/** @const */ krb.TicketFlags.reserved = 0;
/** @const */ krb.TicketFlags.forwardable = 1;
/** @const */ krb.TicketFlags.forwarded = 2;
/** @const */ krb.TicketFlags.proxiable = 3;
/** @const */ krb.TicketFlags.proxy = 4;
/** @const */ krb.TicketFlags.may_postdate = 5;
/** @const */ krb.TicketFlags.postdated = 6;
/** @const */ krb.TicketFlags.invalid = 7;
/** @const */ krb.TicketFlags.renewable = 8;
/** @const */ krb.TicketFlags.initial = 9;
/** @const */ krb.TicketFlags.pre_authent = 10;
/** @const */ krb.TicketFlags.hw_authent = 11;
/** @const */ krb.TicketFlags.transited_policy_checked = 12;
/** @const */ krb.TicketFlags.ok_as_delegate = 13;

krb.TransitedEncoding = new asn1.SEQUENCE(
    [{id: 'trType', type: krb.Int32.tagged(asn1.tag(0))},
     {id: 'contents', type: asn1.OCTET_STRING.tagged(asn1.tag(1))}]);
krb.EncTicketPart = new asn1.SEQUENCE(
    [{id: 'flags', type: krb.TicketFlags.tagged(asn1.tag(0))},
     {id: 'key', type: krb.EncryptionKey.tagged(asn1.tag(1))},
     {id: 'crealm', type: krb.Realm.tagged(asn1.tag(2))},
     {id: 'cname', type: krb.PrincipalName.tagged(asn1.tag(3))},
     {id: 'transited', type: krb.TransitedEncoding.tagged(asn1.tag(4))},
     {id: 'authtime', type: krb.KerberosTime.tagged(asn1.tag(5))},
     {id: 'starttime', type: krb.KerberosTime.tagged(asn1.tag(6)),
      optional: true},
     {id: 'endtime', type: krb.KerberosTime.tagged(asn1.tag(7))},
     {id: 'renewTill', type: krb.KerberosTime.tagged(asn1.tag(8)),
      optional: true},
     {id: 'caddr', type: krb.HostAddresses.tagged(asn1.tag(9)),
      optional: true},
     {id: 'authorizationData', type: krb.AuthorizationData.tagged(asn1.tag(10)),
      optional: true}]
).tagged(asn1.tag(3, asn1.TAG_CONSTRUCTED, asn1.TAG_APPLICATION));

// 5.9.1.  KRB_ERROR Definition
krb.KRB_ERROR = new asn1.SEQUENCE(
    [{id: 'pvno', type: asn1.INTEGER.valueConstrained(5).tagged(asn1.tag(0))},
     {id: 'msgType',
      type: asn1.INTEGER.valueConstrained(30).tagged(asn1.tag(1))},
     {id: 'ctime', type: krb.KerberosTime.tagged(asn1.tag(2)), optional: true},
     {id: 'cusec', type: krb.Microseconds.tagged(asn1.tag(3)), optional: true},
     {id: 'stime', type: krb.KerberosTime.tagged(asn1.tag(4))},
     {id: 'susec', type: krb.Microseconds.tagged(asn1.tag(5))},
     {id: 'errorCode', type: krb.Int32.tagged(asn1.tag(6))},
     {id: 'crealm', type: krb.Realm.tagged(asn1.tag(7)), optional: true},
     {id: 'cname', type: krb.PrincipalName.tagged(asn1.tag(8)), optional: true},
     {id: 'realm', type: krb.Realm.tagged(asn1.tag(9))},
     {id: 'sname', type: krb.PrincipalName.tagged(asn1.tag(10))},
     {id: 'eText', type: krb.KerberosString.tagged(asn1.tag(11)),
      optional: true},
     {id: 'eData', type: asn1.OCTET_STRING.tagged(asn1.tag(12)),
      optional: true}]
).tagged(asn1.tag(30, asn1.TAG_CONSTRUCTED, asn1.TAG_APPLICATION));
krb.METHOD_DATA = new asn1.SEQUENCE_OF(krb.PA_DATA);
krb.TYPED_DATA = new asn1.SEQUENCE(
    [{id: 'dataType', type: krb.Int32.tagged(asn1.tag(0))},
     {id: 'dataValue', type: asn1.OCTET_STRING.tagged(asn1.tag(1)),
      optional: true}]);

// 5.4.1.  KRB_KDC_REQ Definition
krb.KDCOptions = krb.KerberosFlags.subtype();
/** @const */ krb.KDCOptions.reserved = 0;
/** @const */ krb.KDCOptions.forwardable = 1;
/** @const */ krb.KDCOptions.forwarded = 2;
/** @const */ krb.KDCOptions.proxiable = 3;
/** @const */ krb.KDCOptions.proxy = 4;
/** @const */ krb.KDCOptions.allow_postdate = 5;
/** @const */ krb.KDCOptions.postdated = 6;
/** @const */ krb.KDCOptions.renewable = 8;
/** @const */ krb.KDCOptions.opt_hardware_auth = 11;
/** @const */ krb.KDCOptions.disable_transited_check = 26;
/** @const */ krb.KDCOptions.renewable_ok = 27;
/** @const */ krb.KDCOptions.enc_tkt_in_skey = 28;
/** @const */ krb.KDCOptions.renew = 30;
/** @const */ krb.KDCOptions.validate = 31;

krb.KDC_REQ_BODY = new asn1.SEQUENCE(
    [{id: 'kdcOptions', type: krb.KDCOptions.tagged(asn1.tag(0))},
     {id: 'principalName', type: krb.PrincipalName.tagged(asn1.tag(1)),
      optional: true},
     {id: 'realm', type: krb.Realm.tagged(asn1.tag(2))},
     {id: 'sname', type: krb.PrincipalName.tagged(asn1.tag(3)),
      optional: true},
     {id: 'from', type: krb.KerberosTime.tagged(asn1.tag(4)),
      optional: true},
     {id: 'till', type: krb.KerberosTime.tagged(asn1.tag(5))},
     {id: 'rtime', type: krb.KerberosTime.tagged(asn1.tag(6)),
      optional: true},
     {id: 'nonce', type: krb.UInt32.tagged(asn1.tag(7))},
     {id: 'etype', type: new asn1.SEQUENCE_OF(krb.Int32).tagged(asn1.tag(8))},
     {id: 'addresses', type: krb.HostAddresses.tagged(asn1.tag(9)),
      optional: true},
     {id: 'encAuthorizationData', type: krb.EncryptedData.tagged(asn1.tag(10)),
      optional: true},
     {id: 'additionalTickets',
      type: new asn1.SEQUENCE_OF(krb.Ticket).tagged(asn1.tag(10)),
      optional: true}]);
krb.KDC_REQ = new asn1.SEQUENCE(
    [{id: 'pvno', type: asn1.INTEGER.valueConstrained(5).tagged(asn1.tag(1))},
     {id: 'msgType',
      type: asn1.INTEGER.valueConstrained(10, 12).tagged(asn1.tag(2))},
     {id: 'padata',
      type: new asn1.SEQUENCE_OF(krb.PA_DATA).tagged(asn1.tag(3)),
      optional: true},
     {id: 'reqBody', type: krb.KDC_REQ_BODY.tagged(asn1.tag(4))}]);
krb.AS_REQ = krb.KDC_REQ.tagged(asn1.tag(10, asn1.TAG_CONSTRUCTED,
                                         asn1.TAG_APPLICATION));
krb.TGS_REQ = krb.KDC_REQ.tagged(asn1.tag(12, asn1.TAG_CONSTRUCTED,
                                         asn1.TAG_APPLICATION));

// 5.4.2.  KRB_KDC_REP Definition
krb.KDC_REP = new asn1.SEQUENCE(
    [{id: 'pvno', type: asn1.INTEGER.valueConstrained(5).tagged(asn1.tag(0))},
     {id: 'msgType',
      type: asn1.INTEGER.valueConstrained(11, 13).tagged(asn1.tag(1))},
     {id: 'padata',
      type: new asn1.SEQUENCE_OF(krb.PA_DATA).tagged(asn1.tag(2)),
      optional: true},
     {id: 'crealm', type: krb.Realm.tagged(asn1.tag(3))},
     {id: 'cname', type: krb.PrincipalName.tagged(asn1.tag(4))},
     {id: 'ticket', type: krb.Ticket.tagged(asn1.tag(5))},
     {id: 'encPart', type: krb.EncryptedData.tagged(asn1.tag(6))}]);
krb.AS_REP = krb.KDC_REP.tagged(asn1.tag(11, asn1.TAG_CONSTRUCTED,
                                         asn1.TAG_APPLICATION));
krb.TGS_REP = krb.KDC_REP.tagged(asn1.tag(13, asn1.TAG_CONSTRUCTED,
                                          asn1.TAG_APPLICATION));

krb.AS_REP_OR_ERROR = new asn1.CHOICE([krb.AS_REP, krb.KRB_ERROR]);
krb.TGS_REP_OR_ERROR = new asn1.CHOICE([krb.TGS_REP, krb.KRB_ERROR]);

krb.LastReq = new asn1.SEQUENCE_OF(new asn1.SEQUENCE(
    [{id: 'lrType', type: krb.Int32.tagged(asn1.tag(0))},
     {id: 'lrValue', type: krb.KerberosTime.tagged(asn1.tag(1))}]));
krb.EncKDCRepPart = new asn1.SEQUENCE(
    [{id: 'key', type: krb.EncryptionKey.tagged(asn1.tag(0))},
     {id: 'lastReq', type: krb.LastReq.tagged(asn1.tag(1))},
     {id: 'nonce', type: krb.UInt32.tagged(asn1.tag(2))},
     {id: 'keyExpiration', type: krb.KerberosTime.tagged(asn1.tag(3)),
      optional: true},
     {id: 'flags', type: krb.TicketFlags.tagged(asn1.tag(4))},
     {id: 'authtime', type: krb.KerberosTime.tagged(asn1.tag(5))},
     {id: 'starttime', type: krb.KerberosTime.tagged(asn1.tag(6)),
      optional: true},
     {id: 'endtime', type: krb.KerberosTime.tagged(asn1.tag(7))},
     {id: 'renewTill', type: krb.KerberosTime.tagged(asn1.tag(8)),
      optional: true},
     {id: 'srealm', type: krb.Realm.tagged(asn1.tag(9))},
     {id: 'sname', type: krb.PrincipalName.tagged(asn1.tag(10))},
     {id: 'caddr', type: krb.HostAddresses.tagged(asn1.tag(11)),
      optional: true}]);
krb.EncASRepPart = krb.EncKDCRepPart.tagged(asn1.tag(25, asn1.TAG_CONSTRUCTED,
                                                     asn1.TAG_APPLICATION));
krb.EncTGSRepPart = krb.EncKDCRepPart.tagged(asn1.tag(26, asn1.TAG_CONSTRUCTED,
                                                      asn1.TAG_APPLICATION));
// The MIT KDC uses the wrong tag. Sigh.
krb.EncASorTGSRepPart = new asn1.CHOICE([krb.EncASRepPart, krb.EncTGSRepPart]);

// 5.5.1.  KRB_AP_REQ Definition
krb.APOptions = krb.KerberosFlags.subtype();
/** @const */ krb.APOptions.use_session_key = 1;
/** @const */ krb.APOptions.mutual_required = 2;
krb.AP_REQ = new asn1.SEQUENCE(
    [{id: 'pvno', type: asn1.INTEGER.valueConstrained(5).tagged(asn1.tag(0))},
     {id: 'msgType',
      type: asn1.INTEGER.valueConstrained(14).tagged(asn1.tag(1))},
     {id: 'apOptions', type: krb.APOptions.tagged(asn1.tag(2))},
     {id: 'ticket', type: krb.Ticket.tagged(asn1.tag(3))},
     {id: 'authenticator', type: krb.EncryptedData.tagged(asn1.tag(4))}]
).tagged(asn1.tag(14, asn1.TAG_CONSTRUCTED, asn1.TAG_APPLICATION));

krb.Authenticator = new asn1.SEQUENCE(
    [{id: 'authenticatorVno',
      type: asn1.INTEGER.valueConstrained(5).tagged(asn1.tag(0))},
     {id: 'crealm', type: krb.Realm.tagged(asn1.tag(1))},
     {id: 'cname', type: krb.PrincipalName.tagged(asn1.tag(2))},
     {id: 'cksum', type: krb.Checksum.tagged(asn1.tag(3)), optional: true},
     {id: 'cusec', type: krb.Microseconds.tagged(asn1.tag(4))},
     {id: 'ctime', type: krb.KerberosTime.tagged(asn1.tag(5))},
     {id: 'subkey', type: krb.EncryptionKey.tagged(asn1.tag(6)),
      optional: true},
     {id: 'seqNumber', type: krb.UInt32.tagged(asn1.tag(7)), optional: true},
     {id: 'authorizationData', type: krb.AuthorizationData.tagged(asn1.tag(8)),
      optional: true}]
).tagged(asn1.tag(2, asn1.TAG_CONSTRUCTED, asn1.TAG_APPLICATION));


// TODO: 5.5.2.  KRB_AP_REP Definition

// TODO: 5.6.1.  KRB_SAFE Definition

// TODO: 5.7.1.  KRB_PRIV Definition

// TODO: 5.8.1.  KRB_CRED Definition

// 7.5.1.  Key Usage Numbers
/** @const */ krb.KU_AS_REQ_PA_ENC_TIMESTAMP = 1;
/** @const */ krb.KU_KDC_REP_TICKET = 2;
/** @const */ krb.KU_AS_REQ_ENC_PART = 3;
/** @const */ krb.KU_TGS_REQ_BODY_AUTH_DATA = 4;
/** @const */ krb.KU_TGS_REQ_BODY_AUTH_DATA_SUBKEY = 5;
/** @const */ krb.KU_TGS_REQ_PA_TGS_REQ_CKSUM = 6;
/** @const */ krb.KU_TGS_REQ_PA_TGS_REQ = 7;
/** @const */ krb.KU_TGS_REQ_ENC_PART = 8;
/** @const */ krb.KU_TGS_REQ_ENC_PART_SUBKEY = 9;
/** @const */ krb.KU_AP_REQ_AUTHENTICATOR_CKSUM = 10;
/** @const */ krb.KU_AP_REQ_AUTHENTICATOR = 11;
/** @const */ krb.KU_AP_REP_ENC_PART = 12;
/** @const */ krb.KU_KRB_PRIV_ENC_PART = 13;
/** @const */ krb.KU_KRB_CRED_ENC_PART = 14;
/** @const */ krb.KU_KRB_SAFE_CKSUM = 15;
/** @const */ krb.KU_AD_KDC_ISSUED_CKSUM = 19;
/** @const */ krb.KU_GENERIC_ENC = 1024;
/** @const */ krb.KU_GENERIC_CKSUM = 1025;

// 7.5.2.  PreAuthentication Data Types
/** @const */ krb.PA_TGS_REQ                = 1;
/** @const */ krb.PA_ENC_TIMESTAMP          = 2;
/** @const */ krb.PA_PW_SALT                = 3;
/** @const */ krb.PA_ENC_UNIX_TIME          = 5;
/** @const */ krb.PA_SANDIA_SECUREID        = 6;
/** @const */ krb.PA_SESAME                 = 7;
/** @const */ krb.PA_OSF_DCE                = 8;
/** @const */ krb.PA_CYBERSAFE_SECUREID     = 9;
/** @const */ krb.PA_AFS3_SALT              = 10;
/** @const */ krb.PA_ETYPE_INFO             = 11;
/** @const */ krb.PA_SAM_CHALLENGE          = 12;
/** @const */ krb.PA_SAM_RESPONSE           = 13;
/** @const */ krb.PA_PK_AS_REQ_OLD          = 14;
/** @const */ krb.PA_PK_AS_REP_OLD          = 15;
/** @const */ krb.PA_PK_AS_REQ              = 16;
/** @const */ krb.PA_PK_AS_REP              = 17;
/** @const */ krb.PA_ETYPE_INFO2            = 19;
/** @const */ krb.PA_USE_SPECIFIED_KVNO     = 20;
/** @const */ krb.PA_SAM_REDIRECT           = 21;
/** @const */ krb.PA_GET_FROM_TYPED_DATA    = 22;
/** @const */ krb.TD_PADATA                 = 22;
/** @const */ krb.PA_SAM_ETYPE_INFO         = 23;
/** @const */ krb.PA_ALT_PRINC              = 24;
/** @const */ krb.PA_SAM_CHALLENGE2         = 30;
/** @const */ krb.PA_SAM_RESPONSE2          = 31;
/** @const */ krb.PA_EXTRA_TGT              = 41;
/** @const */ krb.TD_PKINIT_CMS_CERTIFICATES= 101;
/** @const */ krb.TD_KRB_PRINCIPAL          = 102;
/** @const */ krb.TD_KRB_REALM              = 103;
/** @const */ krb.TD_TRUSTED_CERTIFIERS     = 104;
/** @const */ krb.TD_CERTIFICATE_INDEX      = 105;
/** @const */ krb.TD_APP_DEFINED_ERROR      = 106;
/** @const */ krb.TD_REQ_NONCE              = 107;
/** @const */ krb.TD_REQ_SEQ                = 108;
/** @const */ krb.PA_PAC_REQUEST            = 128;

// 7.5.3.  Address Types
/** @const */ krb.ADDRESS_IPV4              = 2;
/** @const */ krb.ADDRESS_DIRECTIONAL       = 3;
/** @const */ krb.ADDRESS_CHAOSNET          = 5;
/** @const */ krb.ADDRESS_XNS               = 6;
/** @const */ krb.ADDRESS_ISO               = 7;
/** @const */ krb.ADDRESS_DECNET_PHASE_IV   = 12;
/** @const */ krb.ADDRESS_APPLETALK_UDP     = 16;
/** @const */ krb.ADDRESS_NETBIOS           = 20;
/** @const */ krb.ADDRESS_IPV6              = 24;

// 7.5.4.  Authorization Data Types
/** @const */ krb.AD_IF_RELEVANT                     = 1;
/** @const */ krb.AD_INTENDED_FOR_SERVER             = 2;
/** @const */ krb.AD_INTENDED_FOR_APPLICATION_CLASS  = 3;
/** @const */ krb.AD_KDC_ISSUED                      = 4;
/** @const */ krb.AD_AND_OR                          = 5;
/** @const */ krb.AD_MANDATORY_TICKET_EXTENSIONS     = 6;
/** @const */ krb.AD_IN_TICKET_EXTENSIONS            = 7;
/** @const */ krb.AD_MANDATORY_FOR_KDC               = 8;
/** @const */ krb.OSF_DCE                            = 64;
/** @const */ krb.SESAME                             = 65;
/** @const */ krb.AD_OSF_DCE_PKI_CERTID              = 66;
/** @const */ krb.AD_WIN2K_PAC                       = 128;
/** @const */ krb.AD_ETYPE_NEGOTIATION               = 129;

// 7.5.5.  Transited Encoding Types
/** @const */ krb.DOMAIN_X500_COMPRESS               = 1;

// 7.5.6.  Protocol Version Number
/** @const */ krb.pvno                               = 5;

// 7.5.7.  Kerberos Message Types
/** @const */ krb.KRB_MT_AS_REQ    = 10;
/** @const */ krb.KRB_MT_AS_REP    = 11;
/** @const */ krb.KRB_MT_TGS_REQ   = 12;
/** @const */ krb.KRB_MT_TGS_REP   = 13;
/** @const */ krb.KRB_MT_AP_REQ    = 14;
/** @const */ krb.KRB_MT_AP_REP    = 15;
/** @const */ krb.KRB_MT_SAFE      = 20;
/** @const */ krb.KRB_MT_PRIV      = 21;
/** @const */ krb.KRB_MT_CRED      = 22;
/** @const */ krb.KRB_MT_ERROR     = 30;

// 7.5.8.  Name Types
/** @const */ krb.KRB_NT_UNKNOWN        = 0;
/** @const */ krb.KRB_NT_PRINCIPAL      = 1;
/** @const */ krb.KRB_NT_SRV_INST       = 2;
/** @const */ krb.KRB_NT_SRV_HST        = 3;
/** @const */ krb.KRB_NT_SRV_XHST       = 4;
/** @const */ krb.KRB_NT_UID            = 5;
/** @const */ krb.KRB_NT_X500_PRINCIPAL = 6;
/** @const */ krb.KRB_NT_SMTP_NAME      = 7;
/** @const */ krb.KRB_NT_ENTERPRISE     = 10;

// 7.5.9.  Error Codes
/** @const */ krb.KDC_ERR_NONE                          = 0;
/** @const */ krb.KDC_ERR_NAME_EXP                      = 1;
/** @const */ krb.KDC_ERR_SERVICE_EXP                   = 2;
/** @const */ krb.KDC_ERR_BAD_PVNO                      = 3;
/** @const */ krb.KDC_ERR_C_OLD_MAST_KVNO               = 4;
/** @const */ krb.KDC_ERR_S_OLD_MAST_KVNO               = 5;
/** @const */ krb.KDC_ERR_C_PRINCIPAL_UNKNOWN           = 6;
/** @const */ krb.KDC_ERR_S_PRINCIPAL_UNKNOWN           = 7;
/** @const */ krb.KDC_ERR_PRINCIPAL_NOT_UNIQUE          = 8;
/** @const */ krb.KDC_ERR_NULL_KEY                      = 9;
/** @const */ krb.KDC_ERR_CANNOT_POSTDATE               = 10;
/** @const */ krb.KDC_ERR_NEVER_VALID                   = 11;
/** @const */ krb.KDC_ERR_POLICY                        = 12;
/** @const */ krb.KDC_ERR_BADOPTION                     = 13;
/** @const */ krb.KDC_ERR_ETYPE_NOSUPP                  = 14;
/** @const */ krb.KDC_ERR_SUMTYPE_NOSUPP                = 15;
/** @const */ krb.KDC_ERR_PADATA_TYPE_NOSUPP            = 16;
/** @const */ krb.KDC_ERR_TRTYPE_NOSUPP                 = 17;
/** @const */ krb.KDC_ERR_CLIENT_REVOKED                = 18;
/** @const */ krb.KDC_ERR_SERVICE_REVOKED               = 19;
/** @const */ krb.KDC_ERR_TGT_REVOKED                   = 20;
/** @const */ krb.KDC_ERR_CLIENT_NOTYET                 = 21;
/** @const */ krb.KDC_ERR_SERVICE_NOTYET                = 22;
/** @const */ krb.KDC_ERR_KEY_EXPIRED                   = 23;
/** @const */ krb.KDC_ERR_PREAUTH_FAILED                = 24;
/** @const */ krb.KDC_ERR_PREAUTH_REQUIRED              = 25;
/** @const */ krb.KDC_ERR_SERVER_NOMATCH                = 26;
/** @const */ krb.KDC_ERR_MUST_USE_USER2USER            = 27;
/** @const */ krb.KDC_ERR_PATH_NOT_ACCEPTED             = 28;
/** @const */ krb.KDC_ERR_SVC_UNAVAILABLE               = 29;
/** @const */ krb.KRB_AP_ERR_BAD_INTEGRITY              = 31;
/** @const */ krb.KRB_AP_ERR_TKT_EXPIRED                = 32;
/** @const */ krb.KRB_AP_ERR_TKT_NYV                    = 33;
/** @const */ krb.KRB_AP_ERR_REPEAT                     = 34;
/** @const */ krb.KRB_AP_ERR_NOT_US                     = 35;
/** @const */ krb.KRB_AP_ERR_BADMATCH                   = 36;
/** @const */ krb.KRB_AP_ERR_SKEW                       = 37;
/** @const */ krb.KRB_AP_ERR_BADADDR                    = 38;
/** @const */ krb.KRB_AP_ERR_BADVERSION                 = 39;
/** @const */ krb.KRB_AP_ERR_MSG_TYPE                   = 40;
/** @const */ krb.KRB_AP_ERR_MODIFIED                   = 41;
/** @const */ krb.KRB_AP_ERR_BADORDER                   = 42;
/** @const */ krb.KRB_AP_ERR_BADKEYVER                  = 44;
/** @const */ krb.KRB_AP_ERR_NOKEY                      = 45;
/** @const */ krb.KRB_AP_ERR_MUT_FAIL                   = 46;
/** @const */ krb.KRB_AP_ERR_BADDIRECTION               = 47;
/** @const */ krb.KRB_AP_ERR_METHOD                     = 48;
/** @const */ krb.KRB_AP_ERR_BADSEQ                     = 49;
/** @const */ krb.KRB_AP_ERR_INAPP_CKSUM                = 50;
/** @const */ krb.KRB_AP_PATH_NOT_ACCEPTED              = 51;
/** @const */ krb.KRB_ERR_RESPONSE_TOO_BIG              = 52;
/** @const */ krb.KRB_ERR_GENERIC                       = 60;
/** @const */ krb.KRB_ERR_FIELD_TOOLONG                 = 61;
/** @const */ krb.KDC_ERROR_CLIENT_NOT_TRUSTED          = 62;
/** @const */ krb.KDC_ERROR_KDC_NOT_TRUSTED             = 63;
/** @const */ krb.KDC_ERROR_INVALID_SIG                 = 64;
/** @const */ krb.KDC_ERR_KEY_TOO_WEAK                  = 65;
/** @const */ krb.KDC_ERR_CERTIFICATE_MISMATCH          = 66;
/** @const */ krb.KRB_AP_ERR_NO_TGT                     = 67;
/** @const */ krb.KDC_ERR_WRONG_REALM                   = 68;
/** @const */ krb.KRB_AP_ERR_USER_TO_USER_REQUIRED      = 69;
/** @const */ krb.KDC_ERR_CANT_VERIFY_CERTIFICATE       = 70;
/** @const */ krb.KDC_ERR_INVALID_CERTIFICATE           = 71;
/** @const */ krb.KDC_ERR_REVOKED_CERTIFICATE           = 72;
/** @const */ krb.KDC_ERR_REVOCATION_STATUS_UNKNOWN     = 73;
/** @const */ krb.KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74;
/** @const */ krb.KDC_ERR_CLIENT_NAME_MISMATCH          = 75;
/** @const */ krb.KDC_ERR_KDC_NAME_MISMATCH             = 76;
