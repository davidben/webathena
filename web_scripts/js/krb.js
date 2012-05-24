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
    if (a.nameType != b.nameType)
        return false;
    if (a.nameString.length != b.nameString.length)
        return false;
    for (var i = 0; i < a.nameString.length; i++) {
        if (a.nameString[i] != b.nameString[i])
            return false;
    }
    return true;
}

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
krb.PA_ENC_TIMESTAMP = krb.EncryptedData;
krb.PA_ENC_TS_ENC = new asn1.SEQUENCE(
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
     {id: 's2kparams', type: asn1.OCTET_STRING.tagged(asn1.tag(2))}]);
krb.ETYPE_INFO2 = new asn1.SEQUENCE_OF(krb.ETYPE_INFO2_ENTRY);

// 5.2.8.  KerberosFlags
krb.KerberosFlags = asn1.BIT_STRING.constrained(function (bs) {
    if (bs.length < 32)
        throw "Invalid KerberosFlags";
});
krb.KerberosFlags.makeZeroFlags = function (num) {
    num = num || 32;
    var words = [];
    for (var i = 0; i < num; i++) {
        words.push(0);
    }
    return words;
};

// 5.3.  Tickets
krb.Ticket = new asn1.SEQUENCE(
    [{id: 'tktVno', type: asn1.INTEGER.valueConstrained(5).tagged(asn1.tag(0))},
     {id: 'realm', type: krb.Realm.tagged(asn1.tag(1))},
     {id: 'sname', type: krb.PrincipalName.tagged(asn1.tag(2))},
     {id: 'encPart', type: krb.EncryptedData.tagged(asn1.tag(3))}]
).tagged(asn1.tag(1, asn1.TAG_CONSTRUCTED, asn1.TAG_APPLICATION));

krb.TicketFlags = krb.KerberosFlags.subtype();
krb.TicketFlags.reserved = 0;
krb.TicketFlags.forwardable = 1;
krb.TicketFlags.forwarded = 2;
krb.TicketFlags.proxiable = 3;
krb.TicketFlags.proxy = 4;
krb.TicketFlags.may_postdate = 5;
krb.TicketFlags.postdated = 6;
krb.TicketFlags.invalid = 7;
krb.TicketFlags.renewable = 8;
krb.TicketFlags.initial = 9;
krb.TicketFlags.pre_authent = 10;
krb.TicketFlags.hw_authent = 11;
krb.TicketFlags.transited_policy_checked = 12;
krb.TicketFlags.ok_as_delegate = 13;

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
krb.TYPED_DATA = new asn1.SEQUENCE(
    [{id: 'dataType', type: krb.Int32.tagged(asn1.tag(0))},
     {id: 'dataValue', type: asn1.OCTET_STRING.tagged(asn1.tag(1)),
      optional: true}]);

// 5.4.1.  KRB_KDC_REQ Definition
krb.KDCOptions = krb.KerberosFlags.subtype();
krb.KDCOptions.reserved = 0;
krb.KDCOptions.forwardable = 1;
krb.KDCOptions.forwarded = 2;
krb.KDCOptions.proxiable = 3;
krb.KDCOptions.proxy = 4;
krb.KDCOptions.allow_postdate = 5;
krb.KDCOptions.postdated = 6;
krb.KDCOptions.renewable = 8;
krb.KDCOptions.opt_hardware_auth = 11;
krb.KDCOptions.disable_transited_check = 26;
krb.KDCOptions.renewable_ok = 27;
krb.KDCOptions.enc_tkt_in_skey = 28;
krb.KDCOptions.renew = 30;
krb.KDCOptions.validate = 31;

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
krb.APOptions.use_session_key = 1;
krb.APOptions.mutual_required = 2;
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
// TODO: Transcribe the rest of these...
krb.KU_AS_REQ_ENC_PART = 3;


// 7.5.2.  PreAuthentication Data Types
krb.PA_TGS_REQ                = 1;
krb.PA_ENC_TIMESTAMP          = 2;
krb.PA_PW_SALT                = 3;
krb.PA_ENC_UNIX_TIME          = 5;
krb.PA_SANDIA_SECUREID        = 6;
krb.PA_SESAME                 = 7;
krb.PA_OSF_DCE                = 8;
krb.PA_CYBERSAFE_SECUREID     = 9;
krb.PA_AFS3_SALT              = 10;
krb.PA_ETYPE_INFO             = 11;
krb.PA_SAM_CHALLENGE          = 12;
krb.PA_SAM_RESPONSE           = 13;
krb.PA_PK_AS_REQ_OLD          = 14;
krb.PA_PK_AS_REP_OLD          = 15;
krb.PA_PK_AS_REQ              = 16;
krb.PA_PK_AS_REP              = 17;
krb.PA_ETYPE_INFO2            = 19;
krb.PA_USE_SPECIFIED_KVNO     = 20;
krb.PA_SAM_REDIRECT           = 21;
krb.PA_GET_FROM_TYPED_DATA    = 22;
krb.TD_PADATA                 = 22;
krb.PA_SAM_ETYPE_INFO         = 23;
krb.PA_ALT_PRINC              = 24;
krb.PA_SAM_CHALLENGE2         = 30;
krb.PA_SAM_RESPONSE2          = 31;
krb.PA_EXTRA_TGT              = 41;
krb.TD_PKINIT_CMS_CERTIFICATES= 101;
krb.TD_KRB_PRINCIPAL          = 102;
krb.TD_KRB_REALM              = 103;
krb.TD_TRUSTED_CERTIFIERS     = 104;
krb.TD_CERTIFICATE_INDEX      = 105;
krb.TD_APP_DEFINED_ERROR      = 106;
krb.TD_REQ_NONCE              = 107;
krb.TD_REQ_SEQ                = 108;
krb.PA_PAC_REQUEST            = 128;

// 7.5.3.  Address Types
krb.ADDRESS_IPV4              = 2;
krb.ADDRESS_DIRECTIONAL       = 3;
krb.ADDRESS_CHAOSNET          = 5;
krb.ADDRESS_XNS               = 6;
krb.ADDRESS_ISO               = 7;
krb.ADDRESS_DECNET_PHASE_IV   = 12;
krb.ADDRESS_APPLETALK_UDP     = 16;
krb.ADDRESS_NETBIOS           = 20;
krb.ADDRESS_IPV6              = 24;

// 7.5.4.  Authorization Data Types
krb.AD_IF_RELEVANT                     = 1;
krb.AD_INTENDED_FOR_SERVER             = 2;
krb.AD_INTENDED_FOR_APPLICATION_CLASS  = 3;
krb.AD_KDC_ISSUED                      = 4;
krb.AD_AND_OR                          = 5;
krb.AD_MANDATORY_TICKET_EXTENSIONS     = 6;
krb.AD_IN_TICKET_EXTENSIONS            = 7;
krb.AD_MANDATORY_FOR_KDC               = 8;
krb.OSF_DCE                            = 64;
krb.SESAME                             = 65;
krb.AD_OSF_DCE_PKI_CERTID              = 66;
krb.AD_WIN2K_PAC                       = 128;
krb.AD_ETYPE_NEGOTIATION               = 129;

// 7.5.5.  Transited Encoding Types
krb.DOMAIN_X500_COMPRESS               = 1;

// 7.5.6.  Protocol Version Number
krb.pvno                               = 5;

// 7.5.7.  Kerberos Message Types
krb.KRB_MT_AS_REQ    = 10;
krb.KRB_MT_AS_REP    = 11;
krb.KRB_MT_TGS_REQ   = 12;
krb.KRB_MT_TGS_REP   = 13;
krb.KRB_MT_AP_REQ    = 14;
krb.KRB_MT_AP_REP    = 15;
krb.KRB_MT_SAFE      = 20;
krb.KRB_MT_PRIV      = 21;
krb.KRB_MT_CRED      = 22;
krb.KRB_MT_ERROR     = 30;

// 7.5.8.  Name Types
krb.KRB_NT_UNKNOWN        = 0;
krb.KRB_NT_PRINCIPAL      = 1;
krb.KRB_NT_SRV_INST       = 2;
krb.KRB_NT_SRV_HST        = 3;
krb.KRB_NT_SRV_XHST       = 4;
krb.KRB_NT_UID            = 5;
krb.KRB_NT_X500_PRINCIPAL = 6;
krb.KRB_NT_SMTP_NAME      = 7;
krb.KRB_NT_ENTERPRISE     = 10;

// 7.5.9.  Error Codes
krb.KDC_ERR_NONE                          = 0;
krb.KDC_ERR_NAME_EXP                      = 1;
krb.KDC_ERR_SERVICE_EXP                   = 2;
krb.KDC_ERR_BAD_PVNO                      = 3;
krb.KDC_ERR_C_OLD_MAST_KVNO               = 4;
krb.KDC_ERR_S_OLD_MAST_KVNO               = 5;
krb.KDC_ERR_C_PRINCIPAL_UNKNOWN           = 6;
krb.KDC_ERR_S_PRINCIPAL_UNKNOWN           = 7;
krb.KDC_ERR_PRINCIPAL_NOT_UNIQUE          = 8;
krb.KDC_ERR_NULL_KEY                      = 9;
krb.KDC_ERR_CANNOT_POSTDATE               = 10;
krb.KDC_ERR_NEVER_VALID                   = 11;
krb.KDC_ERR_POLICY                        = 12;
krb.KDC_ERR_BADOPTION                     = 13;
krb.KDC_ERR_ETYPE_NOSUPP                  = 14;
krb.KDC_ERR_SUMTYPE_NOSUPP                = 15;
krb.KDC_ERR_PADATA_TYPE_NOSUPP            = 16;
krb.KDC_ERR_TRTYPE_NOSUPP                 = 17;
krb.KDC_ERR_CLIENT_REVOKED                = 18;
krb.KDC_ERR_SERVICE_REVOKED               = 19;
krb.KDC_ERR_TGT_REVOKED                   = 20;
krb.KDC_ERR_CLIENT_NOTYET                 = 21;
krb.KDC_ERR_SERVICE_NOTYET                = 22;
krb.KDC_ERR_KEY_EXPIRED                   = 23;
krb.KDC_ERR_PREAUTH_FAILED                = 24;
krb.KDC_ERR_PREAUTH_REQUIRED              = 25;
krb.KDC_ERR_SERVER_NOMATCH                = 26;
krb.KDC_ERR_MUST_USE_USER2USER            = 27;
krb.KDC_ERR_PATH_NOT_ACCEPTED             = 28;
krb.KDC_ERR_SVC_UNAVAILABLE               = 29;
krb.KRB_AP_ERR_BAD_INTEGRITY              = 31;
krb.KRB_AP_ERR_TKT_EXPIRED                = 32;
krb.KRB_AP_ERR_TKT_NYV                    = 33;
krb.KRB_AP_ERR_REPEAT                     = 34;
krb.KRB_AP_ERR_NOT_US                     = 35;
krb.KRB_AP_ERR_BADMATCH                   = 36;
krb.KRB_AP_ERR_SKEW                       = 37;
krb.KRB_AP_ERR_BADADDR                    = 38;
krb.KRB_AP_ERR_BADVERSION                 = 39;
krb.KRB_AP_ERR_MSG_TYPE                   = 40;
krb.KRB_AP_ERR_MODIFIED                   = 41;
krb.KRB_AP_ERR_BADORDER                   = 42;
krb.KRB_AP_ERR_BADKEYVER                  = 44;
krb.KRB_AP_ERR_NOKEY                      = 45;
krb.KRB_AP_ERR_MUT_FAIL                   = 46;
krb.KRB_AP_ERR_BADDIRECTION               = 47;
krb.KRB_AP_ERR_METHOD                     = 48;
krb.KRB_AP_ERR_BADSEQ                     = 49;
krb.KRB_AP_ERR_INAPP_CKSUM                = 50;
krb.KRB_AP_PATH_NOT_ACCEPTED              = 51;
krb.KRB_ERR_RESPONSE_TOO_BIG              = 52;
krb.KRB_ERR_GENERIC                       = 60;
krb.KRB_ERR_FIELD_TOOLONG                 = 61;
krb.KDC_ERROR_CLIENT_NOT_TRUSTED          = 62;
krb.KDC_ERROR_KDC_NOT_TRUSTED             = 63;
krb.KDC_ERROR_INVALID_SIG                 = 64;
krb.KDC_ERR_KEY_TOO_WEAK                  = 65;
krb.KDC_ERR_CERTIFICATE_MISMATCH          = 66;
krb.KRB_AP_ERR_NO_TGT                     = 67;
krb.KDC_ERR_WRONG_REALM                   = 68;
krb.KRB_AP_ERR_USER_TO_USER_REQUIRED      = 69;
krb.KDC_ERR_CANT_VERIFY_CERTIFICATE       = 70;
krb.KDC_ERR_INVALID_CERTIFICATE           = 71;
krb.KDC_ERR_REVOKED_CERTIFICATE           = 72;
krb.KDC_ERR_REVOCATION_STATUS_UNKNOWN     = 73;
krb.KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74;
krb.KDC_ERR_CLIENT_NAME_MISMATCH          = 75;
krb.KDC_ERR_KDC_NAME_MISMATCH             = 76;
