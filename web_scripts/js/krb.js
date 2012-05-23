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

// 5.3.  Tickets
krb.Ticket = new asn1.SEQUENCE(
    [{id: 'tktVno', type: asn1.INTEGER.valueConstrained(5).tagged(asn1.tag(0))},
     {id: 'realm', type: krb.Realm.tagged(asn1.tag(1))},
     {id: 'sname', type: krb.PrincipalName.tagged(asn1.tag(2))},
     {id: 'encPart', type: krb.EncryptedData.tagged(asn1.tag(3))}]
).tagged(asn1.tag(1, asn1.TAG_CONSTRUCTED, asn1.TAG_APPLICATION));
krb.TicketFlags = krb.KerberosFlags;
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

// 5.4.1.  KRB_KDC_REQ Definition
krb.KDCOptions = krb.KerberosFlags;
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

// TODO: 5.4.2.  KRB_KDC_REP Definition

// TODO: 5.5.1.  KRB_AP_REQ Definition

// TODO: 5.5.2.  KRB_AP_REP Definition

// TODO: 5.6.1.  KRB_SAFE Definition

// TODO: 5.7.1.  KRB_PRIV Definition

// TODO: 5.8.1.  KRB_CRED Definition

// TODO: 5.9.1.  KRB_ERROR Definition