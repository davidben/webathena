from pyasn1.type import char, namedtype, tag, univ, useful

# 5.2.1.  KerberosString
class KerberosString(char.GeneralString): pass

# 5.2.4.  Constrained Integer Types
class Int32(univ.Integer): pass
class UInt32(univ.Integer): pass
class Microseconds(univ.Integer): pass

# 5.2.2.  Realm and PrincipalName
class Realm(KerberosString): pass

class _KerberosStringSequence(univ.SequenceOf):
    componentType = KerberosString()

class PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'name-type',
            Int32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.NamedType(
            'name-string',
            _KerberosStringSequence().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        )

# 5.2.3.  KerberosTime
class KerberosTime(useful.GeneralizedTime): pass

# 5.2.5.  HostAddress and HostAddresses
class HostAddress(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'addr-type',
            Int32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.NamedType(
            'address',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        )

class HostAddresses(univ.SequenceOf):
    componentType = HostAddress()

# 5.2.6.  AuthorizationData
class _AuthorizationDataEntry(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'ad-type',
            Int32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.NamedType(
            'ad-data',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        )

    # ad-type values
    ad_if_relevant_type = 1
    ad_kdcissued_type = 4
    ad_and_or_type = 5
    ad_mandatory_for_kdc_type = 8

class AuthorizationData(univ.SequenceOf):
    componentType = _AuthorizationDataEntry

# 5.2.6.1.  IF-RELEVANT
class AD_IF_RELEVANT(AuthorizationData): pass

# 5.2.9.  Cryptosystem-Related Types
class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'etype',
            Int32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType(
            'kvno',
            UInt32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        namedtype.NamedType(
            'cipher',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 2))),
        )

class EncryptionKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'keytype',
            Int32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.NamedType(
            'keyvalue',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        )

class Checksum(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'cksumtype',
            Int32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.NamedType(
            'checksum',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        )

# 5.2.6.2.  KDCIssued
class AD_KDCIssued(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'ad-checksum',
            Checksum().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.NamedType(
            'i-realm',
            Realm().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        namedtype.NamedType(
            'i-sname',
            PrincipalName().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 2))),
        namedtype.NamedType(
            'elements',
            AuthorizationData().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 3))),
        )

# 5.2.6.3.  AND-OR
class AD_AND_OR(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'condition-count',
            Int32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.NamedType(
            'elements',
            AuthorizationData().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        )

# 5.2.6.4.  MANDATORY-FOR-KDC
class AD_MANDATORY_FOR_KDC(AuthorizationData): pass

# 5.2.7.  PA-DATA
class PA_DATA(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'padata-type',
            Int32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        namedtype.NamedType(
            'padata-value',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 2))),
        )

    # padata-type values
    pa_tgs_req = 1
    pa_enc_timestamp = 2
    pa_pw_salt = 3
    pa_etype_info = 11
    pa_etype_info2 = 19

# 5.2.7.2.  Encrypted Timestamp Pre-authentication
class PA_ENC_TIMESTAMP(EncryptedData): pass

class PA_ENC_TS_ENC(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'patimestamp',
            KerberosTime().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType(
            'pausec',
            Microseconds().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        )

# 5.2.7.4.  PA-ETYPE-INFO
class ETYPE_INFO_ENTRY(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'etype',
            Int32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType(
            'salt',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        )

class ETYPE_INFO(univ.SequenceOf):
    componentType = ETYPE_INFO_ENTRY

# 5.2.7.5.  PA-ETYPE-INFO2
class ETYPE_INFO2_ENTRY(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'etype',
            Int32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType(
            'salt',
            KerberosString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType(
            's2kparams',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 2))),
        )

class ETYPE_INFO2(univ.SequenceOf):
    componentType = ETYPE_INFO2_ENTRY

# 5.2.8.  KerberosFlags
class KerberosFlags(univ.BitString): pass

# 5.3.  Tickets
class Ticket(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication,
                tag.tagFormatSimple, 1))
    # ^ tagFormatConstructed??
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'tkt-vno',
            univ.Integer().subtype(
                value=5,
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.NamedType(
            'realm',
            Realm().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        namedtype.NamedType(
            'sname',
            PrincipalName().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 2))),
        namedtype.NamedType(
            'enc-part',
            EncryptedData().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 3))),
        )

class TicketFlags(KerberosFlags):
    reserved = 0
    forwardable = 1
    forwarded = 2
    proxiable = 3
    proxy = 4
    may_postdate = 5
    postdated = 6
    invalid = 7
    renewable = 8
    initial = 9
    pre_authent = 10
    hw_authent = 11
    transited_policy_checked = 12
    ok_as_delegate = 13

class TransitedEncoding(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'tr-type',
            Int32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.NamedType(
            'contents',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        )

class EncTicketPart(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication,
                tag.tagFormatSimple, 1))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'flags',
            TicketFlags().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.NamedType(
            'key',
            EncryptionKey().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        namedtype.NamedType(
            'crealm',
            Realm().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 2))),
        namedtype.NamedType(
            'cname',
            PrincipalName().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 3))),
        namedtype.NamedType(
            'transited',
            TransitedEncoding().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 4))),
        namedtype.NamedType(
            'authtime',
            KerberosTime().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 5))),
        namedtype.OptionalNamedType(
            'starttime',
            KerberosTime().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 6))),
        namedtype.NamedType(
            'endtime',
            KerberosTime().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 7))),
        namedtype.OptionalNamedType(
            'renew-till',
            KerberosTime().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 8))),
        namedtype.OptionalNamedType(
            'caddr',
            HostAddresses().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 9))),
        namedtype.OptionalNamedType(
            'authorization-data',
            AuthorizationData().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 10))),
        )

# 5.4.1.  KRB_KDC_REQ Definition
class KDCOptions(KerberosFlags):
    reserved = 0
    forwardable = 1
    forwarded = 2
    proxiable = 3
    proxy = 4
    allow_postdate = 5
    postdated = 6
    renewable = 8
    opt_hardware_auth = 11
    disable_transited_check = 26
    renewable_ok = 27
    enc_tkt_in_skey = 28
    renew = 30
    validate = 31

class Int32Sequence(univ.SequenceOf):
    componentType = Int32
class TicketSequence(univ.SequenceOf):
    componentType = Ticket
class PA_DATA_Sequence(univ.SequenceOf):
    componentType = PA_DATA

class KDC_REQ_BODY(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'kdc-options',
            KDCOptions().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType(
            'principal-name',
            PrincipalName().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        namedtype.NamedType(
            'realm',
            Realm().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType(
            'sname',
            PrincipalName().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType(
            'from',
            KerberosTime().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 4))),
        namedtype.NamedType(
            'till',
            KerberosTime().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 5))),
        namedtype.OptionalNamedType(
            'rtime',
            KerberosTime().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 6))),
        namedtype.NamedType(
            'nonce',
            UInt32().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 7))),
        namedtype.NamedType(
            'etype',
            Int32Sequence().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 8))),
        namedtype.OptionalNamedType(
            'addresses',
            HostAddresses().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 9))),
        namedtype.OptionalNamedType(
            'enc-authorization-data',
            EncryptedData().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 10))),
        namedtype.OptionalNamedType(
            'additional-tickets',
            TicketSequence().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 11))),
        )
    
class KDC_REQ(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'pvno',
            univ.Integer().subtype(
                value=5,
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        namedtype.NamedType(
            'msg-type',
            univ.Integer().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType(
            'padata',
            PA_DATA_Sequence().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 3))),
        namedtype.NamedType(
            'req-body',
            KDC_REQ_BODY().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 4))),
        )

    # msg-type values
    msg_type_as = 10
    msg_type_tgs = 12
    
class AS_REQ(KDC_REQ):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication,
                tag.tagFormatSimple, 10))

class TGS_REQ(KDC_REQ):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication,
                tag.tagFormatSimple, 12))

# 5.4.2.  KRB_KDC_REP Definition

# Skipping this section. We're unlikely to need it (or much of the
# above really) in Python. Just in JavaScript.

# 5.5.1.  KRB_AP_REQ Definition
class APOptions(KerberosFlags):
    use_session_key = 1
    mutual_required = 2

class AP_REQ(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication,
                tag.tagFormatSimple, 14))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'pvno',
            univ.Integer().subtype(
                value=5,
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 0))),
        namedtype.NamedType(
            'msg-type',
            univ.Integer().subtype(
                value=14,
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 1))),
        namedtype.NamedType(
            'ap-options',
            APOptions().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 2))),
        namedtype.NamedType(
            'ticket',
            Ticket().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 3))),
        namedtype.NamedType(
            'authenticator',
            EncryptedData().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple, 4))),
        )

# Skipping Authenticator.

# 5.5.2.  KRB_AP_REP Definition; skipping

# 5.6.1.  KRB_SAFE Definition; skipping

# 5.7.1.  KRB_PRIV Definition; skipping

# 5.8.1.  KRB_CRED Definition; skipping

# 5.9.1.  KRB_ERROR Definition; skipping
