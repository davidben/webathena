/**
 * GSS-API wrapper for Kerberos implementation. For now it's very
 * kerberos-specific. We can add machinery to make it generic if the
 * need ever arises.
 */
var gss = (function() {
    "use strict";

    var gss = { };

    /** @const */ gss.NT_USER_NAME         = "1.2.840.113554.1.2.1.1";
    /** @const */ gss.NT_MACHINE_UID_NAME  = "1.2.840.113554.1.2.1.2";
    /** @const */ gss.NT_STRING_UID_NAME   = "1.2.840.113554.1.2.1.3";
    /** @const */ gss.NT_HOSTBASED_SERVICE = "1.3.6.1.5.6.2";
    /** @const */ gss.NT_ANONYMOUS         = "1.3.6.1.5.6.3";
    /** @const */ gss.NT_EXPORT_NAME       = "1.3.6.1.5.6.4";

    /** @const */ gss.S_BAD_BINDINGS = 1;
    /** @const */ gss.S_BAD_MECH = 2;
    /** @const */ gss.S_BAD_NAME = 3;
    /** @const */ gss.S_BAD_NAMETYPE = 4;
    /** @const */ gss.S_BAD_STATUS = 5;
    /** @const */ gss.S_BAD_SIG = 6;
    /** @const */ gss.S_CONTEXT_EXPIRED = 7;
    /** @const */ gss.S_CREDENTIALS_EXPIRED = 8;
    /** @const */ gss.S_DEFECTIVE_CREDENTIAL = 9;
    /** @const */ gss.S_DEFECTIVE_TOKEN = 10;
    /** @const */ gss.S_FAILURE = 11;
    /** @const */ gss.S_NO_CONTEXT = 12;
    /** @const */ gss.S_NO_CRED = 13;
    /** @const */ gss.S_BAD_QOP = 14;
    /** @const */ gss.S_UNAUTHORIZED = 15;
    /** @const */ gss.S_UNAVAILABLE = 16;
    /** @const */ gss.S_DUPLICATE_ELEMENT = 17;
    /** @const */ gss.S_NAME_NOT_MN = 18;

    /** @const */ gss.S_DUPLICATE_TOKEN = 19;
    /** @const */ gss.S_OLD_TOKEN = 20;
    /** @const */ gss.S_UNSEQ_TOKEN = 21;
    /** @const */ gss.S_GAP_TOKEN = 22;

    /** @const */ gss.KRB5_MECHANISM = "1.2.840.113554.1.2.2";

    /** @const */ gss.KRB5_NT_PRINCIPAL_NAME         = "1.2.840.113554.1.2.2.1";
    /** @const */ gss.KRB5_NT_HOSTBASED_SERVICE_NAME = "1.2.840.113554.1.2.1.4";

    /** @const */ gss.KRB5_S_G_BAD_SERVICE_NAME = 1;
    /** @const */ gss.KRB5_S_G_BAD_STRING_UID = 2;
    /** @const */ gss.KRB5_S_G_NOUSER = 3;
    /** @const */ gss.KRB5_S_G_VALIDATE_FAILED = 4;
    /** @const */ gss.KRB5_S_G_BUFFER_ALLOC = 5;
    /** @const */ gss.KRB5_S_G_BAD_MSG_CTX = 6;
    /** @const */ gss.KRB5_S_G_WRONG_SIZE = 7;
    /** @const */ gss.KRB5_S_G_BAD_USAGE = 8;
    /** @const */ gss.KRB5_S_G_UNKNOWN_QOP = 9;

    /** @const */ gss.KRB5_S_KG_CCACHE_NOMATCH = 10;
    /** @const */ gss.KRB5_S_KG_KEYTAB_NOMATCH = 11;
    /** @const */ gss.KRB5_S_KG_TGT_MISSING = 12;
    /** @const */ gss.KRB5_S_KG_NO_SUBKEY = 13;
    /** @const */ gss.KRB5_S_KG_CONTEXT_ESTABLISHED = 14;
    /** @const */ gss.KRB5_S_KG_BAD_SIGN_TYPE = 15;
    /** @const */ gss.KRB5_S_KG_BAD_LENGTH = 16;
    /** @const */ gss.KRB5_S_KG_CTX_INCOMPLETE = 17;

    var TOK_ID_AP_REQ = 0x0100;
    var TOK_ID_AP_REP = 0x0200;
    var TOK_ID_ERROR  = 0x0300;
    var TOK_ID_EXPORT_NAME = 0x0401;

    /**
     * @constructor
     * @param {number} major
     * @param {number} minor
     * @param {string} message
     */
    gss.Error = function(major, minor, message) {
        this.major = major;
        this.minor = minor;
        this.message = message;
    };
    /** @return {string} */
    gss.Error.prototype.toString = function() {
        return this.message;
    };

    /**
     * Creates a gss.Name that wraps a krb.Principal.
     * @constructor
     * @param {krb.Principal} principal
     */
    gss.Name = function(principal) {
        this.principal = principal;
    };
    /**
     * GSS_Import_name. For now just returns a gss.Name. If we want to
     * do some sort of host canonicalization, that may want a promise
     * object from Q.
     *
     * @param {ArrayBufferView|string} data The input bytes.
     * @param {string} nameType An OID for the name type.
     * @return {gss.Name} The resulting name.
     */
    gss.Name.importName = function(data, nameType) {
        if (nameType === gss.NT_EXPORT_NAME) {
            // TODO: For sanity, importName should take a string for
            // all the sane name types. Should we avoid type confusion
            // and just force everything into a string?
            data = arrayutils.asUint8Array(data);
            var dataview = new DataView(data.buffer,
                                        data.byteOffset,
                                        data.byteLength);
            // Strip off the header.
            if (data.length < 4)
                throw new gss.Error(gss.S_BAD_NAME, 0, "Bad format");
            if (dataview.getUint16(0) != TOK_ID_EXPORT_NAME)
                throw new gss.Error(gss.S_BAD_NAME, 0, "Bad TOK_ID");
            var mechOidLen = dataview.getUint16(2);
            if (data.length < 4 + mechOidLen + 4)
                throw new gss.Error(gss.S_BAD_NAME, 0, "Bad format");
            try {
                var mechOid = asn1.OBJECT_IDENTIFIER.decodeDER(
                    data.subarray(4, 4 + mechOidLen));
            } catch (e) {
                if (e instanceof asn1.Error)
                    throw new gss.Error(gss.S_BAD_NAME, 0, e.toString());
                throw e;
            }
            // We only support KRB5.
            if (mechOid !== gss.KRB5_MECHANISM)
                throw new gss.Error(gss.S_BAD_MECH, 0,
                                    "Only krb5 names supported");
            var nameLen = dataview.getUint32(4 + mechOidLen);
            if (data.length != (4 + mechOidLen + 4 + nameLen))
                throw new gss.Error(gss.S_BAD_NAME, 0, "Bad length");
            try {
                return new gss.Name(krb.Principal.fromString(
                    arrayutils.toUTF16(data.subarray(4 + mechOidLen + 4))));
            } catch (e) {
                throw new gss.Error(gss.S_BAD_NAME, 0, e);
            }
        } else if (nameType === gss.NT_HOSTBASED_SERVICE ||
                   nameType === gss.KRB5_NT_HOSTBASED_SERVICE_NAME) {
            // Format is service@hostname. Hostname is optional, but
            // for now require it. Probably the most reasonable
            // interpretation of "the canonicalized name of the local
            // host" is location.host, but meh.
            var at = data.indexOf("@");
            if (at < 0)
                throw new gss.Error(
                    gss.S_BAD_NAME, gss.KRB5_S_G_BAD_SERVICE_NAME,
                    "Default host not supported");
            var service = data.substring(0, at);
            var host = data.substring(at + 1);
            // FIXME: Hostname canonicalization??
            return new gss.Name(new krb.Principal({
                nameType: krb.KRB_NT_SRV_HST,
                nameString: [service, host]
            }, krb.realm));
        } else if (nameType === gss.KRB5_NT_PRINCIPAL_NAME) {
            try {
                return new gss.Name(krb.Principal.fromString(data));
            } catch (e) {
                throw new gss.Error(gss.S_BAD_NAME, 0, e);
            }
        } else if (nameType === gss.NT_USER_NAME) {
            return new gss.Name(new krb.Principal({
                nameType: krb.KRB_NT_PRINCIPAL,
                nameString: [data]
            }, krb.realm));
        } else {
            throw new gss.Error(gss.S_BAD_NAMETYPE, 0, "Bad nametype");
        }
    };
    gss.Name.prototype.canonicalize = function() {
        // TODO
    };
    /** @return {Uint8Array} */
    gss.Name.prototype.exportName = function() {
        // Build it backwards.
        var b = new asn1.Buffer();
        var nameLen =
            b.prependBytes(arrayutils.fromUTF16(this.principal.toString()));
        b.prependUint32(name.length);
        var mechOidLen =
            asn1.OBJECT_IDENTIFIER.encodeDERTriple(gss.KRB5_MECHANISM, b);
        b.prependUint16(mechOidLen);
        // tokId is 0x04 0x01
        b.prependUint16(TOK_ID_EXPORT_NAME);
        return b.contents();
    };

    var GSSAPI_TOKEN_TAG = 0x60;  // [APPLICATION 0]

    /** @param {ArrayBufferView}
     *  @returns {{thisMech:string, innerToken:Uint8Array}}
     */
    function decodeGSSToken(token) {
        try {
            // This is weirdo pseudo-ASN.1 with a hole in it. We could
            // hack it into our parser, but it's easy to parse manually.
            var tvr = asn1.decodeTagLengthValueDER(token);
            var tag = tvr[0], value = tvr[1], rest = tvr[2];
            if (tag !== GSSAPI_TOKEN_TAG)
                throw new gss.Error(gss.S_DEFECTIVE_TOKEN, 0, "Bad token");
            if (rest)  // Bad length.
                throw new gss.Error(gss.S_DEFECTIVE_TOKEN, 0, "Bad token");

            // Pull out the mechanism.
            var mr = asn1.OBJECT_IDENTIFIER.decodeDERPrefix(value);
            var mech = mr[0], rest = mr[1];

            return {
                thisMech: mech,
                innerToken: rest
            };
        } catch (e) {
            if (e instanceof asn1.Error)
                throw new gss.Error(gss.S_DEFECTIVE_TOKEN, 0, e.toString());
            throw e;
        }
    }

    var DELEG_FLAG    = 1;
    var MUTUAL_FLAG   = 2;
    var REPLAY_FLAG   = 4;
    var SEQUENCE_FLAG = 8;
    var CONF_FLAG     = 16;
    var INTEG_FLAG    = 32;

    // Context states.
    var INITIAL_STATE = 1;
    var PENDING_AP_REP = 2;
    var ESTABLISHED_STATE = 3;

    /**
     * Creates an initiator GSS context. If the need ever arises, we
     * can arrange for acceptor contexts to be supported, but it's
     * unlikely this'll ever run outside a client.
     *
     * The constructor takes an options dictionary with various
     * optional keys. The keys are:
     *   delegation : boolean
     *   mutualAuthentication : boolean
     *   replayDetection : boolean
     *   sequence : boolean
     *   anonymous : boolean
     *   confidentiality : boolean
     *   integrity : boolean
     *   lifetime : number (default: 0)
     *   bindings : ?ArrayBufferView (default: null)
     *
     * Not all flags can be provided, so the corresponding attributes
     * should be checked on the returned gss.Context object.
     *
     * @constructor
     */
    gss.Context = function(peer, mechanism, credential, opts) {
        if (mechanism !== gss.KRB5_MECHANISM)
            throw new gss.Error(gss.S_BAD_MECH, 0, "Only krb5 is supported");
        this.state = INITIAL_STATE;
        this.credential = credential;
        this.peer = peer;

        // this.delegation = opts.delegation || false;
        this.delegation = false;
        this.mutualAuthentication = opts.mutualAuthentication || false;
        this.replayDetection = opts.replayDetection || false;
        this.sequence = opts.sequence || false;
        // this.anonymous = opts.anonymous || false;
        this.confidentiality = opts.confidentiality || false;
        this.integrity = opts.integrity || false;

        // TODO: This is actually the MD5 sum of something...
        this.bindings = opts.bindings || new Uint8Array(16);

        // TODO...
    };
    gss.Context.prototype.initSecContext = function(token) {
        if (this.state === INITIAL_STATE) {
            var cksumBuf = new asn1.Buffer();
            //  Octet      Name      Description
            // ---------------------------------------------------------------
            //  n..last    Exts    Extensions [optional].
            if (this.delegation) {
                //  28..(n-1)  Deleg   A KRB_CRED message (n = Dlgth + 28)
                //                     [optional].
                //  26..27     Dlgth   The length of the Deleg field in
                //                     little-endian order [optional].
                //  24..25     DlgOpt  The delegation option identifier (=1) in
                //                     little-endian order [optional].  This
                //                     field and the next two fields are present
                //                     if and only if GSS_C_DELEG_FLAG is set as
                //                     described in section 4.1.1.1.
                throw "Delegation not implemented.";
            }
            //  20..23     Flags   Four-octet context-establishment flags in
            //                     little-endian order as described in section
            //                     4.1.1.1.
            var flags = 0;
            if (this.delegation)
                flags |= DELEG_FLAG;
            if (this.mutualAuthentication)
                flags |= MUTUAL_FLAG;
            if (this.replayDetection)
                flags |= REPLAY_FLAG;
            if (this.sequence)
                flags |= SEQUENCE_FLAG;
            if (this.confidentiality)
                flags |= CONF_FLAG;
            if (this.integrity)
                flags |= INTEG_FLAG;
            cksumBuf.prependUint32(flags, true);
            //  4..19      Bnd     Channel binding information, as described in
            //                     section 4.1.1.2.
            var bndLen = cksumBuf.prependBytes(this.bindings);
            //  0..3       Lgth    Number of octets in Bnd field;  Represented
            //                     in little-endian order;  Currently contains
            //                     hex value 10 00 00 00 (16).
            cksumBuf.prependUint32(bndLen, true);
            var apReq = this.credential.makeAPReq(
                krb.KU_AP_REQ_AUTHENTICATOR,
                { cksumtype: 0x8003,
                  checksum: cksumBuf.contents() },
                ???,
                ???);
        }
        // TODO
    };
    gss.Context.prototype.isEstablished = function() {
        // TODO
    };

    return gss;
}());
