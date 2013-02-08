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

    // FIXME: These numbers are no good. They conflict with the
    // kerberos protocol error codes.

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
            if (rest.length > 0)  // Bad length.
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

    function prependTokenWrapping(mech, buf) {
        var length = buf.contents().byteLength;
        length += asn1.OBJECT_IDENTIFIER.encodeDERTriple(mech, buf);
        asn1.encodeLengthDER(length, buf);
        asn1.encodeTagDER(GSSAPI_TOKEN_TAG, buf);
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
        // FIXME: get a session for peer from the TGT session??
        // Somewhat awkward in that requiring you to both specify the
        // peer and get the service ticket yourself is weird and I'm
        // pretty sure contrary to how GSS-API is supposed to
        // work. But having this get the ticket puts a dependency on
        // the KDC proxy so it can't be used by other people. Also if
        // we want to support anonymity (RFC 6112) that requires
        // getting the ticket funny.
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

        // Fields to be initialized later.
        this.subkey = null;
        this.ctime = -1;
        this.cusec = -1;
        this.sendSeqno = -1;
        this.recvSeqno = -1;

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

            var apOptions = krb.APOptions.make();
            if (this.mutualAuthentication) {
                apOptions[krb.APOptions.mutual_required] = 1;
            }

            // FIXME: retry for random or something.
            var context = this.credential.makeAPReq(
                krb.KU_AP_REQ_AUTHENTICATOR,
                { cksumtype: 0x8003,
                  checksum: cksumBuf.contents() },
                { apOptions: apOptions,
                  useSeqNumber: true,
                  useSubkey: true
                });

            var buf = new asn1.Buffer();
            krb.AP_REQ.encodeDERTriple(context.apReq, buf);
            buf.prependUint16(TOK_ID_AP_REQ);
            prependTokenWrapping(gss.KRB5_MECHANISM, buf);

            // Save the key, seqno, and date.
            this.subkey = context.subkey;
            this.sendSeqno = context.seqNumber;
            this.ctime = context.authenticator.ctime.getTime();
            this.cusec = context.authenticator.cusec;
            // Do we also set recvSeqno here? We're going to get one
            // back, but not if mutual auth is off...

            this.state = this.mutualAuthentication ?
                PENDING_AP_REP : ESTABLISHED_STATE;
            return buf.contents();
        } else if (this.state === PENDING_AP_REP) {
            try {
                var decoded = decodeGSSToken(token);
                if (decoded.thisMech !== gss.KRB5_MECHANISM)
                    throw new gss.Error(gss.S_BAD_MECH, 0,
                                        "Mechanism mismatch");
                var tokId = new DataView(
                    decoded.innerToken.buffer,
                    decoded.innerToken.byteOffset,
                    decoded.innerToken.byteLength
                ).getUint16(0);
                var data = decoded.innerToken.subarray(2);

                if (tokId === TOK_ID_ERROR) {
                    var error = krb.KRB_ERROR.decodeDER(data);
                    // FIXME: Reusing protocol error codes here is a
                    // nuisance. The numbers conflict. MIT kerberos
                    // uses this kooky set of offsets and stuff. Maybe
                    // we should just reuse them.
                    throw new gss.Error(gss.S_FAILURE,
                                        krb.errorCode, krb.eText);
                }

                if (tokId !== TOK_ID_AP_REP)
                    throw new gss.Error(gss.S_DEFECTIVE_TOKEN, 0, "Bad token");

                var apRep = krb.AP_REP.decodeDER(data);
                // If a KRB_AP_REP message is returned, the client
                // uses the session key from the credentials obtained
                // for the server to decrypt the message and verifies
                // that the timestamp and microsecond fields match
                // those in the Authenticator it sent to the server.
                // If they match, then the client is assured that the
                // server is genuine.  The sequence number and subkey
                // (if present) are retained for later use.  (Note
                // that for encrypting the KRB_AP_REP message, the
                // sub-session key is not used, even if it is present
                // in the Authentication.)
                var encApRepPart = this.credential.key.decryptAs(
                    krb.EncAPRepPart, krb.KU_AP_REP_ENC_PART, apRep.encPart);
                if (encApRepPart.ctime.getTime() !== this.ctime ||
                    encApRepPart.cusec !== this.cusec)
                    throw new gss.Error(gss.S_DEFECTIVE_TOKEN,
                                        gss.KRB5_S_G_VALIDATE_FAILED,
                                        "Mutual authentication failed");

                // TODO: Save subkey and stuff.
                this.state = ESTABLISHED_STATE;
                return null;
            } catch (e) {
                if (e instanceof asn1.Error)
                    throw new gss.Error(gss.S_DEFECTIVE_TOKEN, 0, e.toString());
                if (e instanceof kcrypto.DecryptionError)
                    throw new gss.Error(gss.S_DEFECTIVE_TOKEN,
                                        gss.KRB5_S_G_VALIDATE_FAILED,
                                        "Mutual authentication failed");
                throw e;
            }
        }
        // TODO
    };
    gss.Context.prototype.isEstablished = function() {
        return this.state === ESTABLISHED_STATE;
    };

    return gss;
}());
