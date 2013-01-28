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
     * Creates a gss.Name that wraps a KDC.Principal.
     * @constructor
     * @param {KDC.Principal} principal
     */
    gss.Name = function(principal) {
        this.principal = principal;
    };
    /**
     * GSS_Import_name. For now just returns a gss.Name. If we want to
     * do some sort of host canonicalization, that may want a promise
     * object from Q.
     *
     * @param {string} data The input bytes.
     * @param {string} nameType An OID for the name type.
     * @return {gss.Name} The resulting name.
     */
    gss.Name.importName = function(data, nameType) {
        if (nameType === gss.NT_EXPORT_NAME) {
            // Strip off the header.
            if (data.length < 4)
                throw new gss.Error(gss.S_BAD_NAME, 0, "Bad format");
            if (data.substring(0, 2) != '\x04\x01')
                throw new gss.Error(gss.S_BAD_NAME, 0, "Bad TOK_ID");
            var mechOidLen = (data.charCodeAt(2) << 8) | data.charCodeAt(3);
            if (data.length < 4 + mechOidLen + 4)
                throw new gss.Error(gss.S_BAD_NAME, 0, "Bad format");
            try {
                var mechOid = asn1.OBJECT_IDENTIFIER.decodeDER(
                    data.substring(4, 4 + mechOidLen));
            } catch (e) {
                if (e instanceof asn1.Error)
                    throw new gss.Error(gss.S_BAD_NAME, 0, e.toString());
                throw e;
            }
            // We only support KRB5.
            if (mechOid !== gss.KRB5_MECHANISM)
                throw new gss.Error(gss.S_BAD_MECH, 0,
                                    "Only krb5 names supported");
            var nameLen =
                (data.charCodeAt(4 + mechOidLen) << 24) |
                (data.charCodeAt(4 + mechOidLen + 1) << 16) |
                (data.charCodeAt(4 + mechOidLen + 2) << 8) |
                data.charCodeAt(4 + mechOidLen + 3);
            if (data.length != (4 + mechOidLen + 4 + nameLen))
                throw new gss.Error(gss.S_BAD_NAME, 0, "Bad length");
            try {
                return new gss.Name(KDC.Principal.fromString(
                    data.substring(4 + mechOidLen + 4)));
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
            return new gss.Name(new KDC.Principal({
                nameType: krb.KRB_NT_SRV_HST,
                nameString: [service, host]
            }, KDC.realm));
        } else if (nameType === gss.KRB5_NT_PRINCIPAL_NAME) {
            try {
                return new gss.Name(KDC.Principal.fromString(data));
            } catch (e) {
                throw new gss.Error(gss.S_BAD_NAME, 0, e);
            }
        } else if (nameType === gss.NT_USER_NAME) {
            return new gss.Name(new KDC.Principal({
                nameType: krb.KRB_NT_PRINCIPAL,
                nameString: [data]
            }, KDC.realm));
        } else {
            throw new gss.Error(gss.S_BAD_NAMETYPE, 0, "Bad nametype");
        }
    };
    gss.Name.prototype.canonicalize = function() {
        // TODO
    };
    /** @return {string} */
    gss.Name.prototype.exportName = function() {
        var tokId = "\x04\x01";
        var mechOid = asn1.OBJECT_IDENTIFIER.encodeDER(gss.KRB5_MECHANISM);
        var mechOidLen = String.fromCharCode(
            mechOid.length >>> 8,
            mechOid.length & 0xff);
        var name = this.principal.toString();
        var nameLen = String.fromCharCode(
            name.length >>> 24,
            (name.length >>> 16) & 0xff,
            (name.length >>> 8) & 0xff,
            name.length & 0xff);
        return tokId + mechOidLen + mechOid + nameLen + name;
    };

    /** @constructor */
    gss.Context = function() {
        // TODO...
    };

    return gss;
}());
