"use strict";

$(function() {
    $('#whatis a').click(function() {
        $('#info').slideToggle();
        return false;
    });
    $('#logout button').click(function() {
        window.location.reload();
    });
    
    $('#authed').slideUp(0);
    
    $('#login').submit(function() {
        var username = this.username.value,
            password = this.password.value,
            fail = false;
        if(!username) {
            $('#username + .error').fadeIn();
            fail = true;
        } else {
            $('#username + .error').fadeOut();
        }
        if(!password) {
            $('#password + .error').fadeIn();
            fail = true;
        } else {
            $('#password + .error').fadeOut();
        }
        if(fail)
            return false;
        
        this.password.value = '';
        var text = $('#submit').text();
        $('#submit').attr('disabled', 'disabled').text('.');
        var interval = setInterval(function() {
          $('#submit').text(($('#submit').text() + '.').replace('.....', '.'));
        }, 500);
        var reset = function() {
            clearInterval(interval);
            $('#submit').attr('disabled', null).text(text);
        };
        KDC.asReq(username, function(reply) {
            console.log(username);
            console.log(reply);

            // 3.1.5.  Receipt of KRB_AS_REP Message

            // If any padata fields are present, they may be used to
            // derive the proper secret key to decrypt the message.
            if (reply.padata) {
	        // TODO: Do something about this one.
            }

            // The default salt string, if none is provided via
            // pre-authentication data, is the concatenation of the
            // principal's realm and name components, in order, with
            // no separators.
            var salt = KDC.realm + username;
            var encProfile = krb.encProfiles[reply.encPart.etype];
            if (encProfile === undefined) {
                console.log("Unsupported enctype " + reply.encPart.etype)
                reset();
                return;
            }

            var key = encProfile.stringToKey(password, salt);
            // The key usage value for encrypting this field is 3 in
            // an AS-REP message, using the client's long-term key or
            // another key selected via pre-authentication mechanisms.
            var derivedKey = encProfile.deriveKey(key, krb.KU_AS_REQ_ENC_PART);

            // The client decrypts the encrypted part of the response
            // using its secret key...
	    var t = encProfile.decrypt(
                derivedKey,
                encProfile.initialCipherState(derivedKey, false),
                reply.encPart.cipher);
            // Some ciphers add padding, so we can't abort if there is
            // data left over. Also allow an EncTGSRepPart because the
            // MIT KDC is screwy.
            var encRepPart = krb.EncASorTGSRepPart.decodeDERPrefix(t[1])[0][1];
            console.log(encRepPart);

            reset();
            $('#login').slideUp();
            $('#authed').slideDown();
            $('#principal').text(reply.cname.nameString + '@' + reply.crealm);
        }, function(error) {
            console.log("Error in AS_REQ: " + error); // TODO actual error reporting
            reset();
        });
        return false;
    });
});
