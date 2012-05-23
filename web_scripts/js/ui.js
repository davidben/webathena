"use strict";

$(function() {
    $('#whatis').click(function() {
        $('#info').slideToggle();
        return false;
    });
    
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

	    if (reply.msgType == krb.KRB_MT_ERROR) {
		// TODO: Do something with this.
		console.log("Got KRB_ERROR");
		reset();
		return;
	    }

	    // 3.1.5.  Receipt of KRB_AS_REP Message

	    // If the reply message type is KRB_AS_REP, then the
	    // client verifies that the cname and crealm fields in the
	    // cleartext portion of the reply match what it requested.
	    if (reply.crealm != KDC.realm) {
		console.log("AS_REQ crealm does not match");
		reset();
		return;
	    }
	    if (reply.cname.nameType != krb.KRB_NT_PRINCIPAL ||
		reply.cname.nameString.length != 1 ||
		reply.cname.nameString[0] != username) {
		console.log("AS_REQ cname does not match");
		reset();
		return;
	    }


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
	    var key = krb.stringToKey(reply.encPart.etype, password, salt);

	    // The client decrypts the encrypted part of the response
	    // using its secret key...
	    var encPart = krb.decryptEncrypedData(
		reply.encPart, krb.EncASRepPart, key);

            reset();
        }, function(error) {
            console.log("Error in AS_REQ: " + error); // TODO actual error reporting
            reset();
        });
        return false;
    });
});
