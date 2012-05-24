"use strict";

$(function() {
    $('<img src="eye-small.png">').css({ left: 78, top: 12 })
                                  .appendTo('#logo');
    $('<img src="eye-large.png">').css({ left: 87, top: 16 })
                                  .appendTo('#logo');
    $('<img src="eye-large.png">').css({ left: 105, top: 16 })
                                  .appendTo('#logo');
    $('<img src="eye-small.png">').css({ left: 121, top: 12 })
                                  .appendTo('#logo');
    $(document).mousemove(function(event) {
        $('#logo img').each(function() {
            var dx = event.pageX - $(this).offset().left - $(this).width() / 2,
                dy = event.pageY - $(this).offset().top - $(this).height() / 2,
                transform = 'rotate(' + Math.atan2(dx, -dy) + 'rad)';
            $(this).css({ transform: transform,
                          '-moz-transform': transform,
                          '-webkit-transform': transform,
                          '-ms-transform': transform,
                          '-o-transform': transform });
        });
    });
    
    $('#whatis a').click(function() {
        $('#info').slideToggle();
        return false;
    });
    $('#logout button').click(function() {
        window.location.reload();
    });
    
    $('#authed').fadeOut(0);
    
    $('#login').submit(function(e) {
	// Even if we throw an exception, don't submit the form.
	e.preventDefault();

        var username = $('#username')[0].value,
            password = $('#password')[0].value,
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
        
        $('#password')[0].value = '';
        var text = $('#submit').text();
        $('#submit').attr('disabled', 'disabled').text('.');
        var interval = setInterval(function() {
          $('#submit').text(($('#submit').text() + '.').replace('.....', '.'));
        }, 500);
        var resetForm = function() {
            clearInterval(interval);
            $('#submit').attr('disabled', null).text(text);
        };
        var onError = function(error) {
            // TODO actual error reporting
            console.log("Error in AS_REQ: " + error);
            resetForm();
        };
        
        KDC.asReq(username, function(reply) {
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
                onError('Unsupported enctype ' + reply.encPart.etype);
                return;
            }

            var key = encProfile.stringToKey(password, salt);
            // The key usage value for encrypting this field is 3 in
            // an AS-REP message, using the client's long-term key or
            // another key selected via pre-authentication mechanisms.
            var derivedKey = encProfile.deriveKey(key, krb.KU_AS_REQ_ENC_PART);

            // The client decrypts the encrypted part of the response
            // using its secret key...
            try {
                var t = encProfile.decrypt(
                    derivedKey,
                    encProfile.initialCipherState(derivedKey, false),
                    reply.encPart.cipher);
            } catch(e) {
                alert(e);
                resetForm();
                return;
            }
            // Some ciphers add padding, so we can't abort if there is
            // data left over. Also allow an EncTGSRepPart because the
            // MIT KDC is screwy.
            var encRepPart = krb.EncASorTGSRepPart.decodeDERPrefix(t[1])[0][1];
            console.log(encRepPart);

            resetForm();
            $('#login').fadeOut();
            $('#authed').fadeIn();
            $('#principal').text(reply.cname.nameString + '@' + reply.crealm);
        }, onError);
        return false;
    });
});
