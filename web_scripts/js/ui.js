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
