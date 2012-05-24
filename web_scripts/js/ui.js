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
        $('#info').slideToggle(0)
                  .css('height', $('#info').height())
                  .slideToggle(0)
                  .slideToggle();
        return false;
    });
    $('#logout button').click(function() {
        window.location.reload(); // XXX
    });
    
    $('#login').submit(function(e) {
        // Even if we throw an exception, don't submit the form.
        e.preventDefault();

        $('#alert').slideUp();
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
            switch(error) {
                case 'Checksum mismatch!':
                    error = 'Incorrect password!';
                    break;
                case 'Client not found in Kerberos database (6)':
                    error = 'Username does not exist!';
                    break;
            }
            $('#alert #content').html('<b>Error logging in:</b><br>' + error);
            $('#alert').slideDown();
            resetForm();
        };
        
        KDC.getTGTSession(username, password, function(session) {
            console.log(session);

            resetForm();
            $('#login').fadeOut();
            $('#authed').fadeIn();
            $('#principal').text(session.cname.nameString + '@' + session.crealm);
        }, onError);
        return false;
    });
});
