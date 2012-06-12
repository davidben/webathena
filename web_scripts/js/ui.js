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
        localStorage.removeItem('tgtSession');
        window.location.reload(); // XXX
    });
    
    $('#login').submit(function(e) {
        // Even if we throw an exception, don't submit the form.
        e.preventDefault();

        $('#alert').slideUp(100);
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
            var string;
            if(error instanceof Err) {
                if(error.ctx == Err.Context.ENC && error.code == 4)
                    string = 'Incorrect password!';
                else if(error.ctx = Err.Context.KDC && error.code == 6)
                    string = 'Username does not exist!';
                else
                    string = error.msg + ' (' + error.code + ')';
            } else {
                string = String(error);
            }
            $('#alert-title').text('Error logging in:');
            $('#alert-text').text(string);
            $('#alert').slideDown(100);
            resetForm();
        };
        
        KDC.getTGTSession(username, password, function(tgtSession) {
            console.log(tgtSession);
            // Save in local storage.
            localStorage.setItem('tgtSession', JSON.stringify(tgtSession));

            resetForm();
            $('#login').fadeOut();
            $('#authed').fadeIn();
            // FIXME: Property stringifying of principals
            $('#principal').text(tgtSession.cname.nameString.join('/') + '@' + tgtSession.crealm);
        }, onError);
        return false;
    });

    // Check if we're already logged in.
    if (localStorage.getItem('tgtSession')) {
        var tgtSession = KDC.Session.fromDict(
            JSON.parse(localStorage.getItem('tgtSession')));
        // TODO: check tgtSession.isExpired
        $('#login').hide();
        $('#authed').show();
        // FIXME: Property stringifying of principals
        $('#principal').text(tgtSession.cname.nameString.join('/') + '@' + tgtSession.crealm);
    }
});
