"use strict";

function showLoginPrompt() {
    var deferred = Q.defer();
    var login = $('#login-template').children().clone();
    login.appendTo(document.body);
    login.find('.username').focus();

    login.submit(function(e) {
        e.preventDefault();

        $('#alert').slideUp(100);
        var usernameInput = $(this).find('.username')[0],
            passwordInput = $(this).find('.password')[0],
            username = usernameInput.value,
            password = passwordInput.value,
            fail = false;
        if (!username) {
            $(this).find('.username + .error').fadeIn();
            fail = true;
        } else {
            $(this).find('.username + .error').fadeOut();
        }
        if (!password) {
            $(this).find('.password + .error').fadeIn();
            fail = true;
        } else {
            $(this).find('.password + .error').fadeOut();
        }
        if (fail)
            return;

        passwordInput.value = '';
        var submit = $(this).find('.submit');
        var text = submit.text();
        submit.attr('disabled', 'disabled').text('.');
        var interval = setInterval(function() {
            submit.text((submit.text() + '.').replace('.....', '.'));
        }, 500);
        var resetForm = function() {
            clearInterval(interval);
            submit.attr('disabled', null).text(text);
        };
        var principal = KDC.Principal.fromString(username);
        KDC.getTGTSession(principal, password).then(function(tgtSession) {
            resetForm();
            login.fadeOut(function() { $(this).remove(); });
            deferred.resolve(tgtSession);
        }, function(error) {
            var string;
            if (error instanceof kcrypto.DecryptionError) {
                string = 'Incorrect password!';
            } else if (error instanceof KDC.Error) {
                if (error.code == krb.KDC_ERR_C_PRINCIPAL_UNKNOWN)
                    string = 'User does not exist!';
                else if (error.code == krb.KDC_ERR_PREAUTH_FAILED ||
                         error.code == krb.KRB_AP_ERR_BAD_INTEGRITY)
                    string = 'Incorrect password!';
                else
                    string = error.message;
            } else {
                string = String(error);
            }
            $('#alert-title').text('Error logging in:');
            $('#alert-text').text(string);
            $('#alert').slideDown(100);
            resetForm();
        }).done();
    });
    return deferred.promise;
}

function showRenewPrompt(oldSession) {
    var deferred = Q.defer();
    var login = $('#renew-template').children().clone();
    login.find('.client-principal').text(oldSession.client.toString());
    login.find('.logout-link').click(function(e) {
        e.preventDefault();
        login.remove(); // TODO: Fade out?
        deferred.resolve(showLoginPrompt());
    });
    login.appendTo(document.body);
    login.find('.password').focus();

    login.submit(function(e) {
        e.preventDefault();

        $('#alert').slideUp(100);
        var passwordInput = $(this).find('.password')[0],
            password = passwordInput.value;
        if (!password) {
            $(this).find('.password + .error').fadeIn();
            return;
        }
        $(this).find('.password + .error').fadeOut();

        passwordInput.value = '';
        var submit = $(this).find('.submit');
        var text = submit.text();
        submit.attr('disabled', 'disabled').text('.');
        var interval = setInterval(function() {
            submit.text((submit.text() + '.').replace('.....', '.'));
        }, 500);
        var resetForm = function() {
            clearInterval(interval);
            submit.attr('disabled', null).text(text);
        };
        KDC.getTGTSession(oldSession.client, password).then(function(tgtSession) {
            resetForm();
            login.fadeOut(function() { $(this).remove(); });
            deferred.resolve(tgtSession);
        }, function(error) {
            var string;
            if (error instanceof kcrypto.DecryptionError) {
                string = 'Incorrect password!';
            } else if (error instanceof KDC.Error) {
                if (error.code == krb.KDC_ERR_C_PRINCIPAL_UNKNOWN)
                    string = 'User does not exist!';
                else if (error.code == krb.KDC_ERR_PREAUTH_FAILED ||
                         error.code == krb.KRB_AP_ERR_BAD_INTEGRITY)
                    string = 'Incorrect password!';
                else
                    string = error.message;
            } else {
                string = String(error);
            }
            $('#alert-title').text('Error logging in:');
            $('#alert-text').text(string);
            $('#alert').slideDown(100);
            resetForm();
        }).done();
    });
    return deferred.promise;
}


function getTGTSession() {
    // Check if we're already logged in.
    var sessionJson = localStorage.getItem('tgtSession');
    if (sessionJson) {
        var tgtSession = KDC.Session.fromDict(JSON.parse(sessionJson));
        if (tgtSession.isExpired())
            return showRenewPrompt(tgtSession).then(function(tgtSession) {
                // Save in local storage.
                localStorage.setItem('tgtSession',
                                     JSON.stringify(tgtSession.toDict()));
                return [tgtSession, true];
            });
        return Q.resolve([tgtSession, false]);
    }

    return showLoginPrompt().then(function(tgtSession) {
        // Save in local storage.
        localStorage.setItem('tgtSession',
                             JSON.stringify(tgtSession.toDict()));
        return [tgtSession, true];
    });
}

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

    function mainPage() {
        getTGTSession().then(function(r) {
            var tgtSession = r[0], prompted = r[1];
            log(tgtSession);

            var authed = $('#authed-template').children().clone();
            authed.appendTo(document.body);
            if (prompted)
                authed.fadeIn();
            // TODO: The main page should be more useful. Maybe a
            // listing of random things you can do with your Athena
            // account.
            authed.find('.client-principal').text(tgtSession.client.toString());
            authed.find('button.logout').click(function() {
                localStorage.removeItem('tgtSession');
                // TODO: Fade this out and the login panel
                // in. Probably fades of the currently active panel
                // should be handled be a container.
                authed.remove();
                mainPage();
            });
        }).done();
    }

    if (location.hash == '#!request_ticket_v1') {
        registerTicketAPI();
    } else {
        mainPage();
    }
});
