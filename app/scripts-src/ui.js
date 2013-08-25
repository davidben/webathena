"use strict";

sjcl.random.startCollectors();
// Get some randomness from the server; ideally every browser would
// have a decent source of real randomness, but we don't. We use SJCL,
// so we'll use what entropy we can get (including
// crypto.getRandomValues), so if legitimate randomness is available,
// it will be used. But if not, instead of being obnoxious and popping
// up an angry warning, trust the proxy a bit more and seed the
// entropy pool. It's not /completely/ terrible since most of these
// are nonces and not encryption keys. (When we do generate a key, we
// incorporate the KDC-generated session key since the KDC is already
// a trusted third party in Kerberos. Also GSS-API mutual auth allows
// the server to pick the final key.)
KDC.xhrRequest(null, 'urandom').then(function(data) {
    var bytes = arrayutils.fromBase64(data);
    var words = new Uint32Array(bytes.buffer,
                                bytes.byteOffset,
                                bytes.byteLength / 4);
    // The polyfill + closure compiler conflicts with SJCL's ability
    // to detect Uint32Array, so use a normal array.
    var arr = [];
    for (var i = 0; i < words.length; i++) {
        arr.push(words[i]);
    }
    sjcl.random.addEntropy(arr, arr.length * 32, 'server');
}).done();

function showLoginPrompt() {
    var deferred = Q.defer();
    var login = $('#login-template').children().clone();
    login.appendTo(document.body);
    login.find('.username').focus();

    login.find('form').submit(function(e) {
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
        var principal = krb.Principal.fromString(username);
        KDC.getTGTSession(principal, password).then(function(tgtSession) {
            resetForm();
            // Position-absolute it so it doesn't interfere with its
            // replacement. jQuery's position function tries to take
            // the margins into account and this seems to be
            // buggy. Just compute the position straight and be done
            // with it.
            var position = login.get(0).getBoundingClientRect();
            var parentPosition =
                login.offsetParent().get(0).getBoundingClientRect();
            login.css({
                margin: '0',
                position: 'absolute',
                top: (position.top - parentPosition.top) + 'px',
                left: (position.left - parentPosition.left) + 'px'
            });
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

    login.find('form').submit(function(e) {
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
            // Position-absolute it so it doesn't interfere with its
            // replacement. jQuery's position function tries to take
            // the margins into account and this seems to be
            // buggy. Just compute the position straight and be done
            // with it.
            var position = login.get(0).getBoundingClientRect();
            var parentPosition =
                login.offsetParent().get(0).getBoundingClientRect();
            login.css({
                margin: '0',
                position: 'absolute',
                top: (position.top - parentPosition.top) + 'px',
                left: (position.left - parentPosition.left) + 'px'
            });
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
            } else if (error instanceof KDC.NetworkError) {
                string = error.message;
            } else {
                // TODO: Just throw this or something?
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
    // Blow away ccache on format changes.
    var currentVersion = '1';
    if (localStorage.getItem('version') !== currentVersion) {
        localStorage.clear();
        localStorage.setItem('version', currentVersion);
    }

    // Check if we're already logged in.
    var sessionJson = localStorage.getItem('tgtSession');
    if (sessionJson) {
        var tgtSession = krb.Session.fromDict(JSON.parse(sessionJson));
        // Treat as expired if we have less than an hour left. It'd be
        // poor to give clients an old ticket.
        if (tgtSession.timeRemaining() < 60 * 60 * 1000) {
            return showRenewPrompt(tgtSession).then(function(tgtSession) {
                // Save in local storage.
                localStorage.setItem('tgtSession',
                                     JSON.stringify(tgtSession.toDict()));
                return [tgtSession, true];
            });
        }
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
    $('#eye1').css({ left: 78, top: 12 }).removeAttr('hidden');
    $('#eye2').css({ left: 87, top: 16 }).removeAttr('hidden');
    $('#eye3').css({ left: 105, top: 16 }).removeAttr('hidden');
    $('#eye4').css({ left: 121, top: 12 }).removeAttr('hidden');
    $(document).mousemove(function(event) {
        $('#logo img').each(function() {
            var dx = event.pageX - $(this).offset().left - $(this).width() / 2,
                dy = event.pageY - $(this).offset().top - $(this).height() / 2,
                transform = 'rotate(' + Math.atan2(dx, -dy) + 'rad)';
            // jQuery handles prefixes for us. Also browsers are
            // unprefixing this anyway.
            $(this).css({ transform: transform });
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
