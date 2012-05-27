"use strict";

window.addEventListener("message", function (e) {
    var request = JSON.parse(e.data);

    // TODO: Open a popup and stuff to login.
    // TODO: Probably want error codes too in this API.
    if (!localStorage.getItem('tgtSession')) {
        e.source.postMessage(JSON.stringify({
            status: 'ERROR',
            message: 'Not logged in'
        }), e.origin);
        return;
    }

    // Pull out the ticket.
    var tgtSession = KDC.Session.fromDict(
        JSON.parse(localStorage.getItem('tgtSession')));

    // TODO: Open a popup and stuff. I guess this error might actually
    // appear if the popup has a cancel button or something.
    if (tgtSession.isExpired()) {
        e.source.postMessage(JSON.stringify({
            status: 'ERROR',
            message: 'Ticket expired'
        }), e.origin);
        return;
    }

    var principal = {
        nameType: krb.KRB_NT_UNKNOWN,
        nameString: request.principal
    };
    // HACK: Prompt user for permission and stuff instead of just
    // hardcoding these.
    if (e.origin != 'https://davidben.scripts.mit.edu'
        || request.realm != 'ATHENA.MIT.EDU'
        || !krb.principalNamesEqual(
            principal,
            { nameString: ['zephyr', 'zephyr'] })) {
        e.source.postMessage(JSON.stringify({
            status: 'ERROR',
            message: 'Not allowed'
        }), e.origin);
        return;
    }

    // User gave us permission and we have a legit TGT. Let's go!
    tgtSession.getServiceSession(
        [principal, request.realm],
        function (session) {
            e.source.postMessage(JSON.stringify({
                status: 'OK',
                session: session,
                nonce: request.nonce
            }), e.origin);
        },
        function (error) {
            // Should we send the error back? Probably want to figure
            // that out when we sort out error handling in our own
            // origin.
            e.source.postMessage(JSON.stringify({
                status: 'ERROR',
                message: 'Something bad happened'
            }), e.origin);
        });
});