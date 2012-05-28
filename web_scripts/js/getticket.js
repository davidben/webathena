"use strict";

window.addEventListener("message", function (e) {
    var request = JSON.parse(e.data);
    console.log("Request", request);
    if (request.method == "get_ticket") {
        getTicket(e, request);
    } else {
        e.source.postMessage(JSON.stringify({
            status: 'ERROR',
            code: 'BAD_METHOD',
            message: 'Unknown method: ' + request.method
        }), e.origin);
    }
});

function getTicket(e, request) {
    // TODO: Open a popup and stuff to login.
    // TODO: Probably want error codes too in this API.
    if (!localStorage.getItem('tgtSession')) {
        console.log('Not logged in');
        e.source.postMessage(JSON.stringify({
            status: 'ERROR',
            code: 'NOT_ALLOWED',
            message: 'Not allowed'
        }), e.origin);
        return;
    }

    // Pull out the ticket.
    var tgtSession = KDC.Session.fromDict(
        JSON.parse(localStorage.getItem('tgtSession')));

    // TODO: Open a popup and stuff. I guess this error might actually
    // appear if the popup has a cancel button or something.
    if (tgtSession.isExpired()) {
        console.log('Ticket expired');
        e.source.postMessage(JSON.stringify({
            status: 'ERROR',
            code: 'NOT_ALLOWED',
            message: 'Not allowed'
        }), e.origin);
        return;
    }

    var principal = {
        nameType: krb.KRB_NT_UNKNOWN,
        nameString: request.principal
    };
    // HACK: Prompt user for permission and stuff instead of just
    // hardcoding these.
    if (e.origin != 'https://davidben.scripts.mit.edu:444'
        || request.realm != 'ATHENA.MIT.EDU'
        || !krb.principalNamesEqual(
            principal,
            { nameString: ['zephyr', 'zephyr'] })) {
        console.log('Not allowed');
        e.source.postMessage(JSON.stringify({
            status: 'ERROR',
            code: 'NOT_ALLOWED',
            message: 'Not allowed'
        }), e.origin);
        return;
    }

    // User gave us permission and we have a legit TGT. Let's go!
    tgtSession.getServiceSession(
        [principal, request.realm],
        function (session) {
            // TODO: Do we want to store this in the ccache too, so a
            // service which doesn't cache its own tickets needn't get
            // new ones all the time? Also, the ccache needs some
            // fancy abstraction or something.
            e.source.postMessage(JSON.stringify({
                status: 'OK',
                session: session,
                nonce: request.nonce
            }), e.origin);
        },
        function (error) {
            console.log(error);
            // Should we send the error back? Probably want to figure
            // that out when we sort out error handling in our own
            // origin.
            e.source.postMessage(JSON.stringify({
                status: 'ERROR',
                code: 'NOT_ALLOWED',
                message: 'Not allowed'
            }), e.origin);
        });
}
