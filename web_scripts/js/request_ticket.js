"use strict";

WinChan.onOpen(function (origin, args, cb) {
    // NOTE: origin is a trusted value we get from the browser. args
    // is untrusted data from some other origin. It is absolutely
    // critical that we do not eval anything in there, including as
    // HTML. If attaching it to DOM, only use textContent and
    // equivalent APIs.

    // FIXME: ui.js should probably provide some sane API. Maybe a
    // logged in callback? I dunno. Really the UI flow should probably
    // be controlled by the page with ui.js or something similar just
    // providing the functions to actually create these things? I
    // dunno. This currently has silliness where, if onOpen gets
    // called after the UI is shown, placeholder values are visible.

    // TODO: Sanitize this request some more?
    if (!args.realm || !args.principal) {
        cb({
            status: "ERROR",
            code: "BAD_REQUEST",
        });
        return;
    }

    function deny() {
        cb({
            status: "DENIED",
            code: "NOT_ALLOWED"
        });
    }

    // Require everyone to use SSL. (Is there no better way to do this
    // check.) We'll want to allow things like chrome-extension:// in
    // future probably, though chrome-extension://aslkdfjsdlkfjdslkfs
    // is not a useful string.
    if (origin.substring(0, 8) != "https://") {
        deny();
        return;
    }

    var principal = new KDC.Principal({
        nameType: krb.KRB_NT_UNKNOWN,
        nameString: args.principal
    }, args.realm);

    document.getElementById("foreign-origin").textContent = origin;
    document.getElementById("service-principal").textContent =
        principal.toString();
    
    document.getElementById("request-ticket-allow").addEventListener(
        "click", function (e) {
            // None of these errors should really happen. Ideally this
            // file would be in control of the UI and this event
            // listener would only be hooked up when we've got a valid
            // tgtSession.
            if (!localStorage.getItem("tgtSession")) {
                log('No ticket');
                deny();
                return;
            }

            // Pull out the ticket.
            var tgtSession = KDC.Session.fromDict(
                JSON.parse(localStorage.getItem('tgtSession')));

            if (tgtSession.isExpired()) {
                // I guess this is actually possible if the ticket
                // expires while this user is deliberating.
                log('Ticket expired');
                deny();
                return;
            }

            // User gave us permission and we have a legit TGT. Let's go!
            tgtSession.getServiceSession(principal).then(
                function (session) {
                    // TODO: Do we want to store this in the ccache
                    // too, so a service which doesn't cache its own
                    // tickets needn't get new ones all the time?
                    // Also, the ccache needs some fancy abstraction
                    // or something.
                    cb({
                        status: 'OK',
                        session: session,
                    });
                },
                function (error) {
                    log(error);
                    deny();
                }).end();
        });

    document.getElementById("request-ticket-deny").addEventListener("click", deny);
});
