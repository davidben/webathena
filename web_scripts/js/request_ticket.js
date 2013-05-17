"use strict";

// Friendly names of known service principals.
// TODO(davidben): Cross-realm?
// TODO(davidben): Move this to a config.js.
var SERVICES = { };
SERVICES["krbtgt/" + krb.realm + "@" + krb.realm] = {
  dangerous: true,
  desc: "Full access to your Athena account"
};
SERVICES["moira/moira7.mit.edu" + "@" + krb.realm] = {
  dangerous: true,
  desc: "View and modify your mailing lists and groups"
};
SERVICES["afs/athena.mit.edu" + "@" + krb.realm] = {
  dangerous: true,
  desc: "Full access to all your files on Athena"
};
SERVICES["zephyr/zephyr" + "@" + krb.realm] = {
  desc: "Send and receive zephyr notices as you"
};

function makeServiceNode(service) {
  var serviceStr = service.toString();

  var li = document.createElement("li");
  var abbr = document.createElement("abbr");
  li.appendChild(abbr);
  abbr.title = serviceStr;
  if (serviceStr in SERVICES) {
    var info = SERVICES[serviceStr];
    if (info.dangerous)
      li.className = "dangerous";
    $(abbr).text(info.desc);
  } else {
    // Label it "Access BLAH on your behalf".
    // (Okay, fine, dealing with the DOM directly can be annoying.)
    var target = document.createElement("code");
    target.className = "identifier";
    if (service.principalName.nameString.length === 2 &&
        service.principalName.nameString[0] === "host") {
      $(target).text(service.principalName.nameString[1]);
    } else {
      $(target).text(serviceStr);
    }
    abbr.appendChild(document.createTextNode("Access "));
    abbr.appendChild(target);
    abbr.appendChild(document.createTextNode(" on your behalf"));
  }
  return li;
}

function registerTicketAPI() {
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

    // Makes a principal, but is picky about types.
    function makePrincipal(principal, realm) {
      if (typeof realm !== "string")
        throw new TypeError();
      if (!(principal instanceof Array))
        throw new TypeError();
      principal.forEach(function(component) {
        if (typeof component !== "string")
          throw new TypeError();
      });
      return new krb.Principal({
        nameType: krb.KRB_NT_UNKNOWN,
        nameString: principal
      }, realm);
    }

    var services = [];
    var returnList = true;
    try {
      if (args.services) {
        if (!(args.services instanceof Array))
          throw TypeError();
        services = args.services.map(function(service) {
          return makePrincipal(service.principal, service.realm);
        });
        if (services.length == 0)
          throw Error();
      } else {
        services = [makePrincipal(args.principal, args.realm)];
        returnList = false;
      }
    } catch (e) {
      cb({
        status: "ERROR",
        code: "BAD_REQUEST"
      });
      throw e;
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
    // is not a useful string. Also allow things running over
    // localhost. Overwise testing is a nightmare.
    if (origin.substring(0, 8) != "https://" &&
        origin.substring(0, 17) != "http://localhost:") {
        deny();
        return;
    }

    getTGTSession().then(function(r) {
        var tgtSession = r[0], prompted = r[1];

        var authed = $('#request-ticket-template').children().clone();
        authed.appendTo(document.body);
        if (prompted)
            authed.fadeIn();

        authed.find('.client-principal').text(tgtSession.client.toString());
        authed.find('.foreign-origin').text(origin);
        var permissionList = authed.find('.permission-list');
        services.forEach(function(service) {
          permissionList.append(makeServiceNode(service));
        });
        authed.find('.service-principal').text(
          services.map(function(service) {
            return service.toString(); }).join(', '));

        authed.find('.request-ticket-deny').click(deny);
        authed.find('.request-ticket-allow').click(function(e) {
            // None of these errors should really happen. Ideally this
            // file would be in control of the UI and this event
            // listener would only be hooked up when we've got a valid
            // tgtSession.
            if (!localStorage.getItem("tgtSession")) {
                log('No ticket');
                deny();
                return;
            }

            if (tgtSession.isExpired()) {
                // I guess this is actually possible if the ticket
                // expires while this user is deliberating.
                log('Ticket expired');
                deny();
                return;
            }

            // User gave us permission and we have a legit TGT. Let's go!
            Q.all(services.map(function(service) {
              return KDC.getServiceSession(tgtSession, service);
            })).then(function(sessions) {
              // TODO: Do we want to store this in the ccache
              // too, so a service which doesn't cache its own
              // tickets needn't get new ones all the time?
              // Also, the ccache needs some fancy abstraction
              // or something.
              if (returnList) {
                cb({
                  status: 'OK',
                  sessions: sessions.map(function(session) {
                    return session.toDict();
                  })
                });
              } else {
                cb({
                  status: 'OK',
                  session: sessions[0].toDict()
                });
              }
            }, function (error) {
              // TODO(davidben): This is an internal error. We
              // shouldn't close just yet.
              log(error);
              deny();
            }).done();
        });
    }).done();
  });
}
