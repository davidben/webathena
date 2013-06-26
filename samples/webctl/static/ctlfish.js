var ccache = { };
function getCredential(peer) {
    var key = peer.principal.toString();
    if (ccache[key])
        return Q.resolve(ccache[key]);

    var deferred = Q.defer();
    WinChan.open({
        url: WEBATHENA_HOST + "/#!request_ticket_v1",
        relay_url: WEBATHENA_HOST + "/relay.html",
	params: {
	    realm: peer.principal.realm,
	    principal: peer.principal.principalName.nameString
	}
    }, function (err, r) {
	if (err) {
	    deferred.reject(err);
	    return;
	}
	if (r.status !== "OK") {
	    deferred.reject(r);
	    return;
	}
        var session = krb.Session.fromDict(r.session);
        ccache[key] = session;
        deferred.resolve(session);
    });
    return deferred.promise;
}

function makeSpan(className, text) {
    var span = document.createElement("span");
    span.className = className;
    span.textContent = text;
    return span;
}

window.addEventListener("load", function() {
    var form = document.getElementById("remctl-form");
    var output = document.getElementById("output");
    form.addEventListener("submit", function(ev) {
        ev.preventDefault();

        output.textContent = '';

        var server = form.server.value;
        var command = form.command.value.split(" ");  // Bah.

        var peer = gss.Name.importName("host@" + server,
                                       gss.NT_HOSTBASED_SERVICE);

        getCredential(peer).then(function(credential) {
	    // Silliness.
	    var proxy = '';
	    if (location.host === 'ctlfish-davidben.rhcloud.com')
		proxy = 'https://ctlfish-davidben.rhcloud.com:8443';

            var session = new RemctlSession(proxy, peer, credential, server);
            var streams = { };

            function flushStreams() {
                for (var key in streams) {
                    if (!streams.hasOwnProperty(key)) continue;
                    output.appendChild(makeSpan("stream" + key,
                                                streams[key].decode()));
                }
            }

            session.ready().then(function() {
                // TODO: Keep established sessions around for
                // keep-alive and the like.
                return session.command(command, function(stream, data) {
                    if (!streams[stream])
                        streams[stream] = new TextDecoder("utf-8");
                    output.appendChild(
                        makeSpan("stream" + stream,
                                 streams[stream].decode(data, {stream:true})));
                });
            }, function(error) {
                output.appendChild(
                    makeSpan("error",
                             "Failed to establish session: " + error.message));
            }).then(function(status) {
                flushStreams();
                if (status) {
                    output.appendChild(
                        makeSpan("error",
                                 "Command exited with status: " + status));
                }
            }, function(error) {
                flushStreams();
                if (error instanceof RemctlError) {
                    output.appendChild(makeSpan("error",
                                                "ERROR: " + error.message));
                } else {
                    throw error;
                }
            }).done();

            session.end().then(function() {
                console.log('Disconnected');
            }).done();
        }, function(err) {
            output.appendChild(makeSpan("error", "Failed to get credentials"));
        }).done();
    });
});

// Start SJCL's collectors. TODO: Probably also pull some entropy from
// webathena.mit.edu? We are getting some from the session ticket key,
// as MIT kerberos does, which is enough to appease SJCL's default
// paranoia value. But still.
sjcl.random.startCollectors();
