(function () {
    var WEBATHENA_HOST = "https://webathena.mit.edu";
    var REMOTE_HOST = "linerva.mit.edu";
    var REALM = "ATHENA.MIT.EDU";
    var SHELL_URL = "/shell-webathena";

    var button = document.getElementById("login");
    var container = document.getElementById("siab");
    // Pfft. Firefox seems to leave it disabled sometimes.
    button.disabled = false;
    button.addEventListener("click", function (ev) {
	button.disabled = true;

	// TODO: Also support delegating a TGT?
        WinChan.open({
            url: WEBATHENA_HOST + "/#!request_ticket_v1",
            relay_url: WEBATHENA_HOST + "/relay.html",
	    params: {
		realm: REALM,
		principal: ["host", REMOTE_HOST]
	    }
	}, function (err, r) {
	    if (err) {
		button.disabled = false;
		// TODO: Report the error.
		console.log(err);
		return;
	    }
	    if (r.status !== "OK") {
		button.disabled = false;
		// TODO: Report the error.
		console.log(r);
		return;
	    }

	    // We don't need the Kerberos implementation. The SIAB
	    // helper just wants it as a JSON blob, so we forward to
	    // the server.
            var session = JSON.stringify(r.session);

	    container.innerHTML = "";
	    var iframe = document.createElement("iframe");
	    iframe.src = SHELL_URL + "?cred=" + encodeURIComponent(session);
	    container.appendChild(iframe);
	});
    });
})();