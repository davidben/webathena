"use strict";

var WEBATHENA_HOST = "http://localhost:5000"; // "https://webathena.mit.edu";

var REMCTL_PORT = 4373;

var TOKEN_NOOP = 0x01;
var TOKEN_CONTEXT = 0x02;
var TOKEN_DATA = 0x04;
var TOKEN_CONTEXT_NEXT = 0x10;
var TOKEN_PROTOCOL = 0x40;

var MESSAGE_COMMAND = 0x01;
var MESSAGE_QUIT = 0x02;
var MESSAGE_OUTPUT = 0x03;
var MESSAGE_STATUS = 0x04;
var MESSAGE_ERROR = 0x05;
var MESSAGE_VERSION = 0x06;
var MESSAGE_NOOP = 0x07;

var MAX_TOKEN_SIZE = 1048576;
var MAX_WRAP_SIZE = 65536;

function RemctlSocket(host, port) {
    if (port === undefined) port = REMCTL_PORT;

    // Default callbacks to no-ops.
    this.onready = this.onpacket = this.onerror = this.onend = function() { };

    // True if buffer is waiting on a header, rather than data.
    this.pendingHeader = true;
    // If pendingHeader is false, the flags for the message we're reading.
    this.flags = -1;
    // The buffer for our current stage.
    this.buffer = new Uint8Array(5);
    // How far we are into the buffer.
    this.bufferPos = 0;

    this.socket = io.connect('', { 'force new connection': true });
    this.socket.on('connect', function() {
        this.socket.emit('init', host, port);
    }.bind(this));
    this.socket.on('ready', function() {
        this.onready();
    }.bind(this));
    this.socket.on('data', function(b64) {
        // We got more data. Copy what we can into the current buffer.
        var data = arrayutils.fromByteString(atob(b64));
        while (data.length > 0) {
            var count = Math.min(this.buffer.length - this.bufferPos,
                                 data.length);
            // Copy data into the current buffer.
            this.buffer.set(data.subarray(0, count), this.bufferPos);
            this.bufferPos += count;
            data = data.subarray(count);

            // See if we've completed a buffer.
            if (this.bufferPos >= this.buffer.length) {
                // We've either just gotten a 5-byte header or
                // finished some data.
                if (this.pendingHeader) {
                    var dataview = new DataView(this.buffer.buffer);
                    var len = dataview.getUint32(1);
                    if (len > MAX_TOKEN_SIZE) {
                        // Too long. Disconnect and error.
                        this.onerror("Packet too long.");
                        this.disconnect();
                        return;
                    }
                    this.pendingHeader = false;
                    this.flags = dataview.getUint8(0);
                    this.buffer = new Uint8Array(len);
                    this.bufferPos = 0;
                } else {
                    this.onpacket(this.flags, this.buffer);
                    this.pendingHeader = true;
                    this.buffer = new Uint8Array(5);
                    this.bufferPos = 0;
                }
            }
        }
    }.bind(this));
    this.socket.on('end', function() {
        this.disconnect();
    }.bind(this));
    this.socket.on('timeout', function() {
        this.onerror("Timeout");
        this.disconnect();
    }.bind(this));
    this.socket.on('close', function() {
        this.disconnect();
    }.bind(this));
    this.socket.on('error', function(err) {
        this.onerror(err);
    }.bind(this));
}

RemctlSocket.prototype.sendPacket = function(flags, data) {
    // Prepend the header.
    data = arrayutils.asUint8Array(data);
    var buf = new Uint8Array(1 + 4 + data.length);
    buf[0] = flags;
    new DataView(buf.buffer).setUint32(1, data.length);
    buf.set(data, 5);
    // And write.
    this.socket.emit('write', btoa(arrayutils.toByteString(buf)));
};

RemctlSocket.prototype.disconnect = function() {
    if (this.socket) {
        this.onend();
        this.socket.disconnect();
        this.socket = null;
    }
};

function RemctlSession(peer, credential, host, port) {
    this.onready = this.onmessage = this.onerror = this.onend = function() { };

    this.context = new gss.Context(peer, gss.KRB5_MECHANISM, credential, {
        mutualAuthentication: true,
        confidentiality: true,
        integrity: true,
        sequence: true,
        replayDetection: true
    });
    this.socket = new RemctlSocket(host, port);
    this.socket.onready = function() {
        this.socket.sendPacket(TOKEN_NOOP | TOKEN_CONTEXT_NEXT | TOKEN_PROTOCOL,
                               new Uint8Array(0));
        this._processAuthToken();
    }.bind(this);
    this.socket.onpacket = function(flags, data) {
        if (this.context.isEstablished()) {
            if (flags !== (TOKEN_DATA|TOKEN_PROTOCOL)) {
                this.onerror("Bad flags");
                this.disconnect();
                return;
            }
            var unwrapped = this.context.unwrap(data).message;
            if (unwrapped.length < 2) {
                this.onerror("Bad message length");
                this.disconnect();
                return;
            }
            var version = unwrapped[0];
            var type = unwrapped[1];
            var data = unwrapped.subarray(2);
            this.onmessage(version, type, data);
        } else {
            if (flags !== (TOKEN_CONTEXT|TOKEN_PROTOCOL)) {
                this.onerror("Bad flags");
                this.disconnect();
                return;
            }
            this._processAuthToken(data);
        }
    }.bind(this);
    this.socket.onerror = function(error) {
        this.onerror(error);
    }.bind(this);
    this.socket.onend = function() {
        this.onend();
    }.bind(this);
}
RemctlSession.prototype._processAuthToken = function(token) {
    var resp = this.context.initSecContext(token);
    if (resp) {
        this.socket.sendPacket(TOKEN_CONTEXT|TOKEN_PROTOCOL, resp);
    }
    if (this.context.isEstablished()) {
        this.onready();
    }
};
RemctlSession.prototype.sendMessage = function(data) {
    // Meh. Probably could pass the version/type and have it assemble
    // this for you.
    this.socket.sendPacket(TOKEN_DATA | TOKEN_PROTOCOL,
                           this.context.wrap(data, true));
};
RemctlSession.prototype.disconnect = function() {
    if (this.socket) {
        this.socket.disconnect();
        this.socket = null;
    }
};
RemctlSession.prototype.command = function(args, keepAlive) {
    // Most commands are small, so figure out how much we need instead
    // of always allocating MAX_WRAP_SIZE.
    var len = 4 + 4;
    for (var i = 0; i < args.length; i++) {
        len += (4 + args[i].length);
    }
    var firstSend = true;
    var buffer = new Uint8Array(Math.min(len, MAX_WRAP_SIZE));
    // Reserve two bytes for the keep-alive and continue flags, in
    // addition to the message header.
    var offset = 4;

    // Various functions for buffering and sending buffers out when full.
    var flushBuffer = function(finish) {
        buffer[0] = 2;  // protocol version
        buffer[1] = MESSAGE_COMMAND;
        buffer[2] = keepAlive ? 1 : 0;
        if (firstSend)
            buffer[3] = finish ? 0 : 1;
        else
            buffer[3] = finish ? 3 : 2;
        this.sendMessage(buffer.subarray(0, offset));
        // Reserve two bytes for the keep-alive and continue flags, in
        // addition to the message header.
        offset = 4;
        firstSend = false;
    }.bind(this);
    var appendBytes = function(bytes) {
        while (bytes.length > 0) {
            // Flush buffer if full.
            if (offset === buffer.length)
                flushBuffer(false);
            // Append what we can.
            var len = Math.min(buffer.length - offset, bytes.length);
            buffer.set(bytes.subarray(0, len), offset);
            offset += len;
            bytes = bytes.subarray(len);
        }
    };
    var appendUint32 = function(val) {
        var buf = new Uint8Array(4);
        new DataView(buf.buffer).setUint32(0, val);
        appendBytes(buf);
    };

    // Phew. All that's out of the way. Now format the message.
    appendUint32(args.length);
    for (var i = 0; i < args.length; i++) {
        appendUint32(args[i].length);
        appendBytes(arrayutils.fromUTF16(args[i]));
    }
    flushBuffer(true);
};

function getCredential(peer) {
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
	deferred.resolve(krb.Session.fromDict(r.session));
    });
    return deferred.promise;
}

function doSomething() {
    var server = "zygorthian-space-raiders.mit.edu";  // "xvm-remote.mit.edu";
    var cmd = ["volume", "get"];  // ["list"];

    var peer = gss.Name.importName("host@" + server, gss.NT_HOSTBASED_SERVICE);

    return getCredential(peer).then(function(credential) {
        var session = new RemctlSession(peer, credential, server);
        session.onready = function() {
            session.command(cmd);
        };
        session.onmessage = function(version, type, data) {
            if (type === MESSAGE_OUTPUT && version === 2) {
                var dataview = new DataView(data.buffer,
                                            data.byteOffset,
                                            data.byteLength);
                var stream = dataview.getUint8(0);
                // What's the point of this? Whatever.
                var length = dataview.getUint32(1);
                var output = data.subarray(5, 5 + length);
                console.log(stream, arrayutils.toByteString(output));
            } else if (type === MESSAGE_STATUS && version === 2) {
                var status = data[0];
                console.log("Exit code", status);
            } else {
                console.log('unknown', version, type,
                            arrayutils.toByteString(data));
            }
        };
        session.onerror = function(error) {
            console.log('ERROR', error);
        };
        session.onend = function() {
            console.log('Disconnected');
        };
    }).done();
}
