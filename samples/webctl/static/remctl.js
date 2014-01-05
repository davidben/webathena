"use strict";

// Socket proxy errors.
var ERR_BAD_FORMAT = 4000;
var ERR_BAD_PARAMS = 4001;
var ERR_ALREADY_INITIALIZED = 4002;
var ERR_FORBIDDEN_ENDPOINT = 4003;
var ERR_SOCKET_ERROR = 4004;
var ERR_UNINITIALIZED = 4005;
var ERR_BAD_MESSAGE_TYPE = 4006;

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

var ERROR_INTERNAL           = 1;
var ERROR_BAD_TOKEN          = 2;
var ERROR_UNKNOWN_MESSAGE    = 3;
var ERROR_BAD_COMMAND        = 4;
var ERROR_UNKNOWN_COMMAND    = 5;
var ERROR_ACCESS             = 6;
var ERROR_TOOMANY_ARGS       = 7;
var ERROR_TOOMUCH_DATA       = 8;
var ERROR_UNEXPECTED_MESSAGE = 9;

var MAX_TOKEN_SIZE = 1048576;
var MAX_WRAP_SIZE = 65536;

function RemctlError(code, message) {
    this.code = code;
    this.message = message;
}
RemctlError.prototype.toString = function() {
    return this.message;
};

function RemctlSocket(proxy, host, port) {
    if (port === undefined) port = REMCTL_PORT;

    // Default callbacks to no-ops.
    this.onpacket = function() { };

    // Various deferred's to get a nicer API for when the socket is
    // open or closed.
    this.deferredReady = Q.defer();
    this.deferredEnd = Q.defer();

    // True if buffer is waiting on a header, rather than data.
    this.pendingHeader = true;
    // If pendingHeader is false, the flags for the message we're reading.
    this.flags = -1;
    // The buffer for our current stage.
    this.buffer = new Uint8Array(5);
    // How far we are into the buffer.
    this.bufferPos = 0;

    this.socket = new SockJS(proxy);
    this.socket.addEventListener('open', function() {
        this.socket.send(JSON.stringify({
            type: 'init',
            host: host,
            port: port
        }));
    }.bind(this));
    this.socket.addEventListener('message', function(ev) {
        try {
            var msg = JSON.parse(ev.data);
        } catch (err) {
            this.disconnect(new Error('Bad server message format'));
            throw err;
        }
        if (msg.type === 'ready') {
            this.deferredReady.resolve(null);
        } else if (msg.type === 'data') {
            var b64 = msg.data;
            // We got more data. Copy what we can into the current buffer.
            var data = arrayutils.fromBase64(b64);
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
                            this.disconnect(new Error("Packet too long."));
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
        } else {
            if (window.console && console.log)
                console.log('Unexpected message', msg);
        }
    }.bind(this));
    this.socket.addEventListener('close', function(ev) {
        if (ev.code === 1000) {
            this.disconnect();
        } else {
            // TODO(davidben): Pass the exit code along too.
            this.disconnect(new Error(ev.reason));
        }
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
    this.socket.send(JSON.stringify({
        type: 'write',
        data: arrayutils.toBase64(buf)
    }));
};
RemctlSocket.prototype.ready = function() {
    return this.deferredReady.promise;
};
RemctlSocket.prototype.end = function() {
    return this.deferredEnd.promise;
};
RemctlSocket.prototype.disconnect = function(reason) {
    if (this.deferredEnd.promise.isPending()) {
        if (this.deferredReady.promise.isPending())
            this.deferredReady.reject(reason);
        this.deferredEnd.resolve(reason);
        this.socket.close();
        this.socket = null;
    }
};

function RemctlSession(proxy, peer, credential, host, port) {
    this.deferredReady = Q.defer();

    // State for the current command.
    this.deferredStatus = null;
    this.onOutput = null;

    this.context = new gss.Context(peer, gss.KRB5_MECHANISM, credential, {
        mutualAuthentication: true,
        confidentiality: true,
        integrity: true,
        sequence: true,
        replayDetection: true
    });

    this.socket = new RemctlSocket(proxy, host, port);

    this.socket.ready().then(function() {
        this.socket.sendPacket(TOKEN_NOOP | TOKEN_CONTEXT_NEXT | TOKEN_PROTOCOL,
                               new Uint8Array(0));
        this._processAuthToken();
    }.bind(this), function(err) {
        this.deferredReady.reject(err);
    }.bind(this)).done();

    this.socket.end().then(function() {
        // If we haven't completed the context yet, we were never
        // ready. Make it throw.
        if (this.deferredReady.promise.isPending())
            this.deferredReady.reject(new Error("Disconnected"));
    }.bind(this)).done();

    this.socket.onpacket = function(flags, data) {
        if (this.context.isEstablished()) {
            if (flags !== (TOKEN_DATA|TOKEN_PROTOCOL)) {
                this.disconnect(new Error("Bad flags"));
                return;
            }
            var unwrapped = this.context.unwrap(data).message;
            if (unwrapped.length < 2) {
                this.disconnect(new Error("Bad message length"));
                return;
            }
            var version = unwrapped[0];
            var type = unwrapped[1];
            var data = unwrapped.subarray(2);
            this._handleMessage(version, type, data);
        } else {
            if (flags !== (TOKEN_CONTEXT|TOKEN_PROTOCOL)) {
                this.disconnect(new Error("Bad flags"));
                return;
            }
            this._processAuthToken(data);
        }
    }.bind(this);
}
RemctlSession.prototype._processAuthToken = function(token) {
    try {
        var resp = this.context.initSecContext(token);
        if (resp) {
            this.socket.sendPacket(TOKEN_CONTEXT|TOKEN_PROTOCOL, resp);
        }
        if (this.context.isEstablished()) {
            this.deferredReady.resolve(null);
        }
    } catch (e) {
        // I don't think it's possible for this to fail, but things
        // might have been reordered?
        if (this.deferredReady.promise.isPending())
            this.deferredReady.reject(e);
        // GSS error. Disconnect.
        this.socket.disconnect();
    }
};
RemctlSession.prototype._handleMessage = function(version, type, data) {
    // We should only receive messages when there is a pending
    // command.
    if (!this.deferredStatus) {
        this.disconnect(new Error("Unexpected message"));
        return;
    }
    if (type === MESSAGE_OUTPUT) {
        if (this.onOutput) {
            var dataview = new DataView(data.buffer,
                                        data.byteOffset,
                                        data.byteLength);
            var stream = dataview.getUint8(0);
            // What's the point of this? Whatever. We'll pull out that
            // length and check it.
            var length = dataview.getUint32(1);
            if (5 + length > data.length) {
                this.disconnect(new Error("Bad message"));
                return;
            }
            var output = data.subarray(5, 5 + length);
            this.onOutput(stream, output);
        }
    } else if (type === MESSAGE_STATUS) {
        var status = data[0];
        this.deferredStatus.resolve(status);
        this.deferredStatus = null;
        this.onOutput = null;
    } else if (type === MESSAGE_ERROR) {
        var dataview = new DataView(data.buffer,
                                    data.byteOffset,
                                    data.byteLength);
        var code = dataview.getUint32(0);
        // What's the point of this? Whatever. We'll pull out that
        // length and check it.
        var length = dataview.getUint32(4);
        if (8 + length > data.length) {
            this.disconnect(new Error("Bad message"));
            return;
        }
        var message = data.subarray(8, 8 + length);
        this.deferredStatus.reject(
            new RemctlError(code, arrayutils.toString(message)));
        this.deferredStatus = null;
        this.onOutput = null;
    } else if (type === MESSAGE_VERSION) {
        // TODO: If we handle MESSAGE_NOOP, we'll care about this.
    } else {
        this.disconnect(new Error("Unknown message type " + type));
    }
};
RemctlSession.prototype.ready = function() {
    return this.deferredReady.promise;
};
RemctlSession.prototype.end = function() {
    return this.socket.end();
};
RemctlSession.prototype.sendMessage = function(data) {
    // Meh. Probably could pass the version/type and have it assemble
    // this for you.
    this.socket.sendPacket(TOKEN_DATA | TOKEN_PROTOCOL,
                           this.context.wrap(data, true));
};
RemctlSession.prototype.disconnect = function(reason) {
    if (this.socket) {
        // If we got a disconnect mid-command, that's an error.
        if (this.deferredStatus)
            this.deferredStatus.reject(reason);
        this.socket.disconnect(reason);
        this.socket = null;
    }
};
RemctlSession.prototype.quit = function() {
    this.sendMessage(new Uint8Array([2, MESSAGE_QUIT]));
};
RemctlSession.prototype.command = function(args, onOutput, keepAlive) {
    // Only one command at a time. (Can you pipeline? Meh.)
    if (this.deferredStatus) {
        return Q.reject(new Error("remctl session is busy"));
    }

    this.onOutput = onOutput;
    this.deferredStatus = Q.defer();

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
        var arg = arrayutils.fromString(args[i]);
        appendUint32(arg.length);
        appendBytes(arg);
    }
    flushBuffer(true);

    return this.deferredStatus.promise;
};
