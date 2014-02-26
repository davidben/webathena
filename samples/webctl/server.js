var Buffer = require('buffer').Buffer;
var fs = require('fs');
var http = require('http');
var net = require('net');
var sockjs = require('sockjs');
var nodeStatic = require('node-static');

var ALLOWED_HOSTS = {
    'primary-key.mit.edu': true,
    'foreign-key.mit.edu': true,
    'sql.mit.edu': true,
    'xvm-remote.mit.edu': true,
    'zygorthian-space-raiders.mit.edu': true,
    'pergamon.mit.edu': true
};
var REMCTL_PORT = 4373;

function isAllowedEndpoint(host, port) {
    return ALLOWED_HOSTS[host] && port === REMCTL_PORT;
}

var file = new nodeStatic.Server(__dirname + '/static/');
var app = http.createServer(function(req, res) {
    req.addListener('end', function() {
        file.serve(req, res);
    }).resume();
});

var ERR_BAD_FORMAT = 4000;
var ERR_BAD_PARAMS = 4001;
var ERR_ALREADY_INITIALIZED = 4002;
var ERR_FORBIDDEN_ENDPOINT = 4003;
var ERR_SOCKET_ERROR = 4004;
var ERR_UNINITIALIZED = 4005;
var ERR_BAD_MESSAGE_TYPE = 4006;

var sockServer = sockjs.createServer({
    sockjs_url: '/sockjs.min.js'
});
sockServer.on('connection', function(socket) {
    var tcp = null;

    socket.on('data', function(data) {
        try {
            var msg = JSON.parse(data);
        } catch (err) {
            return socket.close(ERR_BAD_FORMAT, 'Bad message format');
        }

        if (msg.type === 'init') {
            if (typeof msg.host !== 'string' || typeof msg.port !== 'number') {
                return socket.close(ERR_BAD_PARAMS, 'Bad message parameters');
            }
            if (tcp !== null) {
                return socket.close(ERR_ALREADY_INITIALIZED,
                                    'Already initialized');
            }

            if (!isAllowedEndpoint(msg.host, msg.port)) {
                return socket.close(ERR_FORBIDDEN_ENDPOINT,
                                    'Forbidden endpoint');
            }

            // Bah.
            if (/^v0\.6\./.exec(process.version)) {
                tcp = net.createConnection(msg.port, msg.host, function() {
                    socket.write(JSON.stringify({type: 'ready'}));
                });
            } else {
                tcp = net.createConnection({
                    host: msg.host,
                    port: msg.port
                }, function() {
                    socket.write(JSON.stringify({type: 'ready'}));
                });
            }

            tcp.on('data', function(buffer) {
                socket.write(JSON.stringify({
                    type: 'data',
                    data: buffer.toString('base64')
                }));
            });
            tcp.on('end', function() {
                socket.close();
            });
            tcp.on('error', function(e) {
                // TODO: Send a more structured error along?
                socket.close(ERR_SOCKET_ERROR, e.toString());
            });
            tcp.on('close', function(had_error) {
                if (had_error) {
                    socket.close(ERR_SOCKET_ERROR, 'Socket error');
                } else {
                    socket.close();
                }
            });
        } else if (msg.type === 'write') {
            if (tcp === null)
                return socket.close(ERR_UNINITIALIZED, 'Uninitialized');
            if (typeof msg.data !== 'string')
                return socket.close(ERR_BAD_PARAMS, 'Bad message parameters');
            try {
                var buf = new Buffer(msg.data, 'base64');
            } catch (err) {
                return socket.close(ERR_BAD_PARAMS, 'Invalid base64');
            }
            tcp.write(buf);
        } else if (msg.type === 'close') {
            if (tcp === null)
                return socket.close(ERR_UNINITIALIZED, 'Uninitialized');
            tcp.end();
        } else {
            return socket.close(ERR_BAD_MESSAGE_TYPE, 'Bad message type');
        }
    });
});
sockServer.installHandlers(app, {prefix: '/socket'});

app.listen(process.env.OPENSHIFT_INTERNAL_PORT || 8080,
           process.env.OPENSHIFT_INTERNAL_IP || '127.0.0.1');
