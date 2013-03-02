var fs = require('fs');
var http = require('http');
var net = require('net');
var socketIo = require('socket.io');
var nodeStatic = require('node-static');

var ALLOWED_HOSTS = {
    'xvm-remote.mit.edu': true,
    'zygorthian-space-raiders.mit.edu': true
};
var REMCTL_PORT = 4373;

function isAllowedEndpoint(host, port) {
    return ALLOWED_HOSTS[host] && port === REMCTL_PORT;
}

var file = new nodeStatic.Server(__dirname + '/static/');
var app = http.createServer(function(req, res) {
    req.addListener('end', function() {
        file.serve(req, res);
    });
});

var io = socketIo.listen(app);

io.sockets.on('connection', function(socket) {
    var tcp = null;

    socket.on('init', function(host, port) {
        if (tcp !== null)
            return;  // Ignore.
        if (!isAllowedEndpoint(host, port)) {
            socket.emit('init-error', 'Bad host/port');
            socket.disconnect();
            return;
        }

        tcp = net.createConnection({host: host, port: port}, function() {
            socket.emit('ready');
        });

        tcp.on('data', function(buffer) {
            socket.emit('data', buffer.toString('base64'));
        });
        tcp.on('end', function() {
            socket.emit('end');
        });
        tcp.on('error', function(e) {
            // TODO: Send a more structured error along?
            socket.emit('error', e.toString());
        });
        tcp.on('close', function() {
            socket.emit('close');
            socket.disconnect();
        });
    });

    socket.on('write', function(data) {
        if (tcp === null)
            return;  // Ignore.
        tcp.write(data, 'base64');
    });
    socket.on('end', function() {
        if (tcp === null)
            return;  // Ignore.
        tcp.end();
    });
});

app.listen(1337, '127.0.0.1');
