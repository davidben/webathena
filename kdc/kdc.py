import base64
import dns.resolver
import json
import select
import socket

from werkzeug.exceptions import HTTPException
from werkzeug.routing import Map, Rule
from werkzeug.wrappers import Request, Response

import settings

def wait_on_sockets(socks, timeout):
    rs, _, _ = select.select(socks, [], [], timeout)
    for r in rs:
        data = r.recv(4096)
        if data:
            return data
    return None

# Algorithm borrowed from MIT kerberos code. This probably works or
# something.
def send_request(socks, data):
    delay = 2
    for p in range(3):
        for s in socks:
            # Send the request.
            ret = s.send(data)
            if ret == len(data):
                # Wait for a reply for a second.
                reply = wait_on_sockets(socks, 1)
                if reply is not None:
                    return reply
        # Wait for a reply from anyone.
        reply = wait_on_sockets(socks, delay)
        if reply is not None:
            return reply
        delay *= 2
    return None

class WebKDC(object):

    def __init__(self, realm=settings.REALM):
        self.realm = realm
        self.url_map = Map([
            Rule('/v1/<krb_req_b64>', endpoint='request'),
        ])

    def on_request(self, request, krb_req_b64):
        krb_req = base64.b64decode(krb_req_b64)

        # TODO: Support TCP as well as UDP. I think MIT's KDC only
        # support's UDP though.
        srv_query = '_kerberos._udp.' + self.realm
        srv_records = list(dns.resolver.query(srv_query, 'SRV'))
        srv_records.sort(key = lambda r: r.priority)

        socks = []
        try:
            for r in srv_records:
                host = str(r.target)
                port = int(r.port)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setblocking(0)
                s.connect((host, port))
                socks.append(s)

            krb_rep = send_request(socks, krb_req)
        finally:
            for s in socks:
                s.close()

        if krb_rep is None:
            data = { 'status': 'TIMEOUT' }
        else:
            data = {
                'status': 'OK',
                'reply': base64.b64encode(krb_rep)
                }
        return Response(json.dumps(data), mimetype='application/json')

    def dispatch_request(self, request):
        adapter = self.url_map.bind_to_environ(request.environ)
        try:
            endpoint, values = adapter.match()
            return getattr(self, 'on_' + endpoint)(request, **values)
        except HTTPException, e:
            return e

    def wsgi_app(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)


def create_app():
    return WebKDC()


if __name__ == '__main__':
    from werkzeug.serving import run_simple
    app = create_app()
    run_simple('127.0.0.1', 5000, app, use_debugger=True, use_reloader=True)
