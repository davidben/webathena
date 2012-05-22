import base64
import dns.resolver
import json
import select
import socket

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.error import PyAsn1Error

from werkzeug.exceptions import HTTPException
from werkzeug.routing import Map, Rule
from werkzeug.wrappers import Request, Response

import krb_asn1
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
        # TODO: Move these out of the URL. It should be POST data or
        # something. Ideally something that form posts can't send
        # (Content-Type: application/json) so that we don't have to
        # care about those DDoS that involve a bunch of visitors all
        # submitting forms and stuff.
        self.url_map = Map([
            Rule('/v1/AS_REQ/<req_b64>', endpoint=('AS_REQ', krb_asn1.AS_REQ)),
            Rule('/v1/TGS_REQ/<req_b64>', endpoint=('TGS_REQ', krb_asn1.TGS_REQ)),
        ])


    def validate_AS_REQ(self, req_asn1):
        msg_type = int(req_asn1.getComponentByName('msg-type'))
        if msg_type != krb_asn1.KDC_REQ.msg_type_as:
            raise ValueError('Bad msg-type')

    def validate_TGS_REQ(self, req_asn1):
        msg_type = int(req_asn1.getComponentByName('msg-type'))
        if msg_type != krb_asn1.KDC_REQ.msg_type_tgs:
            raise ValueError('Bad msg-type')


    def _error_response(self, e):
        data = { 'status': 'ERROR',
                 'msg': str(e) }
        return Response(json.dumps(data), mimetype='application/json')

    def proxy_kdc_request(self, request, endpoint, req_b64):
        req_name, asn1Type = endpoint

        try:
            req_der = base64.b64decode(req_b64)
        except TypeError, e:
            return self._error_response(e)

        # Make sure we don't send garbage to the KDC. Otherwise it
        # doesn't reply and we time out, which is kinda awkward.
        try:
            req_asn1, rest = der_decoder.decode(req_der,
                                                asn1Spec=asn1Type())
            if rest:
                raise ValueError('Garbage after request')
            getattr(self, 'validate_' + req_name)(req_asn1)
        except (PyAsn1Error, ValueError), e:
            return self._error_response(e)

        # Okay, it seems good. Go on and send it, reencoded.
        krb_rep = self.send_krb_request(der_encoder.encode(req_asn1))

        if krb_rep is None:
            data = { 'status': 'TIMEOUT' }
        else:
            data = {
                'status': 'OK',
                'reply': base64.b64encode(krb_rep)
                }
        return Response(json.dumps(data), mimetype='application/json')

    def send_krb_request(self, krb_req):
        # TODO: Support TCP as well as UDP. I think MIT's KDC only
        # supports UDP though.
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

            return send_request(socks, krb_req)
        finally:
            for s in socks:
                s.close()

    def dispatch_request(self, request):
        adapter = self.url_map.bind_to_environ(request.environ)
        try:
            endpoint, values = adapter.match()
            return self.proxy_kdc_request(request, endpoint, **values)
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
