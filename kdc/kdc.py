#!/usr/bin/env python
""" Web-based proxy to a Kerberos KDC for Webathena. """
import base64
import dns.resolver
import json
import os
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

# This is the same limit used internally in MIT Kerberos it seems.
MAX_PACKET_SIZE = 4096

# How many bytes of randomness to return
URANDOM_BYTES = 1024 / 8

def wait_on_sockets(socks, timeout):
    """
    Selects on a list of UDP sockets until one becomes readable or we
    hit a timeout. If one returns a packet we return it. Otherwise
    None.
    """
    ready_r, _, _ = select.select(socks, [], [], timeout)
    for sock in ready_r:
        data = sock.recv(MAX_PACKET_SIZE)
        if data:
            return data
    return None

# Algorithm borrowed from MIT kerberos code. This probably works or
# something.
def send_request(socks, data):
    """
    Attempts to send a single request to a number of UDP sockets until
    one returns or we timeout. Handles retry.
    """
    delay = 2
    for _ in range(3):
        for sock in socks:
            # Send the request.
            ret = sock.send(data)
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
            Rule('/v1/AS_REQ', endpoint=('AS_REQ', krb_asn1.AS_REQ)),
            Rule('/v1/TGS_REQ',
                 endpoint=('TGS_REQ', krb_asn1.TGS_REQ)),
            Rule('/v1/AP_REQ', endpoint=('AP_REQ', krb_asn1.AP_REQ)),
            Rule('/v1/urandom', endpoint=('urandom', None)),
        ])


    def validate_AS_REQ(self, req_asn1):
        msg_type = int(req_asn1.getComponentByName('msg-type'))
        if msg_type != krb_asn1.KDC_REQ.msg_type_as:
            raise ValueError('Bad msg-type')

    def validate_TGS_REQ(self, req_asn1):
        msg_type = int(req_asn1.getComponentByName('msg-type'))
        if msg_type != krb_asn1.KDC_REQ.msg_type_tgs:
            raise ValueError('Bad msg-type')

    def validate_AP_REQ(self, req_asn1):
        pass


    def _error_response(self, e):
        """ Returns a Response corresponding to some exception e. """
        data = { 'status': 'ERROR',
                 'msg': str(e) }
        return Response(json.dumps(data), mimetype='application/json')

    def handle_urandom(self):
        random = os.urandom(URANDOM_BYTES)
        # FIXME: We probably should be using a constant-time encoding
        # scheme here...
        return Response(
            base64.b64encode(random),
            mimetype='application/base64',
            headers=[('Content-Disposition',
                      'attachment; filename="b64_response.txt"')])

    def proxy_kdc_request(self, request, endpoint):
        """
        Common code for all proxied KDC requests. endpoint is a
        (req_name, asn1Type) tuple and comes from the URL map. req_b64
        is base64-encoded request. Calls self.validate_${req_name} to
        perform additional checks before sending it along.
        """
        req_name, asn1Type = endpoint

        if request.method != 'POST':
            return self._error_response('Bad method')

        if req_name == "urandom":
            return self.handle_urandom()

        # Werkzeug docs make a big deal about memory problems if the
        # client sends you MB of data. So, fine, we'll limit it.
        length = request.headers.get('Content-Length', type=int)
        if length is None or length > MAX_PACKET_SIZE * 2:
            return self._error_response('Payload too large')
        req_b64 = request.data

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
        krb_rep = self.send_krb_request(
            der_encoder.encode(req_asn1),
            use_master=request.args.has_key('use_master'))

        if krb_rep is None:
            data = { 'status': 'TIMEOUT' }
        else:
            # TODO: The JSON wrapping here is really kinda
            # pointless. Just make this base64 and report errors with
            # HTTP status codes + JSON or whatever.
            data = {
                'status': 'OK',
                'reply': base64.b64encode(krb_rep)
                }
        # Per Tangled Web, add a defensive Content-Disposition to
        # prevent an extremely confused browser from interpreting this
        # as HTML. Though even navigating to this would be pretty
        # difficult as we require a random header be sent.
        return Response(
            json.dumps(data),
            mimetype='application/json',
            headers=[('Content-Disposition',
                      'attachment; filename="json_response.txt"')])

    def send_krb_request(self, krb_req, use_master):
        """
        Sends Kerberos request krb_req, returns the response or None
        if we time out. If use_master is true, we only talk to the
        master KDC.
        """
        svctype = '_kerberos-master' if use_master else '_kerberos'
        # TODO: Support TCP as well as UDP. I think MIT's KDC only
        # supports UDP though.
        socktype = '_udp'
        srv_query = '%s.%s.%s' % (svctype, socktype, self.realm)
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
    import sys
    from werkzeug.serving import run_simple
    app = create_app()
    ip = '127.0.0.1'
    port = 5000
    if len(sys.argv) > 1:
        ip, port = sys.argv[1].rsplit(':', 1)
        port = int(port)
    run_simple(ip, port, app, use_debugger=True, use_reloader=True)
