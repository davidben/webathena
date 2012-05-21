import dns.resolver
import json

from werkzeug.exceptions import HTTPException
from werkzeug.routing import Map, Rule
from werkzeug.wrappers import Request, Response

import settings

class WebKDC(object):

    def __init__(self):
        self.url_map = Map([
            Rule('/v1/<arg>', endpoint='query'),
        ])

    def on_query(self, request, arg):
        # TODO: Support TCP as well as UDP. I think MIT's KDC only
        # support's UDP though.
        srv_query = '_kerberos._udp.' + settings.REALM
        srv_records = list(dns.resolver.query(srv_query, 'SRV'))
        srv_records.sort(key = lambda r: r.priority)

        data = [{'target': str(r.target), 'port': int(r.port)} for r in srv_records]
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
