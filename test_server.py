#!/usr/bin/env python

# # Enter the virtualenv
# import os.path
# _activate = os.path.join(os.path.dirname(__file__),
#                          'env/bin/activate_this.py')
# execfile(_activate, dict(__file__=_activate))

# Add our code to path.
import os.path
import re
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'kdc'))

from werkzeug.exceptions import NotFound
from werkzeug.wsgi import SharedDataMiddleware, DispatcherMiddleware

import kdc

HEADER_RE = re.compile(r'Header +add +([^ ]+) "([^"]+)"')

def parse_htaccess():
    """
    Parse some subset of .htaccess so we can serve the same headers.
    """
    headers = {}
    htaccess = os.path.join(os.path.dirname(__file__), 'web_scripts/.htaccess')
    with open(htaccess) as f:
        for line in f:
            line = line.strip()
            # TODO: Support Header set, etc. Also we'll need <Files>
            # and stuff later. We also don't handle escaping, but
            # whatever.
            m = HEADER_RE.match(line)
            if m:
                header = m.group(1)
                value = m.group(2)
                headers[header] = value
    return headers

def create_app():
    """
    Serves the entire mess, including hack to make index.html work.
    """
    kdc_app = kdc.create_app()

    web_scripts = os.path.join(os.path.dirname(__file__), 'web_scripts')

    def with_index_html(environ, start_response):
        environ['PATH_INFO'] = environ.get('PATH_INFO', '') + '/index.html'
        app = SharedDataMiddleware(NotFound(), { '/': web_scripts, })
        return app(environ, start_response)
    static_app = SharedDataMiddleware(with_index_html, { '/': web_scripts, })

    return DispatcherMiddleware(static_app, { '/kdc': kdc_app, })

def apply_htaccess(app):
    htaccess_headers = parse_htaccess()
    del htaccess_headers['Strict-Transport-Security']

    def wrapped(environ, start_response):
        def wrapped_start_response(status, headers):
            headers = [(h, v) for (h, v) in headers
                       if h not in htaccess_headers]
            for key, value in htaccess_headers.items():
                headers.append((key, value))
            start_response(status, headers)
        return app(environ, wrapped_start_response)
    return wrapped

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    app = create_app()
    app = apply_htaccess(app)
    run_simple('127.0.0.1', 5000, app, use_debugger=True, use_reloader=True)
