#!/usr/bin/env python

# Add our code to path.
import os.path
import re
import sys

BASEDIR = os.path.dirname(__file__)
sys.path.append(os.path.join(BASEDIR, 'kdc'))

from werkzeug.exceptions import NotFound
from werkzeug.wsgi import SharedDataMiddleware, DispatcherMiddleware

import kdc

HEADER_RE = re.compile(r'Header +(set|add|unset) +([^ ]+)( +"([^"]+)")?')
FILES_RE = re.compile(r'<Files ([^>]+)>')
FILES_CLOSE_RE = re.compile(r'</Files>')

def parse_htaccess():
    """
    Parse some subset of .htaccess so we can serve the same headers.
    """
    directives = []
    htaccess = os.path.join(BASEDIR, 'app/.htaccess')
    with open(htaccess) as f:
        for line in f:
            line = line.strip()
            m = HEADER_RE.match(line)
            if m:
                action = m.group(1)
                header = m.group(2)
                value = m.group(4)
                if header != 'Strict-Transport-Security':
                    directives.append(('Header', action, header, value))
                continue
            m = FILES_RE.match(line)
            if m:
                filename = m.group(1)
                directives.append(('Files', filename))
                continue
            m = FILES_CLOSE_RE.match(line)
            if m:
                directives.append(('/Files',))
                continue
    return directives

def create_static_app(root):
    """
    Serves a directory, with hack to make index.html work.
    """
    def with_index_html(environ, start_response):
        environ['PATH_INFO'] = environ.get('PATH_INFO', '') + '/index.html'
        app = SharedDataMiddleware(NotFound(), { '/': root, })
        return app(environ, start_response)
    return SharedDataMiddleware(with_index_html, { '/': root, })

def create_app():
    """
    Serves the entire mess, including hack to make index.html work.
    """
    web_scripts = os.path.join(BASEDIR, 'app')
    test = os.path.join(BASEDIR, 'test-old')

    return DispatcherMiddleware(create_static_app(web_scripts), {
            '/kdc': kdc.create_app(),
            '/test': create_static_app(test),
            })

def apply_htaccess(app):
    directives = parse_htaccess()

    def wrapped(environ, start_response):
        def wrapped_start_response(status, headers):
            enabled = [True]
            for directive in directives:
                if directive[0] == 'Files':
                    enabled.append(environ['PATH_INFO'] ==
                                   os.path.join('/', directive[1]))
                elif directive[0] == '/Files':
                    enabled.pop()
                elif enabled[-1]:
                    if directive[0] == 'Header':
                        _, action, header, value = directive
                        if action in ('set', 'unset'):
                            headers = [(k, v) for (k, v) in headers
                                       if k != header]
                        if action in ('add', 'set'):
                            headers.append((header, value))
                    else:
                        raise ValueError(directive)
            start_response(status, headers)
        return app(environ, wrapped_start_response)
    return wrapped

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    app = create_app()
    app = apply_htaccess(app)
    run_simple('127.0.0.1', 5000, app, use_debugger=True, use_reloader=True)
