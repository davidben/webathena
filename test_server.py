#!/usr/bin/python

# Enter the virtualenv
import os.path
_activate = os.path.join(os.path.dirname(__file__),
                         'env/bin/activate_this.py')
execfile(_activate, dict(__file__=_activate))

# Add our code to path.
import sys
sys.path.append(os.path.join(os.path.dirname(__file__),
                             'web_scripts/kdc'))

from werkzeug.exceptions import NotFound
from werkzeug.wsgi import SharedDataMiddleware, DispatcherMiddleware

import kdc

def create_app():
    """
    Serves the entire mess, including hack to make index.html work.
    """
    kdc_app = kdc.create_app()

    web_scripts = os.path.join(os.path.dirname(__file__), 'web_scripts')

    def throw_not_found(e, s): raise NotFound()
    static_app = SharedDataMiddleware(throw_not_found, { '/': web_scripts, })
    def index_html_hack(environ, start_response):
        try:
            return static_app(environ, start_response)
        except NotFound, e:
            environ['PATH_INFO'] = environ.get('PATH_INFO', '') + '/index.html'
            try:
                return static_app(environ, start_response)
            except NotFound, e:
                return e(environ, start_response)

    return DispatcherMiddleware(index_html_hack, { '/kdc': kdc_app, })

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    app = create_app()
    run_simple('127.0.0.1', 5000, app, use_debugger=True, use_reloader=True)
