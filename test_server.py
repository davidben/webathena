#!/usr/bin/env python

# # Enter the virtualenv
# import os.path
# _activate = os.path.join(os.path.dirname(__file__),
#                          'env/bin/activate_this.py')
# execfile(_activate, dict(__file__=_activate))

# Add our code to path.
import os.path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'kdc'))

from werkzeug.exceptions import NotFound
from werkzeug.wsgi import SharedDataMiddleware, DispatcherMiddleware

import kdc

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

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    app = create_app()
    run_simple('127.0.0.1', 5000, app, use_debugger=True, use_reloader=True)
