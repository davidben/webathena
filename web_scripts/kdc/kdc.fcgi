#!/usr/bin/python

# # Enter the virtualenv
# import os.path
# _activate = os.path.join(os.path.dirname(__file__),
#                          '../../env/bin/activate_this.py')
# execfile(_activate, dict(__file__=_activate))

from flup.server.fcgi import WSGIServer
from kdc import create_app

if __name__ == '__main__':
    app = create_app()
    WSGIServer(app).run()
