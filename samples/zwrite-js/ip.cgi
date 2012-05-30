#!/usr/bin/env python

import cgitb
cgitb.enable()
import json
import socket

print "Content-Type: application/json"
print

from_ip = socket.inet_aton(socket.gethostbyname(socket.gethostname()))
ip = "0x" + "".join("%02X" % ord(c) for c in from_ip)
print json.dumps({"ip": ip})
