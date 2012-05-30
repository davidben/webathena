#!/usr/bin/env python

import base64
import json
import os
import socket
import sys

print "Content-Type: application/json"
print

if os.environ["REQUEST_METHOD"] != "POST" or os.environ.get("HTTP_X_ZWRITE_JS") != "OK":
    print json.dumps({"status": "ERROR"})
    sys.exit(0)

# Meh?
clength = int(os.environ.get("CONTENT_LENGTH", "100000"))
if clength > 4096:
    print json.dumps({"status": "ERROR"})
    sys.exit(0)

notice = base64.b64decode(sys.stdin.read(clength))

addr = socket.getaddrinfo("localhost", "zephyr-hm", socket.AF_INET, 0, socket.IPPROTO_UDP)[0]
s = socket.socket(*addr[0:3])
s.sendto(notice, addr[4])
print json.dumps({"status": "OK"})
