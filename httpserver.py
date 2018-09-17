#!/usr/bin/env python
import sys
import string
import cgi
import time
import os
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

myname = os.path.basename(__file__)
myfile = os.path.realpath(__file__)
mypath = os.path.dirname(myfile)

# Serve all files in current directory
appzipresources = [f for f in os.listdir('.') if os.path.isfile(f)]

################################################################################

def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

################################################################################

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            print "[+] HTTP GET request: %s" % self.path
            for resource in appzipresources:
                requested = self.path.lstrip('/')
                if requested == resource:
                    resourcefullpath = os.path.join(mypath,resource)
                    resourcesizebytes = os.path.getsize(resourcefullpath)
                    resourcesizebytes_human = sizeof_fmt(resourcesizebytes)
                    print "[+] sending: %s (%s)" % (resourcefullpath,resourcesizebytes_human)
                    f = open(resourcefullpath,'rb')
                    self.send_response(200)
                    #self.send_header('Content-type','application/zip')
                    #self.send_header('Content-length',resourcesizebytes)
                    self.end_headers()
                    self.wfile.write(f.read())
                    f.close()
                    break
        except IOError:
            self.send_error(404,'File Not Found: %s' % self.path)

################################################################################

if len(sys.argv) != 2:
    print "Usage: %s <port>" % myname
    sys.exit(0)

port = int(sys.argv[1].strip())

try:
    server = HTTPServer(('', port), MyHandler)
    print '[+] running httpserver on port %s' % port
    server.serve_forever()
except KeyboardInterrupt:
    print '[+] shutting down server'
    server.socket.close()

################################################################################
