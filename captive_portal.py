#!/usr/bin/python3
import http.server
import subprocess
import cgi
import os
import datetime
import binascii
import re
import threading
import ssl
import urllib

# Server Information
LOCAL_SERVER_IP = "192.168.20.1"
HTTP_SERVER_PORT = 80
HTTPS_SERVER_PORT = 443
REMOTE_SERVER_DOMAIN = "captive.ddns.net"
REMOTE_SERVER_IP = "213.16.145.248"
# Interfaces
INTERFACE_INPUT = "wlan0"
INTERFACE_OUTPUT = "eth0"
# Files
PAGES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pages')
# iptables
IPTABLES_RESET = True
IPTABLES_FORWARD = True
IPTABLES_INIT = True
# HTTPS
SSL_CERT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cert.pem')
SSL_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'key.pem')
# Custom certificate
# openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

# SSO (Configuration has to be inside the sso_config.py file)
SSO_FACEBOOK_APP_ID = None
SSO_FACEBOOK_APP_SECRET = None
from sso_config import *

# Create remotelink
REMOTE_SERVER_LINK = "https://" + REMOTE_SERVER_DOMAIN + ":" + str(HTTPS_SERVER_PORT) + "/"
if str(HTTPS_SERVER_PORT) == "443":
    REMOTE_SERVER_LINK = "https://" + REMOTE_SERVER_DOMAIN + "/"


# This it the HTTP server used by the the captive portal
class CaptivePortal(http.server.BaseHTTPRequestHandler):

    server_variables = {
        "server_ip" : LOCAL_SERVER_IP,
        "server_port" : HTTPS_SERVER_PORT,
        "year" : datetime.datetime.now().year
    }

    sessions = {}

    route = {
        #"/index": {"file": "index.html", "cached": False},
        "/login": {"file": "login.html", "cached": False},
        "/favicon.ico": {"file": "favicon.ico", "cached": False},
        "/css/custom.css": {"file": "css/custom.css", "cached": False},
        "/css/bootstrap.min.css": {"file": "css/bootstrap.min.css", "cached": False},
        "/css/bootstrap.lumen.min.css": {"file": "css/bootstrap.lumen.min.css", "cached": False},
        "/js/jquery.min.js": {"file": "js/jquery.min.js", "cached": False},
        "/js/popper.min.js": {"file": "js/popper.min.js", "cached": False},
        "/js/bootstrap.min.js": {"file": "js/bootstrap.min.js", "cached": False},
        "/img/portal.png": {"file": "img/portal.png", "cached": False},
    }

    route_alias = {
        "/": "/login"
    }

    def get_route(self, rawUrl):
        url = urllib.parse.urlparse(rawUrl)
        parms = urllib.parse.parse_qs(url.query)
        path = url.path
        #print(parms['a'][0])
        #print(parms.keys())
        # Check alias
        if path in self.route_alias.keys():
            path = self.route_alias[path]
        print("url : " + rawUrl)
        print("path : " + path)
        # Get file
        data = self.get_file(path);
        # Headers
        headers = {}

        # Check
        if path == '/login':
            self.session_update()
            data = self.replace_keys(data.decode("utf-8"), {
                "facebook-link" : "https://www.facebook.com/v7.0/dialog/oauth?client_id=%s&redirect_uri=%s&state=%s" % (SSO_FACEBOOK_APP_ID, REMOTE_SERVER_LINK + "facebook/oauth", "whatisup")
            }).encode()
        elif path == '/facebook/oauth':
            self.session_update()
            data = 'Works'
            data = data.encode()

            conn = http.client.HTTPSConnection("graph.facebook.com")
            conn.request("GET", "/v7.0/oauth/access_token?client_id=%s&redirect_uri=%s&client_secret=%s&code=%s" % (SSO_FACEBOOK_APP_ID, REMOTE_SERVER_LINK + "facebook/oauth", SSO_FACEBOOK_APP_SECRET, "whatisup"))
            res = conn.getresponse()
            print(res.status)
            print(res.reason)
            response = res.read()
            print(response)
            conn.close()
            # https://www.facebook.com/v7.0/dialog/oauth?client_id=1161336397564018&redirect_uri=https://captive.ddns.net/facebook/oauth&state=whatisup

        return data, headers;

    def get_file(self, name):
        # If route exists
        if name in self.route.keys():
            # If not cached
            if self.route[name]["cached"] == False:
                self.route[name]["cached"] = self.load_file(self.route[name]["file"])
            # Return file
            return self.route[name]["cached"]
        # File not found
        return None

    def load_file(self, path):
        # Calculate path
        path = os.path.join(PAGES_PATH, path)
        # Load file
        file = open(path, "rb")
        data = file.read()
        file.close()
        # If HTML
        name, ext = os.path.splitext(path)
        if ext == ".html":
            data = self.replace_keys(data.decode("utf-8"), self.server_variables)
            data = data.encode()
        # Return file
        return data

    def replace_keys(self, html, variables):
        for name, value in variables.items():
            html = html.replace("{{" + name + "}}", str(value))
        return html

    def get_content_type(self, ext):
        # Common files
        if ext == ".css" :
            return "text/css"
        elif ext == ".css" :
            return "text/css"
        elif ext == ".html" :
            return "text/html"
        elif ext == ".js" :
            return "text/javascript"
        elif ext == ".png" :
            return "image/png"
        elif ext == ".jpg" or ext == ".jpeg" :
            return "image/jpeg"
        elif ext == ".svg" :
            return "image/svg+xml"
        elif ext == ".ico" :
            return "image/x-icon"
        return "text/html"

    def session_init(self):
        ip = self.client_address[0]
        mac = getMacFromIp(ip)
        self._session = {
            "ip" : ip,
            "mac" : mac
        }
        if not (ip in self.sessions.keys()):
            self.sessions[ip] = {
                "ip" : ip,
                "mac" : mac,
                "authenticated" : False,
                "expiration" : datetime.datetime.now() + datetime.timedelta(hours=1),
                "data" : {}
            }
        return

    def session_update(self):
        ip = self._session["ip"]
        self.sessions[ip]["expiration"] = datetime.datetime.now() + datetime.timedelta(hours=1)
        return

    def session_set(self, key, value):
        self._session = session
        self.sessions[self._session["ip"]]["data"][key] = value

    def session_get(self, key, defvalue):
        if key in self.sessions[self._session["ip"]]["data"].keys():
            return self.sessions[self._session["ip"]]["data"][key]
        else:
            return defvalue
    
    # Handle GET requests
    def do_GET(self):
        self.session_init()
        # Get file
        body, headers = self.get_route(self.path)
        if body == None :
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(str("404: file not found").encode())
            return
        # Path info
        file_name, file_extension = os.path.splitext(self.path)
        # Create headers
        self.send_response(200)
        self.send_header("Content-type", self.get_content_type(file_extension))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        # Return file
        self.wfile.write(body)

    # Handle POST requests
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        form = cgi.FieldStorage(
            fp=self.rfile, 
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST','CONTENT_TYPE':self.headers['Content-Type']}
        )
        username = form.getvalue("username")
        password = form.getvalue("password")
        #dummy security check
        if username == 'nikos' and password == 'fotiou':
            #authorized user
            remote_IP = self.client_address[0]
            print('New authorization from '+ remote_IP)
            print('Updating IP tables')
            subprocess.call(["iptables","-t", "nat", "-I", "PREROUTING","1", "-s", remote_IP, "-j" ,"ACCEPT"])
            subprocess.call(["iptables", "-I", "FORWARD", "-s", remote_IP, "-j" ,"ACCEPT"])
            self.wfile.write("You are now authorized. Navigate to any URL")
        else:
            #show the login form
            self.wfile.write(self.html_login)
        
    #the following function makes server produce no output
    #comment it out if you want to print diagnostic messages
    #def log_message(self, format, *args):
    #    return

# http://192.168.1.94/
class RedirectPortal(http.server.BaseHTTPRequestHandler):
    def do_handle(self):
        #self.send_response(301)
        #self.send_header("Content-type", "text/html")
        #self.send_header("Location", "https://captive.ddns.net/")
        #self.end_headers()
        #body = '<!DOCTYPE html><html lang="en"><head><meta http-equiv="Refresh" content="0; URL="https://captive.ddns.net/"></head><body>Redirecting ...<script>window.location = "https://captive.ddns.net/";</script></body></html>'
        #self.wfile.write(body.encode())
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        body = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"></head><body style="text-align: center;"><br><br>Redirecting ...<br><a href="{{redirect-url}}">Click here if you are not reditected automaticaly.</a><script>setTimeout(function(){window.location="{{redirect-url}}"},{{timeout}});</script></body></html>'
        body = self.replace_keys(body, {
            "redirect-url": REMOTE_SERVER_LINK,
            "timeout": str(2000),
        })
        self.wfile.write(body.encode())

    def replace_keys(self, html, variables):
        for name, value in variables.items():
            html = html.replace("{{" + name + "}}", str(value))
        return html

    # Handle GET requests
    def do_GET(self):
        self.do_handle()

    def do_POST(self):
        self.do_handle()

# Run command
def callCmd(cmd):
    subprocess.call(cmd)

def runCmd(cmd):
    return subprocess.run(cmd, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

# List ARP information
def getArpList():
    # Get arp
    result = runCmd('arp -a')
    if result.returncode != 0:
        return []
    # Parse data
    data = result.stdout.decode('utf-8')
    data = re.findall(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9A-Za-z]+:[0-9A-Za-z]+:[0-9A-Za-z]+:[0-9A-Za-z]+:[0-9A-Za-z]+:[0-9A-Za-z]+)\s+\[([^\]]*)\]", data)
    devices = []
    for device in data:
        devices.append({
            'ip' : device[0],
            'mac' : device[1],
            'interface' : device[2]
        })
    # Return data
    return devices

# Get MAC from IP
def getMacFromIp(ip):
    devices = getArpList()
    for device in devices:
        #print(device['ip'] + ' : ' + device['ip'])
        if device['ip'] == ip:
            return device['mac']
    return '00:00:00:00:00:00'

# Start Server
def start_server():
    threading.Thread(target = server_http).start()
    threading.Thread(target = server_https).start()

def server_http():
    print("[webserver] Start HTTP")
    server = http.server.ThreadingHTTPServer(('', HTTP_SERVER_PORT), RedirectPortal)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()

def server_https():
    print("[webserver] Start HTTPS")
    #server = http.server.HTTPServer(('', 443), CaptivePortal)
    #server = http.server.ThreadingHTTPServer(('', 443), CaptivePortal)
    server = http.server.ThreadingHTTPServer(('', HTTPS_SERVER_PORT), CaptivePortal)
    server.socket = ssl.wrap_socket(server.socket, keyfile=SSL_KEY_PATH, certfile=SSL_CERT_PATH, server_side=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()

# iptables
def iptables_reset():
    if IPTABLES_RESET == True:
        print("[iptables] Reset")
        callCmd(["iptables", "-P", "INPUT", "ACCEPT"])
        callCmd(["iptables", "-P", "FORWARD", "ACCEPT"])
        callCmd(["iptables", "-P", "OUTPUT", "ACCEPT"])
        callCmd(["iptables", "-t", "nat", "-F"])
        callCmd(["iptables", "-t", "mangle", "-F"])
        callCmd(["iptables", "-F"])
        callCmd(["iptables", "-X"])
    if IPTABLES_FORWARD == True:
        callCmd(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", INTERFACE_OUTPUT, "-j", "MASQUERADE"])

def iptables_init():
    if IPTABLES_INIT == True:
        print("[iptables] Initialize")
        # Allow DNS
        callCmd(["iptables", "-A", "FORWARD", "-i", INTERFACE_INPUT, "-p", "tcp", "--dport", "53", "-j" , "ACCEPT"])
        callCmd(["iptables", "-A", "FORWARD", "-i", INTERFACE_INPUT, "-p", "udp", "--dport", "53", "-j" , "ACCEPT"])
        # Forward traffic to captive portal
        callCmd(["iptables", "-A", "FORWARD", "-i", INTERFACE_INPUT, "-p", "tcp", "-d", LOCAL_SERVER_IP, "--dport", str( HTTP_SERVER_PORT), "-j", "ACCEPT"])
        callCmd(["iptables", "-A", "FORWARD", "-i", INTERFACE_INPUT, "-p", "tcp", "-d", LOCAL_SERVER_IP, "--dport", str(HTTPS_SERVER_PORT), "-j", "ACCEPT"])
        # Block all other traffic
        #callCmd(["iptables", "-A", "FORWARD", "-i", INTERFACE_INPUT, "-j" , "DROP"])
        # Redirecting HTTP traffic to captive portal
        callCmd(["iptables", "-t", "nat", "-A",  "PREROUTING", "-i", INTERFACE_INPUT, "-p", "tcp",                         "--dport", str( HTTP_SERVER_PORT), "-j", "DNAT", "--to-destination",  LOCAL_SERVER_IP + ":" + str( HTTP_SERVER_PORT)])
        callCmd(["iptables", "-t", "nat", "-A",  "PREROUTING",                        "-p", "tcp", "-d", REMOTE_SERVER_IP, "--dport", str(HTTPS_SERVER_PORT), "-j", "DNAT", "--to-destination",  LOCAL_SERVER_IP + ":" + str(HTTPS_SERVER_PORT)])
        callCmd(["iptables", "-t", "nat", "-A", "POSTROUTING",                        "-p", "tcp", "-d", LOCAL_SERVER_IP,  "--dport", str(HTTPS_SERVER_PORT), "-j", "SNAT",      "--to-source", REMOTE_SERVER_IP])

# Run script
if __name__ == '__main__':
    # Check if root
    if os.getuid() != 0:
        print("Need to run with root rights.")
    else:
        # Set up ip tables
        iptables_reset()
        iptables_init()
        # Start Server
        start_server()
