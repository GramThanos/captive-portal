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
import json
import html

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
        "/img/portal-other.png": {"file": "img/portal-other.png", "cached": False},

        # Facebook pages
        "/facebook/success": {"file": "login_success.html", "cached": False},

        # Other pages
        ".redirect": {"file": "redirect.html", "cached": False},
        ".message": {"file": "message.html", "cached": False},
    }

    route_alias = {
        "/": "/login"
    }

    def get_route(self, rawUrl):
        # Analise URL
        url = urllib.parse.urlparse(rawUrl)
        parms = urllib.parse.parse_qs(url.query)
        path = url.path
        # Check alias
        if path in self.route_alias.keys():
            path = self.route_alias[path]
        # Get file
        data = self.get_file(path);
        # Headers
        headers = {}
        # Status
        status = 200

        # Print info
        print("url : " + rawUrl)
        print("path : " + path)

        # Login Page
        if path == '/login':
            self.session_update()
            data = self.replace_keys_decode(data, {
                "facebook-link" : "/facebook/init"
            })

        # Facebook - Pre-Oauth
        elif path == '/facebook/init':
            self.session_update()
            fb_redirect = self.facebook_pre_oauth()
            data, headers, status = self.do_redirect(fb_redirect, "<p>Redirecting to Facebook...</p>")
        # Facebook - Post-Oauth
        elif path == '/facebook/oauth':
            self.session_update()
            if ('code' in parms.keys()) and ('state' in parms.keys()):
                fb_authcode = parms['code'][0]
                fb_state = parms['state'][0]
                error = self.facebook_post_oauth(fb_authcode, fb_state)
                if error == None:
                    data, headers, status = self.do_redirect("/facebook/success", "<p>Redirecting...</p>")
                else:
                    data, headers, status = self.do_message("Failed", "<p>Failed to login with Facebook</p><p><small>Error: %s</small></p>" % html.escape(error))
            else:
                data, headers, status = self.do_message("Failed", "<p>Failed to login with Facebook</p>")
        # Facebook - Login Success
        elif path == '/facebook/success':
            self.session_update()
            fb_user_info = self.session_get("fb-user-info", None)
            if (fb_user_info != None) and ("name" in fb_user_info.keys()):
                data = self.replace_keys_decode(data, {
                    "success-msg" : "<p>You are connected as </p><h2>%s</h2><p><small>(You now have Internet access)</small></p>" % (html.escape(fb_user_info["name"]))
                })
            # Redirect to login
            else:
                data, headers, status = self.do_redirect("/login", "<p>Redirecting to login...</p>")

        return data, headers, status;

    def facebook_pre_oauth(self):
        fb_state = binascii.b2a_hex(os.urandom(32)).decode("utf-8")
        self.session_set("fb-access-token", None)
        self.session_set("fb-user-info", None)
        self.session_set("fb-state", fb_state)
        self.session_set("fb-authorized", 0)
        return "https://www.facebook.com/v7.0/dialog/oauth?client_id=%s&redirect_uri=%s&state=%s" % (SSO_FACEBOOK_APP_ID, REMOTE_SERVER_LINK + "facebook/oauth", fb_state)

    def facebook_post_oauth(self, fb_authcode, fb_state):
        # Check state
        if not (fb_state == self.session_get("fb-state", None)):
            return "Invalid oauth state."
        # Get Facebook access token
        #print("https://graph.facebook.com" + ("/v7.0/oauth/access_token?client_id=%s&redirect_uri=%s&client_secret=%s&code=%s" % (SSO_FACEBOOK_APP_ID, REMOTE_SERVER_LINK + "facebook/oauth", SSO_FACEBOOK_APP_SECRET, fb_authcode)))
        conn = http.client.HTTPSConnection("graph.facebook.com")
        conn.request("GET", "/v7.0/oauth/access_token?client_id=%s&redirect_uri=%s&client_secret=%s&code=%s" % (SSO_FACEBOOK_APP_ID, REMOTE_SERVER_LINK + "facebook/oauth", SSO_FACEBOOK_APP_SECRET, fb_authcode))
        res = conn.getresponse()
        #print(type(res.status), res.status)
        #print(type(res.reason), res.reason)
        #if res.status != 200 or res.reason != "OK":
        #    return "Invalid status was returned (%s,%s)." % (str(res.status), res.reason)
        response = res.read()
        conn.close()
        # Parse response
        fb_access_token = json.loads(response)
        if not ("access_token" in fb_access_token.keys()):
            return "Failed to get access token."
        fb_access_token = fb_access_token["access_token"]
        # Get user info
        conn = http.client.HTTPSConnection("graph.facebook.com")
        conn.request("GET", "/v7.0/me?fields=id,name,email&access_token=%s" % (fb_access_token))
        res = conn.getresponse()
        #if res.status != 200 or res.reason != "OK":
        #    return "Invalid status was returned (%s,%s)." % (str(res.status), res.reason)
        response = res.read()
        conn.close()
        fb_user_info = json.loads(response)
        if not ("id" in fb_user_info.keys() and "name" in fb_user_info.keys()):
            return "Failed to get user info."
        # Save session data
        self.session_set("fb-access-token", fb_access_token)
        self.session_set("fb-user-info", fb_user_info)
        self.session_set("fb-state", None)
        self.session_set("fb-authorized", datetime.datetime.now() + datetime.timedelta(hours=1))
        return None

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
            data = self.replace_keys_decode(data, self.server_variables)
        # Return file
        return data

    def replace_keys(self, html, variables):
        for name, value in variables.items():
            html = html.replace("{{" + name + "}}", str(value))
        return html

    def replace_keys_decode(self, data, variables):
        return self.replace_keys(data.decode("utf-8"), variables).encode()

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
        body, headers, status = self.get_route(self.path)
        if body == None :
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(str("404: file not found").encode())
            return
        # Path info
        file_name, file_extension = os.path.splitext(self.path)
        # Create headers
        self.send_response(status)
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

    def do_redirect(self, location, message, seconds = 0):
        #status = 302
        status = 200
        headers = {"Location": location}
        data = self.get_file(".redirect");
        data = self.replace_keys_decode(data, {
            "location" : location,
            "message" : message,
            "seconds" : str(seconds)
        })
        return data, headers, status;

    def do_message(self, title, message):
        status = 200
        headers = {}
        data = self.get_file(".message");
        data = self.replace_keys_decode(data, {
            "title" : title,
            "message" : message
        })
        return data, headers, status;

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
