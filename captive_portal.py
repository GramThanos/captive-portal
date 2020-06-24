#!/usr/bin/python
import http.server
import http.cookies
import subprocess
import cgi
import os
import datetime
import binascii


# These variables are used as settings
PORT       = 9090         # the port in which the captive portal web server listens 
IFACE      = "wlan2"      # the interface that captive portal protects
IP_ADDRESS = "172.16.0.1" # the ip address of the captive portal (it can be the IP of IFACE)
PAGES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pages')
# HTTPS
SSL_HTTPS = False
SSL_CERT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cert.pem')
SSL_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'key.pem')
# Custom certificate
# openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

SESSION_COOKIE_NAME = "openItsMe"
SESSION_COOKIE_SIZE = 32


# This it the HTTP server used by the the captive portal
class CaptivePortal(http.server.BaseHTTPRequestHandler):

    server_variables = {
        "server_ip" : IP_ADDRESS,
        "server_port" : PORT,
        "year" : datetime.datetime.now().year
    }

    sessions = {

    }

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

    def get_route(self, name):
        # Check alias
        if name in self.route_alias.keys():
            name = self.route_alias[name]
        # Get file
        data = self.get_file(name);
        # Headers
        headers = {}

        # Check
        if name == '/login':
            self.session_update()
            headers["Set-Cookie"] = SESSION_COOKIE_NAME + "=" + self._session["hash"] + "; path=/" # expires=Thu, 24-Jun-2021 19:07:39 GMT; Max-Age=31536000; 

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
        self._session = {
            "cookies" : {}
        }
        # Load cookies
        if "Cookie" in self.headers.keys():
            sCookie = http.cookies.SimpleCookie()
            sCookie.load(self.headers["Cookie"])
            for key, obj in sCookie.items():
                self._session["cookies"][key] = obj.value
        # Check hash
        now = datetime.datetime.now()
        expiration = now + datetime.timedelta(hours=1)
        shash = False
        if SESSION_COOKIE_NAME in self._session["cookies"].keys():
            shash = self._session["cookies"][SESSION_COOKIE_NAME]
            if not ((shash in self.sessions.keys()) and (self.sessions[shash]["expiration"] > now)):
                shash = False

        self._session["hash"] = shash
        return

    def session_update(self):
        # Check hash
        now = datetime.datetime.now()
        expiration = now + datetime.timedelta(hours=1)
        shash = self._session["hash"]

        if shash == False:
            shash = binascii.b2a_hex(os.urandom(SESSION_COOKIE_SIZE)).decode("utf-8")
            self.sessions[shash] = {
                "authenticated" : False,
                "expiration" : expiration,
                "data" : {}
            }
        else:
            self.sessions[shash]["expiration"] = expiration

        self._session["hash"] = shash
        self._session["expiration"] = expiration
        return

    def session_set(self, key, value):
        self._session = session
        self.sessions[self._session["hash"]]["data"][key] = value

    def session_get(self, key, defvalue):
        if key in self.sessions[self._session["hash"]]["data"].keys():
            return self.sessions[self._session["hash"]]["data"][key]
        else:
            return defvalue
    
    '''
    if the user requests the login page show it, else
    use the redirect page
    '''
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

    '''
    this is called when the user submits the login form
    '''
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        form = cgi.FieldStorage(
            fp=self.rfile, 
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
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


if __name__ == '__main__':

    print("Starting web server")
    #httpd = http.server.ThreadingHTTPServer(('', PORT), CaptivePortal)
    server = http.server.HTTPServer(('', PORT), CaptivePortal)
    if SSL_HTTPS != False:
        import ssl
        server.socket = ssl.wrap_socket(server.socket, keyfile=SSL_KEY_PATH, certfile=SSL_CERT_PATH, server_side=True)


    #print("*********************************************")
    #print("* Note, if there are already iptables rules *")
    #print("* this script may not work. Flush iptables  *")
    #print("* at your own risk using iptables -F        *")
    #print("*********************************************")
    #print("Updating iptables")
    #print(".. Allow TCP DNS")
    #subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", "53", "-j" ,"ACCEPT"])
    #print(".. Allow UDP DNS")
    #subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "udp", "--dport", "53", "-j" ,"ACCEPT"])
    #print(".. Allow traffic to captive portal")
    #subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", str(PORT),"-d", IP_ADDRESS, "-j" ,"ACCEPT"])
    #print(".. Block all other traffic")
    #subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-j" ,"DROP"])
    #print("Redirecting HTTP traffic to captive portal")
    #subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", IFACE, "-p", "tcp", "--dport", "80", "-j" ,"DNAT", "--to-destination", IP_ADDRESS+":"+str(PORT)])

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
