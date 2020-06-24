#!/usr/bin/python
import http.server
import subprocess
import cgi
import os
import datetime


# These variables are used as settings
PORT       = 9090         # the port in which the captive portal web server listens 
IFACE      = "wlan2"      # the interface that captive portal protects
IP_ADDRESS = "172.16.0.1" # the ip address of the captive portal (it can be the IP of IFACE)
PAGES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pages')

'''
This it the HTTP server used by the the captive portal
'''
class CaptivePortal(http.server.BaseHTTPRequestHandler):

    server_variables = {
        "server_ip" : IP_ADDRESS,
        "server_port" : PORT,
        "year" : datetime.datetime.now().year
    }

    route_files = {
        "/index": os.path.join(PAGES_PATH, "index.html"),
        "/login": os.path.join(PAGES_PATH, "login.html"),

        "/css/custom.css": os.path.join(PAGES_PATH, "css/custom.css"),
        "/css/bootstrap.min.css": os.path.join(PAGES_PATH, "css/bootstrap.min.css"),
        "/css/bootstrap.lumen.min.css": os.path.join(PAGES_PATH, "css/bootstrap.lumen.min.css"),
        "/js/jquery.min.js": os.path.join(PAGES_PATH, "js/jquery.min.js"),
        "/js/popper.min.js": os.path.join(PAGES_PATH, "js/popper.min.js"),
        "/js/bootstrap.min.js": os.path.join(PAGES_PATH, "js/bootstrap.min.js")
    }
    route_files_cache = {}
    route_alias = {
        "/": "/index"
    }

    def get_route(self, name):
        data = self.get_file(name);
        return data


    def get_file(self, name):
        if name in self.route_alias.keys():
            name = self.route_alias[name]
        if name in self.route_files_cache.keys():
            return self.route_files_cache[name]
        elif name in self.files.keys():
            file = open(self.route_files[name])
            self.route_files_cache[name] = self.replace_keys(file.read(), self.server_variables)
            file.close()
            return self.route_files_cache[name]
        return None

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
        return "text/html"
    
    '''
    if the user requests the login page show it, else
    use the redirect page
    '''
    def do_GET(self):
        # Get file
        data = self.get_route(self.path)
        if data == None :
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(str("404: file not found").encode())
            return
        # Path info
        file_name, file_extension = os.path.splitext(self.path)
        print(file_name)
        print(file_extension)
        # Create headers
        self.send_response(200)
        self.send_header("Content-type", self.get_content_type(file_extension))
        self.end_headers()
        # Return file
        self.wfile.write(data.encode())

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
    print("*********************************************")
    print("* Note, if there are already iptables rules *")
    print("* this script may not work. Flush iptables  *")
    print("* at your own risk using iptables -F        *")
    print("*********************************************")
    print("Updating iptables")
    print(".. Allow TCP DNS")
    #subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", "53", "-j" ,"ACCEPT"])
    print(".. Allow UDP DNS")
    #subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "udp", "--dport", "53", "-j" ,"ACCEPT"])
    print(".. Allow traffic to captive portal")
    #subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", str(PORT),"-d", IP_ADDRESS, "-j" ,"ACCEPT"])
    print(".. Block all other traffic")
    #subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-j" ,"DROP"])
    print("Starting web server")
    #httpd = http.server.ThreadingHTTPServer(('', PORT), CaptivePortal)
    httpd = http.server.HTTPServer(('', PORT), CaptivePortal)
    print("Redirecting HTTP traffic to captive portal")
    #subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", IFACE, "-p", "tcp", "--dport", "80", "-j" ,"DNAT", "--to-destination", IP_ADDRESS+":"+str(PORT)])

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
