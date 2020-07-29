#!/usr/bin/python3
import http.server
import subprocess
import cgi
import os
import sys
import datetime
import binascii
import re
import threading
import ssl
import urllib
import json
import html
import socket
import time
import sqlite3
import hashlib




''' Configuration
-----------------------------------'''

# Server Information
LOCAL_SERVER_IP = "192.168.20.1"
HTTP_SERVER_PORT = 80
HTTPS_SERVER_PORT = 443
REMOTE_SERVER_DOMAIN = "captive.ddns.net"
try:
    REMOTE_SERVER_IP = socket.gethostbyname(REMOTE_SERVER_DOMAIN)
except socket.gaierror:
    REMOTE_SERVER_IP = LOCAL_SERVER_IP
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
SSO_FACEBOOK = True
SSO_FACEBOOK_APP_ID = None
SSO_FACEBOOK_APP_SECRET = None
SSO_GOOGLE = True
SSO_GOOGLE_CLIENT_ID = None
SSO_GOOGLE_CLIENT_SECRET = None
from sso_config import *

# Local DNS Server
USE_CUSTOM_DNS_SERVER = True
LOCAL_DNS_SERVER_IP = LOCAL_SERVER_IP
DNS_SERVER_PORT = 53

# Exclude Facebook addresses
SSO_FACEBOOK_EXCLUDE_DOMAINS = [
    "facebook.com",
    "www.facebook.com",
    "static.xx.fbcdn.net"
]
SSO_GOOGLE_EXCLUDE_DOMAINS = [
    #"accounts.google.com",
    #"accounts.google.gr",
    "lh3.googleusercontent.com",
    "fonts.gstatic.com",
    "ssl.gstatic.com",
    "accounts.youtube.com",
    "play.google.com"
]
SSO_GOOGLE_EXCLUDE_DOMAINS_COUNTRIES = ['.com', '.ac', '.ad', '.ae', '.com.af', '.com.ag', '.com.ai', '.al', '.am', '.co.ao', '.com.ar', '.as', '.at', '.com.au', '.az', '.ba', '.com.bd', '.be', '.bf', '.bg', '.com.bh', '.bi', '.bj', '.com.bn', '.com.bo', '.com.br', '.bs', '.bt', '.co.bw', '.by', '.com.bz', '.ca', '.com.kh', '.cc', '.cd', '.cf', '.cat', '.cg', '.ch', '.ci', '.co.ck', '.cl', '.cm', '.cn', '.com.co', '.co.cr', '.com.cu', '.cv', '.com.cy', '.cz', '.de', '.dj', '.dk', '.dm', '.com.do', '.dz', '.com.ec', '.ee', '.com.eg', '.es', '.com.et', '.fi', '.com.fj', '.fm', '.fr', '.ga', '.ge', '.gf', '.gg', '.com.gh', '.com.gi', '.gl', '.gm', '.gp', '.gr', '.com.gt', '.gy', '.com.hk', '.hn', '.hr', '.ht', '.hu', '.co.id', '.iq', '.ie', '.co.il', '.im', '.co.in', '.io', '.is', '.it', '.je', '.com.jm', '.jo', '.co.jp', '.co.ke', '.ki', '.kg', '.co.kr', '.com.kw', '.kz', '.la', '.com.lb', '.com.lc', '.li', '.lk', '.co.ls', '.lt', '.lu', '.lv', '.com.ly', '.co.ma', '.md', '.me', '.mg', '.mk', '.ml', '.com.mm', '.mn', '.ms', '.com.mt', '.mu', '.mv', '.mw', '.com.mx', '.com.my', '.co.mz', '.com.na', '.ne', '.com.nf', '.com.ng', '.com.ni', '.nl', '.no', '.com.np', '.nr', '.nu', '.co.nz', '.com.om', '.com.pk', '.com.pa', '.com.pe', '.com.ph', '.pl', '.com.pg', '.pn', '.com.pr', '.ps', '.pt', '.com.py', '.com.qa', '.ro', '.rs', '.ru', '.rw', '.com.sa', '.com.sb', '.sc', '.se', '.com.sg', '.sh', '.si', '.sk', '.com.sl', '.sn', '.sm', '.so', '.st', '.sr', '.com.sv', '.td', '.tg', '.co.th', '.com.tj', '.tk', '.tl', '.tm', '.to', '.tn', '.com.tr', '.tt', '.com.tw', '.co.tz', '.com.ua', '.co.ug', '.co.uk', '.com', '.com.uy', '.co.uz', '.com.vc', '.co.ve', '.vg', '.co.vi', '.com.vn', '.vu', '.ws', '.co.za', '.co.zm', '.co.zw']
SSO_GOOGLE_EXCLUDE_IPS = []
SSO_FACEBOOK_EXCLUDE_IPS = []

# Credentials Sign in
CREDENTIALS_SIGNIN = True
SQLITE3_DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.db')

# Create remote link
REMOTE_SERVER_LINK = "https://" + REMOTE_SERVER_DOMAIN + ":" + str(HTTPS_SERVER_PORT) + "/"
if str(HTTPS_SERVER_PORT) == "443":
    REMOTE_SERVER_LINK = "https://" + REMOTE_SERVER_DOMAIN + "/"

# Authorizations Daemon
AUTHDAEMON_INTERVAL_CHECK = 10
AUTHDAEMON_MAC_CHANGE_CHECK = True

# Access Times
ACCESS_TIME_INTERNET = 2*60*60
ACCESS_TIME_FACEBOOK_LOGIN = 2*60
ACCESS_TIME_GOOGLE_LOGIN = 2*60

LOG_DEBUG = 0
LOG_VERBOSE = 2
LOG_NORMAL = 4
#LOG_LEVEL = LOG_NORMAL
LOG_LEVEL = LOG_NORMAL

''' Database
-----------------------------------'''
database = None
class Database:
    def __init__(self):
        # Init path
        self.path = SQLITE3_DATABASE_PATH
        # Try to connect to db
        try:
            self.conn = sqlite3.connect(self.path, check_same_thread=False)
        except sqlite3.Error as e:
            self.conn = None
            self.log("Error: " + str(e))
            return;
        # Create dummy password
        self.dummy_pass = self.hash_password('dummy')
        # Init users table
        self.conn.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)')
        # Init tokens table
        #self.conn.execute('CREATE TABLE IF NOT EXISTS tokens (hash TEXT PRIMARY KEY, seconds int)')

    def createUser(self, username, password):
        try:
            self.conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, self.hash_password(password)))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            self.log("Failed: " + str(e))
            return False

    def authenticateUser(self, username, password):
        c = self.conn.cursor()
        c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        data = c.fetchone()
        if not data or len(data) < 1:
            # Dummy calculations to avoid time attack
            self.verify_password(self.dummy_pass, 'invalid-dummy')
            return False
        else:
            return self.verify_password(data[0], password)

    # Hash a password for storing.
    def hash_password(self, password, alg='sha512'):
        salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac(alg, password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    # Verify a stored password against one provided by user
    def verify_password(self, stored_password, provided_password, alg='sha512'):
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac(alg, provided_password.encode('utf-8'), salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def log(self, message, level = LOG_LEVEL):
        msgLog("Database", message, level)



''' Authorizations Monitor Daemon
-----------------------------------'''
authDaemon = None
class AuthorizationsDaemon:
    def __init__(self):
        self.authorizations = {}
        self.clients = {}
        self.sessions = []
        self.ip_sessions = {}

    def runChecks(self):
        self.checkExpiredSessions()
        self.checkMacBindings()

    def checkExpiredSessions(self):
        now = datetime.datetime.now()
        expired = []
        for session in self.sessions:
            if session["expiration"] < now:
                expired.append(session)
        # Revoke authorization on expired session
        self.deauthorizeSessions(expired)

    def checkMacBindings(self):
        now = datetime.datetime.now()
        clients = getArpList()
        for client in clients:
            ip = client["ip"]
            mac = client["mac"]
            # If client was previously logged
            if ip in self.clients.keys() and self.clients[ip]["mac"] != None:
                # Check if MAC matches previous MAC
                if AUTHDAEMON_MAC_CHANGE_CHECK != False and self.clients[ip]["mac"] != mac:
                    self.log("MAC change detected on " + ip + " : " + self.clients[ip]["mac"] + " --> " + mac)
                    # De-authorize client
                    self.clients[ip]["mac"] = None
                    self.clients[ip]["logged"] = now
                    self.deauthorizeIP_All(ip);
            # Log user
            else:
                self.clients[ip] = {
                    "mac" : mac,
                    "logged" : now
                }

    def prepare_session(self, ip, stype, expiration):
        session = {
            "ip" : ip,
            "mac" : getMacFromIp(ip),
            "type" : stype,
            "expiration" : expiration
        }
        return session

    # Update Authorizations
    def reauthorizeSession(self, session, seconds):
        self.log("Update " + session["ip"] + " to " + session["type"])
        session["expiration"] = datetime.datetime.now() + datetime.timedelta(seconds=seconds)

    def reauthorizeSessions(self, sessions, seconds):
        for session in sessions:
            self.reauthorizeSession(session, seconds)


    # Authorizations
    def authorizeSession(self, session):
        self.log("Authorize " + session["ip"] + " to " + session["type"])
        self.sessions.append(session)
        ip = session["ip"]
        if not (ip in self.ip_sessions.keys()):
            self.ip_sessions[ip] = []
        self.ip_sessions[ip].append(session)
        # Allow access to Internet
        if session["type"] == "Internet":
            # The nat rule has to be inserted under the captive's portal domain
            callCmd(["iptables", "-t", "nat", "-I", "PREROUTING", "2", "-s", ip, "-j" ,"ACCEPT"])
            callCmd(["iptables",              "-I",    "FORWARD", "1", "-s", ip, "-j" ,"ACCEPT"])
        # Allow access to Facebook
        elif session["type"] == "Facebook-Login":
            # Allow Facebook IPs
            for ip_addresses in SSO_FACEBOOK_EXCLUDE_IPS:
                callCmd(["iptables", "-I", "FORWARD", "-i", INTERFACE_INPUT, "-p", "tcp", "-s", ip, "-d", ip_addresses, "--dport", str(443), "-j" , "ACCEPT"])
        # Allow access to Google
        elif session["type"] == "Google-Login":
            # Allow Google IPs
            for ip_addresses in SSO_GOOGLE_EXCLUDE_IPS:
                callCmd(["iptables", "-I", "FORWARD", "-i", INTERFACE_INPUT, "-p", "tcp", "-s", ip, "-d", ip_addresses, "--dport", str(443), "-j" , "ACCEPT"])
        # Update client info
        self.setClientAuthorizations(ip, session["type"], True)

    def authorizeSessions(self, sessions):
        for session in sessions:
            self.authorizeSession(self, session)

    def authorizeIP_Internet(self, ip, seconds):
        sessions = self.getSessionsByIP(ip, "Internet")
        if len(sessions) > 0:
            self.reauthorizeSessions(sessions, seconds)
        else:
            session = self.prepare_session(ip, "Internet", datetime.datetime.now() + datetime.timedelta(seconds=seconds))
            self.authorizeSession(session)

    def authorizeIP_FacebookLogin(self, ip, seconds):
        sessions = self.getSessionsByIP(ip, "Facebook-Login")
        if len(sessions) > 0:
            self.reauthorizeSessions(sessions, seconds)
        else:
            session = self.prepare_session(ip, "Facebook-Login", datetime.datetime.now() + datetime.timedelta(seconds=seconds))
            self.authorizeSession(session)

    def authorizeIP_GoogleLogin(self, ip, seconds):
        sessions = self.getSessionsByIP(ip, "Google-Login")
        if len(sessions) > 0:
            self.reauthorizeSessions(sessions, seconds)
        else:
            session = self.prepare_session(ip, "Google-Login", datetime.datetime.now() + datetime.timedelta(seconds=seconds))
            self.authorizeSession(session)


    # De-authorizations
    def deauthorizeSession(self, session):
        self.log("De-authorize " + session["ip"] + " from " + session["type"])
        self.sessions.remove(session)
        ip = session["ip"]
        if ip in self.ip_sessions.keys():
            self.ip_sessions[ip].remove(session)
        # Block access to Internet
        if session["type"] == "Internet":
            callCmd(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-j" ,"ACCEPT"])
            callCmd(["iptables",              "-D",    "FORWARD", "-s", ip, "-j" ,"ACCEPT"])
        # Block access to Facebook
        elif session["type"] == "Facebook-Login":
            # Allow Facebook IPs
            for ip_addresses in SSO_FACEBOOK_EXCLUDE_IPS:
                callCmd(["iptables", "-D", "FORWARD", "-i", INTERFACE_INPUT, "-p", "tcp", "-s", ip, "-d", ip_addresses, "--dport", str(443), "-j" , "ACCEPT"])
        # Block access to Google
        elif session["type"] == "Google-Login":
            # Allow Google IPs
            for ip_addresses in SSO_GOOGLE_EXCLUDE_IPS:
                callCmd(["iptables", "-D", "FORWARD", "-i", INTERFACE_INPUT, "-p", "tcp", "-s", ip, "-d", ip_addresses, "--dport", str(443), "-j" , "ACCEPT"])
        # Update client info
        self.setClientAuthorizations(ip, session["type"], False)

    def deauthorizeSessions(self, sessions):
        for session in sessions:
            self.deauthorizeSession(session)

    def deauthorizeIP_Internet(self, ip):
        session = self.getSessionsByIP(ip, "Internet")
        self.deauthorizeSessions(session)

    def deauthorizeIP_FacebookLogin(self, ip):
        session = self.getSessionsByIP(ip, "Facebook-Login")
        self.deauthorizeSessions(session)

    def deauthorizeIP_GoogleLogin(self, ip):
        session = self.getSessionsByIP(ip, "Google-Login")
        self.deauthorizeSessions(session)

    def deauthorizeIP_All(self, ip):
        session = self.getSessionsByIP(ip)
        self.deauthorizeSessions(session)


    # Client info
    def getClientAuthorizations(self, ip):
        if not (ip in self.authorizations.keys()):
            self.authorizations[ip] = {
                "Internet" : False,
                "Facebook-Login" : False,
                "Google-Login" : False
            }
        return self.authorizations[ip]

    def setClientAuthorizations(self, ip, stype, value):
        self.getClientAuthorizations(ip)
        self.authorizations[ip][stype] = value
    
    def hasClientAuthorization(self, ip, stype):
        info = self.getClientAuthorizations(ip);
        if stype in self.authorizations[ip].keys():
            return self.authorizations[ip][stype]
        return False

    def hasClient_Internet(self, ip):
        return self.hasClientAuthorization(ip, "Internet")


    # Other function
    def getSessionsByIP(self, ip, stype=None):
        sessions = []
        if ip in self.ip_sessions.keys():
            for session in self.ip_sessions[ip]:
                if stype == None or stype == session["type"]:
                    sessions.append(session)
        return sessions

    def log(self, message, level = LOG_LEVEL):
        msgLog("AuthDaemon", message, level)





''' HTTPS Captive Portal (Main Captive Portal)
-----------------------------------'''

# This it the HTTP server used by the the captive portal
class CaptivePortal(http.server.BaseHTTPRequestHandler):

    server_variables = {
        "server-ip" : LOCAL_SERVER_IP,
        "server-port" : HTTPS_SERVER_PORT,
        "footer-note" : "&copy; Unipi " + str(datetime.datetime.now().year)
    }

    sessions = {}

    route = {
        #"/index": {"file": "index.html", "cached": False},
        "/login": {"file": "login.html", "cached": False},
        "/status": {"file": "status.html", "cached": False},
        "/favicon.ico": {"file": "favicon.ico", "cached": False},
        "/css/custom.css": {"file": "css/custom.css", "cached": False},
        "/css/bootstrap.min.css": {"file": "css/bootstrap.min.css", "cached": False},
        "/css/bootstrap.lumen.min.css": {"file": "css/bootstrap.lumen.min.css", "cached": False},
        "/js/jquery.min.js": {"file": "js/jquery.min.js", "cached": False},
        "/js/popper.min.js": {"file": "js/popper.min.js", "cached": False},
        "/js/bootstrap.min.js": {"file": "js/bootstrap.min.js", "cached": False},
        "/img/portal.png": {"file": "img/portal.png", "cached": False},
        "/img/portal-other.png": {"file": "img/portal-other.png", "cached": False},

        # Other pages
        ".redirect": {"file": "redirect.html", "cached": False},
        ".message": {"file": "message.html", "cached": False},
        ".credentials": {"file": "credentials.html", "cached": False},
        ".terms": {"file": "ToU.txt", "cached": False},
    }

    route_alias = {
        "/": "/login"
    }

    def get_route(self, method, rawUrl):
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
        msgLog("Portal", "Request " + path, LOG_VERBOSE)
        msgLog("Portal", "User-Agent " + self.headers["User-Agent"], LOG_DEBUG)
        #print("url : " + rawUrl)
        #print("path : " + path)

        # Login Page
        if path == '/login':
            # Check if logged in
            loggedin = self.get_logged_in()
            if loggedin == "Facebook" or loggedin == "Google":
                data, headers, status = self.do_redirect("/status", "<p>Redirecting...</p>")
            else:
                # Check if webview (google does not allow login from webview)
                isWebView = self.isWebView()
                # Replace data
                data = self.replace_keys_decode(data, {
                    # CREDENTIALS_SIGNIN
                    "credentials-btn-type" : ("btn-info" if CREDENTIALS_SIGNIN else "d-none"),
                    "credentials-link" : "/credentials",
                    "facebook-btn-type" : ("btn-primary" if SSO_FACEBOOK else "d-none"),
                    "facebook-link" : "/facebook/init",
                    "google-btn-type" : (("btn-secondary" if isWebView else "btn-primary") if SSO_GOOGLE else "d-none"),
                    "google-link" : "/google/init"
                })
        # Logout page
        if path == '/logout':
            self.set_logged_out()
            data, headers, status = self.do_redirect("/", "<p>Logging out...</p>", 5)
        # Status page
        elif path == '/status':
            info = getRuleFromIp(self._session["ip"])
            if info == None:
                info = {"packets" : 0, "bytes" : 0}
            # Check if logged in
            loggedin = self.get_logged_in()
            if loggedin == "Facebook":
                data = self.replace_keys_decode(data, {
                    "title" : "Connected",
                    "name" : html.escape(self.facebook_get_user_name()),
                    "login-type" : "Facebook Login",
                    "packets" : format(info["packets"],',d'),
                    "bytes" : bytes_sizeof_format(info["bytes"]),
                    "refresh-link" : "/status",
                    "logout-link" : "/logout"
                })
            elif loggedin == "Google":
                data = self.replace_keys_decode(data, {
                    "title" : "Connected",
                    "name" : html.escape(self.google_get_user_name()),
                    "login-type" : "Google Login",
                    "packets" : format(info["packets"],',d'),
                    "bytes" : bytes_sizeof_format(info["bytes"]),
                    "refresh-link" : "/status",
                    "logout-link" : "/logout"
                })
            elif loggedin == "Credentials":
                data = self.replace_keys_decode(data, {
                    "title" : "Connected",
                    "name" : html.escape(self.credentials_get_user_name()),
                    "login-type" : "Credentials Login",
                    "packets" : format(info["packets"],',d'),
                    "bytes" : bytes_sizeof_format(info["bytes"]),
                    "refresh-link" : "/status",
                    "logout-link" : "/logout"
                })
            else:
                data, headers, status = self.do_redirect("/login", "<p>Redirecting...</p>")

        # Credentials
        elif CREDENTIALS_SIGNIN and path == '/credentials':
            alert = {"type" : "d-none", "message" : ""}
            authenticated = False
            if method == 'POST':
                form = self.parse_posted_data()
                if form != None and not ('checkbox' in form.keys()):
                    alert["type"] = "alert-danger"
                    alert["message"] = "Please accept the terms"
                elif form != None and ('username' in form.keys()) and ('password' in form.keys()):
                    authenticated = database.authenticateUser(form['username'], form['password'])
                    if authenticated:
                        authenticated = form['username']
                    else:
                        alert["type"] = "alert-danger"
                        alert["message"] = "Authentication failed"
                else:
                    alert["type"] = "alert-danger"
                    alert["message"] = "Invalid data posted"
            if not authenticated:
                data = self.get_file(".credentials");
                data = self.replace_keys_decode(data, {
                    "action-link" : "credentials",
                    "checkbox-class" : "", #"d-none",
                    "checkbox-html" : 'Accept the <a href="/terms">Terms of Use</a>',
                    # Alet info
                    "alert-type" : alert["type"], #alert-danger
                    "alert-message" : alert["message"],
                })
            else:
                self.credentials_auth(authenticated)
                self.authorize_internet()
                data, headers, status = self.do_redirect("/status", "<p>Redirecting...</p>")

        elif CREDENTIALS_SIGNIN and path == '/terms':
            #headers = {"Content-type": "text/html; charset=UTF-8"}
            txt = self.get_file(".terms").decode("utf-8");
            data, headers, status = self.do_message(
                "Terms of Use",
                ("<p style=\"text-align: left;\">%s</p>" +
                "<a href=\"%s\" class=\"btn btn-outline-primary\">&lt; Back</a>" +
                "") % (html.escape(txt).replace("\n","<br>"), REMOTE_SERVER_LINK)
            )
        
        # Facebook - Pre-Oauth
        elif SSO_FACEBOOK and path == '/facebook/init':
            fb_redirect = self.facebook_pre_oauth()
            data, headers, status = self.do_redirect(fb_redirect, "<p>You have %d seconds to sign in...</p>" % ACCESS_TIME_FACEBOOK_LOGIN, 5)
        # Facebook - Post-Oauth
        elif SSO_FACEBOOK and path == '/facebook/oauth':
            fb_authcode = ''
            fb_state = ''
            if ('code' in parms.keys()) and ('state' in parms.keys()):
                fb_authcode = parms['code'][0]
                fb_state = parms['state'][0]
            error = self.facebook_post_oauth(fb_authcode, fb_state)
            if error == None:
                self.authorize_internet()
                data, headers, status = self.do_redirect("/status", "<p>Redirecting...</p>")
            else:
                data, headers, status = self.do_message(
                    "Failed",
                    ("<p>Failed to login with Facebook</p><p><small>Error: %s</small></p>" +
                    "<a href=\"%s\" class=\"btn btn-outline-primary\">&lt; Back</a>" +
                    "") % (html.escape(error), REMOTE_SERVER_LINK)
                )

        # Google - Pre-Oauth
        elif SSO_GOOGLE and path == '/google/init':
            if self.isWebView():
                data, headers, status = self.do_message(
                    "Failed",
                    ("<p>This browser does not support Google sign in.<br>" +
                    "Please open this page using another browser (e.g. Chrome, Firefox)</p>" +
                    "<input type=\"text\" value=\"%s\" style=\"text-align:center;\"><br><br>" +
                    "<a href=\"%s\" class=\"btn btn-outline-primary\">&lt; Back</a>" +
                    "") % (REMOTE_SERVER_LINK, REMOTE_SERVER_LINK)
                )
            else:
                gg_redirect = self.google_pre_oauth()
                data, headers, status = self.do_redirect(gg_redirect, "<p>You have %d seconds to sign in...</p>" % ACCESS_TIME_GOOGLE_LOGIN, 5)
        # Google - Post-Oauth
        elif SSO_GOOGLE and path == '/google/oauth':
            gg_code = ''
            gg_scope = ''
            if ('code' in parms.keys()) and ('scope' in parms.keys()):
                gg_code = parms['code'][0]
                gg_scope = parms['scope'][0]
            error = self.google_post_oauth(gg_code, gg_scope)
            if error == None:
                self.authorize_internet()
                data, headers, status = self.do_redirect("/status", "<p>Redirecting...</p>")
            else:
                data, headers, status = self.do_message(
                    "Failed",
                    ("<p>Failed to login with Google</p><p><small>Error: %s</small></p>" +
                    "<a href=\"%s\" class=\"btn btn-outline-primary\">&lt; Back</a>" +
                    "") % (html.escape(error), REMOTE_SERVER_LINK)
                )

        return data, headers, status;

    def parse_posted_data(self):
        data = None
        if 'Content-Length' in self.headers.keys():
            length = int(self.headers['Content-Length'])
            body = self.rfile.read(length)
            if 'Content-Type' in self.headers.keys():
                if self.headers['Content-Type'] == "application/x-www-form-urlencoded":
                    binary = urllib.parse.parse_qs(body)
                    data = {}
                    for key in binary.keys():
                        data[key.decode('ascii')] = binary[key][0].decode('ascii')
        return data

    def get_logged_in(self):
        if self.session_hasInternet():
            date = self.session_get("authorized", datetime.datetime(1970, 1, 1))
            if date > datetime.datetime.now():
                date = self.session_get("fb-authorized", datetime.datetime(1970, 1, 1))
                if date > datetime.datetime.now():
                    fb_user_info = self.session_get("fb-user-info", None)
                    if (fb_user_info != None) and ("name" in fb_user_info.keys()):
                        return "Facebook"
                date = self.session_get("gg-authorized", datetime.datetime(1970, 1, 1))
                if date > datetime.datetime.now():
                    gg_user_info = self.session_get("gg-user-info", None)
                    if (gg_user_info != None) and ("name" in gg_user_info.keys()):
                        return "Google"
                date = self.session_get("cr-authorized", datetime.datetime(1970, 1, 1))
                if date > datetime.datetime.now():
                    cr_user_info = self.session_get("cr-user-info", None)
                    if (cr_user_info != None) and ("name" in cr_user_info.keys()):
                        return "Credentials"
        return None

    def set_logged_out(self):
        self.deauthorize_internet()
        self.facebook_deoauth()
        self.google_deoauth()
        self.credentials_deoauth()

    # Credentials
    def credentials_auth(self, username):
        user_info = {"name" : username}
        # Save session data
        self.session_set("cr-user-info", user_info)
        self.session_set("cr-authorized", datetime.datetime.now() + datetime.timedelta(seconds=ACCESS_TIME_INTERNET))
        msgLog("Credentials", "Authorized user \"" + user_info["name"] + "\"")
        return None

    def credentials_deoauth(self):
        self.session_set("cr-user-info", None)
        self.session_set("cr-authorized", datetime.datetime(1970, 1, 1))

    def credentials_get_user_name(self):
        return self.session_get("cr-user-info", {"name":"Unknown"})["name"]

    # Facebook Login
    def facebook_deoauth(self):
        self.session_set("fb-access-token", None)
        self.session_set("fb-user-info", None)
        self.session_set("fb-state", None)
        self.session_set("fb-authorized", datetime.datetime(1970, 1, 1))

    def facebook_pre_oauth(self):
        self.facebook_deoauth()
        authDaemon.authorizeIP_FacebookLogin(self._session["ip"], ACCESS_TIME_FACEBOOK_LOGIN)
        fb_state = binascii.b2a_hex(os.urandom(32)).decode("utf-8")
        self.session_set("fb-state", fb_state)
        return "https://www.facebook.com/v7.0/dialog/oauth?client_id=%s&redirect_uri=%s&state=%s" % (SSO_FACEBOOK_APP_ID, REMOTE_SERVER_LINK + "facebook/oauth", fb_state)

    def facebook_post_oauth(self, fb_authcode, fb_state):
        authDaemon.deauthorizeIP_FacebookLogin(self._session["ip"])
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
        self.session_set("fb-authorized", datetime.datetime.now() + datetime.timedelta(seconds=ACCESS_TIME_INTERNET))
        msgLog("Facebook", "Authorized Facebook user \"" + fb_user_info["name"] + "\" [#" + fb_user_info["id"] + "]")
        return None

    def facebook_get_user_id(self):
        return self.session_get("fb-user-info", {"id":0})["id"]

    def facebook_get_user_name(self):
        return self.session_get("fb-user-info", {"name":"Unknown"})["name"]

    # Google Login
    def google_deoauth(self):
        self.session_set("gg-access-token", None)
        self.session_set("gg-refresh-token", None)
        self.session_set("gg-user-info", None)
        self.session_set("gg-code-verifier", None)
        self.session_set("gg-authorized", datetime.datetime(1970, 1, 1))

    def google_pre_oauth(self):
        self.google_deoauth()
        authDaemon.authorizeIP_GoogleLogin(self._session["ip"], ACCESS_TIME_GOOGLE_LOGIN)
        gg_code_verifier = binascii.b2a_hex(os.urandom(32)).decode("utf-8")
        self.session_set("gg-code-verifier", gg_code_verifier)
        return "https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&code_challenge=%s&response_type=code&scope=email profile" % (SSO_GOOGLE_CLIENT_ID, REMOTE_SERVER_LINK + "google/oauth", gg_code_verifier)

    def google_post_oauth(self, gg_code, gg_scope):
        authDaemon.deauthorizeIP_GoogleLogin(self._session["ip"])
        # Check scope?
        # Get code verifier
        gg_code_verifier = self.session_get("gg-code-verifier", None)
        if gg_code_verifier == None:
            return "Invalid oauth code verifier."
        # Wait
        time.sleep(0.5)
        # Get Google access token
        conn = http.client.HTTPSConnection("oauth2.googleapis.com")
        conn.request("POST", "/token", urllib.parse.urlencode({
            "client_id" : SSO_GOOGLE_CLIENT_ID,
            "client_secret" : SSO_GOOGLE_CLIENT_SECRET,
            "code" : gg_code,
            "code_verifier" : gg_code_verifier,
            "grant_type" : "authorization_code",
            "redirect_uri" : REMOTE_SERVER_LINK + "google/oauth",
        }), {
            "Content-type": "application/x-www-form-urlencoded",
            #"Accept": "text/plain"
        })
        res = conn.getresponse()
        #if res.status != 200 or res.reason != "OK":
        #    return "Invalid status was returned (%s,%s)." % (str(res.status), res.reason)
        response = res.read()
        conn.close()
        # Parse response
        gg_data = json.loads(response)
        if not ("access_token" in gg_data.keys()):
            return "Failed to get access token."
        gg_access_token = gg_data["access_token"]
        #gg_refresh_token = gg_data["refresh_token"]
        #gg_expire_in = gg_data["expires_in"]
        # Get user info
        conn = http.client.HTTPSConnection("www.googleapis.com")
        conn.request("GET", "/oauth2/v2/userinfo?access_token=%s" % (gg_access_token))
        res = conn.getresponse()
        #if res.status != 200 or res.reason != "OK":
        #    return "Invalid status was returned (%s,%s)." % (str(res.status), res.reason)
        response = res.read()
        conn.close()
        gg_user_info = json.loads(response)
        if not ("id" in gg_user_info.keys() and "name" in gg_user_info.keys()):
            return "Failed to get user info."
        # Save session data
        self.session_set("gg-access-token", gg_access_token)
        #self.session_set("gg-refresh-token", gg_refresh_token)
        self.session_set("gg-user-info", gg_user_info)
        self.session_set("gg-code-verifier", None)
        self.session_set("gg-authorized", datetime.datetime.now() + datetime.timedelta(seconds=ACCESS_TIME_INTERNET))
        msgLog("Google", "Authorized Google user \"" + gg_user_info["name"] + "\" [#" + gg_user_info["id"] + "]")
        return None

    def google_get_user_id(self):
        return self.session_get("gg-user-info", {"id":0})["id"]

    def google_get_user_name(self):
        return self.session_get("gg-user-info", {"name":"Unknown"})["name"]

    def isWebView(self):
        # Check requested with header
        if ("X-Requested-With" in self.headers.keys()):
            # Android Web View
            if self.headers["X-Requested-With"] == "com.android.htmlviewer":
                return True
        # Check browser user agent
        if ("User-Agent" in self.headers.keys()):
            # Android Web View
            if "; wv" in self.headers["User-Agent"]:
                return True
        # Probably not
        return False
    

    def get_file(self, name):
        # If route exists
        if name in self.route.keys():
            if self.route[name]["cached"] == None:
                return self.load_file(self.route[name]["file"])
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
        elif ext == ".txt" :
            return "text/plain"
        elif ext == ".crt" :
            return "application/x-x509-ca-cert"
        elif ext == ".pdf" :
            return "application/pdf"
        return "text/html"

    def session_init(self):
        ip = self.client_address[0]
        #mac = getMacFromIp(ip)
        self._session = {
            "ip" : ip,
            #"mac" : mac
        }
        if not (ip in self.sessions.keys()):
            self.sessions[ip] = {
                "ip" : ip,
                #"mac" : mac,
                "data" : {}
            }
        return

    def session_hasInternet(self):
        if authDaemon.hasClient_Internet(self._session["ip"]) == False:
            return False
        return True

    def session_set(self, key, value):
        self.sessions[self._session["ip"]]["data"][key] = value

    def session_get(self, key, defvalue):
        if key in self.sessions[self._session["ip"]]["data"].keys():
            return self.sessions[self._session["ip"]]["data"][key]
        else:
            return defvalue

    def authorize_internet(self):
        ip = self._session["ip"]
        self.session_set("authorized", datetime.datetime.now() + datetime.timedelta(seconds=ACCESS_TIME_INTERNET))
        authDaemon.authorizeIP_Internet(self._session["ip"], ACCESS_TIME_INTERNET)

    def deauthorize_internet(self):
        ip = self._session["ip"]
        self.session_set("authorized", datetime.datetime(1970, 1, 1))
        authDaemon.deauthorizeIP_All(self._session["ip"])
    
    # Handle GET requests
    def do_GET(self):
        self.session_init()
        # Get file
        body, headers, status = self.get_route('GET', self.path)
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
        self.session_init()
        # Get file
        body, headers, status = self.get_route('POST', self.path)
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
    def log_message(self, format, *args):
        return



''' HTTP Captive Portal
-----------------------------------'''

class RedirectPortal(CaptivePortal):
    route = {
        "/favicon.ico": {"file": "favicon.ico", "cached": False},
        "/css/custom.css": {"file": "css/custom.css", "cached": False},
        "/css/bootstrap.min.css": {"file": "css/bootstrap.min.css", "cached": False},
        "/css/bootstrap.lumen.min.css": {"file": "css/bootstrap.lumen.min.css", "cached": False},
        "/js/jquery.min.js": {"file": "js/jquery.min.js", "cached": False},
        "/js/popper.min.js": {"file": "js/popper.min.js", "cached": False},
        "/js/bootstrap.min.js": {"file": "js/bootstrap.min.js", "cached": False},
        "/img/portal.png": {"file": "img/portal.png", "cached": False},
        "/img/portal-other.png": {"file": "img/portal-other.png", "cached": False},

        # Other pages
        ".redirect": {"file": "redirect.html", "cached": False},
        ".message": {"file": "message.html", "cached": False},
    }

    def get_route(self, method, rawUrl):
        # Analise URL
        url = urllib.parse.urlparse(rawUrl)
        path = url.path
        # Headers
        headers = {}
        # Status
        status = 200

        # Get file
        data = self.get_file(path)

        # If file not found
        if data == None:
            data, headers, status = self.do_redirect(REMOTE_SERVER_LINK, "<p>Redirecting to captive portal...</p>", 2)

        return data, headers, status;

    # Handle GET requests
    def do_GET(self):
        # Get file
        body, headers, status = self.get_route('GET', self.path)
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

    def do_POST(self):
        # Get file
        body, headers, status = self.get_route('POST', self.path)
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



''' Other Functions
-----------------------------------'''

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
        if device['ip'] == ip:
            return device['mac']
    return '00:00:00:00:00:00'

# List rules information
def getRulesList():
    # Get rules
    result = runCmd('iptables -L FORWARD -n -v -x')
    if result.returncode != 0:
        return []
    # Parse data
    # 7609  2108649 ACCEPT     all  --  *      *       192.168.20.97        0.0.0.0/0
    data = result.stdout.decode('utf-8')
    data = re.findall(r"\s+(\d+)\s+(\d+)\s+ACCEPT\s+all\s+--\s+\*\s+\*\s+(\d+\.\d+\.\d+\.\d+)\s+0\.0\.0\.0\/0", data)
    rules = []
    for rule in data:
        rules.append({
            'packets' : int(rule[0]),
            'bytes' : int(rule[1]),
            'ip' : rule[2]
        })
    # Return data
    return rules

# Get Rule from IP
def getRuleFromIp(ip):
    rules = getRulesList()
    for rule in rules:
        if rule['ip'] == ip:
            return rule
    return None

def bytes_sizeof_format(num, suffix='B'):
    for unit in ['','K','M','G','T','P','E','Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Y', suffix)



''' Script Start Functions
-----------------------------------'''

# Start Server
def start_server():
    threading.Thread(target = server_http).start()
    threading.Thread(target = server_https).start()

def server_http():
    msgLog("WebServer", "Starting HTTP server")
    server = http.server.ThreadingHTTPServer(('', HTTP_SERVER_PORT), RedirectPortal)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()

def server_https():
    msgLog("WebServer", "Starting HTTPS server")
    #server = http.server.HTTPServer(('', 443), CaptivePortal)
    #server = http.server.ThreadingHTTPServer(('', 443), CaptivePortal)
    server = http.server.ThreadingHTTPServer(('', HTTPS_SERVER_PORT), CaptivePortal)
    server.socket = ssl.wrap_socket(server.socket, keyfile=SSL_KEY_PATH, certfile=SSL_CERT_PATH, server_side=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()

def database_init():
    if CREDENTIALS_SIGNIN == True:
        global database
        msgLog("Database", "Initializing database")
        database = Database()
        # Create Users Example
        #database.createUser('test', 'test')
        #database.createUser('unipi', 'unipi')

def iptables_reset():
    if IPTABLES_RESET == True:
        msgLog("iptables", "Reseting iptables")
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
        msgLog("iptables", "Initializing iptables")
        # Allow DNS if not custom DNS
        if not USE_CUSTOM_DNS_SERVER:
            callCmd(["iptables", "-A", "FORWARD", "-i", INTERFACE_INPUT, "-p", "tcp", "--dport", "53", "-j" , "ACCEPT"])
            callCmd(["iptables", "-A", "FORWARD", "-i", INTERFACE_INPUT, "-p", "udp", "--dport", "53", "-j" , "ACCEPT"])
        # Allow traffic to captive portal
        callCmd(["iptables", "-A", "FORWARD", "-i", INTERFACE_INPUT, "-p", "tcp", "-d", LOCAL_SERVER_IP, "--dport", str( HTTP_SERVER_PORT), "-j", "ACCEPT"])
        callCmd(["iptables", "-A", "FORWARD", "-i", INTERFACE_INPUT, "-p", "tcp", "-d", LOCAL_SERVER_IP, "--dport", str(HTTPS_SERVER_PORT), "-j", "ACCEPT"])
        # Block all other traffic
        callCmd(["iptables", "-A", "FORWARD", "-i", INTERFACE_INPUT, "-j" , "DROP"])
        # Redirecting HTTPS traffic to captive portal (traffic towards the domain)
        callCmd(["iptables", "-t", "nat", "-A",  "PREROUTING", "-i", INTERFACE_INPUT, "-p", "tcp", "-d", REMOTE_SERVER_IP, "--dport", str(HTTPS_SERVER_PORT), "-j", "DNAT", "--to-destination",  LOCAL_SERVER_IP + ":" + str(HTTPS_SERVER_PORT)])
        callCmd(["iptables", "-t", "nat", "-A", "POSTROUTING"                       , "-p", "tcp", "-d", LOCAL_SERVER_IP,  "--dport", str(HTTPS_SERVER_PORT), "-j", "SNAT",      "--to-source", REMOTE_SERVER_IP])
        # Redirecting HTTP traffic to captive portal (all HTTP traffic)
        callCmd(["iptables", "-t", "nat", "-A",  "PREROUTING", "-i", INTERFACE_INPUT, "-p", "tcp",                         "--dport", str( HTTP_SERVER_PORT), "-j", "DNAT", "--to-destination",  LOCAL_SERVER_IP + ":" + str( HTTP_SERVER_PORT)])
        # Forward DNS traffic to local DNS
        if USE_CUSTOM_DNS_SERVER:
            callCmd(["iptables", "-t", "nat", "-A",  "PREROUTING", "-i", INTERFACE_INPUT, "-p", "tcp", "--dport", str(53), "-j", "DNAT", "--to-destination",  LOCAL_DNS_SERVER_IP + ":" + str(DNS_SERVER_PORT)])
            callCmd(["iptables", "-t", "nat", "-A",  "PREROUTING", "-i", INTERFACE_INPUT, "-p", "udp", "--dport", str(53), "-j", "DNAT", "--to-destination",  LOCAL_DNS_SERVER_IP + ":" + str(DNS_SERVER_PORT)])

def sso_init():
    global SSO_FACEBOOK_EXCLUDE_DOMAINS, SSO_FACEBOOK_EXCLUDE_IPS, SSO_GOOGLE_EXCLUDE_DOMAINS, SSO_GOOGLE_EXCLUDE_DOMAINS_COUNTRIES,SSO_GOOGLE_EXCLUDE_IPS
    # Turn facebook domains to server IPs
    if SSO_FACEBOOK:
        msgLog("SSO", "Loading Facebook IPs ...")
        for domain in SSO_FACEBOOK_EXCLUDE_DOMAINS:
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                ip = None
            if ip != None:
                if not (ip in SSO_FACEBOOK_EXCLUDE_IPS):
                    SSO_FACEBOOK_EXCLUDE_IPS.append(ip)
        msgLog("SSO", "Found " + str(len(SSO_FACEBOOK_EXCLUDE_IPS)) + " Facebook IPs")
    # Turn google domains to server IPs
    if SSO_GOOGLE:
        msgLog("SSO", "Loading Google IPs ...")
        for domain in SSO_GOOGLE_EXCLUDE_DOMAINS:
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                ip = None
            if ip != None:
                if not (ip in SSO_GOOGLE_EXCLUDE_IPS):
                    SSO_GOOGLE_EXCLUDE_IPS.append(ip)
        for toplevel in SSO_GOOGLE_EXCLUDE_DOMAINS_COUNTRIES:
            try:
                ip = socket.gethostbyname('accounts.google' + toplevel)
            except socket.gaierror:
                ip = None
            if ip != None:
                if not (ip in SSO_GOOGLE_EXCLUDE_IPS):
                    SSO_GOOGLE_EXCLUDE_IPS.append(ip)
        msgLog("SSO", "Found " + str(len(SSO_GOOGLE_EXCLUDE_IPS)) + " Google IPs")


# Start Monitor Daemon
def start_auth_daemon():
    global authDaemon
    msgLog("AuthDaemon", "Start Authorizations Daemon")
    authDaemon = AuthorizationsDaemon()
    auth_daemon_interval()

def auth_daemon_interval():
    threading.Timer(AUTHDAEMON_INTERVAL_CHECK, auth_daemon_interval).start()
    authDaemon.runChecks()

def msgLog(stype, message, level = LOG_NORMAL):
    if level >= LOG_LEVEL:
        print("[%s] %s" % (stype, message))
        sys.stdout.flush()


''' Script Start
-----------------------------------'''
if __name__ == '__main__':
    # Check if root
    if os.getuid() != 0:
        msgLog("Portal", "Need to run with root rights")
    else:
        # Set up database
        database_init()
        # Set up iptables
        iptables_reset()
        iptables_init()
        # SSO init
        sso_init()
        # Monitor Daemon
        start_auth_daemon()
        # Start Server
        start_server()
