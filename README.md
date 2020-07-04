# Basic Secure Captive Portal

A captive portal based on Python3 and IPtables. This is based on @nikosft's implementation, is an improved version aiming at providing *security* and ease of access through *Single sign-on* (SSO).

![img](https://raw.githubusercontent.com/GramThanos/captive-portal/master/pages/img/portal.png)

## Features
 - HTTPS Captive Portal
    - No-IP domain
    - Let's encrypt SSL certificate
 - Login Methods
    - Credentials login (SQLite3)
    - Facebook SSO login
    - Google SSO login
 - Load HTML and assets from files (routes defined in the code)
 - MAC Address Change detection
 - Timed Internet Access
 
### Future ToDo
 - Move configuration to other file
 - Write tutorial
 - Add CSRF tokens
 - Add token login method
 - Add admin panel / console commands
 - Add other SSO services? (Any other?)
 - Add cooldowns between unsuccessful logins?
 - Monitor traffic during login?

## Preview

![img](https://raw.githubusercontent.com/GramThanos/captive-portal/master/preview/login-page.jpg)
![img](https://raw.githubusercontent.com/GramThanos/captive-portal/master/preview/status-page.jpg)
![img](https://raw.githubusercontent.com/GramThanos/captive-portal/master/preview/logout-modal.jpg)

## Set up

### Clone repo
Start by cloning the repository:
```
git clone https://github.com/GramThanos/captive-portal.git
cd captive-portal
```

### Edit the configuration
Edit the configuration on the top of `captive_portal.py`.

First change the IP address of the server you are running the captive portal.
```
LOCAL_SERVER_IP = "192.168.20.1"
```

Set the domain to use for HTTPS (you will neet to have access to the SSL certificate and key of the domain)
```
REMOTE_SERVER_DOMAIN = "captive.ddns.net"
```
You will also need to copy the SSL certificate (as `cert.pem`) and the private key (as `key.pem`) of the domain at the same directory.
For testing, you may create custom ones by running (add the domain when asked for `Common Name (e.g. server FQDN or YOUR name)`):
```
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```


Then create and edit the configuration of your Facebook app
```
cp ./sso_config.example.py ./sso_config.py
nano ./sso_config.py
```
Add your app id and secret.

## Using it
You can launch the captive portal by running
```
sudo python3 ./captive_portal.py
```

## About

This web page was developed as part of the "Web-based authentication on WLANs" project during the postgraduate program "Digital Systems Security"

University of Piraeus, Department of Digital Systems, Digital Systems Security

Authors: Athanasios Vasileios Grammatopoulos, George Zamanis, Sotirios Papadopoulos
