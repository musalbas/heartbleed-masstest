#!/usr/bin/env python

from subprocess import Popen, PIPE
import re
import time
import os
import sys
import simplejson as json

def download_cert(ip, starttls_method=None, port=None):
    if not re.match('^\d+\.\d+\.\d+\.\d+$', ip):
        raise Exception("Invalid ip address passes")

    if starttls_method is None:
        if port is None:
            port=443
        cmd = ["./timeout3", "-t 5",
               "openssl",
               "s_client",
               "-connect",
               "%s:%s" % (ip, port)]
    else:
        if port is None:
            raise Exception("port is mandatory for starttls")
        cmd = ["./timeout3", "-t 5",
               "openssl",
               "s_client",
               "-starttls",
               starttls_method,
               "-connect",
               "%s:%s" % (ip, port)]

    p = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE, shell=False)
    p.stdin.close()

    cert = ""
    # Try to read the certificate
    for l in p.stdout.readlines():
        if cert:
            cert += l
            if l.startswith("-----END CERTIFICATE-----"):
                break
        elif l.startswith("-----BEGIN CERTIFICATE"):
            cert += l

    return cert

def save_cert(ip, cert, proto="https"):
    if not re.match('^\d+\.\d+\.\d+\.\d+$', ip):
        raise Exception("Invalid ip address passes")

    try:
        os.mkdir("data/certs")
        os.mkdir("data/certs/%s" % proto)
    except:
        pass
    filename = "data/certs/%s/%s" % (proto, ip)
    fh = open(filename, "w")
    fh.write(str(cert))
    fh.close()

def download_cert_https(ip):
    download_cert(ip, port=443)

def download_cert_smtp(ip):
    download_cert(ip, port=25, starttls_method="smtp")

def download_cert_ldapi(ip):
    download_cert(ip, port=389, starttls_method="ldap")

def download_cert_ldap(ip):
    download_cert(ip, port=636)

def parse_heartbleed_json(json_file):
    fh = open(json_file)
    return json.load(fh)
        
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s <scan-json-file>" % sys.argv[0])
        sys.exit(1)

    heartbleed_servers = parse_heartbleed_json(sys.argv[1])

    count = 0
    for ip in heartbleed_servers.keys():
        if heartbleed_servers[ip]['status'] is not True:
            continue
        count += 1
        # Wait a bit every 20 hosts
        if (count % 20) == 0:
            time.sleep(10)
        # Fork into background each job
        if not os.fork():
            cert = download_cert_https(ip)
            save_cert(ip, cert, "https")
            sys.exit(0)

# vim: sts=4 expandtab autoindent
