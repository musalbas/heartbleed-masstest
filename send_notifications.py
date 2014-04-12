#!/usr/bin/env python
"""
    This script reads a list of vulnerable heartbleed hosts from heartbleed.json and then looks up
    any email addresses found in the whois database.


"""
import os
import subprocess
import json
import ssltest
import datetime
from collections import defaultdict
data_dir = "data/whois"

emails = defaultdict(list)


def generate_whois_info(address):
    """ Look address up in whois database and save the information in data_dir

        returns the filename which contains the whois output
    """
    filename = data_dir + "/" + address
    if os.path.exists(filename):
        return filename
    command = ['whois', address]
    proc = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,)
    stdout, stderr = proc.communicate('through stdin to stdout')
    print "Saving whois info for", address
    with open(filename, 'w') as f:
        f.write(stdout)
    return filename


def guess_emails(address):
    """ Gather email address information from whois database regarding specific address
    """
    filename = generate_whois_info(address)
    with open(filename) as f:
        words = f.read().split()
        emails = filter(lambda x: '@' in x, words)
        emails = map(lambda x: x.strip('"'), emails)
        emails = map(lambda x: x.strip("'"), emails)
        return emails


def send_out_emails():
    """ Send out a warning email to addresses in the emails global var

    """
    all_vulnerable_hosts = filter(lambda x: x.get('status'), ssltest.host_status.values())
    total_vulnerable_hosts = len(all_vulnerable_hosts)

    for email, hostlist in emails.items():
        # Ripe does not need to be bothered, even though their
        # address appears in the whois
        if 'ripe' in email:
            continue
        number_of_vulnerable_hosts = len(hostlist)
        message = EMAIL_HEADER

        message += "%-15s %-10s\n" % ("Host", "Last Scan")
        hostlist = sorted(hostlist)
        for i in hostlist:
            last_scan = int(i['last_scan'])
            last_scan = datetime.datetime.fromtimestamp(last_scan).strftime('%Y-%m-%d %H:%M:%S')
            entry = "%-15s %-10s\n" % (i['host'], last_scan)
            message += entry

        message += EMAIL_FOOTER
        message = message.format(**locals())
        subject = "Some of your hosts are vulnerable to heartbleed security vulnerability"
        send_email(message=message, from_address="adagios@opensource.is", to_address=email, subject=subject)


def send_email(message, from_address, to_address, subject):
    # Import smtplib for the actual sending function
    import smtplib

    # Import the email modules we'll need
    from email.mime.text import MIMEText

    message = MIMEText(message)
    message['Subject'] = subject
    message['From'] = from_address
    message['To'] = to_address

    # Send the message via our own SMTP server, but don't include the
    # envelope header.
    s = smtplib.SMTP('localhost')
    s.sendmail(from_address, [to_address], message.as_string())
    s.quit()


def main():
    if not ssltest.opts.json_file:
        ssltest.opts.json_file = "heartbleed.json"
    ssltest.import_json(ssltest.opts.json_file)
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    for host, data in ssltest.host_status.items():
        data['host'] = host
        if data['status'] is True:
            for email in guess_emails(host):
                if not data in emails[email]:
                    emails[email].append(data)

    send_out_emails()


EMAIL_HEADER = """Dear {email},

We, the nice people running the Monitor Iceland project have been looking
closely at heartbleed (http://heartbleed.com) security vulnerability and we
discovered that there are some vulnerable hosts out there which according to
the WHOIS database you are responsible for.

You (or your customers) have a serious security vulnerability, and you need
to update openssl on those hosts and regenerate all ssl certificates. You
might or might not already have a security breach on those systems.

According to our scans displayed ath ttp://iceland.adagios.org/heartbleed)
there are at least {total_vulnerable_hosts} hosts still vulnerable in Iceland.

These {number_of_vulnerable_hosts} belong to you:

"""

EMAIL_FOOTER = """
Please help us do the responsible thing and make sure these hosts are patched.

Don't hesitate to contact if there is anything we can do to help.
Kind Regards,
The Monitor Iceland Team
"""


if __name__ == '__main__':
    main()
