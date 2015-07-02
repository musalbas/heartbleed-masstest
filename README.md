This tool allows you to scan multiple hosts for Heartbleed, in an efficient multi-threaded manner.

This tests for OpenSSL versions vulnerable to Heartbleed without exploiting the server, so the heartbeat request does not cause the server to leak any data from memory or expose any data in an unauthorized manner. This [Mozilla blog post](http://blog.mozilla.org/security/2014/04/12/testing-for-heartbleed-vulnerability-without-exploiting-the-server) outlines the method used.

<pre>Usage: ssltest.py <network> [network2] [network3] ...

Test for SSL heartbleed vulnerability (CVE-2014-0160) on multiple domains

Options:
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  Port to scan on all hosts or networks, default 443
  -i INPUT_FILE, --input=INPUT_FILE
                        Optional input file of networks or ip addresses, one
                        address per line
  -o LOG_FILE, --logfile=LOG_FILE
                        Optional logfile destination
  --resume              Do not rescan hosts that are already in the logfile
  -t TIMEOUT, --timeout=TIMEOUT
                        How long to wait for remote host to respond before
                        timing out
  --threads=THREADS     If specific, run X concurrent threads
  --json=JSON_FILE      Save data as json into this file
  --only-vulnerable     Only scan hosts that have been scanned before and were
                        vulnerable
  --only-unscanned      Only scan hosts that appear in the json file but have
                        not been scanned
  --summary             Useful with --json. Don't scan, just print old results
  --verbose             Print verbose information to screen
  --max=MAX             Exit program after scanning X hosts. Useful with
                        --only-unscanned</pre>
