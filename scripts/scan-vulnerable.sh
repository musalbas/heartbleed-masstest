#!/bin/sh

cd /root/heartbleed-masstest

python ssltest.py --timeout 30 --json heartbleed.json --only-vulnerable
git commit heartbleed.json -m "Scanned all vulnerable hosts" > /dev/null


python ssltest.py --timeout 30 --json heartbleed.json --only-unscanned
git commit heartbleed.json -m "Scanned all new hosts" > /dev/null
