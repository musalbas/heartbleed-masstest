#!/bin/sh

cd /root/heartbleed-masstest

python ssltest.py --timeout 30 --json heartbleed.json
git commit heartbleed.json -m "Scanned all hosts" > /dev/null
