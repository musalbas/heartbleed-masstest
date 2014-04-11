heartbleed-masstest
===================

This repo contains a script to automatically test sites for vulnerability to the [Heartbleed Bug (CVE-2014-0160)](http://heartbleed.com/).

This is forked from https://github.com/musalbas/heartbleed-masstest with the specific intent of scanning all icelandic ip ranges.

Results are being collected at http://iceland.adagios.org/heartbleed

Usage:
```
    python ssltest.py 127.0.0.0/25 127.0.0.128/25 127.0.0.1/32
```



