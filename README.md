heartbleed-masstest
===================

The purpose of this repo is to monitor the vulnerability state of top websites to Heartbleed, so that users may know which websites may or may not have been safe, which passwords should be changed and if their data may have been compromised.

This repo contains a script to automatically test sites for vulnerability to the [Heartbleed Bug (CVE-2014-0160)](http://heartbleed.com/).

*Note: the proof-of-concept has been modified to test for OpenSSL versions vulnerable to Heartbleed without exploiting the server, so the heartbeat request does not cause the server to leak any data from memory or expose any data in an unauthorized manner. See the [Mozilla blog post](http://blog.mozilla.org/security/2014/04/12/testing-for-heartbleed-vulnerability-without-exploiting-the-server) for an explanation.*

To check if a site is still vulnerable, you may use the tool at http://filippo.io/Heartbleed/.

Please note that subdomains aren't tested, so sites that don't have SSL on their main domain will appear as "no SSL".

