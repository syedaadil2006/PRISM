# Threat intelligence

Put indicator files here; PRISM reads them on start (and on Admin > Detection > Reload).

* `*.json` - STIX 2.1 bundles (`indicator` objects with domain, IP, URL or file-hash patterns)
* `*.csv` - columns `type,value,description` (type: domain, ip, sha256, md5, sha1, url)
* `*.txt` - one indicator per line; `#` starts a comment

Files here stay on this computer and are not committed to Git. PRISM never downloads feeds itself.
