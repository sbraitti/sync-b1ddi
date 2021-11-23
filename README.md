
# BloxOne DDI Sync

Version 0.1
Author: Stefan Braitti

About
-----------
Script to compare and synchronize Infoblox BloxOne DDI records to other DNS using DNS Transfer

This tool is experimental.


Description
-----------
The idea behind this tools is to get zonetransfer from two NameServers, compare it based on record types and make changes in the BloxOneDDI to synchronize it. 

Feel free to contribute! I'm not a developer..

# Thanks
Special thanks to John Neerdael and Chris Marrison for their contribution to the community =) 

# Usage
<pre>
usage: b1ddi-sync.py [-h] -z ZONE --source SERVER1 --dest SERVER2 [-a] [-t]
                     [-m] [--aaaa] [--cname] [--tags TAGS] --view VIEWNAME
                     [--debug] [--ignore-ttl] [--stop-on-error] -c CONFIG
                     [--logfile LOGFILE] [-v]

This is a simple Zone comparison tool

optional arguments:
  -h, --help            show this help message and exit
  -z ZONE               Zone to compare
  --source SERVER1      Source NameServer
  --dest SERVER2        Destination NameServer
  -a, --arecord         Sync A record data
  -t, --txtrecord       Sync TXT record data
  -m, --mxrecord        Sync MX record data
  --aaaa                Sync AAAA record data
  --cname               Sync CNAME record data
  --tags TAGS           Tags to apply to imported objects
  --view VIEWNAME       View name
  --debug               Log debug
  --ignore-ttl          Ignore TTL
  --stop-on-error       Quit script on error
  -c CONFIG, --config CONFIG
                        Path to ini file with API key
  --logfile LOGFILE     Log file name (Default: logfile.log)
  -v, --version         show program's version number and exit</pre>
  
  Prerequisites
-------------

Python 3.6 or above

Non-standard modules:

    - bloxone 0.5.6+

The latest version of the bloxone module is available on PyPI and can simply be
installed using::

    pip3 install bloxone --user

To upgrade to the latest version::

    pip3 install bloxone --user --upgrade

Complete list of modules::
    import dns.resolver
    import dns.zone
    import bloxone, 
    import logging
    import json
