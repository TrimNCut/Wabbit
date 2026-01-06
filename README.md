Wabbit v1.0
by Trim 

STILL UNDER DEVELOPMENT

Purpose:
Network port scanner with banner grabbing

TODO:
DNS Probing for some banners like HTTPS, HTTP etc

Scans 1024 ports in less than 6s with timeouts

usage: wabbit.py [-h] [-p PORT] [-o] [-r RANGE] [-O] [-t] target

Wabbit v1.0, network and port scanning tool

positional arguments:
  target             Target IP/URL The URL e.g www.example.com or the IP
                     Address e.g 127.0.0.1 of the target

options:
  -h, --help         show this help message and exit
  -p, --port PORT    Specific port to scan e.g 43
  -o, --output       Saves open ports in a text file
  -r, --range RANGE  Scans from 1 to the set range (max 65535) Default is 1024   
  -O, --onlyopen     Ouput only open ports
  -t, --threading    Make use of threading, less stealthier