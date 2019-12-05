#!/usr/bin/env python3
# Author: Buanzo
# Date: Nov-2019
# Description: This tool takes a list of internal sites, and a list
# of external sites, and for each public-facing IP it checks if
# forcing access to each internal fqdn is possible.
#
# Helps find misconfigured virtualhosts, etc.
#
# Usage:
# ./http-internal-tester.py --help
#
# Example:
# ./http-internal-tester.py -i lista_interno -e lista_externo
#
# Each file must contain one fqdn per line
#
# Example:
# site.domain.com
# anothersite.domain.com
# etc.domain.com

import sys
import time
import random
import socket
import argparse
import requests
import urllib3
from bs4 import BeautifulSoup
from pprint import pprint
from tqdm import tqdm
urllib3.disable_warnings()

try:
    from forcediphttpsadapter.adapters import ForcedIPHTTPSAdapter
except ImportError:
    ForcedIPHTTPSAdapter = None

__default_timeout__ = 30


class HttpInternalTester():
    def __init__(self,
                 internos=None,
                 externos=None,
                 fix_fqdn_internos='',
                 fix_fqdn_externos='',
                 ip_blacklist=[]):
        if internos is None:
            raise(ValueError)
        if externos is None:
            raise(ValueError)
        self.fix_fqdn_internos = fix_fqdn_internos
        self.fix_fqdn_externos = fix_fqdn_externos
        self.external_ips = []
        self.invalid_records = []
        self.ip_blacklist = ip_blacklist

        with open(internos) as f:
            self.internos = f.read().splitlines()
            print("INTERNOS PRE SANITIZE: {}".format(len(self.internos)))

        with open(externos) as f:
            self.externos = f.read().splitlines()
            print("EXTERNOS PRE SANITIZE: {}".format(len(self.externos)))

        # Sanitize, Validate and Prepare the necessary data
        self.internos = self.sanitize(self.internos,
                                      self.fix_fqdn_internos,
                                      save_ips=False)
        self.externos = self.sanitize(self.externos,
                                      self.fix_fqdn_externos,
                                      save_ips=True)
        print("Internals after SANITIZE: {}".format(len(self.internos)))
        print("Externals after SANITIZE: {}".format(len(self.externos)))
        print("Invalid records:")
        pprint(self.invalid_records)
        print("External IP addresses to test against:")
        pprint(self.external_ips)

    def sanitize(self, list=[], domain_fix='', save_ips=False):
        if len(list) < 1:
            return([])
        sanitized = []
        for item in tqdm(list):
            if len(item) < 2:
                continue
            # strip
            item = item.split()[0].strip().rstrip('.')
            # append
            if domain_fix not in item:
                item = "{}{}".format(item, domain_fix)
            # validate-remove-notify
            if save_ips:
                ip = self.get_ipv4_record(item)
                if ip is None:
                    self.invalid_records.append(item)
                else:
                    sanitized.append(item)
                    if ip not in self.external_ips:
                        self.external_ips.append(ip)
            else:
                sanitized.append(item)
        return(sanitized)

    def start(self):
        for dominio in tqdm(self.internos):
            for ip in self.external_ips:
                if ip in self.ip_blacklist:
                    continue
                self.test_direct_clear(ip=ip, domain=dominio)
                self.test_direct_ssl(ip=ip, domain=dominio)

    def get_ipv4_record(self, dominio):  # TODO: support IPv6
        socket.setdefaulttimeout(10)
        try:
            ip = socket.gethostbyname(dominio)
        except Exception:
            return(None)
        return(ip)

    def test_direct_clear(self, ip, domain):
        headers = {'Host': domain}
        url = "http://{}".format(ip)
        try:
            r = requests.get(url,
                             headers=headers,
                             timeout=60,
                             verify=False,
                             allow_redirects=False)
        except requests.Timeout:
            print("Timeout para {} via {}".format(domain, ip))
        except Exception:
            print("Error accediendo a {} via {}.".format(domain, ip))
            if 'status_code' in r:
                print("STATUS CODE = {}".format(r.status_code))
        else:
            if r.status_code is not requests.codes.ok:
                print("Status Code: {} via {} no es 200.".format(domain, ip))
            host_based_html = r.text
            title = self.extraer_title(host_based_html).decode('utf8')
            print("WARNING:{}:{}:FINAL_URL={}:TITLE={}".format(domain,
                                                               ip,
                                                               r.url,
                                                               title))
        print('=============================================================')

    def test_direct_ssl(self, ip, domain):
        # test_direct3 provides TransportAdapter support for specific-ip HTTPS
        session = requests.Session()
        headers = {'Host': domain}
        url = "https://{}".format(domain)
        if ForcedIPHTTPSAdapter:
            session.mount(url, ForcedIPHTTPSAdapter(dest_ip=ip))
            try:
                r = session.get(url,
                                headers=headers,
                                timeout=60,
                                verify=False,
                                allow_redirects=False)  # TODO: check True
            except requests.Timeout:
                print("Timeout for {} via {}".format(domain, ip))
            except Exception:
                print("Error accessing a {} via {}.".format(domain, ip))
                if 'status_code' in r:
                    print("STATUS CODE = {}".format(r.status_code))
            else:
                if r.status_code is not requests.codes.ok:
                    print("Status Code for {} via {} not 200.".format(domain,
                                                                      ip))
                host_based_html = r.text
                title = self.extraer_title(host_based_html)
                t = "WARNING:{}:{}:FINAL_URL={}:TITLE={}"
                print(t.format(domain,
                               ip,
                               r.url,
                               title))
                print('=====================================================')
        else:
            print("CRITICAL ERROR: ForcedIPHTTPSAdapter not working")
            sys.exit(5)

    def extraer_title(self, html):
        try:
            soup = BeautifulSoup(html, 'lxml')
            title = soup.find('title')
        except Exception:
            title = 'No TITLE tag'
        else:
            return(title.renderContents().decode('utf8'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SSH Multi host cred testing")
    parser.add_argument("-i",
                        dest="internos",
                        required=True,
                        help="One internal site per line, fqdn only.",
                        metavar="FILE")
    parser.add_argument("-e",
                        dest="externos",
                        required=True,
                        help="One external site per line, fqdn only.",
                        metavar="FILE")
    parser.add_argument("-n",
                        dest="fix_fqdn_internos",
                        required=False,
                        help="If internals lack ORIGIN, append this.",
                        metavar="string",
                        default='')
    parser.add_argument("-x",
                        dest="fix_fqdn_externos",
                        required=False,
                        help="If externals lack ORIGIN, append this.",
                        metavar="string",
                        default='')
    parser.add_argument("-b",
                        dest="ip_blacklist",
                        required=False,
                        help="Do not use this IP. Allows multiple uses.",
                        action="append",  # No extend on most envs
                        default=[])
    args = parser.parse_args()
    hit = HttpInternalTester(internos=args.internos,
                             externos=args.externos,
                             fix_fqdn_internos=args.fix_fqdn_internos,
                             fix_fqdn_externos=args.fix_fqdn_externos,
                             ip_blacklist=args.ip_blacklist)
    hit.start()
