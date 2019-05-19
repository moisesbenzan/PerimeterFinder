#! /usr/bin/env python3

import argparse
import requests
import re
from bs4 import BeautifulSoup as bs

VERSION = "perimeterFinder-0.01"

CRT_SH = "https://crt.sh/"
DNS_DUMPSTER_URL = 'https://dnsdumpster.com/'

VERBOSE = False
EXTENDED_RESULTS = False


def log_verbose(s):
    if VERBOSE:
        print(s)


def init_parser():
    parser = argparse.ArgumentParser(
        prog=VERSION,
        description='Finds the exposed network perimeter of a domain.')

    parser.add_argument('--version',
                        action='version',
                        version=VERSION,
                        help="Prints the version information and exits.")

    parser.add_argument("--verbose", "-v",
                        action="store_true",
                        default=False,
                        help="Makes output verbose. Might get messy output.")

    parser.add_argument("--extended-results", "-A",
                        action="store_true",
                        help="Parses more dns information from external databases.")

    mutually_exclusive = parser.add_mutually_exclusive_group(required=True)

    mutually_exclusive.add_argument("--interactive",
                                    action="store_true",
                                    help="Launches the script in interactive mode.")

    mutually_exclusive.add_argument('--target', "-t",
                                    action="append",
                                    help="Target domain to search for subdomains.")

    mutually_exclusive.add_argument("--target-list", "-T",
                                    action="store",
                                    help="Load targets from a file. One target per line")

    return parser


def _parse_dnsdumpster_table(table):
    domains_found = []
    trs = table.findAll('tr')
    for tr in trs:
        tds = tr.findAll('td')
        pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
        try:
            ip = re.findall(pattern_ip, tds[1].text)[0]
            domain = str(tds[0]).split('<br/>')[0].split('>')[1]

            data = {'domain': domain,
                    'ip': ip
                    }
            domains_found.append(data)
        except Exception as e:
            log_verbose("Exception {} occured.".format(e))
            pass

    return domains_found


def get_dnsdumpster_perimeter(domain):
    session = requests.Session()

    req = session.get(DNS_DUMPSTER_URL)
    soup = bs(req.content, 'html.parser')

    csrf_middleware = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']
    log_verbose('Retrieved token: %s' % csrf_middleware)

    req = session.post(DNS_DUMPSTER_URL,
                       cookies={
                           'csrftoken': csrf_middleware},
                       data={
                           'csrfmiddlewaretoken': csrf_middleware,
                           'targetip': domain},
                       headers={
                           'Referer': DNS_DUMPSTER_URL,
                           'User-Agent': VERSION}
                       )

    if req.status_code != 200:
        log_verbose("Unexpected status code from {url}: {code}".format(url=DNS_DUMPSTER_URL, code=req.status_code))
        return []

    if 'error' in req.content.decode('utf-8'):
        log_verbose("There was an error getting results")
        return []

    soup = bs(req.content, 'html.parser')
    tables = soup.findAll('table')

    res = _parse_dnsdumpster_table(tables[3])
    session.close()

    return res


def get_ssl_perimeter(pattern):
    per = set()

    payload = {'q': pattern}
    res = requests.get(CRT_SH, params=payload).text.strip()

    soup = bs(res, 'html.parser')
    table = soup.find_all('table')[2]

    rows = table.find_all('tr')

    if len(rows) < 2:
        log_verbose("No entries found.")

        return []

    for row in rows[1:]:
        addr = row.find_all('td')[4].string
        per.add(addr)

    return list(per)


def interactive():
    print("Wildcard character is: %")
    while True:
        try:
            pattern = input("> ")

            if pattern == "quit" or pattern == "exit" or pattern == "q":
                break

            per = get_ssl_perimeter(pattern)
            for i in per:
                print("\t-->\t{}".format(i))
            if EXTENDED_RESULTS:
                d_target = pattern.replace("%.", "")
                ddumpster = get_dnsdumpster_perimeter(d_target)
                ddumpster_target_perim_summary(d_target, ddumpster, iscontinuation=True)

        except Exception as e:
            log_verbose("Error, {}".format(e))
            print("Not found. Check if target exists or try dictionary attack.")
    exit(0)


def ssl_target_perim_summary(c_target, c_perim, iscontinuation=False):
    if not iscontinuation:
        print("Found the following endpoints using passive discovery for: {}".format(c_target))
    for i in c_perim:
        print("\t-->\t{}".format(i))


def ddumpster_target_perim_summary(c_target, c_perim, iscontinuation=False):
    if not iscontinuation:
        print("Found the following endpoints using database discovery for: {}".format(c_target))

    for i in c_perim:
        print("\t-->\t{}\t\t-->\t{}".format(i['domain'], i['ip']))


def get_perimeter_list(target_list):
    for target in target_list:
        perim = get_ssl_perimeter("%." + target)
        ssl_target_perim_summary(target, perim)

        if EXTENDED_RESULTS:
            ddumpster = get_dnsdumpster_perimeter(target)
            ddumpster_target_perim_summary(target, ddumpster, iscontinuation=True)


if __name__ == '__main__':
    args = init_parser().parse_args()
    VERBOSE = args.verbose
    EXTENDED_RESULTS = args.extended_results

    log_verbose("Verbose output activated.")
    log_verbose(args)

    if args.interactive:
        # Automatically exits program.
        interactive()

    if args.target_list is not None:
        targets = []
        with open(args.target_list, 'r') as f:
            for line in f.readlines():
                targets.append(line.strip())
        get_perimeter_list(targets)
        exit(0)

    if len(args.target) < 1:
        print("Supply at least one target via flags or use interactive mode.")
    else:
        get_perimeter_list(args.target)
        exit(0)
