#! /usr/bin/env python3

import argparse
import requests
from bs4 import BeautifulSoup as bs

VERSION = "perimeterFinder-0.01"
CRT_SH = "https://crt.sh/"
VERBOSE = False


def init_parser():
    parser = argparse.ArgumentParser(
        description='Finds the exposed network perimeter of a domain.')

    parser.add_argument('--version',
                        action='version',
                        version=VERSION,
                        help="Prints the version information and exits.")

    parser.add_argument('--target', "-t",
                        action="append",
                        help="Target domain to search for subdomains.")

    parser.add_argument("--interactive",
                        action="store_true",
                        help="Launches the script in interactive mode.")

    parser.add_argument("--verbose", "-v",
                        action="store_true",
                        default=False,
                        help="Makes output verbose. Might get messy output.")

    return parser


def get_perimeter(pattern):

    per = set()

    payload = {'q': pattern}
    res = requests.get(CRT_SH, params=payload).text.strip()

    soup = bs(res, 'html.parser')
    table = soup.find_all('table')[2]

    rows = table.find_all('tr')

    if len(rows) < 2:
        if VERBOSE:
            print("No entries found.")

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

            per = get_perimeter(pattern)
            for i in per:
                print("\t-->\t{}".format(i))
        except Exception as e:
            if VERBOSE:
                print("Error, {}".format(e))
            print("Not found. Check if target exists or try dictionary attack.")


def target_perim_summary(c_target, c_perim):
    print("Found the following endpoints using passive discovery for: {}".format(c_target))
    for i in c_perim:
        print("\t-->\t{}".format(i))


def get_perimeter_list(target_list):
    for target in target_list:
        perim = get_perimeter(target)
        target_perim_summary(target, perim)


if __name__ == '__main__':
    args = init_parser().parse_args()
    VERBOSE = args.verbose

    if VERBOSE:
        print("Verbose output activated.")
        print(args)

    if args.interactive:
        interactive()
    else:
        if len(args.target) < 1:
            print("Supply at least one target via flags or use interactive mode.")
        else:
            get_perimeter_list(args.target)
