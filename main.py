#! /usr/bin/env python3

from requests import Session
from bs4 import BeautifulSoup as bs

sess = Session()


def get_perimeter(pattern):
    crt_sh = "https://crt.sh/"
    per = set()

    payload = {'q': pattern}
    res = (sess.get(crt_sh, params=payload).text).strip()

    soup = bs(res, 'html.parser')
    table = soup.find_all('table')[2]

    rows = table.find_all('tr')

    if len(rows) < 2:
        print("No entries found.")
        return []

    for row in rows[1:]:
        addr = row.find_all('td')[4].string
        per.add(addr)

    for i in per:
        print("\t-->\t{}".format(i))

    return list(per)


def main():
    print("Wildcard character is: %")
    while True:
        try:
            pattern = input("> ")

            if pattern == "quit" or pattern == "exit":
                break

            get_perimeter(pattern)
        except Exception as e:
            print("Error, {}".format(e))


main()
