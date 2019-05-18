"""
This is the (unofficial) Python API for dnsdumpster.com Website.
Using this code, you can retrieve subdomains

"""

import requests
import re
from bs4 import BeautifulSoup

VERBOSE = False


def log_verbose(s):
    if VERBOSE:
        print('[verbose] %s' % s)


def retrieve_dnsdumpster_results(table):
    domains_found = []
    trs = table.findAll('tr')
    for tr in trs:
        tds = tr.findAll('td')
        pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
        try:
            ip = re.findall(pattern_ip, tds[1].text)[0]
            domain = str(tds[0]).split('<br/>')[0].split('>')[1]
            reverse_dns = tds[1].find('span', attrs={}).text

            country = tds[2].find('span', attrs={}).text

            data = {'domain': domain,
                    'ip': ip,
                    'reverse_dns': reverse_dns,
                    'country': country
                    }
            domains_found.append(data)
        except Exception as e:
            log_verbose("Exception {} occured.".format(e))
            pass

    return domains_found


def search(domain):
    dnsdumpster_url = 'https://dnsdumpster.com/'
    session = requests.Session()

    req = session.get(dnsdumpster_url)
    soup = BeautifulSoup(req.content, 'html.parser')
    csrf_middleware = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']
    log_verbose('Retrieved token: %s' % csrf_middleware)

    cookies = {'csrftoken': csrf_middleware}
    headers = {'Referer': dnsdumpster_url}
    data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain}
    req = session.post(dnsdumpster_url, cookies=cookies, data=data, headers=headers)

    if req.status_code != 200:
        if VERBOSE:
            print(
                "Unexpected status code from {url}: {code}".format(
                    url=dnsdumpster_url, code=req.status_code)
            )
        return []

    if 'error' in req.content.decode('utf-8'):
        if VERBOSE:
            print("There was an error getting results")
        return []

    soup = BeautifulSoup(req.content, 'html.parser')
    tables = soup.findAll('table')

    res = retrieve_dnsdumpster_results(tables[3])

    return res


if __name__ == '__main__':
    doms = search("unibe.edu.do")
    print(doms)
