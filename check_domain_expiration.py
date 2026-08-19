#!/usr/bin/env python3

"""
    Nagios plugin to check when a domain name expires.

    Asks RDAP first and falls back to whois when the TLD serves no RDAP, which
    is the case for most ccTLDs. The whois server comes from IANA, so no local
    table is needed and the whois binary is not used. Standard library only.

    by Dorance <dorancemc@gmail.com>
"""

import argparse
import json
import re
import socket
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timezone

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3

BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
IANA_WHOIS = "whois.iana.org"

WHOIS_KEYS = re.compile(
    r"^\s*(registry expiry date|registrar registration expiration date|"
    r"expiry date|expiration date|expires on|expires|expire|paid-till|"
    r"renewal date|valid-date)\s*:?\s*(.+)$",
    re.IGNORECASE,
)

ISO_DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
DOTTED_DATE = re.compile(r"(\d{4})\.(\d{2})\.(\d{2})")
SLASHED_DATE = re.compile(r"(\d{4})/(\d{2})/(\d{2})")
DMY_DATE = re.compile(r"(\d{2})-([A-Za-z]{3})-(\d{4})")

MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun",
     "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def fetch(url, timeout):
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def rdap_base_url(tld, timeout):
    for services in fetch(BOOTSTRAP, timeout)["services"]:
        tlds, urls = services[0], services[1]
        if tld in tlds:
            return urls[0].rstrip("/")
    return None


def parse_date(text):
    match = ISO_DATE.search(text) or DOTTED_DATE.search(text) or SLASHED_DATE.search(text)
    if match:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    match = DMY_DATE.search(text)
    if match and match.group(2).lower() in MONTHS:
        return date(int(match.group(3)), MONTHS[match.group(2).lower()], int(match.group(1)))
    return None


def from_rdap(domain, timeout):
    base = rdap_base_url(domain.rsplit(".", 1)[-1].lower(), timeout)
    if not base:
        return None, "TLD serves no RDAP"
    data = fetch("{}/domain/{}".format(base, domain), timeout)
    for event in data.get("events", []):
        if event.get("eventAction") == "expiration":
            return parse_date(event.get("eventDate", "")), None
    return None, "RDAP has no expiration event"


def whois_query(server, question, timeout):
    with socket.create_connection((server, 43), timeout=timeout) as connection:
        connection.sendall((question + "\r\n").encode())
        chunks = []
        while True:
            data = connection.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def whois_server(tld, timeout):
    for line in whois_query(IANA_WHOIS, tld, timeout).splitlines():
        if line.lower().startswith("whois:"):
            return line.split(":", 1)[1].strip()
    return None


def from_whois(domain, timeout):
    server = whois_server(domain.rsplit(".", 1)[-1].lower(), timeout)
    if not server:
        return None, "IANA lists no whois server for the TLD"
    body = whois_query(server, domain, timeout)
    if not body.strip():
        return None, "{} returned nothing".format(server)
    for line in body.splitlines():
        match = WHOIS_KEYS.match(line)
        if match:
            expires = parse_date(match.group(2))
            if expires:
                return expires, None
    return None, "{} has no expiry date".format(server)


def main():
    parser = argparse.ArgumentParser(description="Check when a domain name expires")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-w", "--warning", type=int, default=30, help="days")
    parser.add_argument("-c", "--critical", type=int, default=7, help="days")
    parser.add_argument("-t", "--timeout", type=int, default=20, help="seconds")
    options = parser.parse_args()

    if options.critical >= options.warning:
        print("UNKNOWN - critical must be lower than warning")
        return UNKNOWN

    reasons = []
    expires = None
    for source, lookup in (("RDAP", from_rdap), ("whois", from_whois)):
        try:
            expires, reason = lookup(options.domain, options.timeout)
        except (urllib.error.URLError, OSError, ValueError, KeyError) as error:
            expires, reason = None, str(error)
        if expires:
            break
        reasons.append("{}: {}".format(source, reason))

    if not expires:
        print("UNKNOWN - no expiry date for {} ({})".format(
            options.domain, "; ".join(reasons)))
        return UNKNOWN

    left = (expires - datetime.now(timezone.utc).date()).days
    perfdata = "days={};{};{}".format(left, options.warning, options.critical)
    summary = "Domain {} expires on {} ({} days) | {}".format(
        options.domain, expires.isoformat(), left, perfdata)

    if left < 0:
        print("CRITICAL - " + summary)
        return CRITICAL
    if left < options.critical:
        print("CRITICAL - " + summary)
        return CRITICAL
    if left < options.warning:
        print("WARNING - " + summary)
        return WARNING
    print("OK - " + summary)
    return OK


if __name__ == "__main__":
    sys.exit(main())
