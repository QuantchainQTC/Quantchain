#!/usr/bin/env python3
# Copyright (c) 2026 Soqucoin Labs Inc.
# Distributed under the MIT software license.
#
# SDN screener input builder for the genesis-migration snapshot tool.
#
# Reads the OFAC SDN List in its published XML form and writes the file the
# snapshot tool consumes with --sdn-addresses: every "Digital Currency
# Address - <chain>" identifier on the list, one per line, sorted, with a
# header that records the publication date, the record count and the sha256
# of the source file. The snapshot tool records the sha256 of THIS file in
# commitment.txt, so the exact screen input is part of the published
# artifact set and anyone can rebuild it from the same OFAC release.
#
# Every chain's identifiers are kept, not only Solana's. The screen is an
# exact string match, so an address listed for another chain can never match
# a Solana sender by accident, and keeping the whole set means the file needs
# no interpretation of OFAC's chain labels (a label OFAC adds later is picked
# up automatically). No identity data is read or written: names, programs and
# every other identifier type are ignored.
#
# Source: https://www.treasury.gov/ofac/downloads/sdn.xml (the SDN List;
# the Consolidated Non-SDN List is a different file and is NOT the screen
# input). Download it yourself, record the date, run:
#
#   python3 sdn_extract.py --sdn-xml sdn.xml --out sdn-addresses.txt
#
# Standard library only. Streaming parse; the file is ~30 MB.

import argparse
import hashlib
import sys
import xml.etree.ElementTree as ET

ID_TYPE_PREFIX = "Digital Currency Address"


def local_name(tag):
    """Strip the XML namespace: '{ns}idType' -> 'idType'."""
    return tag.rsplit("}", 1)[-1]


def extract(path):
    """Return (publish_date, record_count, sorted list of (chain, address))
    from an SDN XML file. Streaming, so memory stays flat."""
    publish_date = ""
    record_count = ""
    found = set()
    id_type = None
    id_number = None
    for event, elem in ET.iterparse(path, events=("start", "end")):
        name = local_name(elem.tag)
        if event == "start":
            if name == "id":
                id_type = None
                id_number = None
            continue
        # end events
        if name == "Publish_Date":
            publish_date = (elem.text or "").strip()
        elif name == "Record_Count":
            record_count = (elem.text or "").strip()
        elif name == "idType":
            id_type = (elem.text or "").strip()
        elif name == "idNumber":
            id_number = (elem.text or "").strip()
        elif name == "id":
            if id_type and id_type.startswith(ID_TYPE_PREFIX) and id_number:
                chain = id_type[len(ID_TYPE_PREFIX):].strip(" -") or "UNSPECIFIED"
                found.add((chain, id_number))
            id_type = None
            id_number = None
        elif name == "sdnEntry":
            elem.clear()   # free the subtree; identifiers were already read
    return publish_date, record_count, sorted(found)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def render(publish_date, record_count, source_sha, entries):
    lines = [
        "# OFAC SDN List digital-currency address identifiers",
        "# source: sdn.xml publish_date=%s record_count=%s" % (publish_date, record_count),
        "# source_sha256=%s" % source_sha,
        "# addresses=%d" % len(entries),
        "# format: one address per line; text after '#' is a comment (chain label)",
    ]
    for chain, address in entries:
        lines.append("%s # %s" % (address, chain))
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Build the SDN screen input from the OFAC SDN XML")
    ap.add_argument("--sdn-xml", required=True, help="path to the downloaded sdn.xml")
    ap.add_argument("--out", required=True, help="output file for snapshot.py --sdn-addresses")
    args = ap.parse_args()

    publish_date, record_count, entries = extract(args.sdn_xml)
    if not entries:
        raise SystemExit("no digital-currency identifiers found; is this the SDN XML?")
    source_sha = sha256_file(args.sdn_xml)
    text = render(publish_date, record_count, source_sha, entries)
    with open(args.out, "w") as f:
        f.write(text)
    by_chain = {}
    for chain, _ in entries:
        by_chain[chain] = by_chain.get(chain, 0) + 1
    sys.stdout.write("sdn publish_date=%s record_count=%s source_sha256=%s\n"
                     % (publish_date, record_count, source_sha))
    sys.stdout.write("addresses=%d output_sha256=%s\n"
                     % (len(entries), hashlib.sha256(text.encode()).hexdigest()))
    for chain in sorted(by_chain):
        sys.stdout.write("  %s: %d\n" % (chain, by_chain[chain]))


if __name__ == "__main__":
    main()
