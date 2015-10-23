#!/usr//bin/env python

import argparse
import copy
import re
import iptc
from prometheus_client import core
from prometheus_client import CONTENT_TYPE_LATEST
from prometheus_client import generate_latest
from prometheus_client import Counter
from prometheus_client.exposition import BaseHTTPRequestHandler, HTTPServer


IPTABLES_PACKETS = Counter(
    'iptables_packets',
    'Number of matched packets',
    ['table', 'chain', 'rule'],
)
IPTABLES_BYTES = Counter(
    'iptables_bytes',
    'Number of matched bytes',
    ['table', 'chain', 'rule'],
)
TABLES = dict(
    filter=iptc.Table(iptc.Table.FILTER),
    nat=iptc.Table(iptc.Table.NAT),
    mangle=iptc.Table(iptc.Table.MANGLE),
    raw=iptc.Table(iptc.Table.RAW),
)
RE = re.compile('^iptables-exporter (?P<name>.*)$')


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', CONTENT_TYPE_LATEST)
        self.end_headers()
        collect_metrics()
        self.wfile.write(generate_latest(core.REGISTRY))

    def log_message(self, format, *args):
        return


def collect_metrics():
    data = dict()
    for name, table in TABLES.iteritems():
        labels = dict(table=name)
        for chain in table.chains:
            labels['chain'] = chain.name.lower()
            for rule in chain.rules:
                exporter_name = get_exporter_name(rule)
                if exporter_name:
                    labels['rule'] = exporter_name
                    key = (labels['table'], labels['chain'], labels['rule'])
                    if not key in data:
                        data[key] = dict(labels=copy.copy(labels), packets=0, bytes=0)
                    packets, bytes = rule.get_counters()
                    data[key]['packets'] += packets
                    data[key]['bytes'] += bytes
    for value in data.itervalues():
        labels = value['labels']
        IPTABLES_PACKETS.labels(labels)._value._value = value['packets']
        IPTABLES_BYTES.labels(labels)._value._value = value['bytes']


def get_exporter_name(rule):
    name = None
    for match in rule.matches:
        if 'comment' in match.parameters:
            comment = match.parameters['comment']
            match = RE.match(comment)
            if match:
                return match.groupdict()['name']
    return name


def dump_data():
    collect_metrics()
    print(generate_latest(core.REGISTRY))


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Iptables Prometheus exporter.'
    )
    parser.add_argument(
        '--address', metavar='IP', type=str, default='',
        help='Listening address, default: all'
    )
    parser.add_argument(
        '--port', metavar='PORT', type=int, default=9119,
        help='Listening port, default: 9119'
    )
    parser.add_argument(
        '--dump-data', action='store_true', default=False,
        help='Prints collected data and exits'
    )
    args = parser.parse_args()

    # Test mode
    if args.dump_data:
        dump_data()
        exit(0)

    # Start http server
    httpd = HTTPServer((args.address, args.port), MetricsHandler)
    httpd.serve_forever()
