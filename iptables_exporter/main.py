#!/usr//bin/env python

import argparse
import copy
import re
import iptc
from prometheus_client import core
from prometheus_client import CONTENT_TYPE_LATEST
from prometheus_client import generate_latest
from prometheus_client import Counter, Gauge
from prometheus_client.exposition import BaseHTTPRequestHandler, HTTPServer


IPTABLES_PACKETS = Counter(
    'iptables_packets',
    'Number of matched packets',
    ['ip_version', 'table', 'chain', 'rule'],
)
IPTABLES_BYTES = Counter(
    'iptables_bytes',
    'Number of matched bytes',
    ['ip_version', 'table', 'chain', 'rule'],
)
IPTABLES_RULES = Gauge(
    'iptables_rules',
    'Number of rules',
    ['ip_version', 'table', 'chain'],
)
TABLES = dict(
    filter=iptc.Table.FILTER,
    nat=iptc.Table.NAT,
    mangle=iptc.Table.MANGLE,
    raw=iptc.Table.RAW,
    security=iptc.Table.SECURITY,
)
IP_VERSION_CHOICES = ['4', '6']
TABLE_CHOICES = TABLES.keys()
DEFAULT_TABLE_CHOICES = ['filter']
RE = re.compile('^iptables-exporter (?P<name>.*)$')


class MetricsHandler(BaseHTTPRequestHandler):
    ip_versions = IP_VERSION_CHOICES
    tables = DEFAULT_TABLE_CHOICES

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', CONTENT_TYPE_LATEST)
        self.end_headers()
        collect_metrics(self.ip_versions, self.tables)
        self.wfile.write(generate_latest(core.REGISTRY))


def collect_metrics(ip_versions, tables):
    data = dict()
    for ip_version in ip_versions:
        labels = dict(ip_version=ip_version)
        for name in tables:
            if ip_version == '4':
                table = iptc.Table(TABLES[name])
            else:
                table = iptc.Table6(TABLES[name])
            table.refresh()
            labels['table'] = name
            for chain in table.chains:
                labels['chain'] = chain.name.lower()
                rule_count = 0
                for rule in chain.rules:
                    rule_count += 1
                    exporter_name = get_exporter_name(rule)
                    if exporter_name:
                        labels['rule'] = exporter_name
                        key = (labels['table'], labels['chain'], labels['rule'])
                        if not key in data:
                            data[key] = dict(labels=copy.copy(labels), packets=0, bytes=0)
                        packets, bytes = rule.get_counters()
                        data[key]['packets'] += packets
                        data[key]['bytes'] += bytes
                rules_labels = dict(ip_version=labels['ip_version'], table=labels['table'], chain=labels['chain'])
                IPTABLES_RULES.labels(**rules_labels).set(rule_count)
    for value in data.values():
        labels = value['labels']
        IPTABLES_PACKETS.labels(**labels)._value._value = value['packets']
        IPTABLES_BYTES.labels(**labels)._value._value = value['bytes']


def get_exporter_name(rule):
    name = None
    for match in rule.matches:
        if 'comment' in match.parameters:
            comment = match.parameters['comment']
            match = RE.match(comment)
            if match:
                return match.groupdict()['name']
    return name


def dump_data(ip_versions, tables):
    collect_metrics(ip_versions, tables)
    print(generate_latest(core.REGISTRY).decode('utf8'))


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
        '--ip-versions', metavar='V', type=str, nargs='+',
        choices=IP_VERSION_CHOICES, default=IP_VERSION_CHOICES,
        help='List of IP versions, default: {}'.format(', '.join(IP_VERSION_CHOICES))
    )
    parser.add_argument(
        '--tables', metavar='TABLE', type=str, nargs='+',
        choices=TABLE_CHOICES, default=DEFAULT_TABLE_CHOICES,
        help='List of tables, default: {}'.format(', '.join(DEFAULT_TABLE_CHOICES))
    )
    parser.add_argument(
        '--dump-data', action='store_true', default=False,
        help='Prints collected data and exits'
    )
    args = parser.parse_args()

    # Test mode
    if args.dump_data:
        dump_data(args.ip_versions, args.tables)
        exit(0)

    # Start http server
    httpd = HTTPServer((args.address, args.port), MetricsHandler)
    httpd.RequestHandlerClass.ip_versions = args.ip_versions
    httpd.RequestHandlerClass.tables = args.tables
    httpd.serve_forever()
