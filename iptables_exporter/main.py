#!/usr//bin/env python

import argparse
import copy
import re
import iptc
from prometheus_client import generate_latest
from prometheus_client import make_wsgi_app
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY
from wsgiref.simple_server import make_server


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


class IptablesCollector(object):
    def __init__(self, ip_versions=IP_VERSION_CHOICES, tables=DEFAULT_TABLE_CHOICES):
        self.ip_versions = ip_versions
        self.tables = tables

    def collect(self):
        # Metrics
        iptables_rules = GaugeMetricFamily(
            'iptables_rules',
            'Number of rules',
            labels=['ip_version', 'table', 'chain'],
        )
        iptables_packets = CounterMetricFamily(
            'iptables_packets',
            'Number of matched packets',
            labels=['ip_version', 'table', 'chain', 'rule'],
        )
        iptables_bytes = CounterMetricFamily(
            'iptables_bytes',
            'Number of matched bytes',
            labels=['ip_version', 'table', 'chain', 'rule'],
        )
        for ip_version in self.ip_versions:
            labels = dict(ip_version=ip_version)
            for table_name in self.tables:
                if ip_version == '4':
                    table = iptc.Table(TABLES[table_name])
                else:
                    table = iptc.Table6(TABLES[table_name])
                table.refresh()
                labels['table'] = table_name
                for chain in table.chains:
                    labels['chain'] = chain.name.lower()
                    rule_count = 0
                    for rule in chain.rules:
                        rule_count += 1
                        exporter_name = get_exporter_name(rule)
                        if exporter_name:
                            labels['rule'] = exporter_name
                            counter_labels = [labels['ip_version'], labels['table'], labels['chain'], labels['rule']]
                            packets, bytes = rule.get_counters()
                            iptables_packets.add_metric(counter_labels, packets)
                            iptables_bytes.add_metric(counter_labels, bytes)
                    rules_labels = [labels['ip_version'], labels['table'], labels['chain']]
                    iptables_rules.add_metric(rules_labels, rule_count)
        yield iptables_rules
        yield iptables_packets
        yield iptables_bytes


def get_exporter_name(rule):
    name = None
    for match in rule.matches:
        if 'comment' in match.parameters:
            comment = match.parameters['comment']
            match = RE.match(comment)
            if match:
                return match.groupdict()['name']
    return name


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

    REGISTRY.register(IptablesCollector(ip_versions=args.ip_versions, tables=args.tables))

    # Test mode
    if args.dump_data:
        print(generate_latest(REGISTRY).decode('utf8'))
        exit(0)

    # Start http server
    app = make_wsgi_app()
    httpd = make_server(args.address, args.port, app)
    httpd.serve_forever()
