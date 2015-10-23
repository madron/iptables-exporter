#!/usr//bin/env python

import argparse
from prometheus_client import core
from prometheus_client import CONTENT_TYPE_LATEST
from prometheus_client import generate_latest
from prometheus_client import Counter
from prometheus_client.exposition import BaseHTTPRequestHandler, HTTPServer


IPTABLES_PACKETS = Counter(
    'iptables_packets',
    'Number of matched packets',
    ['chain', 'rule_name'],
)
IPTABLES_BYTES = Counter(
    'iptables_bytes',
    'Number of matched bytes',
    ['chain', 'rule_name'],
)


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
    pass


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
        '--port', metavar='PORT', type=int, default=8000,
        help='Listening port, default: 8000'
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
