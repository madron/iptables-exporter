Iptables exporter
=================

iptables-exporter collects traffic data from iptables rules.


Installation
------------

::

    pip install iptables-exporter


Usage
-----

Test run::

    iptables-exporter --dump-data

Run iptables-exporter::

    iptables-exporter --port 9119

Point your browser to http://localhost:9119/metrics


Configure iptables
------------------

Just add a comment starting with iptables-exporter to your iptables rule::

    iptables -A INPUT --dport ssh -j ACCEPT -m comment --comment "iptables-exporter ssh traffic"

collects packets and bytes counter::

    iptables_packets{table="filter",chain="input",rule="ssh traffic"} 347.0
    iptables_bytes{table="filter",chain="input",rule="ssh traffic"} 44512.0

More rules with same name::

    iptables -A INPUT -s 10.0.0.0/8     --dport ssh -j ACCEPT -m comment --comment "iptables-exporter ssh traffic"
    iptables -A INPUT -s 172.16.0.0/12  --dport ssh -j ACCEPT -m comment --comment "iptables-exporter ssh traffic"
    iptables -A INPUT -s 192.168.0.0/16 --dport ssh -j ACCEPT -m comment --comment "iptables-exporter ssh traffic"

exports only the total of the 3 rules as they have same table, chain and name.
