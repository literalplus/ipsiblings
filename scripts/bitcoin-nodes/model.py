#!/usr/bin/env python3
import ipaddress


class Node:
    def __init__(self, addr, raw):
        self.addr = addr
        (self.ip, _, self.port) = addr.rpartition(':')
        self.ip = self.ip.replace("[", "").replace("]", "")
        self.is_onion = self.ip.endswith(".onion")
        self.raw = raw
        self.protocol_version = raw[0]
        self.user_agent = raw[1]
        self.hostname = raw[5]
        self.location = (raw[7], raw[6]) # country, city
        self.timezone = raw[10]
        self.asn = raw[11]
        self.asn_name = raw[12]

    def __str__(self):
        return f"Node({self.ip} at {self.hostname}, from {self.raw})"

    def __repr__(self):
        return str(self)


def is_ds_node_set(nodes):
    if len(nodes) <= 1:
        return False
    non_onions = [n for n in nodes if not n.is_onion]
    ips = [ipaddress.ip_address(n.ip) for n in non_onions]
    versions = set([addr.version for addr in ips])
    return len(versions) > 1