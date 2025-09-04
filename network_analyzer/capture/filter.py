# network_analyzer/capture/filter.py

import logging
import ipaddress
from typing import Dict, List, Callable, Optional, Union, Any

class PacketFilter:
    """
    Provides filtering capabilities for network packets
    """
    def __init__(self):
        self.filters: Dict[str, Callable[..., bool]] = {}
        self._register_default_filters()
    
    def register_filter(self, name: str, func: Callable[..., bool]):
        """Register a new filter function"""
        self.filters[name] = func

    def _register_default_filters(self):
        """Register built-in filter functions"""
        # Protocol filters
        self.register_filter('tcp', lambda pkt: pkt.get('protocol') == 'TCP')
        self.register_filter('udp', lambda pkt: pkt.get('protocol') == 'UDP')
        self.register_filter('icmp', lambda pkt: pkt.get('protocol') == 'ICMP')
        self.register_filter('dns', lambda pkt: pkt.get('protocol') == 'DNS')
        self.register_filter('http', lambda pkt: pkt.get('protocol') == 'HTTP')
        self.register_filter('https', lambda pkt: pkt.get('protocol') == 'HTTPS' or 
                             (pkt.get('protocol') == 'TCP' and pkt.get('dst_port') == 443))

        # Port filters
        self.register_filter('port', lambda pkt, port: 
                             pkt.get('src_port') == port or pkt.get('dst_port') == port)
        self.register_filter('src_port', lambda pkt, port: pkt.get('src_port') == port)
        self.register_filter('dst_port', lambda pkt, port: pkt.get('dst_port') == port)

        # IP filters
        self.register_filter('ip', lambda pkt, ip: 
                             pkt.get('src_ip') == ip or pkt.get('dst_ip') == ip)
        self.register_filter('src_ip', lambda pkt, ip: pkt.get('src_ip') == ip)
        self.register_filter('dst_ip', lambda pkt, ip: pkt.get('dst_ip') == ip)

        # Subnet filters
        self.register_filter('src_subnet', lambda pkt, subnet: self._ip_in_subnet(pkt.get('src_ip'), subnet))
        self.register_filter('dst_subnet', lambda pkt, subnet: self._ip_in_subnet(pkt.get('dst_ip'), subnet))

        # Size filters (packet 'size', not 'length')
        self.register_filter('size', lambda pkt, size: pkt.get('size') == size)
        self.register_filter('size_gt', lambda pkt, size: pkt.get('size', 0) > size)
        self.register_filter('size_lt', lambda pkt, size: pkt.get('size', 0) < size)
        self.register_filter('size_range', lambda pkt, rng: rng[0] <= pkt.get('size', 0) <= rng[1])

    def _ip_in_subnet(self, ip: Optional[str], subnet: str) -> bool:
        """Check if IP is in a given subnet"""
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet)
        except Exception:
            return False

    def apply_filters(self, packet: Dict[str, Any], rules: List[Union[str, tuple]]) -> bool:
        """
        Apply a list of filters to a packet. 
        Each rule can be a string (like 'tcp') or a tuple ('src_ip', '192.168.0.1')
        """
        for rule in rules:
            if isinstance(rule, str):
                filter_func = self.filters.get(rule)
                if not filter_func:
                    logging.warning(f"Unknown filter: {rule}")
                    return False
                if not filter_func(packet):
                    return False
            elif isinstance(rule, tuple) and len(rule) == 2:
                name, value = rule
                filter_func = self.filters.get(name)
                if not filter_func:
                    logging.warning(f"Unknown filter: {name}")
                    return False
                if not filter_func(packet, value):
                    return False
            else:
                logging.warning(f"Invalid rule format: {rule}")
                return False
        return True
