# network_analyzer/parser/arp_parser.py
from .protocol_parser import ProtocolParser
import scapy.all as scapy
from network_analyzer.utils.helpers import safe_get

class ARPParser(ProtocolParser):
    """
    Parser for ARP protocol packets
    """
    def __init__(self):
        super().__init__()
        self.supported_protocols = ["ARP"]
        self.mac_ip_pairs = {}  # Keep track of MAC-IP bindings
    
    def can_parse(self, packet):
        """Check if packet is ARP"""
        return packet.haslayer(scapy.ARP)
    
    def parse(self, packet):
        """Parse ARP packet"""
        arp_layer = packet.getlayer(scapy.ARP)
        
        result = {
            'protocol': 'ARP',
            'timestamp': safe_get(packet, 'time'),
            'op': arp_layer.op,  # 1=request, 2=reply
            'hwsrc': arp_layer.hwsrc,  # Sender MAC
            'hwdst': arp_layer.hwdst,  # Target MAC
            'psrc': arp_layer.psrc,    # Sender IP
            'pdst': arp_layer.pdst,    # Target IP
            'size': len(packet) if hasattr(packet, '__len__') else 0,
            'is_request': arp_layer.op == 1,
            'is_reply': arp_layer.op == 2,
            'problematic': False
        }
        
        # Check for potential ARP spoofing
        if result['is_reply']:
            # If we've seen this IP with a different MAC before
            if result['psrc'] in self.mac_ip_pairs and self.mac_ip_pairs[result['psrc']] != result['hwsrc']:
                result['problematic'] = True
                result['spoofing_details'] = {
                    'previous_mac': self.mac_ip_pairs[result['psrc']],
                    'new_mac': result['hwsrc'],
                    'ip': result['psrc']
                }
            
            # Update MAC-IP mapping
            self.mac_ip_pairs[result['psrc']] = result['hwsrc']
        
        return result