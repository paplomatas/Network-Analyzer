# network_analyzer/parser/icmp_parser.py
from .protocol_parser import ProtocolParser
import scapy.all as scapy
from network_analyzer.utils.helpers import safe_get

class ICMPParser(ProtocolParser):
    """
    Parser for ICMP protocol packets
    """
    def __init__(self):
        super().__init__()
        self.supported_protocols = ["ICMP"]
    
    def can_parse(self, packet):
        """Check if packet is ICMP"""
        return packet.haslayer(scapy.ICMP)
    
    def parse(self, packet):
        """Parse ICMP packet"""
        icmp_layer = packet.getlayer(scapy.ICMP)
        
        result = {
            'protocol': 'ICMP',
            'timestamp': safe_get(packet, 'time'),
            'src_ip': safe_get(packet, 'src'),
            'dst_ip': safe_get(packet, 'dst'),
            'type': icmp_layer.type if hasattr(icmp_layer, 'type') else None,
            'code': icmp_layer.code if hasattr(icmp_layer, 'code') else None,
            'id': icmp_layer.id if hasattr(icmp_layer, 'id') else None,
            'seq': icmp_layer.seq if hasattr(icmp_layer, 'seq') else None,
            'size': len(packet) if hasattr(packet, '__len__') else 0,
            'payload_size': len(icmp_layer.payload) if hasattr(icmp_layer, 'payload') else 0,
            'problematic': False
        }
        
        # Interpret ICMP type
        if result['type'] == 8:
            result['message'] = 'Echo Request (Ping)'
        elif result['type'] == 0:
            result['message'] = 'Echo Reply (Ping response)'
        elif result['type'] == 3:
            result['message'] = 'Destination Unreachable'
        elif result['type'] == 11:
            result['message'] = 'Time Exceeded'
        
        # Check for suspicious patterns
        
        # Unusually large ICMP packets could be covert channel or data exfiltration
        if result['payload_size'] > 1000:
            result['problematic'] = True
        
        # High volume of ICMP traffic could indicate ping sweep or DoS
        # This would be better tracked in the anomaly detection module
        
        return result