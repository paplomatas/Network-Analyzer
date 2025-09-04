# network_analyzer/parser/tcp_parser.py
from .protocol_parser import ProtocolParser
import scapy.all as scapy
from network_analyzer.utils.helpers import safe_get

class TCPParser(ProtocolParser):
    """
    Parser for TCP protocol packets
    """
    def __init__(self):
        super().__init__()
        self.supported_protocols = ["TCP"]

    def can_parse(self, packet):
        """Check if packet is TCP"""
        return packet.haslayer(scapy.TCP)

    def parse(self, packet):
        """Parse TCP packet"""
        tcp_layer = packet.getlayer(scapy.TCP)

        result = {
            'protocol': 'TCP',
            'timestamp': safe_get(packet, 'time'),
            'src_ip': safe_get(packet, 'src'),
            'dst_ip': safe_get(packet, 'dst'),
            'src_port': getattr(tcp_layer, 'sport', None),
            'dst_port': getattr(tcp_layer, 'dport', None),
            'seq': tcp_layer.seq if hasattr(tcp_layer, 'seq') else None,
            'ack': tcp_layer.ack if hasattr(tcp_layer, 'ack') else None,
            'flags': {
                'SYN': bool(tcp_layer.flags & 0x02),
                'ACK': bool(tcp_layer.flags & 0x10),
                'FIN': bool(tcp_layer.flags & 0x01),
                'RST': bool(tcp_layer.flags & 0x04),
                'PSH': bool(tcp_layer.flags & 0x08),
                'URG': bool(tcp_layer.flags & 0x20)
            },
            'window': tcp_layer.window if hasattr(tcp_layer, 'window') else None,
            'size': len(packet) if hasattr(packet, '__len__') else 0,
            'problematic': False
        }

        # Check for potential scan patterns (SYN without ACK)
        if result['flags']['SYN'] and not result['flags']['ACK']:
            result['problematic'] = True

        # Check for RST flags which might indicate blocked or rejected connections
        if result['flags']['RST']:
            result['problematic'] = True

        return result
