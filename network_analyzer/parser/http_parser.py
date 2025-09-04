# network_analyzer/parser/http_parser.py

from .protocol_parser import ProtocolParser
import scapy.all as scapy
from network_analyzer.utils.helpers import safe_get

class HTTPParser(ProtocolParser):
    """
    Parser for HTTP protocol packets
    """
    def __init__(self):
        super().__init__()
        self.supported_protocols = ["HTTP"]

    def can_parse(self, packet):
        return packet.haslayer(scapy.TCP) and (packet.dport == 80 or packet.sport == 80)

    def parse(self, packet):
        result = {
            'protocol': 'HTTP',
            'timestamp': safe_get(packet, 'time'),
            'src_ip': safe_get(packet, 'src'),
            'dst_ip': safe_get(packet, 'dst'),
            'src_port': safe_get(packet, 'sport'),
            'dst_port': safe_get(packet, 'dport'),
            'method': None,
            'host': None,
            'path': None,
            'problematic': False,
            'size': len(packet)
        }

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            try:
                lines = payload.decode(errors='ignore').split("\r\n")
                if lines:
                    request_line = lines[0].split()
                    if len(request_line) >= 2:
                        result['method'] = request_line[0]
                        result['path'] = request_line[1]
                        result['problematic'] = result['method'] in ['POST', 'PUT', 'DELETE']

                for line in lines:
                    if line.lower().startswith('host:'):
                        result['host'] = line.split(':', 1)[1].strip()
                        break
            except Exception:
                pass

        return result
