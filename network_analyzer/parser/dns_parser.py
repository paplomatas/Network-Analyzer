# network_analyzer/parser/dns_parser.py
from .protocol_parser import ProtocolParser
import scapy.all as scapy
from network_analyzer.utils.helpers import safe_get

class DNSParser(ProtocolParser):
    """
    Parser for DNS protocol packets
    """
    def __init__(self):
        super().__init__()
        self.supported_protocols = ["DNS"]
        self.suspicious_domains = [
            "exfil", "malware", "command", "c2", "phish", 
            "ransomware", "trojan", "botnet"
        ]
    
    def can_parse(self, packet):
        """Check if packet is DNS"""
        return packet.haslayer(scapy.DNS)
    
    def parse(self, packet):
        """Parse DNS packet"""
        dns_layer = packet.getlayer(scapy.DNS)
        
        result = {
            'protocol': 'DNS',
            'timestamp': safe_get(packet, 'time'),
            'src_ip': safe_get(packet, 'src'),
            'dst_ip': safe_get(packet, 'dst'),
            'id': dns_layer.id if hasattr(dns_layer, 'id') else None,
            'qr': dns_layer.qr if hasattr(dns_layer, 'qr') else None,  # 0 for query, 1 for response
            'opcode': dns_layer.opcode if hasattr(dns_layer, 'opcode') else None,
            'size': len(packet) if hasattr(packet, '__len__') else 0,
            'query_type': None,
            'query_name': None,
            'answer_rrs': [],
            'is_query': False,
            'is_response': False,
            'problematic': False
        }
        
        # Query details
        if dns_layer.qr == 0:  # Query
            result['is_query'] = True
            if dns_layer.qd:
                qd = dns_layer.qd
                result['query_type'] = qd.qtype
                result['query_name'] = qd.qname.decode() if hasattr(qd, 'qname') else None
                
                # Check for suspiciously long domain names (potential exfiltration)
                if result['query_name'] and len(result['query_name']) > 50:
                    result['problematic'] = True
                
                # Check for suspicious keywords in domain
                if result['query_name']:
                    for keyword in self.suspicious_domains:
                        if keyword in result['query_name'].lower():
                            result['problematic'] = True
                            break
        
        # Response details
        elif dns_layer.qr == 1:  # Response
            result['is_response'] = True
            if dns_layer.an:
                for i in range(dns_layer.ancount):
                    an = dns_layer.an[i]
                    answer = {
                        'name': an.rrname.decode() if hasattr(an, 'rrname') else None,
                        'type': an.type,
                        'ttl': an.ttl,
                        'data': None
                    }
                    
                    # Extract different data based on record type
                    if an.type == 1:  # A Record
                        answer['data'] = an.rdata
                    elif an.type == 5:  # CNAME
                        answer['data'] = an.cname.decode() if hasattr(an, 'cname') else None
                    elif an.type == 15:  # MX
                        answer['data'] = an.exchange.decode() if hasattr(an, 'exchange') else None
                    
                    result['answer_rrs'].append(answer)
        
        return result