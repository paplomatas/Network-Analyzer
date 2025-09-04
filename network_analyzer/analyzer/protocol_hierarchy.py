# network_analyzer/analyzer/protocol_hierarchy.py
class ProtocolHierarchyAnalyzer:
    
    def __init__(self):
        self.protocol_tree = {
            'Ethernet': {
                'count': 0,
                'bytes': 0,
                'children': {
                    'IPv4': {
                        'count': 0,
                        'bytes': 0,
                        'children': {
                            'TCP': {'count': 0, 'bytes': 0, 'children': {
                                'HTTP': {'count': 0, 'bytes': 0, 'children': {}},
                                'HTTPS': {'count': 0, 'bytes': 0, 'children': {}},
                            }},
                            'UDP': {'count': 0, 'bytes': 0, 'children': {
                                'DNS': {'count': 0, 'bytes': 0, 'children': {}},
                            }},
                            'ICMP': {'count': 0, 'bytes': 0, 'children': {}},
                        }
                    },
                    'ARP': {'count': 0, 'bytes': 0, 'children': {}},
                }
            }
        }
        self.total_packets = 0
        self.total_bytes = 0
    
    def add_packet(self, packet_data):
        """Add a packet to the protocol hierarchy"""
        self.total_packets += 1
        size = packet_data.get('size', 0)
        self.total_bytes += size
        
        # Always increment Ethernet
        self.protocol_tree['Ethernet']['count'] += 1
        self.protocol_tree['Ethernet']['bytes'] += size
        
        # Determine protocol path
        protocol = packet_data.get('protocol', 'Unknown')
        
        if protocol in ['TCP', 'UDP', 'ICMP']:
            # IPv4 -> Protocol
            self.protocol_tree['Ethernet']['children']['IPv4']['count'] += 1
            self.protocol_tree['Ethernet']['children']['IPv4']['bytes'] += size
            
            self.protocol_tree['Ethernet']['children']['IPv4']['children'][protocol]['count'] += 1
            self.protocol_tree['Ethernet']['children']['IPv4']['children'][protocol]['bytes'] += size
            
            # Check for application protocols
            if protocol == 'TCP':
                dst_port = packet_data.get('dst_port', 0)
                if dst_port == 80:
                    self.protocol_tree['Ethernet']['children']['IPv4']['children']['TCP']['children']['HTTP']['count'] += 1
                    self.protocol_tree['Ethernet']['children']['IPv4']['children']['TCP']['children']['HTTP']['bytes'] += size
                elif dst_port == 443:
                    self.protocol_tree['Ethernet']['children']['IPv4']['children']['TCP']['children']['HTTPS']['count'] += 1
                    self.protocol_tree['Ethernet']['children']['IPv4']['children']['TCP']['children']['HTTPS']['bytes'] += size
            
            elif protocol == 'UDP':
                dst_port = packet_data.get('dst_port', 0)
                if dst_port == 53:
                    self.protocol_tree['Ethernet']['children']['IPv4']['children']['UDP']['children']['DNS']['count'] += 1
                    self.protocol_tree['Ethernet']['children']['IPv4']['children']['UDP']['children']['DNS']['bytes'] += size
        
        elif protocol == 'ARP':
            # Ethernet -> ARP
            self.protocol_tree['Ethernet']['children']['ARP']['count'] += 1
            self.protocol_tree['Ethernet']['children']['ARP']['bytes'] += size
    
    def get_hierarchy_data(self):
        """Get protocol hierarchy data in a format suitable for visualization"""
        result = []
        
        def process_node(node, path, level):
            children = []
            for proto, data in node.get('children', {}).items():
                if data['count'] > 0:
                    child_path = f"{path}.{proto}" if path else proto
                    children.append(process_node(data, child_path, level + 1))
            
            count = node.get('count', 0)
            bytes_val = node.get('bytes', 0)
            
            percent_packets = (count / self.total_packets * 100) if self.total_packets > 0 else 0
            percent_bytes = (bytes_val / self.total_bytes * 100) if self.total_bytes > 0 else 0
            
            return {
                'protocol': path.split('.')[-1] if path else '',
                'count': count,
                'bytes': bytes_val,
                'percent_packets': percent_packets,
                'percent_bytes': percent_bytes,
                'children': children,
                'level': level
            }
        
        for proto, data in self.protocol_tree.items():
            if data['count'] > 0:
                result.append(process_node(data, proto, 0))
        
        return result