# network_analyzer/export/exporters.py
class ExportManager:
    """Manage various export formats for network data"""
    
    def export_to_pcap(self, packets, filename):
        """Export packets to PCAP format"""
        from network_analyzer.capture.pcap_handler import PCAPHandler
        handler = PCAPHandler()
        return handler.export_pcap(packets, filename)
    
    def export_to_csv(self, packets, filename):
        """Export packet data to CSV format"""
        import csv
        
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 
                          'src_port', 'dst_port', 'size', 'info']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for packet in packets:
                # Prepare row data
                row = {
                    'timestamp': packet.get('timestamp', ''),
                    'src_ip': packet.get('src_ip', ''),
                    'dst_ip': packet.get('dst_ip', ''),
                    'protocol': packet.get('protocol', ''),
                    'src_port': packet.get('src_port', ''),
                    'dst_port': packet.get('dst_port', ''),
                    'size': packet.get('size', ''),
                    'info': self._generate_info_string(packet)
                }
                writer.writerow(row)
        
        return filename
    
    def export_to_json(self, packets, filename):
        """Export packet data to JSON format"""
        import json
        
        # Clean up packets for JSON serialization
        clean_packets = []
        for packet in packets:
            clean_packet = {}
            for key, value in packet.items():
                if isinstance(value, (str, int, float, list, dict, bool, type(None))):
                    clean_packet[key] = value
            clean_packets.append(clean_packet)
        
        with open(filename, 'w') as jsonfile:
            json.dump(clean_packets, jsonfile, indent=2)
        
        return filename
    
    def _generate_info_string(self, packet):
        """Generate an info string similar to Wireshark"""
        protocol = packet.get('protocol', '')
        
        if protocol == 'TCP':
            flags = []
            if packet.get('flags'):
                for flag, value in packet['flags'].items():
                    if value:
                        flags.append(flag)
            
            return f"TCP {packet.get('src_port', '')} → {packet.get('dst_port', '')} [{', '.join(flags)}]"
        
        elif protocol == 'UDP':
            return f"UDP {packet.get('src_port', '')} → {packet.get('dst_port', '')}"
        
        elif protocol == 'ICMP':
            return f"ICMP {packet.get('type', '')} {packet.get('code', '')}"
        
        elif protocol == 'HTTP':
            return f"HTTP {packet.get('method', '')} {packet.get('path', '')}"
        
        elif protocol == 'DNS':
            return f"DNS {'Query' if packet.get('is_query') else 'Response'}: {packet.get('query_name', '')}"
        
        return ""