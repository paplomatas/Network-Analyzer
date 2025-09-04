# network_analyzer/analyzer/endpoint_stats.py
class EndpointStatistics:
    
    def __init__(self):
        self.endpoints = {}  # IP -> stats
        self.conversations = {}  # (IP1, IP2) -> stats
    
    def add_packet(self, packet_data):
        """Process a packet for endpoint statistics"""
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        size = packet_data.get('size', 0)
        timestamp = packet_data.get('timestamp', 0)
        
        if not src_ip or not dst_ip:
            return
        
        # Update source endpoint
        if src_ip not in self.endpoints:
            self.endpoints[src_ip] = {
                'packets_sent': 0,
                'packets_received': 0,
                'bytes_sent': 0,
                'bytes_received': 0,
                'first_seen': timestamp,
                'last_seen': timestamp
            }
        
        self.endpoints[src_ip]['packets_sent'] += 1
        self.endpoints[src_ip]['bytes_sent'] += size
        self.endpoints[src_ip]['last_seen'] = max(self.endpoints[src_ip]['last_seen'], timestamp)
        
        # Update destination endpoint
        if dst_ip not in self.endpoints:
            self.endpoints[dst_ip] = {
                'packets_sent': 0,
                'packets_received': 0,
                'bytes_sent': 0,
                'bytes_received': 0,
                'first_seen': timestamp,
                'last_seen': timestamp
            }
        
        self.endpoints[dst_ip]['packets_received'] += 1
        self.endpoints[dst_ip]['bytes_received'] += size
        self.endpoints[dst_ip]['last_seen'] = max(self.endpoints[dst_ip]['last_seen'], timestamp)
        
        # Update conversation
        conv_key = tuple(sorted([src_ip, dst_ip]))
        if conv_key not in self.conversations:
            self.conversations[conv_key] = {
                'packets': 0,
                'bytes': 0,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'a_to_b_packets': 0,
                'b_to_a_packets': 0,
                'a_to_b_bytes': 0,
                'b_to_a_bytes': 0
            }
        
        self.conversations[conv_key]['packets'] += 1
        self.conversations[conv_key]['bytes'] += size
        self.conversations[conv_key]['last_seen'] = max(
            self.conversations[conv_key]['last_seen'], timestamp)
        
        # Track direction
        if src_ip == conv_key[0]:
            self.conversations[conv_key]['a_to_b_packets'] += 1
            self.conversations[conv_key]['a_to_b_bytes'] += size
        else:
            self.conversations[conv_key]['b_to_a_packets'] += 1
            self.conversations[conv_key]['b_to_a_bytes'] += size
    
    def get_top_endpoints(self, by='packets_total', limit=10):
        """Get top endpoints by specified metric"""
        result = []
        
        for ip, stats in self.endpoints.items():
            # Calculate totals
            packets_total = stats['packets_sent'] + stats['packets_received']
            bytes_total = stats['bytes_sent'] + stats['bytes_received']
            
            endpoint_data = {
                'ip': ip,
                'packets_sent': stats['packets_sent'],
                'packets_received': stats['packets_received'],
                'packets_total': packets_total,
                'bytes_sent': stats['bytes_sent'],
                'bytes_received': stats['bytes_received'],
                'bytes_total': bytes_total,
                'first_seen': stats['first_seen'],
                'last_seen': stats['last_seen'],
                'duration': stats['last_seen'] - stats['first_seen']
            }
            
            result.append(endpoint_data)
        
        # Sort by the specified metric
        result.sort(key=lambda x: x[by], reverse=True)
        
        return result[:limit]
    
    def get_top_conversations(self, by='packets', limit=10):
        """Get top conversations by specified metric"""
        result = []
        
        for ips, stats in self.conversations.items():
            conversation_data = {
                'ip_a': ips[0],
                'ip_b': ips[1],
                'packets': stats['packets'],
                'bytes': stats['bytes'],
                'a_to_b_packets': stats['a_to_b_packets'],
                'b_to_a_packets': stats['b_to_a_packets'],
                'a_to_b_bytes': stats['a_to_b_bytes'],
                'b_to_a_bytes': stats['b_to_a_bytes'],
                'first_seen': stats['first_seen'],
                'last_seen': stats['last_seen'],
                'duration': stats['last_seen'] - stats['first_seen']
            }
            
            result.append(conversation_data)
        
        # Sort by the specified metric
        result.sort(key=lambda x: x[by], reverse=True)
        
        return result[:limit]