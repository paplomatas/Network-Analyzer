# network_analyzer/analyzer/protocol_stats.py
from collections import defaultdict, Counter
import time

class ProtocolStatisticsAnalyzer:
    """
    Analyzes protocol usage statistics and patterns
    """
    def __init__(self, time_window=300):  # 5 minute window by default
        self.time_window = time_window
        self.packets_by_protocol = defaultdict(list)
        self.protocol_counts = Counter()
        self.port_usage = defaultdict(Counter)  # protocol -> {port: count}
        self.protocol_bandwidth = defaultdict(int)  # protocol -> bytes
        self.start_time = time.time()
    
    def add_packet(self, packet_data):
        """Add packet to protocol statistics"""
        # Skip packets without protocol info
        if 'protocol' not in packet_data:
            return
        
        protocol = packet_data['protocol']
        timestamp = packet_data.get('timestamp', time.time())
        size = packet_data.get('size', 0)
        
        # Update protocol count
        self.protocol_counts[protocol] += 1
        
        # Update protocol bandwidth
        self.protocol_bandwidth[protocol] += size
        
        # Store packet timestamp for time-based analysis
        self.packets_by_protocol[protocol].append((timestamp, size))
        
        # Update port usage for TCP/UDP packets
        if protocol in ['TCP', 'UDP']:
            src_port = packet_data.get('src_port')
            dst_port = packet_data.get('dst_port')
            
            if src_port:
                self.port_usage[protocol][src_port] += 1
            
            if dst_port:
                self.port_usage[protocol][dst_port] += 1
        
        # Clean old entries outside time window
        self._clean_old_entries()
    
    def _clean_old_entries(self):
        """Remove entries outside the time window"""
        current_time = time.time()
        cutoff_time = current_time - self.time_window
        
        for protocol in self.packets_by_protocol:
            self.packets_by_protocol[protocol] = [
                entry for entry in self.packets_by_protocol[protocol]
                if entry[0] >= cutoff_time
            ]
    
    def get_protocol_distribution(self):
        """Get protocol distribution statistics"""
        total = sum(self.protocol_counts.values())
        if total == 0:
            return {}
        
        return {
            proto: {
                'count': count,
                'percentage': (count / total) * 100
            }
            for proto, count in self.protocol_counts.items()
        }
    
    def get_protocol_bandwidth(self, normalize=False):
        """Get bandwidth usage by protocol"""
        if normalize:
            elapsed_time = time.time() - self.start_time
            return {
                proto: {
                    'total_bytes': bytes_count,
                    'bytes_per_second': bytes_count / elapsed_time
                }
                for proto, bytes_count in self.protocol_bandwidth.items()
            }
        
        return {
            proto: bytes_count
            for proto, bytes_count in self.protocol_bandwidth.items()
        }
    
    def get_top_ports(self, protocol='TCP', limit=10):
        """Get top used ports for a protocol"""
        if protocol not in self.port_usage:
            return {}
        
        return {
            port: count
            for port, count in self.port_usage[protocol].most_common(limit)
        }
    
    def get_protocol_activity_over_time(self, bin_size=60):
        """Get protocol activity over time in bins"""
        results = {}
        
        for protocol in self.packets_by_protocol:
            if not self.packets_by_protocol[protocol]:
                continue
            
            # Get time range
            timestamps = [entry[0] for entry in self.packets_by_protocol[protocol]]
            min_time = min(timestamps)
            max_time = max(timestamps)
            
            # Create time bins
            bins = {}
            for t in range(int(min_time), int(max_time) + bin_size, bin_size):
                bins[t] = {'count': 0, 'bytes': 0}
            
            # Fill bins
            for timestamp, size in self.packets_by_protocol[protocol]:
                bin_key = int(timestamp) - (int(timestamp) % bin_size)
                bins[bin_key]['count'] += 1
                bins[bin_key]['bytes'] += size
            
            results[protocol] = {
                'time_bins': list(bins.keys()),
                'counts': [bins[t]['count'] for t in bins],
                'bytes': [bins[t]['bytes'] for t in bins]
            }
        
        return results