import pandas as pd
import numpy as np
from collections import defaultdict
import time
import logging

logger = logging.getLogger(__name__)

class TrafficAnalyzer:
    """
    Analyzes network traffic patterns
    """
    def __init__(self, max_history=1000):
        self.protocol_counts = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.destination_ips = defaultdict(int)
        self.connections = defaultdict(int)
        self.packet_sizes = []
        self.timestamps = []
        self.max_history = max_history
        self.packets_processed = 0
        self.start_time = time.time()
        
    def add_packet(self, packet_data):
        """Add a packet to the analysis"""
        self.packets_processed += 1
        
        # Extract relevant data
        protocol = packet_data.get('protocol', 'Unknown')
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        size = packet_data.get('size', 0)
        timestamp = packet_data.get('timestamp')
        
        # If timestamp is missing, use current time
        if timestamp is None:
            timestamp = time.time()
        
        # Update statistics
        self.protocol_counts[protocol] += 1
        
        if src_ip:
            self.source_ips[src_ip] += 1
        
        if dst_ip:
            self.destination_ips[dst_ip] += 1
        
        if src_ip and dst_ip:
            self.connections[(src_ip, dst_ip)] += 1
        
        if size:
            self.packet_sizes.append(size)
            # Keep packet sizes history within limits
            if len(self.packet_sizes) > self.max_history:
                self.packet_sizes.pop(0)
        
        if timestamp:
            self.timestamps.append(timestamp)
            # Keep timestamp history within limits
            if len(self.timestamps) > self.max_history:
                self.timestamps.pop(0)
        
        # Log processing statistics periodically
        if self.packets_processed % 500 == 0:
            elapsed = time.time() - self.start_time
            rate = self.packets_processed / elapsed if elapsed > 0 else 0
            logger.debug(f"Traffic analyzer has processed {self.packets_processed} packets ({rate:.2f} packets/sec)")
    
    def get_protocol_distribution(self):
        """Get protocol distribution statistics"""
        total = sum(self.protocol_counts.values())
        if total == 0:
            return {}
        return {proto: (count, count/total*100) for proto, count in self.protocol_counts.items()}
    
    def get_top_talkers(self, n=10):
        """Get top n IP addresses by packet count"""
        return {
            'sources': dict(sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)[:n]),
            'destinations': dict(sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True)[:n])
        }
    
    def get_traffic_over_time(self, bin_size=60):
        """Get traffic volume over time, binned by bin_size seconds"""
        if not self.timestamps:
            return {}
        
        # Convert any EDecimal timestamps to float
        timestamp_floats = []
        for ts in self.timestamps:
            try:
                # Handle both float and EDecimal timestamps
                timestamp_floats.append(float(ts))
            except (ValueError, TypeError):
                # Skip invalid timestamps
                pass
        
        if not timestamp_floats:
            return {}
        
        df = pd.DataFrame({'timestamp': timestamp_floats})
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
        df = df.set_index('timestamp')
        traffic = df.resample(f'{bin_size}S').size()
        
        return {
            'times': [t.timestamp() for t in traffic.index],
            'counts': traffic.values.tolist()
        }