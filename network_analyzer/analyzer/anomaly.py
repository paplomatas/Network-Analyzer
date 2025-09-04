# network_analyzer/analyzer/anomaly.py
import numpy as np
from scipy import stats
import pandas as pd

class AnomalyDetector:
    """
    Detects anomalies in network traffic
    """
    def __init__(self, window_size=100, z_threshold=3.0):
        self.window_size = window_size
        self.z_threshold = z_threshold
        self.packet_history = []
        self.baseline_established = False
        self.baseline_stats = {}
        self.anomalies = []
    
    def add_packet(self, packet_data):
        """Add a packet and check for anomalies"""
        self.packet_history.append(packet_data)
        
        # Keep history limited to window size
        if len(self.packet_history) > self.window_size:
            self.packet_history.pop(0)
        
        # Establish baseline after collecting enough packets
        if len(self.packet_history) == self.window_size and not self.baseline_established:
            self._establish_baseline()
            self.baseline_established = True
        
        # Check for anomalies if baseline is established
        if self.baseline_established:
            return self._check_anomalies(packet_data)
        
        return None
    
    def _establish_baseline(self):
        """Establish baseline statistics"""
        # Example: calculate baseline for packet sizes
        sizes = [p.get('size', 0) for p in self.packet_history]
        self.baseline_stats['size_mean'] = np.mean(sizes)
        self.baseline_stats['size_std'] = np.std(sizes)
        
        # Calculate protocol distribution
        protocols = [p.get('protocol', 'Unknown') for p in self.packet_history]
        protocol_counts = pd.Series(protocols).value_counts(normalize=True)
        self.baseline_stats['protocol_dist'] = protocol_counts.to_dict()
    
    def _check_anomalies(self, packet_data):
        """Check for anomalies in the current packet"""
        anomalies = []
        
        # Check packet size anomaly
        size = packet_data.get('size', 0)
        size_mean = self.baseline_stats['size_mean']
        size_std = self.baseline_stats['size_std']
        
        if size_std > 0:
            z_score = abs(size - size_mean) / size_std
            if z_score > self.z_threshold:
                anomalies.append({
                    'type': 'size_anomaly',
                    'severity': min(10, int(z_score)),
                    'details': f'Packet size {size} is {z_score:.2f} standard deviations from mean'
                })
        
        # Check protocol anomaly
        protocol = packet_data.get('protocol', 'Unknown')
        if protocol not in self.baseline_stats['protocol_dist'] or \
           self.baseline_stats['protocol_dist'][protocol] < 0.01:
            anomalies.append({
                'type': 'protocol_anomaly',
                'severity': 7,
                'details': f'Unusual protocol {protocol} detected'
            })
        
        # Check for other security issues
        if packet_data.get('problematic', False):
            anomalies.append({
                'type': 'security_issue',
                'severity': 8,
                'details': f'Potentially problematic packet detected'
            })
        
        if anomalies:
            self.anomalies.append({
                'timestamp': packet_data.get('timestamp'),
                'issues': anomalies,
                'packet_data': packet_data
            })
            return anomalies
        
        return None