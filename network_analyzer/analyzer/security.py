# network_analyzer/analyzer/security.py
from collections import defaultdict
import time

class SecurityAnalyzer:
    """
    Analyzes packets for security issues and potential attacks
    """
    def __init__(self, scan_threshold=5, time_window=60):
        self.scan_threshold = scan_threshold  # Number of ports/hosts to trigger alert
        self.time_window = time_window        # Time window for detection in seconds
        
        # Tracking data structures
        self.port_scans = defaultdict(list)   # src_ip -> [(timestamp, dst_ip, dst_port), ...]
        self.alerts = []
        self.known_vulnerabilities = {
            80: ["Open HTTP - Consider using HTTPS"],
            21: ["FTP uses cleartext authentication"],
            23: ["Telnet uses cleartext authentication"],
            3389: ["RDP might be exposed - verify if intended"]
        }
    
    def add_packet(self, packet_data):
        """Analyze a packet for security issues"""
        # Skip packets without protocol info
        if 'protocol' not in packet_data:
            return None
        
        alerts = []
        
        # Check if packet is already flagged as problematic
        if packet_data.get('problematic', False):
            alerts.append({
                'type': 'flagged_packet',
                'severity': 6,
                'details': 'Packet flagged as problematic by protocol parser',
                'timestamp': packet_data.get('timestamp', time.time())
            })
        
        # TCP-specific checks
        if packet_data['protocol'] == 'TCP':
            # Check for port scanning
            src_ip = packet_data.get('src_ip')
            dst_ip = packet_data.get('dst_ip')
            dst_port = packet_data.get('dst_port')
            timestamp = packet_data.get('timestamp', time.time())
            
            if src_ip and dst_ip and dst_port is not None:
                # Record connection attempt
                self.port_scans[src_ip].append((timestamp, dst_ip, dst_port))
                
                # Clean old entries outside time window
                cutoff_time = timestamp - self.time_window
                self.port_scans[src_ip] = [
                    entry for entry in self.port_scans[src_ip]
                    if entry[0] >= cutoff_time
                ]
                
                # Check for many connections to different ports on same host
                dst_ports = set()
                current_dst_ip = None
                
                for _, scan_dst_ip, scan_dst_port in self.port_scans[src_ip]:
                    if current_dst_ip is None:
                        current_dst_ip = scan_dst_ip
                    
                    if scan_dst_ip == current_dst_ip:
                        dst_ports.add(scan_dst_port)
                
                if len(dst_ports) >= self.scan_threshold:
                    alerts.append({
                        'type': 'port_scan',
                        'severity': 7,
                        'details': f'Possible port scan: {src_ip} -> {current_dst_ip} ({len(dst_ports)} ports)',
                        'timestamp': timestamp
                    })
            
            # Check for known vulnerable services
            if dst_port in self.known_vulnerabilities:
                alerts.append({
                    'type': 'vulnerable_service',
                    'severity': 5,
                    'details': f'Potentially vulnerable service on port {dst_port}: {self.known_vulnerabilities[dst_port][0]}',
                    'timestamp': packet_data.get('timestamp', time.time())
                })
        
        # Check for HTTP-specific issues
        elif packet_data['protocol'] == 'HTTP':
            # Check for sensitive HTTP methods
            method = packet_data.get('method')
            if method in ['POST', 'PUT', 'DELETE']:
                alerts.append({
                    'type': 'sensitive_http_method',
                    'severity': 5,
                    'details': f'Sensitive HTTP method {method} detected',
                    'timestamp': packet_data.get('timestamp', time.time())
                })
        
        # Check for DNS-specific issues
        elif packet_data['protocol'] == 'DNS':
            query_name = packet_data.get('query_name')
            if query_name and ('exfil' in query_name.lower() or len(query_name) > 50):
                alerts.append({
                    'type': 'dns_exfiltration',
                    'severity': 8,
                    'details': f'Possible DNS exfiltration attempt: {query_name}',
                    'timestamp': packet_data.get('timestamp', time.time())
                })
        
        # Record alerts if any found
        if alerts:
            self.alerts.extend(alerts)
            return alerts
        
        return None
    
    def get_recent_alerts(self, count=10):
        """Get most recent alerts"""
        return sorted(self.alerts, key=lambda x: x.get('timestamp', 0), reverse=True)[:count]