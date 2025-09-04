# network_analyzer/analyzer/flow.py
from collections import defaultdict
import time
import logging
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

class NetworkFlow:
    """Represents a network flow (connection)"""
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = time.time()
        self.last_time = self.start_time
        self.packet_count = 0
        self.byte_count = 0
        self.forward_packets = 0  # Source to destination
        self.backward_packets = 0  # Destination to source
        self.forward_bytes = 0
        self.backward_bytes = 0
        self.active = True
        self.tcp_flags = set()  # Track all observed TCP flags
    
    def add_packet(self, packet_data):
        """Add a packet to this flow"""
        self.packet_count += 1
        self.last_time = packet_data.get('timestamp', time.time())
        size = packet_data.get('size', 0)
        self.byte_count += size
        
        # Determine direction
        if (packet_data.get('src_ip') == self.src_ip and 
            packet_data.get('dst_ip') == self.dst_ip and
            packet_data.get('src_port') == self.src_port and
            packet_data.get('dst_port') == self.dst_port):
            # Forward direction
            self.forward_packets += 1
            self.forward_bytes += size
        else:
            # Backward direction
            self.backward_packets += 1
            self.backward_bytes += size
        
        # Track TCP flags if present
        if packet_data.get('protocol') == 'TCP' and 'flags' in packet_data:
            for flag, value in packet_data['flags'].items():
                if value:
                    self.tcp_flags.add(flag)
    
    def get_duration(self):
        """Get flow duration in seconds"""
        return self.last_time - self.start_time
    
    def is_long_flow(self, threshold=60):
        """Check if flow duration exceeds threshold"""
        return self.get_duration() > threshold
    
    def is_expired(self, timeout=300):
        """Check if flow has expired based on timeout"""
        return (time.time() - self.last_time) > timeout
    
    def is_idle(self, idle_threshold=30):
        """Check if flow is idle"""
        return (time.time() - self.last_time) > idle_threshold
    
    def get_flow_type(self):
        """Determine flow type based on characteristics"""
        if 'SYN' in self.tcp_flags and 'ACK' in self.tcp_flags:
            if self.packet_count > 10:
                return "ESTABLISHED_CONNECTION"
            return "SHORT_CONNECTION"
        
        if 'SYN' in self.tcp_flags and self.packet_count <= 3:
            return "SCAN"
        
        if self.protocol == 'ICMP':
            return "ICMP"
        
        if self.protocol == 'UDP':
            if self.dst_port == 53 or self.src_port == 53:
                return "DNS"
            return "UDP"
        
        return "OTHER"
    
    def to_dict(self):
        """Convert flow to dictionary representation"""
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'start_time': self.start_time,
            'last_time': self.last_time,
            'duration': self.get_duration(),
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'forward_packets': self.forward_packets,
            'backward_packets': self.backward_packets,
            'forward_bytes': self.forward_bytes,
            'backward_bytes': self.backward_bytes,
            'tcp_flags': list(self.tcp_flags),
            'flow_type': self.get_flow_type(),
            'active': self.active
        }


class FlowAnalyzer:
    """
    Analyzes network traffic at the flow level (similar to NetFlow/IPFIX)
    """
    def __init__(self, flow_timeout=300, active_timeout=1800):
        self.flow_timeout = flow_timeout      # Idle timeout in seconds
        self.active_timeout = active_timeout  # Max flow duration before forcing termination
        self.active_flows = {}               # Key: flow tuple, Value: NetworkFlow object
        self.completed_flows = []             # List of completed flows
        self.flow_stats = {
            'total_created': 0,
            'total_completed': 0,
            'active_count': 0
        }
    
    def _get_flow_key(self, packet_data):
        """Generate a unique key for a flow based on 5-tuple"""
        protocol = packet_data.get('protocol', 'UNKNOWN')
        
        # For TCP/UDP, use 5-tuple
        if protocol in ['TCP', 'UDP']:
            src_ip = packet_data.get('src_ip', '0.0.0.0')
            dst_ip = packet_data.get('dst_ip', '0.0.0.0')
            src_port = packet_data.get('src_port', 0)
            dst_port = packet_data.get('dst_port', 0)
            
            # Always order the tuple so src has lower IP/port for consistent keying
            if src_ip > dst_ip or (src_ip == dst_ip and src_port > dst_port):
                return (dst_ip, src_ip, dst_port, src_port, protocol)
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        
        # For ICMP, use 3-tuple (src IP, dst IP, protocol)
        elif protocol == 'ICMP':
            src_ip = packet_data.get('src_ip', '0.0.0.0')
            dst_ip = packet_data.get('dst_ip', '0.0.0.0')
            
            if src_ip > dst_ip:
                return (dst_ip, src_ip, 0, 0, protocol)
            return (src_ip, dst_ip, 0, 0, protocol)
        
        # Default case - just use available fields
        return (
            packet_data.get('src_ip', '0.0.0.0'),
            packet_data.get('dst_ip', '0.0.0.0'),
            packet_data.get('src_port', 0),
            packet_data.get('dst_port', 0),
            protocol
        )
    
    def add_packet(self, packet_data):
        """Process a packet and update flow information"""
        # Skip packets without required fields
        if not packet_data.get('protocol'):
            return
        
        # Check if packet belongs to an existing flow
        flow_key = self._get_flow_key(packet_data)
        
        if flow_key in self.active_flows:
            # Add packet to existing flow
            self.active_flows[flow_key].add_packet(packet_data)
            
            # Check if flow should be terminated due to max duration
            if (self.active_flows[flow_key].get_duration() > self.active_timeout or
                ('FIN' in self.active_flows[flow_key].tcp_flags and 'ACK' in self.active_flows[flow_key].tcp_flags) or
                'RST' in self.active_flows[flow_key].tcp_flags):
                self._complete_flow(flow_key)
        else:
            # Create a new flow
            src_ip, dst_ip, src_port, dst_port, protocol = flow_key
            new_flow = NetworkFlow(src_ip, dst_ip, src_port, dst_port, protocol)
            new_flow.add_packet(packet_data)
            self.active_flows[flow_key] = new_flow
            self.flow_stats['total_created'] += 1
            self.flow_stats['active_count'] += 1
        
        # Clean up expired flows
        self._cleanup_expired_flows()
    
    def _cleanup_expired_flows(self):
        """Remove expired flows"""
        expired_keys = []
        current_time = time.time()
        
        for key, flow in self.active_flows.items():
            if current_time - flow.last_time > self.flow_timeout:
                expired_keys.append(key)
        
        for key in expired_keys:
            self._complete_flow(key)
    
    def _complete_flow(self, flow_key):
        """Mark a flow as completed and move it to the history"""
        if flow_key in self.active_flows:
            flow = self.active_flows[flow_key]
            flow.active = False
            self.completed_flows.append(flow.to_dict())
            del self.active_flows[flow_key]
            self.flow_stats['total_completed'] += 1
            self.flow_stats['active_count'] -= 1
    
    def get_active_flows(self, limit=50, sort_by='last_time', descending=True):
        """Get active flows (optionally sorted)"""
        flows = [flow.to_dict() for flow in self.active_flows.values()]
        
        if sort_by:
            flows.sort(key=lambda x: x.get(sort_by, 0), reverse=descending)
        
        return flows[:limit]
    
    def get_completed_flows(self, limit=50, sort_by='last_time', descending=True):
        """Get completed flows (optionally sorted)"""
        flows = self.completed_flows.copy()
        
        if sort_by:
            flows.sort(key=lambda x: x.get(sort_by, 0), reverse=descending)
        
        return flows[:limit]
    
    def get_all_flows(self, limit=100, sort_by='last_time', descending=True):
        """Get all flows (active and completed)"""
        active = [flow.to_dict() for flow in self.active_flows.values()]
        all_flows = active + self.completed_flows
        
        if sort_by:
            all_flows.sort(key=lambda x: x.get(sort_by, 0), reverse=descending)
        
        return all_flows[:limit]
    
    def get_flow_stats(self):
        """Get summary statistics about flows"""
        stats = self.flow_stats.copy()
        
        # Add derived stats
        active_flows = [flow.to_dict() for flow in self.active_flows.values()]
        
        # Count flows by protocol
        protocol_counts = defaultdict(int)
        for flow in active_flows:
            protocol_counts[flow['protocol']] += 1
        
        # Count flows by type
        flow_types = defaultdict(int)
        for flow in active_flows:
            flow_types[flow['flow_type']] += 1
        
        stats['protocols'] = dict(protocol_counts)
        stats['flow_types'] = dict(flow_types)
        
        return stats
    
    def get_top_talkers(self, n=10):
        """Get top n IP addresses by flow count"""
        sources = defaultdict(int)
        destinations = defaultdict(int)
        
        # Add active flows
        for flow in self.active_flows.values():
            sources[flow.src_ip] += 1
            destinations[flow.dst_ip] += 1
        
        # Add completed flows
        for flow in self.completed_flows:
            sources[flow['src_ip']] += 1
            destinations[flow['dst_ip']] += 1
        
        return {
            'sources': dict(sorted(sources.items(), key=lambda x: x[1], reverse=True)[:n]),
            'destinations': dict(sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:n])
        }
    
    def get_flow_duration_stats(self):
        """Get statistics about flow durations"""
        durations = []
        
        # Add active flows
        for flow in self.active_flows.values():
            durations.append(flow.get_duration())
        
        # Add completed flows
        for flow in self.completed_flows:
            durations.append(flow['duration'])
        
        if not durations:
            return {
                'min': 0,
                'max': 0,
                'mean': 0,
                'median': 0
            }
        
        return {
            'min': min(durations),
            'max': max(durations),
            'mean': sum(durations) / len(durations),
            'median': sorted(durations)[len(durations) // 2]
        }

    def get_flow_data_for_graph(self):
        """Get flow data in a format suitable for network visualization"""
        nodes = set()
        edges = []
        
        # Process active flows
        for flow in self.active_flows.values():
            src = flow.src_ip
            dst = flow.dst_ip
            nodes.add(src)
            nodes.add(dst)
            
            # Add edge with data
            edges.append({
                'from': src,
                'to': dst,
                'protocol': flow.protocol,
                'packets': flow.packet_count,
                'bytes': flow.byte_count,
                'active': True,
                'port': f"{flow.src_port}->{flow.dst_port}"
            })
        
        # Process recent completed flows (limit to top 50 most recent)
        recent_completed = sorted(
            self.completed_flows, 
            key=lambda x: x['last_time'], 
            reverse=True
        )[:50]
        
        for flow in recent_completed:
            src = flow['src_ip']
            dst = flow['dst_ip']
            nodes.add(src)
            nodes.add(dst)
            
            # Add edge with data
            edges.append({
                'from': src,
                'to': dst,
                'protocol': flow['protocol'],
                'packets': flow['packet_count'],
                'bytes': flow['byte_count'],
                'active': False,
                'port': f"{flow['src_port']}->{flow['dst_port']}"
            })
        
        # Convert nodes to expected format
        node_list = [{'id': node, 'label': node} for node in nodes]
        
        return {
            'nodes': node_list,
            'edges': edges
        }