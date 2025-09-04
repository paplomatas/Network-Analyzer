# network_analyzer/visualizer/reports.py
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64
from datetime import datetime
import jinja2

class ReportGenerator:
    """
    Generates reports based on network analysis data
    """
    def __init__(self):
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader('templates')
        )
    
    def generate_traffic_report(self, traffic_analyzer, security_analyzer, 
                               anomaly_detector, protocol_stats, report_title="Network Traffic Report"):
        """Generate a comprehensive traffic report"""
        # Prepare report data
        report_data = {
            'title': report_title,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': self._generate_summary(traffic_analyzer, security_analyzer, anomaly_detector),
            'protocol_data': self._generate_protocol_data(protocol_stats),
            'security_data': self._generate_security_data(security_analyzer),
            'anomaly_data': self._generate_anomaly_data(anomaly_detector),
            'charts': self._generate_charts(traffic_analyzer, protocol_stats)
        }
        
        # Render report template
        template = self.template_env.get_template('traffic_report.html')
        return template.render(**report_data)
    
    def _generate_summary(self, traffic_analyzer, security_analyzer, anomaly_detector):
        """Generate summary statistics for the report"""
        # Top talkers
        top_talkers = traffic_analyzer.get_top_talkers(5)
        
        # Alert counts
        security_alert_count = len(security_analyzer.alerts) if hasattr(security_analyzer, 'alerts') else 0
        anomaly_alert_count = len(anomaly_detector.anomalies) if hasattr(anomaly_detector, 'anomalies') else 0
        
        return {
            'total_packets': sum(traffic_analyzer.protocol_counts.values()),
            'top_source_ips': top_talkers['sources'],
            'top_destination_ips': top_talkers['destinations'],
            'security_alerts': security_alert_count,
            'anomaly_alerts': anomaly_alert_count
        }
    
    def _generate_protocol_data(self, protocol_stats):
        """Generate protocol statistics for the report"""
        protocol_dist = protocol_stats.get_protocol_distribution()
        bandwidth_data = protocol_stats.get_protocol_bandwidth(normalize=True)
        
        top_tcp_ports = protocol_stats.get_top_ports('TCP', 5)
        top_udp_ports = protocol_stats.get_top_ports('UDP', 5)
        
        return {
            'distribution': protocol_dist,
            'bandwidth': bandwidth_data,
            'top_tcp_ports': top_tcp_ports,
            'top_udp_ports': top_udp_ports
        }
    
    def _generate_security_data(self, security_analyzer):
        """Generate security information for the report"""
        return {
            'recent_alerts': security_analyzer.get_recent_alerts(10)
        }
    
    def _generate_anomaly_data(self, anomaly_detector):
        """Generate anomaly information for the report"""
        # Sort anomalies by timestamp (newest first)
        sorted_anomalies = sorted(
            anomaly_detector.anomalies, 
            key=lambda x: x.get('timestamp', 0), 
            reverse=True
        )[:10]
        
        return {
            'recent_anomalies': sorted_anomalies
        }
    
    def _generate_charts(self, traffic_analyzer, protocol_stats):
        """Generate charts for the report"""
        charts = {}
        
        # Traffic over time chart
        traffic_data = traffic_analyzer.get_traffic_over_time(bin_size=60)
        if traffic_data and 'times' in traffic_data and 'counts' in traffic_data:
            plt.figure(figsize=(10, 5))
            plt.plot(traffic_data['times'], traffic_data['counts'])
            plt.xlabel('Time')
            plt.ylabel('Packets per minute')
            plt.title('Network Traffic Over Time')
            
            # Convert plot to base64 for embedding in HTML
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            charts['traffic_over_time'] = base64.b64encode(buffer.read()).decode('utf-8')
            plt.close()
        
        # Protocol distribution pie chart
        protocol_dist = protocol_stats.get_protocol_distribution()
        if protocol_dist:
            protocols = []
            percentages = []
            
            for proto, data in protocol_dist.items():
                protocols.append(proto)
                percentages.append(data['percentage'])
            
            plt.figure(figsize=(8, 8))
            plt.pie(percentages, labels=protocols, autopct='%1.1f%%')
            plt.title('Protocol Distribution')
            
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            charts['protocol_distribution'] = base64.b64encode(buffer.read()).decode('utf-8')
            plt.close()
        
        return charts
    
    def save_report(self, report_content, filename=None):
        """Save report to a file"""
        if filename is None:
            filename = f"network_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        with open(filename, 'w') as f:
            f.write(report_content)
        
        return filename