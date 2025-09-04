# network_analyzer/capture/pcap_handler.py
import os
import logging
from scapy.all import rdpcap, wrpcap
from datetime import datetime

logger = logging.getLogger(__name__)

class PCAPHandler:
    """
    Handles PCAP file import and export operations
    """
    def __init__(self, output_dir="./captures"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def import_pcap(self, file_path):
        """
        Import packets from a PCAP file
        
        Args:
            file_path: Path to the PCAP file
        
        Returns:
            List of scapy packets
        """
        try:
            logger.info(f"Importing packets from {file_path}")
            packets = rdpcap(file_path)
            logger.info(f"Successfully imported {len(packets)} packets")
            return packets
        except Exception as e:
            logger.error(f"Failed to import PCAP file {file_path}: {e}")
            raise
    
    def export_pcap(self, packets, filename=None):
        """
        Export packets to a PCAP file
        
        Args:
            packets: List of packets to export
            filename: Optional filename (default: timestamp-based)
        
        Returns:
            Path to the saved PCAP file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"capture_{timestamp}.pcap"
        
        file_path = os.path.join(self.output_dir, filename)
        
        try:
            logger.info(f"Exporting {len(packets)} packets to {file_path}")
            wrpcap(file_path, packets)
            logger.info(f"Successfully exported packets to {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Failed to export packets to {file_path}: {e}")
            raise
    
    def get_pcap_info(self, file_path):
        """
        Get summary information about a PCAP file
        
        Args:
            file_path: Path to the PCAP file
        
        Returns:
            Dictionary with PCAP statistics
        """
        try:
            packets = rdpcap(file_path)
            
            # Extract timestamps of first and last packets
            # Handle different timestamp formats safely
            packet_times = []
            for pkt in packets:
                if hasattr(pkt, 'time'):
                    try:
                        # Try to convert any non-standard time format to float
                        packet_times.append(float(pkt.time))
                    except:
                        # Skip packets with invalid time formats
                        pass
            
            # Safely calculate timestamps if we have valid times
            if packet_times:
                start_time = min(packet_times)
                end_time = max(packet_times)
                duration = end_time - start_time
            else:
                # Default values if no valid timestamps found
                start_time = 0
                end_time = 0
                duration = 0
            
            # Count packets by protocol
            protocol_counts = {}
            for pkt in packets:
                proto = "Other"
                if pkt.haslayer("TCP"):
                    proto = "TCP"
                elif pkt.haslayer("UDP"):
                    proto = "UDP"
                elif pkt.haslayer("ICMP"):
                    proto = "ICMP"
                elif pkt.haslayer("DNS"):
                    proto = "DNS"
                elif pkt.haslayer("ARP"):
                    proto = "ARP"
                
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            
            return {
                "file_path": file_path,
                "file_size": os.path.getsize(file_path),
                "packet_count": len(packets),
                "start_time": datetime.fromtimestamp(start_time) if start_time > 0 else "Unknown",
                "end_time": datetime.fromtimestamp(end_time) if end_time > 0 else "Unknown",
                "duration": duration,
                "protocols": protocol_counts
            }
        except Exception as e:
            logger.error(f"Failed to get PCAP info for {file_path}: {e}")
            raise