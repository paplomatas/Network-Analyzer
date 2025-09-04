# network_analyzer/main.py
import argparse
import logging
import threading
import time
import signal
import sys
import os
from queue import Empty, Queue
from scapy.all import conf, rdpcap

from network_analyzer.capture.sniffer import PacketSniffer
from network_analyzer.analyzer.traffic import TrafficAnalyzer
from network_analyzer.analyzer.security import SecurityAnalyzer
from network_analyzer.analyzer.anomaly import AnomalyDetector
from network_analyzer.analyzer.protocol_stats import ProtocolStatisticsAnalyzer
from network_analyzer.analyzer.flow import FlowAnalyzer
from network_analyzer.parser.http_parser import HTTPParser
from network_analyzer.parser.tcp_parser import TCPParser
from network_analyzer.parser.dns_parser import DNSParser
from network_analyzer.parser.arp_parser import ARPParser
from network_analyzer.parser.icmp_parser import ICMPParser
from network_analyzer.visualizer.dashboard import NetworkDashboard
from network_analyzer.visualizer.reports import ReportGenerator
from network_analyzer.utils.helpers import get_default_interface, get_network_interfaces
from network_analyzer.capture.pcap_handler import PCAPHandler

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('network_analyzer')

# Set Scapy to not print verbose warnings
conf.verb = 0

# Global flag for graceful shutdown
running = None

def signal_handler(sig, frame):
    """Handle Ctrl+C to gracefully shutdown"""
    global running
    if running:
        logger.info("Interrupt received, shutting down...")
        running.clear()

class PCAPPlayer:
    """
    Plays back packets from a PCAP file at a controlled rate
    """
    def __init__(self, pcap_file, target_rate=10, loop=False):
        self.pcap_file = pcap_file
        self.target_rate = target_rate
        self.loop = loop
        self.packet_queue = Queue()
        self.running = threading.Event()
        self.playback_thread = None
        self.total_packets = 0
        self.start_time = time.time()

    def start_playback(self):
        """Start the PCAP playback thread"""
        if self.playback_thread and self.playback_thread.is_alive():
            logger.info("PCAP playback already running")
            return
            
        self.running.set()
        self.total_packets = 0
        self.start_time = time.time()
        
        self.playback_thread = threading.Thread(target=self._play_pcap, daemon=True)
        self.playback_thread.start()
        logger.info(f"PCAP playback started from {self.pcap_file}")

    def _play_pcap(self):
        """Internal method to play packets from the PCAP file"""
        try:
            while self.running.is_set():
                logger.info(f"Loading packets from {self.pcap_file}")
                packets = rdpcap(self.pcap_file)
                logger.info(f"Loaded {len(packets)} packets from PCAP file")
                
                if not packets:
                    logger.warning("No packets found in PCAP file")
                    if not self.loop:
                        break
                    continue
                
                # Process each packet
                for i, packet in enumerate(packets):
                    if not self.running.is_set():
                        break
                        
                    # Add to queue
                    self.packet_queue.put(packet)
                    self.total_packets += 1
                    
                    # Log status periodically
                    if self.total_packets % 50 == 0:
                        elapsed = time.time() - self.start_time
                        rate = self.total_packets / elapsed if elapsed > 0 else 0
                        logger.info(f"Played back {self.total_packets} packets from PCAP ({rate:.2f} packets/sec)")
                    
                    # Control playback rate
                    if self.target_rate > 0:
                        time.sleep(1.0 / self.target_rate)
                
                # Break if not looping
                if not self.loop:
                    break
                
                logger.info("PCAP playback reached end of file.")
                if self.loop:
                    logger.info("Looping PCAP file from beginning.")
                    time.sleep(1.0)  # Brief pause before restarting
                
        except Exception as e:
            logger.error(f"Error in PCAP playback: {e}")
        finally:
            logger.info("PCAP playback complete")
            
    def stop_playback(self):
        """Stop the PCAP playback"""
        if not self.running.is_set():
            logger.info("PCAP playback already stopped")
            return
            
        logger.info("Stopping PCAP playback...")
        self.running.clear()
        
        if self.playback_thread and self.playback_thread.is_alive():
            self.playback_thread.join(timeout=3.0)
            
        # Log playback statistics
        elapsed = time.time() - self.start_time
        rate = self.total_packets / elapsed if elapsed > 0 else 0
        logger.info(f"PCAP playback stopped. Played {self.total_packets} packets in {elapsed:.1f} seconds ({rate:.2f} packets/sec)")

def main():
    global running
    
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer')
    parser.add_argument('-i', '--interface', type=str, help='Network interface to capture packets from', required=False)
    parser.add_argument('-f', '--filter', type=str, help='BPF filter for capturing packets', default="")
    parser.add_argument('-o', '--output', type=str, help='Output file for traffic report', required=False)
    parser.add_argument('-p', '--pcap', type=str, help='PCAP file to read packets from instead of live capture')
    parser.add_argument('--loop-pcap', action='store_true', help='Loop PCAP file playback')
    parser.add_argument('--write-pcap', type=str, help='Save captured packets to PCAP file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--version', action='version', version='network-analyzer 0.1.0')
    parser.add_argument('--list-interfaces', action='store_true', help='List available interfaces and exit')
    parser.add_argument('--target-rate', type=int, default=10, help='Target packet processing rate (packets/sec)')
    parser.add_argument('--pcap-info', type=str, help='Show information about a PCAP file and exit')
    args = parser.parse_args()

    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    # Configure logging based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    # Handle --pcap-info option
    if args.pcap_info:
        pcap_handler = PCAPHandler()
        try:
            pcap_info = pcap_handler.get_pcap_info(args.pcap_info)
            print(f"\nPCAP File Information: {args.pcap_info}")
            print(f"File Size: {pcap_info['file_size']} bytes")
            print(f"Packet Count: {pcap_info['packet_count']}")
            print(f"Start Time: {pcap_info['start_time']}")
            print(f"End Time: {pcap_info['end_time']}")
            print(f"Duration: {pcap_info['duration']:.2f} seconds")
            print("\nProtocol Distribution:")
            for proto, count in pcap_info['protocols'].items():
                print(f"  • {proto}: {count} packets")
            return 0
        except Exception as e:
            logger.error(f"Error analyzing PCAP file: {e}")
            return 1

    # Handle --list-interfaces
    if args.list_interfaces:
        interfaces = get_network_interfaces()
        print("Available Interfaces:")
        for iface in interfaces:
            ip = iface.get('ip', 'No IP')
            display_name = iface.get('display_name', iface['name'])
            print(f"• {iface['name']} - {display_name} ({ip})")
        return 0

    # Check if running with proper permissions for live capture
    if not args.pcap and os.name == 'posix' and os.geteuid() != 0:
        logger.warning("Not running as root/administrator. Packet capture may be limited.")
        logger.warning("For full functionality, run with 'sudo' or as administrator.")
    
    # Initialize components
    traffic_analyzer = TrafficAnalyzer()
    protocol_stats = ProtocolStatisticsAnalyzer()
    security_analyzer = SecurityAnalyzer()
    anomaly_detector = AnomalyDetector()
    flow_analyzer = FlowAnalyzer()
    pcap_handler = PCAPHandler()

    # Set up the running event for graceful shutdown
    running = threading.Event()
    running.set()
    
    # Packet source: PCAP file or live capture
    packet_source = None
    
    if args.pcap:
        # Use PCAP file as packet source
        if not os.path.exists(args.pcap):
            logger.error(f"PCAP file not found: {args.pcap}")
            return 1
            
        logger.info(f"Using PCAP file as packet source: {args.pcap}")
        packet_source = PCAPPlayer(args.pcap, target_rate=args.target_rate, loop=args.loop_pcap)
    else:
        # Use live capture as packet source
        # Select interface
        interface = args.interface
        if not interface:
            interface = get_default_interface()
            if not interface:
                logger.error("Could not determine default interface. Please specify with -i/--interface.")
                available = get_network_interfaces()
                if available:
                    logger.info("Available interfaces:")
                    for iface in available:
                        display_name = iface.get('display_name', iface['name'])
                        logger.info(f"• {iface['name']} - {display_name} ({iface.get('ip', 'No IP')})")
                return 1

        # Use a more permissive filter to capture more packets if none specified
        packet_filter = args.filter
        if not packet_filter:
            # Capture a wide range of commonly used protocols
            packet_filter = "ip or arp or icmp or tcp or udp"
            logger.info(f"No filter specified, using default filter: '{packet_filter}'")

        logger.info(f"Starting packet capture on interface {interface} with filter '{packet_filter}'...")
        packet_source = PacketSniffer(interface=interface, packet_filter=packet_filter)

    # Initialize packet parsers
    parsers = [
        HTTPParser(),
        TCPParser(),
        DNSParser(),
        ARPParser(),
        ICMPParser()
    ]

    # PCAP writer if requested
    pcap_writer = None
    if args.write_pcap:
        pcap_writer = []  # List to store packets for writing to PCAP
        logger.info(f"Will save captured packets to PCAP file: {args.write_pcap}")

    def process_packets():
        """Process packets from the packet source"""
        packets_processed = 0
        start_time = time.time()
        last_log_time = start_time
        
        # Target rate and timing control
        target_rate = args.target_rate  # packets per second
        min_interval = 1.0 / target_rate if target_rate > 0 else 0
        last_process_time = time.time()
        
        while running.is_set() or not packet_source.packet_queue.empty():
            try:
                # Rate limiting - ensure we don't process too quickly
                current_time = time.time()
                time_since_last = current_time - last_process_time
                
                if time_since_last < min_interval:
                    # Small sleep to maintain target rate
                    time.sleep(max(0, min_interval - time_since_last) / 2)
                
                # Use a timeout to allow for checking if we should still be running
                packet = packet_source.packet_queue.get(timeout=0.5)
                last_process_time = time.time()
                
                # Save packet for PCAP writing if enabled
                if pcap_writer is not None:
                    pcap_writer.append(packet)
                
                # Parse packet
                packet_data = None
                for parser in parsers:
                    if parser.can_parse(packet):
                        packet_data = parser.parse(packet)
                        break

                if packet_data:
                    # Process the packet with all analyzers
                    traffic_analyzer.add_packet(packet_data)
                    protocol_stats.add_packet(packet_data)
                    security_analyzer.add_packet(packet_data)
                    anomaly_detector.add_packet(packet_data)
                    flow_analyzer.add_packet(packet_data)
                    
                    packets_processed += 1
                    current_time = time.time()
                    
                    # Log processing rate periodically
                    if current_time - last_log_time >= 5:
                        elapsed = current_time - start_time
                        rate = packets_processed / elapsed if elapsed > 0 else 0
                        queue_size = packet_source.packet_queue.qsize()
                        logger.info(f"Processed {packets_processed} packets ({rate:.1f} packets/sec). Queue size: {queue_size}")
                        last_log_time = current_time

                packet_source.packet_queue.task_done()

            except Empty:
                # Queue timeout - check if we should still be running
                continue
            except Exception as e:
                logger.error(f"Error processing packet: {e}", exc_info=args.verbose)

    # Start the packet source (PCAP playback or live capture)
    if isinstance(packet_source, PCAPPlayer):
        packet_source.start_playback()
    else:
        packet_source.start_capture()
    
    # Start packet processing thread
    processor_thread = threading.Thread(target=process_packets, daemon=True)
    processor_thread.start()
    
    # Initialize dashboard with the flow analyzer
    logger.info("Starting dashboard on http://localhost:8050")
    dashboard = NetworkDashboard(
        traffic_analyzer=traffic_analyzer,
        protocol_stats=protocol_stats,
        security_analyzer=security_analyzer,
        anomaly_detector=anomaly_detector,
        flow_analyzer=flow_analyzer
    )

    try:
        # Run the dashboard (this will block until server shuts down)
        dashboard.run_server(host='0.0.0.0', port=8050)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
    except Exception as e:
        logger.error(f"Error in dashboard: {e}", exc_info=args.verbose)
    finally:
        # Ensure proper shutdown
        running.clear()
        
        # Stop the packet source
        if isinstance(packet_source, PCAPPlayer):
            packet_source.stop_playback()
        else:
            packet_source.stop_capture()
        
        # Wait for processor to finish
        logger.info("Waiting for processor thread to complete...")
        processor_thread.join(timeout=5.0)
        
        # Save PCAP if requested
        if pcap_writer is not None and args.write_pcap:
            try:
                logger.info(f"Writing {len(pcap_writer)} packets to PCAP file: {args.write_pcap}")
                pcap_handler.export_pcap(pcap_writer, filename=args.write_pcap)
                logger.info(f"PCAP file saved: {args.write_pcap}")
            except Exception as e:
                logger.error(f"Failed to write PCAP file: {e}")
        
        # Generate report if requested
        if args.output:
            try:
                logger.info(f"Saving report to {args.output}...")
                report_generator = ReportGenerator()
                report_content = report_generator.generate_traffic_report(
                    traffic_analyzer, security_analyzer, anomaly_detector, protocol_stats
                )
                report_generator.save_report(report_content, filename=args.output)
                logger.info(f"Report saved to {args.output}")
            except Exception as e:
                logger.error(f"Failed to save report: {e}")

    return 0

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)