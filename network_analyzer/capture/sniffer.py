# network_analyzer/capture/sniffer.py

import threading
import logging
import time
import platform
from queue import Queue
from scapy.all import sniff, conf, get_if_list

logger = logging.getLogger(__name__)

class PacketSniffer:
    """
    Captures packets on the specified interface using Scapy.
    """

    def __init__(self, interface, packet_filter=""):
        self.interface = interface
        self.packet_filter = packet_filter
        self.packet_queue = Queue()
        self.running = threading.Event()
        self.current_packets = 0
        self.total_packets = 0
        self.capture_thread = None
        self.start_time = time.time()
        
        # Optimize scapy settings for better performance
        # Different optimizations based on OS
        system = platform.system().lower()
        
        # Enable promiscuous mode to capture all packets
        conf.sniff_promisc = True
        
        # Use libpcap for better performance when available 
        # This works on most platforms
        try:
            conf.use_pcap = True
        except Exception as e:
            logger.warning(f"Couldn't enable pcap: {e}")
            
        # Some settings are platform-specific
        if system in ['darwin', 'freebsd', 'openbsd']:
            # BSD-specific settings
            try:
                conf.use_bpf = True
            except Exception as e:
                logger.warning(f"Couldn't enable BPF: {e}")
        
        logger.info(f"Running on platform: {system}")
        logger.info(f"Packet capture optimization settings applied for {system}")

    def _process_packet(self, packet):
        """
        Called for each captured packet.
        """
        self.packet_queue.put(packet)
        self.total_packets += 1
        self.current_packets += 1
        
        # Log packet capture status periodically
        if self.total_packets % 50 == 0:
            elapsed = time.time() - self.start_time
            rate = self.total_packets / elapsed if elapsed > 0 else 0
            logger.info(f"Captured {self.total_packets} packets total ({rate:.2f} packets/sec)")
            logger.debug(f"Queue size: {self.packet_queue.qsize()} packets")

    def _capture_packets(self):
        """
        Internal method to start packet sniffing.
        """
        try:
            logger.info(f"Starting packet capture on interface {self.interface} with filter '{self.packet_filter}'...")
            
            # Keep trying to capture in case of temporary failures
            while self.running.is_set():
                try:
                    # Use a higher count limit and shorter timeout to process packets in smaller batches
                    # This helps maintain a steadier capture rate
                    sniff(
                        iface=self.interface,
                        filter=self.packet_filter,
                        prn=self._process_packet,
                        store=False,
                        count=100,  # Process in batches of 100 packets
                        stop_filter=lambda x: not self.running.is_set(),
                        timeout=2   # Short timeout to avoid blocking too long
                    )
                    
                    # Small sleep to prevent CPU hogging but allow a good capture rate
                    if self.running.is_set():
                        time.sleep(0.1)
                        
                except OSError as e:
                    if "permission denied" in str(e).lower():
                        logger.error(f"Permission denied: Try running with sudo/admin privileges. Error: {e}")
                        # Don't keep retrying permission errors
                        break
                    elif "no such device" in str(e).lower():
                        logger.error(f"No such device: Interface '{self.interface}' not found. Error: {e}")
                        # Don't keep retrying if interface doesn't exist
                        break
                    else:
                        logger.error(f"Sniffing error: {e}. Will retry in 2 seconds...")
                        if self.running.is_set():
                            time.sleep(2)
                            
                except Exception as e:
                    logger.error(f"Unexpected error during packet capture: {e}")
                    if self.running.is_set():
                        logger.info("Will retry capture in a moment...")
                        time.sleep(1)
                        
        except Exception as e:
            logger.error(f"Fatal error in packet capture thread: {e}")

    def start_capture(self):
        """
        Starts the packet capture in a separate thread.
        """
        if self.capture_thread and self.capture_thread.is_alive():
            logger.info("Packet capture already running")
            return
            
        # List available interfaces for debugging
        interfaces = get_if_list()
        logger.debug(f"Available interfaces: {interfaces}")
        
        if self.interface not in interfaces and self.interface != "0" and not self.interface.startswith("{"):
            logger.warning(f"Interface {self.interface} not found in available interfaces: {interfaces}")
            logger.warning("This may be an issue with interface name format. Continuing anyway...")
            
        # Reset counters and state
        self.total_packets = 0
        self.current_packets = 0
        self.start_time = time.time()
        self.running.set()
        
        # Start the capture thread
        self.capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        self.capture_thread.start()
        logger.info(f"Packet capture thread started on interface {self.interface}")

    def stop_capture(self):
        """
        Stops the packet capture.
        """
        if not self.running.is_set():
            logger.info("Packet capture already stopped")
            return
            
        logger.info("Stopping packet capture...")
        self.running.clear()
        
        if self.capture_thread and self.capture_thread.is_alive():
            try:
                # Try to join the thread with a timeout
                self.capture_thread.join(timeout=3.0)
                if self.capture_thread.is_alive():
                    logger.warning("Packet capture thread did not exit cleanly")
            except Exception as e:
                logger.error(f"Error while stopping capture thread: {e}")
                
        # Log capture statistics
        elapsed = time.time() - self.start_time
        rate = self.total_packets / elapsed if elapsed > 0 else 0
        logger.info(f"Capture stopped. Captured {self.total_packets} packets in {elapsed:.1f} seconds ({rate:.2f} packets/sec)")