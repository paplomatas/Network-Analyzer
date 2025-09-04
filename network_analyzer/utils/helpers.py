import os
import sys
import logging
import yaml
import json
from datetime import datetime
import ipaddress
import hashlib
import tempfile
import socket
import struct
import re
import platform

from scapy.all import get_if_list, get_if_addr, conf, IFACES
try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    get_windows_if_list = None


def setup_logging(level=logging.INFO, log_file=None):
    """Set up logging configuration"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(file_handler)

    logging.getLogger('matplotlib').setLevel(logging.WARNING)
    logging.getLogger('PIL').setLevel(logging.WARNING)

    return logging.getLogger('network_analyzer')

def safe_get(packet, attr, fallback=None):
    """Safely access packet attributes across Scapy or dict formats."""
    return packet.get(attr, fallback) if isinstance(packet, dict) else getattr(packet, attr, fallback)

def load_config(config_path='config.yaml'):
    """Load configuration from YAML file"""
    default_config = {
        'capture': {
            'interface': 'auto',
            'filter': '',
            'max_packets': 0,
            'snaplen': 65535
        },
        'database': {
            'type': 'sqlite',
            'path': 'network_analyzer.db',
            'max_packets': 1000000,
            'auto_cleanup': True
        },
        'dashboard': {
            'port': 8050,
            'debug': False,
            'theme': 'light',
            'update_interval': 5
        },
        'analyzer': {
            'traffic_interval': 60,
            'detection_threshold': 0.7,
            'learning_period': 3600
        }
    }

    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as file:
                user_config = yaml.safe_load(file)
                if user_config:
                    deep_merge(default_config, user_config)
        except Exception as e:
            logging.warning(f"Failed to load config from {config_path}: {e}")
            logging.warning("Using default configuration")
    else:
        logging.info(f"Config file not found at {config_path}, using defaults")

    return default_config


def deep_merge(base, override):
    """Recursively merge two dictionaries"""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            deep_merge(base[key], value)
        else:
            base[key] = value


def get_default_interface():
    """Determine the default network interface that's actually active
    
    This improved function tries multiple methods to find the active interface,
    with special handling for Windows systems where interface detection can be tricky.
    """
    system = platform.system()
    
    # Try to find an interface that's connected to the internet
    try:
        # Create a temporary socket to determine the interface used for internet connectivity
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(("8.8.8.8", 80))  # Google's DNS server
        connected_ip = temp_socket.getsockname()[0]
        temp_socket.close()
        
        # Now find which interface has this IP
        interfaces = get_network_interfaces()
        for iface in interfaces:
            if iface["ip"] == connected_ip:
                logging.info(f"Found active interface: {iface['name']} with IP {iface['ip']}")
                return iface["name"]
    except Exception as e:
        logging.debug(f"Failed to determine active interface via socket method: {e}")
    
    # Windows-specific method
    if system == "Windows":
        try:
            # On Windows, prioritize interfaces that have a non-local IP address and are "up"
            if get_windows_if_list:
                win_interfaces = get_windows_if_list()
                
                # First try to find any interface that has a real IP (not 169.254.x.x or 0.0.0.0)
                for iface in win_interfaces:
                    try:
                        ip = get_if_addr(iface["guid"])
                        name = iface.get("name", "")
                        description = iface.get("description", "")
                        
                        # Skip interfaces without proper IP or with specific keywords
                        if (ip == "0.0.0.0" or 
                            ip.startswith("169.254") or
                            "virtual" in name.lower() or 
                            "virtual" in description.lower()):
                            continue
                            
                        # Prefer WiFi and Ethernet interfaces
                        if ("wi-fi" in name.lower() or 
                            "wireless" in name.lower() or
                            "ethernet" in name.lower() or
                            "local area connection" in name.lower()):
                            logging.info(f"Selected Windows interface: {name} with IP {ip}")
                            return iface["guid"]
                    except Exception as e:
                        continue
                
                # If no preferred interface found, take first one with valid IP
                for iface in win_interfaces:
                    try:
                        ip = get_if_addr(iface["guid"])
                        if ip != "0.0.0.0" and not ip.startswith("169.254"):
                            logging.info(f"Selected Windows interface (fallback): {iface.get('name')} with IP {ip}")
                            return iface["guid"]
                    except Exception:
                        continue
        except Exception as e:
            logging.debug(f"Failed to determine Windows interface: {e}")
    
    # Platform-specific fallbacks
    if system == "Linux":
        return get_default_linux_interface()
    elif system == "Darwin":  # macOS
        return get_default_macos_interface()
    
    # Final fallback: just use whatever Scapy thinks is the default
    try:
        default_iface = conf.iface
        logging.info(f"Using Scapy's default interface: {default_iface}")
        return default_iface
    except Exception as e:
        logging.error(f"Failed to determine any default interface: {e}")
        
    # Last resort fallback
    interfaces = get_if_list()
    if interfaces:
        logging.warning(f"Using first available interface as fallback: {interfaces[0]}")
        return interfaces[0]
    
    logging.error("No network interfaces found!")
    return None

def get_network_interfaces():
    """Return a list of interfaces with names and IPs if available"""
    interfaces = []
    system = platform.system()

    if system == "Windows" and get_windows_if_list:
        try:
            for iface in get_windows_if_list():
                guid = iface.get("guid")
                name = iface.get("name") or iface.get("description") or guid
                try:
                    ip = get_if_addr(guid)
                    if ip == "0.0.0.0":
                        ip = "Unavailable"
                except Exception:
                    ip = "Unavailable"

                # Skip loopback interfaces and those with no IP
                if ip == "127.0.0.1" or ip == "Unavailable":
                    continue

                # Check if the interface is active (has a valid IP)
                if ip != "0.0.0.0" and not ip.startswith("169.254"):
                    interfaces.append({
                        "name": guid,  # We use GUID as the name for Windows interfaces
                        "display_name": name,  # This is the human-readable name
                        "ip": ip,
                        "platform": system
                    })
        except Exception as e:
            logging.debug(f"Failed to list Windows interfaces: {e}")
    else:
        # For non-Windows systems (Linux, macOS, etc.)
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                
                # Skip loopback interfaces and those with no IP
                if ip in ["127.0.0.1", "0.0.0.0"] or ip.startswith("169.254"):
                    continue
                    
                interfaces.append({
                    "name": iface,
                    "display_name": iface,
                    "ip": ip,
                    "platform": system
                })
            except Exception:
                pass

    return interfaces



def get_default_linux_interface():
    """Get default interface for Linux by examining the routing table"""
    try:
        with open('/proc/net/route', 'r') as f:
            for line in f.readlines():
                parts = line.strip().split()
                if parts[1] == '00000000':  # Default route
                    return parts[0]
    except Exception as e:
        logging.debug(f"Failed to get default Linux interface: {e}")
    
    # Alternative method
    try:
        # Try to find an interface with a real IP
        for iface in get_if_list():
            ip = get_if_addr(iface)
            if ip != "127.0.0.1" and ip != "0.0.0.0" and not ip.startswith("169.254"):
                return iface
    except Exception:
        pass
    
    return None


def get_default_macos_interface():
    """Get default interface for macOS"""
    try:
        import subprocess
        result = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True)
        match = re.search(r'interface: (\w+)', result.stdout)
        if match:
            return match.group(1)
    except Exception as e:
        logging.debug(f"Failed to get default macOS interface via route command: {e}")
    
    # Alternative method
    try:
        for iface in get_if_list():
            ip = get_if_addr(iface)
            if ip != "127.0.0.1" and ip != "0.0.0.0" and not ip.startswith("169.254"):
                return iface
    except Exception:
        pass
    
    return None


def get_default_windows_interface():
    """Get default interface for Windows"""
    try:
        import netifaces
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            return gateways['default'][netifaces.AF_INET][1]
    except ImportError:
        logging.debug("netifaces module not available, trying alternative method")
    except Exception as e:
        logging.debug(f"Failed to get default Windows interface via netifaces: {e}")
    
    # Fall back to the first interface that has a valid IP
    try:
        if get_windows_if_list:
            for iface in get_windows_if_list():
                try:
                    guid = iface.get("guid")
                    ip = get_if_addr(guid)
                    if ip != "0.0.0.0" and ip != "127.0.0.1" and not ip.startswith("169.254"):
                        return guid
                except Exception:
                    continue
    except Exception:
        pass
    
    return None


def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def format_timestamp(timestamp, format_str=None):
    if isinstance(timestamp, (int, float)):
        dt = datetime.fromtimestamp(timestamp)
    elif isinstance(timestamp, datetime):
        dt = timestamp
    else:
        return str(timestamp)

    if format_str:
        return dt.strftime(format_str)
    else:
        return dt.strftime('%Y-%m-%d %H:%M:%S')


def get_protocol_name(protocol_num):
    protocol_map = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        2: 'IGMP',
        89: 'OSPF',
        47: 'GRE'
    }
    return protocol_map.get(protocol_num, f"Protocol {protocol_num}")


def calculate_checksum(data):
    return hashlib.md5(data).hexdigest()


def format_bytes(byte_count):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if byte_count < 1024.0:
            return f"{byte_count:.2f} {unit}"
        byte_count /= 1024.0
    return f"{byte_count:.2f} PB"


def generate_temp_filename(prefix='network_analyzer_', suffix='.tmp'):
    with tempfile.NamedTemporaryFile(prefix=prefix, suffix=suffix, delete=False) as temp:
        return temp.name


def ip_to_int(ip_str):
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except:
        return 0


def int_to_ip(ip_int):
    try:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    except:
        return "0.0.0.0"


def parse_mac_address(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes)


def is_valid_port_range(port):
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def json_serialize(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def safe_json_dumps(data):
    return json.dumps(data, default=json_serialize)