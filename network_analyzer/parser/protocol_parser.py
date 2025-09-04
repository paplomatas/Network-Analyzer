# network_analyzer/parser/protocol_parser.py
class ProtocolParser:
    """
    Base class for all protocol parsers
    """
    def __init__(self):
        self.supported_protocols = []
    
    def can_parse(self, packet):
        """Check if this parser can handle the packet"""
        raise NotImplementedError("Subclasses must implement this method")
    
    def parse(self, packet):
        """Parse the packet and return structured data"""
        raise NotImplementedError("Subclasses must implement this method")