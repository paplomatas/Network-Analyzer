# network_analyzer/capture/filter_builder.py
class FilterBuilder:
    
    def __init__(self):
        self.filter_templates = {
            'host': 'host {0}',
            'src host': 'src host {0}',
            'dst host': 'dst host {0}',
            'port': 'port {0}',
            'src port': 'src port {0}',
            'dst port': 'dst port {0}',
            'ip proto': 'ip proto {0}',
            'tcp': 'tcp',
            'udp': 'udp',
            'icmp': 'icmp',
            'http': 'tcp port 80',
            'https': 'tcp port 443',
            'dns': 'udp port 53',
            'arp': 'arp'
        }
    
    def build_filter(self, criteria):
        """Build a BPF filter string from criteria"""
        if isinstance(criteria, str):
            return criteria  # Already a filter string
        
        if isinstance(criteria, dict):
            filter_parts = []
            
            # Process each criterion
            for key, value in criteria.items():
                if key in self.filter_templates:
                    if '{0}' in self.filter_templates[key]:
                        filter_parts.append(self.filter_templates[key].format(value))
                    else:
                        filter_parts.append(self.filter_templates[key])
            
            # Combine with 'and'
            if filter_parts:
                return ' and '.join(filter_parts)
        
        return ''  # Default to empty filter (capture all)
    
    def validate_filter(self, filter_str):
        """Validate if a filter string is properly formatted"""
        # This is a simplified validation
        # In a real implementation, you'd want to parse and validate the syntax
        
        # Check for balanced parentheses
        if filter_str.count('(') != filter_str.count(')'):
            return False, "Unbalanced parentheses"
        
        # Check for common syntax errors
        if ' and and ' in filter_str or ' or or ' in filter_str:
            return False, "Invalid boolean operator sequence"
        
        # Validate operators
        for operator in ['and', 'or', 'not']:
            if f' {operator} ' not in filter_str and f' {operator}(' in filter_str:
                if operator in filter_str.split():
                    continue
                return False, f"Invalid use of '{operator}' operator"
        
        return True, "Filter syntax is valid"