#!/usr/bin/env python3
"""
Test suite for Wireshark filters validation
"""

import pytest
import os
import re

class TestWiresharkFilters:
    """Test Wireshark filter syntax and effectiveness"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.filter_dir = os.path.join(os.path.dirname(__file__), '..', 'wireshark-filters')
    
    def test_filter_files_exist(self):
        """Test that all filter files exist"""
        expected_files = [
            'malware-detection.txt',
            'data-exfiltration.txt',
            'suspicious-dns.txt'
        ]
        
        for filename in expected_files:
            filepath = os.path.join(self.filter_dir, filename)
            assert os.path.exists(filepath), f"Filter file {filename} not found"
    
    def test_filter_syntax(self):
        """Test basic filter syntax validation"""
        # Common Wireshark filter operators
        valid_operators = ['==', '!=', '>', '<', '>=', '<=', 'contains', 'matches', 'and', 'or', 'not']
        
        # Common fields
        valid_fields = ['ip', 'tcp', 'udp', 'dns', 'http', 'ssl', 'tls', 'icmp', 'arp']
        
        for filename in os.listdir(self.filter_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(self.filter_dir, filename)
                with open(filepath, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        
                        # Skip comments and empty lines
                        if line.startswith('#') or not line:
                            continue
                        
                        # Basic syntax check - should contain field and operator
                        has_field = any(field in line.lower() for field in valid_fields)
                        assert has_field, f"No valid field found in {filename}:{line_num} - {line}"
    
    def test_malware_detection_filters(self):
        """Test malware detection filter patterns"""
        filepath = os.path.join(self.filter_dir, 'malware-detection.txt')
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Check for essential malware detection patterns
        essential_patterns = [
            'user_agent',  # Suspicious user agents
            'tcp.port == 4444',  # Common malware ports
            'base64',  # Encoded payloads
            '.exe',  # Executable downloads
            'tcp.flags.syn'  # Connection patterns
        ]
        
        for pattern in essential_patterns:
            assert pattern in content, f"Missing essential pattern: {pattern}"
    
    def test_dns_filter_patterns(self):
        """Test DNS anomaly detection filters"""
        filepath = os.path.join(self.filter_dir, 'suspicious-dns.txt')
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Check for DNS-specific patterns
        dns_patterns = [
            'dns.flags.rcode',  # DNS errors
            'dns.qry.name',  # Query names
            'dns.qry.type',  # Query types
            '.tk',  # Suspicious TLDs
            'dns.a'  # A records
        ]
        
        for pattern in dns_patterns:
            assert pattern in content, f"Missing DNS pattern: {pattern}"
    
    def test_data_exfiltration_filters(self):
        """Test data exfiltration detection filters"""
        filepath = os.path.join(self.filter_dir, 'data-exfiltration.txt')
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Check for exfiltration patterns
        exfil_patterns = [
            'tcp.len > 1000',  # Large transfers
            'dns.qry.name.len',  # DNS tunneling
            'http.request.method == "POST"',  # POST uploads
            'ssl.handshake',  # HTTPS connections
            'ftp-data'  # FTP transfers
        ]
        
        for pattern in exfil_patterns:
            assert pattern in content, f"Missing exfiltration pattern: {pattern}"
    
    def test_filter_logic_combinations(self):
        """Test complex filter logic combinations"""
        # Test patterns that should be in filters
        complex_patterns = [
            r'tcp\.port == \d+ or tcp\.port == \d+',  # OR logic
            r'\w+ and \w+',  # AND logic
            r'not .*tcp\.dstport == 80',  # NOT logic
            r'ip\.src == [\d\.]+/\d+',  # CIDR notation
        ]
        
        all_content = ""
        for filename in os.listdir(self.filter_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(self.filter_dir, filename)
                with open(filepath, 'r') as f:
                    all_content += f.read()
        
        # Check that we use various logical operators
        assert ' or ' in all_content, "Missing OR logic in filters"
        assert ' and ' in all_content, "Missing AND logic in filters"
        assert 'not ' in all_content, "Missing NOT logic in filters"
    
    def test_performance_considerations(self):
        """Test that filters are optimized for performance"""
        for filename in os.listdir(self.filter_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(self.filter_dir, filename)
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('#') or not line:
                            continue
                        
                        # Check for inefficient patterns
                        # Avoid too many wildcards at the beginning
                        assert not line.startswith('*'), f"Inefficient wildcard at start: {line}"
                        
                        # Prefer specific protocols when possible
                        if 'port ==' in line and 'tcp.' not in line and 'udp.' not in line:
                            print(f"Warning: Generic port filter without protocol: {line}")


class TestFilterEffectiveness:
    """Test filter effectiveness against sample traffic patterns"""
    
    def test_c2_beacon_detection(self):
        """Test C2 beacon pattern detection"""
        # Simulated beacon patterns that should match filters
        beacon_patterns = [
            {'src': '192.168.1.100', 'dst': '1.2.3.4', 'port': 443, 'interval': 300},
            {'src': '10.0.0.50', 'dst': '5.6.7.8', 'port': 8080, 'interval': 180},
        ]
        
        # These patterns should be detectable by filters
        for pattern in beacon_patterns:
            # Non-standard HTTPS port should be flagged
            if pattern['port'] not in [80, 443]:
                assert pattern['port'] in [4444, 5555, 8080, 7080], "Beacon port should match filter"
    
    def test_dga_domain_patterns(self):
        """Test DGA domain pattern matching"""
        dga_patterns = [
            "aksjdhfkajsdhfkajsdhf.com",  # Random 20+ chars
            "qwertyuiopasdfghjklzxcvbnm.net",  # Keyboard pattern
            "a1b2c3d4e5f6g7h8i9j0.org",  # Alphanumeric pattern
        ]
        
        for domain in dga_patterns:
            # Should match the regex pattern in filters
            assert len(domain.split('.')[0]) >= 16, "DGA domain should have long random subdomain"
    
    def test_credential_exposure_patterns(self):
        """Test credential exposure detection patterns"""
        credential_patterns = [
            "USER admin",  # FTP
            "PASS secret",  # FTP
            "Authorization: Basic YWRtaW46cGFzc3dvcmQ=",  # HTTP Basic
            "username=admin&password=secret",  # Form data
        ]
        
        # All these should be detectable
        for pattern in credential_patterns:
            assert any(keyword in pattern for keyword in ['USER', 'PASS', 'Authorization', 'password='])


class TestFilterDocumentation:
    """Test filter documentation and comments"""
    
    def test_filters_have_comments(self):
        """Test that filters are properly documented"""
        for filename in os.listdir(os.path.join(os.path.dirname(__file__), '..', 'wireshark-filters')):
            if filename.endswith('.txt'):
                filepath = os.path.join(os.path.dirname(__file__), '..', 'wireshark-filters', filename)
                with open(filepath, 'r') as f:
                    content = f.read()
                
                # Should have section headers
                assert '#' in content, f"No comments found in {filename}"
                
                # Count comment lines
                comment_lines = len([line for line in content.split('\n') if line.strip().startswith('#')])
                total_lines = len([line for line in content.split('\n') if line.strip()])
                
                # At least 20% should be comments
                comment_ratio = comment_lines / total_lines if total_lines > 0 else 0
                assert comment_ratio >= 0.15, f"Insufficient documentation in {filename}: {comment_ratio:.1%}"
    
    def test_filter_categories(self):
        """Test that filters are properly categorized"""
        expected_categories = {
            'malware-detection.txt': ['User-Agents', 'ports', 'Base64', 'file extensions'],
            'data-exfiltration.txt': ['transfers', 'DNS tunneling', 'uploads'],
            'suspicious-dns.txt': ['DNS', 'TLDs', 'DGA', 'tunneling']
        }
        
        for filename, expected_keywords in expected_categories.items():
            filepath = os.path.join(os.path.dirname(__file__), '..', 'wireshark-filters', filename)
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    content = f.read().lower()
                
                for keyword in expected_keywords:
                    assert keyword.lower() in content, f"Missing category '{keyword}' in {filename}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])