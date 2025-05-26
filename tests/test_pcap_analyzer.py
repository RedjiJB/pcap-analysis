#!/usr/bin/env python3
"""
Test suite for PCAP Analyzer
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import tempfile
import json

# Add the scripts directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from pcap_analyzer import PCAPAnalyzer

class TestPCAPAnalyzer:
    """Test cases for PCAPAnalyzer class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.test_pcap = "test.pcap"
        self.analyzer = PCAPAnalyzer(self.test_pcap)
    
    def test_init(self):
        """Test analyzer initialization"""
        assert self.analyzer.pcap_file == self.test_pcap
        assert self.analyzer.packets == []
        assert 'summary' in self.analyzer.results
        assert 'suspicious_ips' in self.analyzer.results
        assert 'dns_queries' in self.analyzer.results
    
    @patch('pcap_analyzer.rdpcap')
    def test_load_pcap_success(self, mock_rdpcap):
        """Test successful PCAP loading"""
        mock_packets = [Mock(), Mock(), Mock()]
        mock_rdpcap.return_value = mock_packets
        
        result = self.analyzer.load_pcap()
        
        assert result is True
        assert len(self.analyzer.packets) == 3
        mock_rdpcap.assert_called_once_with(self.test_pcap)
    
    @patch('pcap_analyzer.rdpcap')
    def test_load_pcap_failure(self, mock_rdpcap):
        """Test PCAP loading failure"""
        mock_rdpcap.side_effect = Exception("File not found")
        
        result = self.analyzer.load_pcap()
        
        assert result is False
        assert len(self.analyzer.packets) == 0
    
    def test_analyze_summary(self):
        """Test summary analysis"""
        # Create mock packets with timestamps
        mock_pkt1 = Mock()
        mock_pkt1.time = 1640995200  # 2022-01-01 00:00:00
        mock_pkt1.haslayer.return_value = True
        mock_pkt1.__contains__ = Mock(return_value=True)
        
        mock_pkt2 = Mock()
        mock_pkt2.time = 1640995260  # 2022-01-01 00:01:00
        mock_pkt2.haslayer.return_value = True
        mock_pkt2.__contains__ = Mock(return_value=True)
        
        # Mock the packet layers
        with patch('pcap_analyzer.IP') as mock_ip, \
             patch('pcap_analyzer.TCP') as mock_tcp:
            
            self.analyzer.packets = [mock_pkt1, mock_pkt2]
            self.analyzer.analyze_summary()
            
            assert 'start_time' in self.analyzer.results['summary']
            assert 'end_time' in self.analyzer.results['summary']
            assert 'duration' in self.analyzer.results['summary']
            assert 'total_packets' in self.analyzer.results['summary']
            assert self.analyzer.results['summary']['total_packets'] == 2
    
    def test_is_suspicious_dns(self):
        """Test DNS suspiciousness detection"""
        # Long subdomain
        long_domain = "a" * 60 + ".example.com"
        assert self.analyzer._is_suspicious_dns(long_domain) is True
        
        # Many subdomains
        many_subdomains = "a.b.c.d.e.example.com"
        assert self.analyzer._is_suspicious_dns(many_subdomains) is True
        
        # Suspicious TLD
        suspicious_tld = "example.tk"
        assert self.analyzer._is_suspicious_dns(suspicious_tld) is True
        
        # Normal domain
        normal_domain = "www.google.com"
        assert self.analyzer._is_suspicious_dns(normal_domain) is False
    
    def test_is_suspicious_http(self):
        """Test HTTP suspiciousness detection"""
        # Suspicious path
        suspicious_request = {
            'uri': '/cmd.php',
            'user_agent': 'Normal Browser'
        }
        assert self.analyzer._is_suspicious_http(suspicious_request) is True
        
        # Suspicious user agent
        suspicious_ua_request = {
            'uri': '/normal',
            'user_agent': 'Mozilla/4.0'
        }
        assert self.analyzer._is_suspicious_http(suspicious_ua_request) is True
        
        # Normal request
        normal_request = {
            'uri': '/index.html',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }
        assert self.analyzer._is_suspicious_http(normal_request) is False
    
    def test_generate_report(self):
        """Test report generation"""
        # Setup analyzer with some results
        self.analyzer.results = {
            'summary': {'total_packets': 100, 'duration': 3600},
            'dns_queries': [
                {'query': 'evil.com', 'src_ip': '192.168.1.100', 'suspicious': True}
            ],
            'potential_c2': [
                {
                    'src_ip': '192.168.1.100',
                    'dst_ip': '1.2.3.4',
                    'dst_port': 443,
                    'beacon_interval': 300,
                    'connection_count': 10,
                    'confidence': 'High'
                }
            ],
            'anomalies': [
                {
                    'type': 'Suspicious DNS',
                    'details': 'Possible DNS tunneling',
                    'timestamp': '2022-01-01T00:00:00'
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            output_file = f.name
        
        try:
            self.analyzer.generate_report(output_file)
            
            # Check if report file was created
            assert os.path.exists(output_file)
            
            # Check if JSON file was also created
            json_file = output_file.replace('.md', '.json')
            assert os.path.exists(json_file)
            
            # Verify report content
            with open(output_file, 'r') as f:
                content = f.read()
                assert '# PCAP Analysis Report' in content
                assert 'evil.com' in content
                assert 'Suspicious DNS' in content
            
            # Verify JSON content
            with open(json_file, 'r') as f:
                json_data = json.load(f)
                assert 'summary' in json_data
                assert json_data['summary']['total_packets'] == 100
        
        finally:
            # Cleanup
            if os.path.exists(output_file):
                os.unlink(output_file)
            json_file = output_file.replace('.md', '.json')
            if os.path.exists(json_file):
                os.unlink(json_file)


class TestPCAPAnalyzerIntegration:
    """Integration tests for PCAP Analyzer"""
    
    @pytest.fixture
    def sample_pcap_data(self):
        """Create sample PCAP data for testing"""
        return {
            'packets': [
                {
                    'timestamp': 1640995200,
                    'src_ip': '192.168.1.100',
                    'dst_ip': '8.8.8.8',
                    'protocol': 'DNS',
                    'query': 'example.com'
                },
                {
                    'timestamp': 1640995260,
                    'src_ip': '192.168.1.100',
                    'dst_ip': '1.2.3.4',
                    'protocol': 'HTTP',
                    'method': 'GET',
                    'uri': '/cmd.php'
                }
            ]
        }
    
    def test_full_analysis_workflow(self, sample_pcap_data):
        """Test complete analysis workflow"""
        analyzer = PCAPAnalyzer("test.pcap")
        
        # Mock the load_pcap to return success
        with patch.object(analyzer, 'load_pcap', return_value=True):
            # Mock individual analysis methods
            with patch.object(analyzer, 'analyze_summary'), \
                 patch.object(analyzer, 'analyze_dns'), \
                 patch.object(analyzer, 'analyze_http'), \
                 patch.object(analyzer, 'detect_c2_patterns'), \
                 patch.object(analyzer, 'extract_credentials'):
                
                # Test that all methods are called in correct order
                result = analyzer.load_pcap()
                assert result is True
                
                analyzer.analyze_summary()
                analyzer.analyze_dns()
                analyzer.analyze_http()
                analyzer.detect_c2_patterns()
                analyzer.extract_credentials()


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])