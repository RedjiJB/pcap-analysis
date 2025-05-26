#!/usr/bin/env python3
"""
Pytest configuration and fixtures for PCAP Analysis tests
"""

import pytest
import tempfile
import os
from unittest.mock import Mock
from datetime import datetime

@pytest.fixture
def temp_pcap_file():
    """Create a temporary PCAP file for testing"""
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        yield f.name
    # Cleanup
    if os.path.exists(f.name):
        os.unlink(f.name)

@pytest.fixture
def mock_dns_packet():
    """Create a mock DNS packet for testing"""
    packet = Mock()
    packet.time = 1640995200.0
    packet.haslayer.return_value = True
    
    # Mock IP layer
    ip_layer = Mock()
    ip_layer.src = "192.168.1.100"
    ip_layer.dst = "8.8.8.8"
    
    # Mock DNS layer
    dns_layer = Mock()
    dns_layer.qr = 0  # Query
    dns_layer.qd = Mock()
    dns_layer.qd.qname = Mock()
    dns_layer.qd.qname.decode.return_value = "example.com."
    dns_layer.qd.qtype = 1  # A record
    
    packet.__getitem__ = Mock(side_effect=lambda layer: {
        'IP': ip_layer,
        'DNS': dns_layer,
        'DNSQR': dns_layer
    }.get(layer.__name__ if hasattr(layer, '__name__') else str(layer), Mock()))
    
    return packet

@pytest.fixture
def mock_http_packet():
    """Create a mock HTTP packet for testing"""
    packet = Mock()
    packet.time = 1640995200.0
    packet.haslayer.return_value = True
    
    # Mock IP layer
    ip_layer = Mock()
    ip_layer.src = "192.168.1.100"
    ip_layer.dst = "10.0.0.1"
    
    # Mock TCP layer
    tcp_layer = Mock()
    tcp_layer.dport = 80
    tcp_layer.sport = 12345
    
    # Mock Raw layer with HTTP data
    raw_layer = Mock()
    raw_layer.load = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    
    packet.__getitem__ = Mock(side_effect=lambda layer: {
        'IP': ip_layer,
        'TCP': tcp_layer,
        'Raw': raw_layer
    }.get(layer.__name__ if hasattr(layer, '__name__') else str(layer), Mock()))
    
    return packet

@pytest.fixture
def sample_analysis_results():
    """Provide sample analysis results for testing"""
    return {
        'summary': {
            'start_time': datetime(2022, 1, 1, 0, 0, 0),
            'end_time': datetime(2022, 1, 1, 1, 0, 0),
            'duration': 3600,
            'total_packets': 1000,
            'protocols': {'TCP': 600, 'UDP': 300, 'ICMP': 100}
        },
        'dns_queries': [
            {
                'timestamp': '2022-01-01T00:00:00',
                'src_ip': '192.168.1.100',
                'query': 'example.com.',
                'type': 1,
                'suspicious': False
            },
            {
                'timestamp': '2022-01-01T00:05:00',
                'src_ip': '192.168.1.100',
                'query': 'akjsdhfkajsdhfkajsdhf.evil.com.',
                'type': 1,
                'suspicious': True
            }
        ],
        'http_requests': [
            {
                'timestamp': '2022-01-01T00:10:00',
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'method': 'GET',
                'uri': '/index.html',
                'user_agent': 'Mozilla/5.0',
                'suspicious': False
            }
        ],
        'potential_c2': [
            {
                'src_ip': '192.168.1.100',
                'dst_ip': '1.2.3.4',
                'dst_port': 443,
                'beacon_interval': 300.0,
                'connection_count': 20,
                'confidence': 'High'
            }
        ],
        'anomalies': [
            {
                'type': 'Suspicious DNS',
                'details': 'Possible DNS tunneling: akjsdhfkajsdhfkajsdhf.evil.com.',
                'timestamp': '2022-01-01T00:05:00'
            },
            {
                'type': 'Credential Exposure',
                'details': 'FTP credentials detected',
                'src_ip': '192.168.1.100',
                'dst_ip': '192.168.1.10',
                'timestamp': '2022-01-01T00:15:00'
            }
        ]
    }

@pytest.fixture
def dga_domains():
    """Provide sample DGA domains for testing"""
    return [
        "akjsdhfkajsdhfkajsdhf.com",
        "qwertyuiopasdfghjkl.net", 
        "mnbvcxzlkjhgfdsapoiu.org",
        "randomstring123456789.evil.com"
    ]

@pytest.fixture
def legitimate_domains():
    """Provide sample legitimate domains for testing"""
    return [
        "www.google.com",
        "api.microsoft.com", 
        "s3.amazonaws.com",
        "cdn.cloudflare.com",
        "mail.yahoo.com"
    ]

@pytest.fixture
def suspicious_user_agents():
    """Provide sample suspicious user agents"""
    return [
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
        "Wget/1.19.4",
        "curl/7.68.0",
        "python-requests/2.25.1",
        "Go-http-client/1.1"
    ]

@pytest.fixture
def normal_user_agents():
    """Provide sample normal user agents"""
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    ]

class TestDataGenerator:
    """Helper class to generate test data"""
    
    @staticmethod
    def create_beacon_traffic(src_ip, dst_ip, port, interval, count):
        """Generate beacon-like traffic pattern"""
        traffic = []
        base_time = 1640995200  # 2022-01-01 00:00:00
        
        for i in range(count):
            packet = Mock()
            packet.time = base_time + (i * interval)
            packet.__getitem__ = Mock(return_value=Mock(
                src=src_ip,
                dst=dst_ip,
                dport=port
            ))
            traffic.append(packet)
        
        return traffic
    
    @staticmethod
    def create_dns_tunneling_traffic(src_ip, domain_base, count):
        """Generate DNS tunneling-like traffic"""
        traffic = []
        base_time = 1640995200
        
        for i in range(count):
            packet = Mock()
            packet.time = base_time + i
            packet.haslayer.return_value = True
            
            # Create long, data-like subdomain
            data_part = f"{'a' * 50}{i:06d}"
            domain = f"{data_part}.{domain_base}"
            
            packet.__getitem__ = Mock(return_value=Mock(
                src=src_ip,
                qname=Mock(decode=Mock(return_value=domain))
            ))
            traffic.append(packet)
        
        return traffic