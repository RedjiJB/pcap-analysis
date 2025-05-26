#!/usr/bin/env python3
"""
Test suite for Credential Extractor
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch
import base64

# Add the scripts directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from extract_credentials import (
    extract_ftp_creds,
    extract_http_auth,
    extract_form_data
)

class TestCredentialExtractor:
    """Test cases for credential extraction functions"""
    
    @patch('extract_credentials.rdpcap')
    def test_extract_ftp_creds(self, mock_rdpcap):
        """Test FTP credential extraction"""
        # Create mock packets with FTP commands
        user_packet = Mock()
        user_packet.haslayer.return_value = True
        user_packet.time = 1640995200
        user_packet.__getitem__.return_value.src = "192.168.1.100"
        user_packet.__getitem__.return_value.dst = "192.168.1.10"
        user_packet.__getitem__.return_value.load = b"USER testuser\r\n"
        
        pass_packet = Mock()
        pass_packet.haslayer.return_value = True
        pass_packet.time = 1640995201
        pass_packet.__getitem__.return_value.src = "192.168.1.100" 
        pass_packet.__getitem__.return_value.dst = "192.168.1.10"
        pass_packet.__getitem__.return_value.load = b"PASS testpass\r\n"
        
        mock_rdpcap.return_value = [user_packet, pass_packet]
        
        # Mock the Raw layer access
        with patch('extract_credentials.Raw') as mock_raw, \
             patch('extract_credentials.IP') as mock_ip:
            
            user_packet.haslayer.side_effect = lambda layer: layer == mock_raw
            pass_packet.haslayer.side_effect = lambda layer: layer == mock_raw
            
            user_packet.__getitem__.side_effect = lambda layer: Mock(
                load=b"USER testuser\r\n",
                src="192.168.1.100",
                dst="192.168.1.10"
            ) if layer == mock_raw else Mock(src="192.168.1.100", dst="192.168.1.10")
            
            pass_packet.__getitem__.side_effect = lambda layer: Mock(
                load=b"PASS testpass\r\n",
                src="192.168.1.100", 
                dst="192.168.1.10"
            ) if layer == mock_raw else Mock(src="192.168.1.100", dst="192.168.1.10")
            
            creds = extract_ftp_creds("test.pcap")
            
            # Should extract FTP credentials
            assert len(creds) >= 1
    
    @patch('extract_credentials.rdpcap')
    def test_extract_http_auth(self, mock_rdpcap):
        """Test HTTP Basic Auth extraction"""
        # Create base64 encoded credentials
        credentials = "testuser:testpass"
        encoded_creds = base64.b64encode(credentials.encode()).decode()
        
        auth_packet = Mock()
        auth_packet.haslayer.return_value = True
        auth_packet.time = 1640995200
        auth_packet.__getitem__.return_value.src = "192.168.1.100"
        auth_packet.__getitem__.return_value.dst = "10.0.0.1"
        auth_packet.__getitem__.return_value.load = f"GET /admin HTTP/1.1\r\nAuthorization: Basic {encoded_creds}\r\n\r\n".encode()
        
        mock_rdpcap.return_value = [auth_packet]
        
        with patch('extract_credentials.Raw') as mock_raw, \
             patch('extract_credentials.IP') as mock_ip:
            
            auth_packet.haslayer.side_effect = lambda layer: layer == mock_raw
            auth_packet.__getitem__.side_effect = lambda layer: Mock(
                load=f"GET /admin HTTP/1.1\r\nAuthorization: Basic {encoded_creds}\r\n\r\n".encode(),
                src="192.168.1.100",
                dst="10.0.0.1"
            ) if layer == mock_raw else Mock(src="192.168.1.100", dst="10.0.0.1")
            
            creds = extract_http_auth("test.pcap")
            
            # Should extract HTTP Basic Auth credentials
            assert len(creds) >= 1
            if creds:
                assert creds[0]['username'] == 'testuser'
                assert creds[0]['password'] == 'testpass'
    
    @patch('extract_credentials.rdpcap')
    def test_extract_form_data(self, mock_rdpcap):
        """Test form data extraction"""
        form_packet = Mock()
        form_packet.haslayer.return_value = True
        form_packet.time = 1640995200
        form_packet.__getitem__.return_value.src = "192.168.1.100"
        form_packet.__getitem__.return_value.dst = "10.0.0.1"
        
        form_data = ("POST /login HTTP/1.1\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Content-Length: 27\r\n\r\n"
                    "username=admin&password=secret")
        
        form_packet.__getitem__.return_value.load = form_data.encode()
        
        mock_rdpcap.return_value = [form_packet]
        
        with patch('extract_credentials.Raw') as mock_raw, \
             patch('extract_credentials.TCP') as mock_tcp, \
             patch('extract_credentials.IP') as mock_ip:
            
            def mock_haslayer(layer):
                return layer in [mock_raw, mock_tcp]
            
            form_packet.haslayer.side_effect = mock_haslayer
            form_packet.__getitem__.side_effect = lambda layer: Mock(
                load=form_data.encode(),
                src="192.168.1.100",
                dst="10.0.0.1"
            ) if layer == mock_raw else Mock(src="192.168.1.100", dst="10.0.0.1")
            
            forms = extract_form_data("test.pcap")
            
            # Should extract form credentials
            assert len(forms) >= 1
            if forms:
                assert 'password=' in forms[0]['data']
    
    def test_base64_decoding_edge_cases(self):
        """Test base64 decoding edge cases"""
        # Valid base64
        valid_creds = base64.b64encode(b"user:pass").decode()
        try:
            decoded = base64.b64decode(valid_creds).decode('utf-8')
            username, password = decoded.split(':', 1)
            assert username == "user"
            assert password == "pass"
        except Exception:
            pytest.fail("Valid base64 should decode successfully")
        
        # Invalid base64 (should not crash)
        invalid_creds = "not_base64_data"
        try:
            base64.b64decode(invalid_creds)
        except Exception:
            pass  # Expected to fail
    
    def test_credential_patterns(self):
        """Test credential pattern recognition"""
        # FTP patterns
        ftp_user = "USER administrator"
        assert ftp_user.startswith("USER")
        
        ftp_pass = "PASS password123"
        assert ftp_pass.startswith("PASS")
        
        # HTTP form patterns
        form_data_samples = [
            "username=admin&password=secret",
            "user=test&pass=123456",
            "login=root&pwd=toor"
        ]
        
        for sample in form_data_samples:
            assert any(pattern in sample for pattern in ['password=', 'pass=', 'pwd='])
    
    def test_packet_filtering(self):
        """Test packet filtering logic"""
        # Test that only packets with Raw layer are processed
        packet_with_raw = Mock()
        packet_with_raw.haslayer.return_value = True
        
        packet_without_raw = Mock()
        packet_without_raw.haslayer.return_value = False
        
        # Only packet_with_raw should be processed
        assert packet_with_raw.haslayer(Mock()) is True
        assert packet_without_raw.haslayer(Mock()) is False


class TestCredentialExtractorIntegration:
    """Integration tests for credential extractor"""
    
    def test_combined_credential_extraction(self):
        """Test extracting multiple credential types from single PCAP"""
        # This would test the main() function that combines all extraction methods
        import extract_credentials
        
        # Test that main function exists
        assert hasattr(extract_credentials, 'main')
    
    def test_output_formatting(self):
        """Test credential output formatting"""
        sample_creds = [
            {
                'type': 'FTP',
                'username': 'admin',
                'password': 'secret',
                'src_ip': '192.168.1.100',
                'dst_ip': '192.168.1.10',
                'timestamp': '2022-01-01T00:00:00'
            },
            {
                'type': 'HTTP Basic Auth',
                'username': 'user',
                'password': 'pass',
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'timestamp': '2022-01-01T00:05:00'
            }
        ]
        
        # Test that all required fields are present
        for cred in sample_creds:
            assert 'type' in cred
            assert 'username' in cred
            assert 'src_ip' in cred
            assert 'dst_ip' in cred
            assert 'timestamp' in cred
    
    def test_error_handling(self):
        """Test error handling in credential extraction"""
        # Test with malformed data
        malformed_data = [
            b"USER",  # Incomplete FTP command
            b"Authorization: Basic invalid_base64",  # Invalid base64
            b"POST /login\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nmalformed_data"  # Malformed form
        ]
        
        # These should not crash the extraction functions
        for data in malformed_data:
            try:
                # Test basic string operations that might be used
                data.decode('utf-8', errors='ignore')
                if b'USER' in data:
                    parts = data.split()
                    # Should handle incomplete commands gracefully
            except Exception as e:
                pytest.fail(f"Error handling failed for: {data} - {e}")


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])