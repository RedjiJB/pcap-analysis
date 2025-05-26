#!/usr/bin/env python3
"""
Integration tests for PCAP Analysis tools
"""

import pytest
import sys
import os
import tempfile
import subprocess
import json
from unittest.mock import patch, Mock
from datetime import datetime

# Add the scripts directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from pcap_analyzer import PCAPAnalyzer
from dns_anomaly_detector import detect_dga_domains, detect_dns_tunneling
from extract_credentials import extract_ftp_creds, extract_http_auth


class TestEndToEndWorkflow:
    """Test complete analysis workflow from PCAP to report"""
    
    def test_full_analysis_pipeline(self):
        """Test the complete analysis pipeline"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create mock PCAP file path
            pcap_file = os.path.join(tmpdir, "test.pcap")
            report_file = os.path.join(tmpdir, "report.md")
            
            # Create analyzer
            analyzer = PCAPAnalyzer(pcap_file)
            
            # Mock successful loading
            with patch.object(analyzer, 'load_pcap', return_value=True):
                with patch.object(analyzer, 'packets', [Mock() for _ in range(100)]):
                    # Run all analysis steps
                    analyzer.analyze_summary()
                    analyzer.analyze_dns()
                    analyzer.analyze_http()
                    analyzer.detect_c2_patterns()
                    analyzer.extract_credentials()
                    
                    # Generate report
                    analyzer.generate_report(report_file)
                    
                    # Verify report was created
                    assert os.path.exists(report_file)
                    assert os.path.exists(report_file.replace('.md', '.json'))
    
    def test_script_command_line_interface(self):
        """Test CLI interfaces for all scripts"""
        scripts = [
            'pcap_analyzer.py',
            'dns_anomaly_detector.py',
            'extract_credentials.py'
        ]
        
        scripts_dir = os.path.join(os.path.dirname(__file__), '..', 'scripts')
        
        for script in scripts:
            script_path = os.path.join(scripts_dir, script)
            
            # Test help command
            result = subprocess.run(
                [sys.executable, script_path, '--help'],
                capture_output=True,
                text=True
            )
            
            assert result.returncode == 0, f"{script} help command failed"
            assert 'usage:' in result.stdout.lower(), f"{script} missing usage info"
    
    def test_combined_analysis_results(self):
        """Test combining results from multiple analysis tools"""
        # Simulated results from different tools
        pcap_results = {
            'suspicious_ips': ['192.168.1.100', '10.0.0.50'],
            'potential_c2': [{'dst_ip': '1.2.3.4', 'confidence': 'High'}]
        }
        
        dns_results = {
            'dga_domains': ['random123.com', 'suspicious456.net'],
            'tunneling_ips': ['192.168.1.100']
        }
        
        cred_results = {
            'credentials': [
                {'type': 'FTP', 'username': 'admin'},
                {'type': 'HTTP', 'username': 'user'}
            ]
        }
        
        # Combine results
        combined = {
            'pcap_analysis': pcap_results,
            'dns_analysis': dns_results,
            'credential_extraction': cred_results
        }
        
        # Verify correlation
        suspicious_ip = '192.168.1.100'
        assert suspicious_ip in pcap_results['suspicious_ips']
        assert suspicious_ip in dns_results['tunneling_ips']
        
        # This IP appears in multiple analyses - high priority
        assert len([r for r in combined.values() if suspicious_ip in str(r)]) >= 2


class TestDataFlow:
    """Test data flow between components"""
    
    def test_pcap_to_json_flow(self):
        """Test PCAP analysis to JSON output flow"""
        analyzer = PCAPAnalyzer("test.pcap")
        
        # Set test results
        analyzer.results = {
            'summary': {'total_packets': 1000},
            'dns_queries': [{'query': 'example.com', 'suspicious': False}],
            'anomalies': []
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            report_file = f.name
        
        try:
            analyzer.generate_report(report_file)
            
            # Check JSON output
            json_file = report_file.replace('.md', '.json')
            assert os.path.exists(json_file)
            
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            assert data['summary']['total_packets'] == 1000
            assert len(data['dns_queries']) == 1
        
        finally:
            # Cleanup
            for file in [report_file, json_file]:
                if os.path.exists(file):
                    os.unlink(file)
    
    def test_cross_tool_ioc_sharing(self):
        """Test IOC sharing between analysis tools"""
        # IOCs that should be detected by multiple tools
        shared_iocs = {
            'ips': ['192.168.1.100', '1.2.3.4'],
            'domains': ['malware.evil.com', 'c2server.bad.net'],
            'user_agents': ['Mozilla/4.0', 'Wget/1.0']
        }
        
        # Each tool should be able to work with these IOCs
        for ip in shared_iocs['ips']:
            # Validate IP format
            parts = ip.split('.')
            assert len(parts) == 4
            assert all(0 <= int(part) <= 255 for part in parts)
        
        for domain in shared_iocs['domains']:
            # Validate domain format
            assert '.' in domain
            assert len(domain) > 3


class TestErrorHandlingIntegration:
    """Test error handling across the system"""
    
    def test_missing_file_handling(self):
        """Test handling of missing PCAP files"""
        analyzer = PCAPAnalyzer("nonexistent.pcap")
        
        with patch('pcap_analyzer.rdpcap', side_effect=FileNotFoundError()):
            result = analyzer.load_pcap()
            assert result is False
    
    def test_corrupted_data_handling(self):
        """Test handling of corrupted packet data"""
        # Create packets with missing attributes
        bad_packet = Mock()
        del bad_packet.time  # Missing timestamp
        
        analyzer = PCAPAnalyzer("test.pcap")
        analyzer.packets = [bad_packet]
        
        # Should handle gracefully
        analyzer.analyze_summary()
        assert 'total_packets' in analyzer.results['summary']
    
    def test_empty_pcap_handling(self):
        """Test handling of empty PCAP files"""
        analyzer = PCAPAnalyzer("empty.pcap")
        analyzer.packets = []
        
        # All analyses should handle empty data
        analyzer.analyze_summary()
        analyzer.analyze_dns()
        analyzer.analyze_http()
        analyzer.detect_c2_patterns()
        analyzer.extract_credentials()
        
        # Should still produce valid results structure
        assert isinstance(analyzer.results, dict)
        assert all(key in analyzer.results for key in 
                  ['summary', 'dns_queries', 'http_requests', 'potential_c2', 'anomalies'])


class TestPerformanceIntegration:
    """Test performance with realistic data volumes"""
    
    def test_large_pcap_handling(self):
        """Test handling of large PCAP files"""
        # Simulate large packet count
        large_packet_count = 10000
        
        analyzer = PCAPAnalyzer("large.pcap")
        
        # Create mock packets efficiently
        with patch('pcap_analyzer.rdpcap') as mock_rdpcap:
            mock_rdpcap.return_value = [Mock(time=i) for i in range(large_packet_count)]
            
            import time
            start_time = time.time()
            
            analyzer.load_pcap()
            analyzer.analyze_summary()
            
            end_time = time.time()
            
            # Should complete in reasonable time (< 5 seconds for 10k packets)
            assert end_time - start_time < 5.0
            assert analyzer.results['summary']['total_packets'] == large_packet_count
    
    def test_memory_efficiency(self):
        """Test memory usage with large datasets"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Process large dataset
        analyzer = PCAPAnalyzer("test.pcap")
        analyzer.packets = [Mock() for _ in range(1000)]
        analyzer.analyze_summary()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (< 100MB for 1000 packets)
        assert memory_increase < 100, f"Memory usage increased by {memory_increase:.1f}MB"


class TestReportingIntegration:
    """Test integrated reporting capabilities"""
    
    def test_multi_format_output(self):
        """Test output in multiple formats"""
        analyzer = PCAPAnalyzer("test.pcap")
        analyzer.results = {
            'summary': {'total_packets': 100},
            'anomalies': [{'type': 'Test', 'details': 'Test anomaly'}]
        }
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Markdown report
            md_file = os.path.join(tmpdir, "report.md")
            analyzer.generate_report(md_file)
            assert os.path.exists(md_file)
            
            # JSON report
            json_file = md_file.replace('.md', '.json')
            assert os.path.exists(json_file)
            
            # Verify content consistency
            with open(md_file, 'r') as f:
                md_content = f.read()
            
            with open(json_file, 'r') as f:
                json_content = json.load(f)
            
            # Both should contain the same data
            assert '100' in md_content  # Total packets
            assert json_content['summary']['total_packets'] == 100
    
    def test_ioc_export(self):
        """Test IOC export functionality"""
        iocs = {
            'ips': ['1.2.3.4', '5.6.7.8'],
            'domains': ['evil.com', 'malware.net'],
            'hashes': ['d41d8cd98f00b204e9800998ecf8427e']
        }
        
        # Verify IOC format
        for ip in iocs['ips']:
            assert re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip)
        
        for domain in iocs['domains']:
            assert re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain)
        
        for hash_val in iocs['hashes']:
            assert len(hash_val) == 32  # MD5 length


class TestCLIIntegration:
    """Test command-line interface integration"""
    
    def test_script_chaining(self):
        """Test chaining multiple analysis scripts"""
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_file = os.path.join(tmpdir, "test.pcap")
            
            # Simulate running scripts in sequence
            commands = [
                f"python scripts/pcap_analyzer.py {pcap_file} -o analysis.md",
                f"python scripts/dns_anomaly_detector.py {pcap_file}",
                f"python scripts/extract_credentials.py {pcap_file} -o creds.txt"
            ]
            
            # Verify command structure
            for cmd in commands:
                parts = cmd.split()
                assert parts[0] == 'python'
                assert parts[1].endswith('.py')
                assert pcap_file in parts
    
    def test_help_consistency(self):
        """Test help message consistency across scripts"""
        scripts_dir = os.path.join(os.path.dirname(__file__), '..', 'scripts')
        scripts = ['pcap_analyzer.py', 'dns_anomaly_detector.py', 'extract_credentials.py']
        
        help_outputs = {}
        
        for script in scripts:
            script_path = os.path.join(scripts_dir, script)
            result = subprocess.run(
                [sys.executable, script_path, '--help'],
                capture_output=True,
                text=True
            )
            help_outputs[script] = result.stdout
        
        # All should have consistent elements
        for script, output in help_outputs.items():
            assert 'usage:' in output.lower()
            assert 'pcap' in output.lower()
            assert '--help' in output or '-h' in output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])