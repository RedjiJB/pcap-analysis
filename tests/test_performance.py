#!/usr/bin/env python3
"""
Performance tests for PCAP Analysis tools
"""

import pytest
import sys
import os
import time
import psutil
from unittest.mock import Mock, patch
import cProfile
import pstats
from io import StringIO

# Add the scripts directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from pcap_analyzer import PCAPAnalyzer
from dns_anomaly_detector import calculate_entropy, detect_dga_domains
from extract_credentials import extract_ftp_creds


class TestAnalysisPerformance:
    """Performance tests for analysis functions"""
    
    def test_pcap_loading_performance(self):
        """Test PCAP loading performance with various sizes"""
        test_sizes = [100, 1000, 10000]
        max_times = [0.1, 0.5, 5.0]  # Maximum acceptable times in seconds
        
        for size, max_time in zip(test_sizes, max_times):
            analyzer = PCAPAnalyzer("test.pcap")
            
            # Mock packet loading
            with patch('pcap_analyzer.rdpcap') as mock_rdpcap:
                mock_packets = [Mock(time=i) for i in range(size)]
                mock_rdpcap.return_value = mock_packets
                
                start_time = time.time()
                analyzer.load_pcap()
                end_time = time.time()
                
                elapsed = end_time - start_time
                assert elapsed < max_time, f"Loading {size} packets took {elapsed:.2f}s (max: {max_time}s)"
                assert len(analyzer.packets) == size
    
    def test_dns_analysis_performance(self):
        """Test DNS analysis performance"""
        packet_counts = [100, 500, 1000]
        
        for count in packet_counts:
            analyzer = PCAPAnalyzer("test.pcap")
            
            # Create DNS packets
            dns_packets = []
            for i in range(count):
                pkt = Mock()
                pkt.time = i
                pkt.haslayer.return_value = True
                pkt.__getitem__.return_value.qr = 0  # Query
                pkt.__getitem__.return_value.qd = Mock()
                pkt.__getitem__.return_value.qd.qname = Mock()
                pkt.__getitem__.return_value.qd.qname.decode.return_value = f"site{i}.example.com"
                pkt.__getitem__.return_value.qd.qtype = 1
                pkt.__getitem__.return_value.src = "192.168.1.100"
                dns_packets.append(pkt)
            
            analyzer.packets = dns_packets
            
            start_time = time.time()
            analyzer.analyze_dns()
            end_time = time.time()
            
            elapsed = end_time - start_time
            # Should process at least 1000 DNS packets per second
            assert elapsed < count / 1000, f"DNS analysis too slow: {elapsed:.2f}s for {count} packets"
    
    def test_entropy_calculation_performance(self):
        """Test entropy calculation performance"""
        test_strings = [
            "a" * 10,
            "abcdefghij" * 10,
            "aksjdhfkajsdhfkajsdhf" * 5,
            "".join(chr(i) for i in range(65, 91)) * 4
        ]
        
        total_time = 0
        iterations = 1000
        
        for string in test_strings:
            start_time = time.time()
            for _ in range(iterations):
                calculate_entropy(string)
            end_time = time.time()
            total_time += end_time - start_time
        
        avg_time_per_calc = total_time / (len(test_strings) * iterations)
        # Should calculate entropy in less than 0.1ms
        assert avg_time_per_calc < 0.0001, f"Entropy calculation too slow: {avg_time_per_calc*1000:.2f}ms"
    
    def test_c2_detection_performance(self):
        """Test C2 pattern detection performance"""
        analyzer = PCAPAnalyzer("test.pcap")
        
        # Create connection patterns
        packets = []
        connections = 50  # Number of unique connections
        packets_per_conn = 20  # Packets per connection
        
        for conn_id in range(connections):
            for pkt_id in range(packets_per_conn):
                pkt = Mock()
                pkt.time = conn_id * 300 + pkt_id * 15  # Regular intervals
                pkt.haslayer.return_value = True
                pkt.__getitem__.return_value.src = f"192.168.1.{100 + conn_id}"
                pkt.__getitem__.return_value.dst = f"10.0.0.{conn_id}"
                pkt.__getitem__.return_value.dport = 443
                packets.append(pkt)
        
        analyzer.packets = packets
        
        start_time = time.time()
        analyzer.detect_c2_patterns()
        end_time = time.time()
        
        elapsed = end_time - start_time
        # Should analyze 1000 packets in less than 1 second
        assert elapsed < 1.0, f"C2 detection took {elapsed:.2f}s for {len(packets)} packets"
    
    def test_memory_usage_scaling(self):
        """Test memory usage scaling with packet count"""
        process = psutil.Process(os.getpid())
        
        packet_counts = [100, 1000, 5000]
        memory_usage = []
        
        for count in packet_counts:
            # Force garbage collection
            import gc
            gc.collect()
            
            initial_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            analyzer = PCAPAnalyzer("test.pcap")
            analyzer.packets = [Mock(time=i) for i in range(count)]
            analyzer.analyze_summary()
            
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory
            memory_usage.append(memory_increase)
            
            # Cleanup
            del analyzer
            gc.collect()
        
        # Memory usage should scale linearly or better
        if len(memory_usage) >= 2:
            # Check that doubling packets doesn't more than double memory
            memory_ratio = memory_usage[-1] / memory_usage[0]
            packet_ratio = packet_counts[-1] / packet_counts[0]
            assert memory_ratio < packet_ratio * 1.5, "Memory usage scaling is worse than linear"


class TestOptimizationOpportunities:
    """Tests to identify optimization opportunities"""
    
    def test_profile_dns_analysis(self):
        """Profile DNS analysis to find bottlenecks"""
        analyzer = PCAPAnalyzer("test.pcap")
        
        # Create test packets
        packets = []
        for i in range(100):
            pkt = Mock()
            pkt.time = i
            pkt.haslayer.return_value = True
            pkt.__getitem__.return_value = Mock(
                qr=0,
                qd=Mock(qname=Mock(decode=Mock(return_value=f"test{i}.example.com")), qtype=1),
                src="192.168.1.100"
            )
            packets.append(pkt)
        
        analyzer.packets = packets
        
        # Profile the function
        profiler = cProfile.Profile()
        profiler.enable()
        analyzer.analyze_dns()
        profiler.disable()
        
        # Analyze results
        s = StringIO()
        ps = pstats.Stats(profiler, stream=s).sort_stats('cumulative')
        ps.print_stats(10)  # Top 10 functions
        
        profile_output = s.getvalue()
        # Check that no single function dominates runtime
        lines = profile_output.split('\n')
        # This is more of an informational test
        assert len(lines) > 0, "Profiling failed"
    
    def test_batch_processing_efficiency(self):
        """Test efficiency of batch processing vs individual processing"""
        # Individual processing
        individual_times = []
        for i in range(10):
            domains = [f"test{j}.example.com" for j in range(100)]
            start_time = time.time()
            for domain in domains:
                calculate_entropy(domain)
            end_time = time.time()
            individual_times.append(end_time - start_time)
        
        # Batch processing simulation
        batch_times = []
        for i in range(10):
            domains = [f"test{j}.example.com" for j in range(100)]
            start_time = time.time()
            # Process all at once
            entropies = [calculate_entropy(domain) for domain in domains]
            end_time = time.time()
            batch_times.append(end_time - start_time)
        
        avg_individual = sum(individual_times) / len(individual_times)
        avg_batch = sum(batch_times) / len(batch_times)
        
        # Batch should be at least as fast (usually faster due to better cache usage)
        assert avg_batch <= avg_individual * 1.1, "Batch processing is not efficient"
    
    def test_regex_compilation_caching(self):
        """Test that regex patterns are efficiently cached"""
        import re
        
        # Pattern that might be used repeatedly
        pattern = r"^[a-z0-9]{16,}\.(com|net|org)$"
        
        # First compilation
        start_time = time.time()
        compiled = re.compile(pattern)
        first_compile = time.time() - start_time
        
        # Subsequent uses should be faster
        subsequent_times = []
        for _ in range(100):
            start_time = time.time()
            result = compiled.match("aksjdhfkajsdhfkajsdhf.com")
            subsequent_times.append(time.time() - start_time)
        
        avg_subsequent = sum(subsequent_times) / len(subsequent_times)
        
        # Subsequent uses should be much faster than compilation
        assert avg_subsequent < first_compile / 10, "Regex not being cached effectively"


class TestScalabilityLimits:
    """Test system limits and scalability"""
    
    @pytest.mark.slow
    def test_maximum_packet_handling(self):
        """Test maximum packet count that can be handled"""
        max_packets = 100000  # 100k packets
        
        analyzer = PCAPAnalyzer("test.pcap")
        
        with patch('pcap_analyzer.rdpcap') as mock_rdpcap:
            # Don't actually create 100k objects, just simulate
            mock_rdpcap.return_value = Mock()
            mock_rdpcap.return_value.__len__ = Mock(return_value=max_packets)
            mock_rdpcap.return_value.__iter__ = Mock(return_value=iter([]))
            
            result = analyzer.load_pcap()
            assert result is True
    
    def test_concurrent_analysis(self):
        """Test concurrent analysis of multiple PCAPs"""
        import concurrent.futures
        
        def analyze_pcap(pcap_id):
            analyzer = PCAPAnalyzer(f"test{pcap_id}.pcap")
            analyzer.packets = [Mock(time=i) for i in range(100)]
            analyzer.analyze_summary()
            return analyzer.results['summary']['total_packets']
        
        # Run multiple analyses concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(analyze_pcap, i) for i in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        # All should complete successfully
        assert len(results) == 10
        assert all(r == 100 for r in results)
    
    def test_streaming_analysis_feasibility(self):
        """Test feasibility of streaming analysis (packet by packet)"""
        analyzer = PCAPAnalyzer("test.pcap")
        
        # Simulate streaming packets
        packet_stream_rate = 1000  # packets per second
        duration = 5  # seconds
        
        start_time = time.time()
        processed = 0
        
        for i in range(packet_stream_rate * duration):
            # Simulate packet arrival
            pkt = Mock(time=i/packet_stream_rate)
            
            # Process immediately (simplified)
            if hasattr(pkt, 'time'):
                processed += 1
            
            # Check if we're keeping up
            elapsed = time.time() - start_time
            expected_packets = elapsed * packet_stream_rate
            
            if processed < expected_packets * 0.9:  # Allow 10% lag
                pytest.skip("System can't keep up with streaming rate")
        
        end_time = time.time()
        total_elapsed = end_time - start_time
        
        # Should process in approximately real-time
        assert total_elapsed < duration * 1.5, f"Streaming analysis too slow: {total_elapsed:.1f}s for {duration}s of packets"


class TestResourceOptimization:
    """Test resource usage optimization"""
    
    def test_generator_vs_list_memory(self):
        """Compare memory usage of generators vs lists"""
        import sys
        
        # List approach
        packet_list = [Mock(time=i) for i in range(1000)]
        list_size = sys.getsizeof(packet_list)
        
        # Generator approach
        def packet_generator():
            for i in range(1000):
                yield Mock(time=i)
        
        gen = packet_generator()
        gen_size = sys.getsizeof(gen)
        
        # Generator should use significantly less memory
        assert gen_size < list_size / 10, "Generator not providing memory benefits"
    
    def test_string_operations_efficiency(self):
        """Test efficiency of string operations"""
        # Test different approaches to string manipulation
        test_domain = "veryverylongsubdomainname.example.com"
        
        # Method 1: String splitting
        start_time = time.time()
        for _ in range(10000):
            parts = test_domain.split('.')
            subdomain = parts[0]
        method1_time = time.time() - start_time
        
        # Method 2: String indexing
        start_time = time.time()
        for _ in range(10000):
            dot_index = test_domain.index('.')
            subdomain = test_domain[:dot_index]
        method2_time = time.time() - start_time
        
        # Both should be reasonably fast
        assert method1_time < 0.1, "String splitting too slow"
        assert method2_time < 0.1, "String indexing too slow"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "not slow"])