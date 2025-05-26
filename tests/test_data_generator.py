#!/usr/bin/env python3
"""
Test data generator for PCAP Analysis testing
Generates realistic mock packet data for testing without requiring actual PCAP files
"""

import random
import time
import base64
from datetime import datetime, timedelta
from unittest.mock import Mock
import ipaddress


class PacketGenerator:
    """Generate realistic mock packet data"""
    
    def __init__(self):
        self.start_time = time.time()
        self.ip_counter = 0
        
        # Realistic data pools
        self.internal_ips = [f"192.168.1.{i}" for i in range(100, 120)]
        self.external_ips = [
            "8.8.8.8", "1.1.1.1", "208.67.222.222",  # DNS servers
            "93.184.216.34", "172.217.16.142",  # Popular sites
            "185.234.218.84", "91.243.80.142",  # Suspicious IPs
        ]
        
        self.domains = {
            'legitimate': [
                "google.com", "microsoft.com", "amazon.com", "cloudflare.com",
                "github.com", "stackoverflow.com", "wikipedia.org"
            ],
            'suspicious': [
                "mal-ware-c2.tk", "botnet-control.ml", "exfiltrate-data.ga",
                "phishing-site.cf", "ransomware-pay.xyz"
            ],
            'dga': self._generate_dga_domains(20)
        }
        
        self.user_agents = {
            'normal': [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            ],
            'suspicious': [
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                "Wget/1.19.4", "curl/7.68.0", "python-requests/2.25.1"
            ]
        }
    
    def _generate_dga_domains(self, count):
        """Generate DGA-like domain names"""
        dga_domains = []
        chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
        tlds = ['com', 'net', 'org', 'info', 'biz']
        
        for _ in range(count):
            length = random.randint(12, 25)
            subdomain = ''.join(random.choice(chars) for _ in range(length))
            tld = random.choice(tlds)
            dga_domains.append(f"{subdomain}.{tld}")
        
        return dga_domains
    
    def generate_ip_packet(self, packet_type='normal', timestamp=None):
        """Generate a mock IP packet"""
        packet = Mock()
        packet.time = timestamp or (self.start_time + self.ip_counter)
        self.ip_counter += 1
        
        # IP layer
        if packet_type == 'normal':
            packet.src = random.choice(self.internal_ips)
            packet.dst = random.choice(self.external_ips)
        elif packet_type == 'c2':
            packet.src = self.internal_ips[0]  # Infected host
            packet.dst = random.choice(self.external_ips[-2:])  # Suspicious IPs
        elif packet_type == 'scan':
            packet.src = self.internal_ips[0]
            packet.dst = f"192.168.1.{random.randint(1, 254)}"
        
        # Add layer checking
        packet.haslayer = Mock(return_value=True)
        packet.__contains__ = Mock(return_value=True)
        
        return packet
    
    def generate_dns_packet(self, query_type='normal', timestamp=None):
        """Generate a mock DNS packet"""
        packet = self.generate_ip_packet('normal', timestamp)
        
        # DNS layer
        dns_layer = Mock()
        dns_layer.qr = 0  # Query
        dns_layer.qd = Mock()
        
        if query_type == 'normal':
            domain = random.choice(self.domains['legitimate'])
        elif query_type == 'suspicious':
            domain = random.choice(self.domains['suspicious'])
        elif query_type == 'dga':
            domain = random.choice(self.domains['dga'])
        elif query_type == 'tunneling':
            # Long subdomain for DNS tunneling
            data = base64.b64encode(b"exfiltrated data here").decode()
            domain = f"{data}.tunnel.example.com"
        else:
            domain = "example.com"
        
        dns_layer.qd.qname = Mock(decode=Mock(return_value=domain))
        dns_layer.qd.qtype = 1  # A record
        
        # Make packet behave correctly
        packet.__getitem__ = Mock(side_effect=lambda x: {
            'DNS': dns_layer,
            'DNSQR': dns_layer,
            'IP': Mock(src=packet.src, dst=packet.dst)
        }.get(str(x), Mock()))
        
        return packet
    
    def generate_http_packet(self, request_type='normal', timestamp=None):
        """Generate a mock HTTP packet"""
        packet = self.generate_ip_packet('normal', timestamp)
        
        # TCP layer
        tcp_layer = Mock()
        tcp_layer.sport = random.randint(49152, 65535)
        tcp_layer.dport = 80 if request_type != 'https' else 443
        
        # Raw layer with HTTP data
        raw_layer = Mock()
        
        if request_type == 'normal':
            user_agent = random.choice(self.user_agents['normal'])
            uri = random.choice(['/index.html', '/api/data', '/images/logo.png'])
            method = 'GET'
        elif request_type == 'suspicious':
            user_agent = random.choice(self.user_agents['suspicious'])
            uri = random.choice(['/cmd.php', '/shell.aspx', '/upload.jsp'])
            method = random.choice(['GET', 'POST'])
        elif request_type == 'exfiltration':
            user_agent = random.choice(self.user_agents['normal'])
            uri = '/upload'
            method = 'POST'
        else:
            user_agent = "Mozilla/5.0"
            uri = "/"
            method = "GET"
        
        http_request = f"{method} {uri} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: {user_agent}\r\n\r\n"
        
        if method == 'POST' and request_type == 'exfiltration':
            # Add large POST data
            http_request += "a" * 10000  # 10KB of data
        
        raw_layer.load = http_request.encode()
        
        # Setup packet layers
        packet.__getitem__ = Mock(side_effect=lambda x: {
            'TCP': tcp_layer,
            'Raw': raw_layer,
            'IP': Mock(src=packet.src, dst=packet.dst)
        }.get(str(x), Mock()))
        
        return packet
    
    def generate_ftp_credentials(self, timestamp=None):
        """Generate FTP credential packets"""
        packets = []
        
        # USER command
        user_packet = self.generate_ip_packet('normal', timestamp)
        user_packet.__getitem__ = Mock(side_effect=lambda x: 
            Mock(load=b"USER admin\r\n") if str(x) == 'Raw' else Mock()
        )
        packets.append(user_packet)
        
        # PASS command
        pass_packet = self.generate_ip_packet('normal', timestamp + 1 if timestamp else None)
        pass_packet.__getitem__ = Mock(side_effect=lambda x:
            Mock(load=b"PASS password123\r\n") if str(x) == 'Raw' else Mock()
        )
        packets.append(pass_packet)
        
        return packets
    
    def generate_c2_beacon_traffic(self, duration=3600, interval=300):
        """Generate C2 beacon pattern traffic"""
        packets = []
        current_time = self.start_time
        
        for _ in range(duration // interval):
            # Beacon packet
            packet = self.generate_ip_packet('c2', current_time)
            
            # TCP layer
            tcp_layer = Mock()
            tcp_layer.sport = 49999
            tcp_layer.dport = 443
            tcp_layer.flags = 0x18  # PSH+ACK
            
            packet.__getitem__ = Mock(side_effect=lambda x: {
                'TCP': tcp_layer,
                'IP': Mock(src=packet.src, dst=packet.dst)
            }.get(str(x), Mock()))
            
            packets.append(packet)
            
            # Add some jitter
            current_time += interval + random.randint(-10, 10)
        
        return packets
    
    def generate_port_scan_traffic(self, target_network="192.168.1.0/24", ports=[22, 80, 443, 445, 3389]):
        """Generate port scanning traffic"""
        packets = []
        scanner_ip = self.internal_ips[0]
        
        # Generate IPs in target network
        network = ipaddress.ip_network(target_network)
        target_ips = [str(ip) for ip in list(network.hosts())[:20]]  # First 20 hosts
        
        for target_ip in target_ips:
            for port in ports:
                packet = Mock()
                packet.time = self.start_time + len(packets) * 0.001  # 1ms between scans
                packet.src = scanner_ip
                packet.dst = target_ip
                
                # TCP SYN packet
                tcp_layer = Mock()
                tcp_layer.sport = random.randint(49152, 65535)
                tcp_layer.dport = port
                tcp_layer.flags = 0x02  # SYN
                
                packet.haslayer = Mock(return_value=True)
                packet.__contains__ = Mock(return_value=True)
                packet.__getitem__ = Mock(side_effect=lambda x: {
                    'TCP': tcp_layer,
                    'IP': Mock(src=scanner_ip, dst=target_ip)
                }.get(str(x), Mock()))
                
                packets.append(packet)
        
        return packets
    
    def generate_malware_download(self, timestamp=None):
        """Generate malware download traffic"""
        packets = []
        
        # Initial GET request
        request_packet = self.generate_http_packet('suspicious', timestamp)
        request_packet.__getitem__.return_value.load = b"GET /payload.exe HTTP/1.1\r\nHost: malware.bad\r\n\r\n"
        packets.append(request_packet)
        
        # Response with executable
        response_packet = self.generate_ip_packet('normal', timestamp + 1 if timestamp else None)
        response_packet.src, response_packet.dst = response_packet.dst, response_packet.src  # Reverse direction
        
        # Simulate executable content
        exe_header = b"MZ\x90\x00\x03\x00\x00\x00"  # PE header
        response_packet.__getitem__ = Mock(side_effect=lambda x:
            Mock(load=b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n" + exe_header)
            if str(x) == 'Raw' else Mock()
        )
        packets.append(response_packet)
        
        return packets
    
    def generate_data_exfiltration(self, size_mb=10, timestamp=None):
        """Generate data exfiltration traffic"""
        packets = []
        bytes_per_packet = 1400  # Typical MTU minus headers
        total_packets = (size_mb * 1024 * 1024) // bytes_per_packet
        
        current_time = timestamp or self.start_time
        
        for i in range(min(total_packets, 100)):  # Limit to 100 packets for testing
            packet = self.generate_ip_packet('c2', current_time + i * 0.01)
            
            # TCP layer
            tcp_layer = Mock()
            tcp_layer.sport = 50000
            tcp_layer.dport = 443
            tcp_layer.len = bytes_per_packet
            
            # Simulate encrypted data
            raw_layer = Mock()
            raw_layer.load = b'\x00' * bytes_per_packet
            
            packet.__getitem__ = Mock(side_effect=lambda x: {
                'TCP': tcp_layer,
                'Raw': raw_layer,
                'IP': Mock(src=packet.src, dst=packet.dst)
            }.get(str(x), Mock()))
            
            packets.append(packet)
        
        return packets


class ScenarioGenerator:
    """Generate complete attack scenarios"""
    
    def __init__(self):
        self.packet_gen = PacketGenerator()
    
    def generate_apt_scenario(self):
        """Generate Advanced Persistent Threat scenario"""
        packets = []
        base_time = time.time()
        
        # Phase 1: Initial reconnaissance (DNS queries)
        for i in range(10):
            packet = self.packet_gen.generate_dns_packet('normal', base_time + i)
            packets.append(packet)
        
        # Phase 2: Exploit delivery (suspicious HTTP)
        exploit_packets = self.packet_gen.generate_malware_download(base_time + 20)
        packets.extend(exploit_packets)
        
        # Phase 3: C2 establishment (beacons)
        c2_packets = self.packet_gen.generate_c2_beacon_traffic(duration=1800, interval=300)
        packets.extend(c2_packets)
        
        # Phase 4: Lateral movement (port scanning)
        scan_packets = self.packet_gen.generate_port_scan_traffic()
        packets.extend(scan_packets)
        
        # Phase 5: Data exfiltration
        exfil_packets = self.packet_gen.generate_data_exfiltration(size_mb=5)
        packets.extend(exfil_packets)
        
        return packets
    
    def generate_ransomware_scenario(self):
        """Generate ransomware attack scenario"""
        packets = []
        base_time = time.time()
        
        # Initial infection vector (email attachment simulation)
        packets.extend(self.packet_gen.generate_malware_download(base_time))
        
        # C2 check-in
        for i in range(5):
            packet = self.packet_gen.generate_ip_packet('c2', base_time + 10 + i * 60)
            packets.append(packet)
        
        # Rapid file encryption (lots of local activity - not network visible)
        # But followed by:
        
        # Ransom note delivery attempts
        for i in range(10):
            packet = self.packet_gen.generate_http_packet('suspicious', base_time + 600 + i)
            packet.__getitem__.return_value.load = b"POST /ransom-paid HTTP/1.1\r\n\r\nBTC_ADDRESS=1A1zP1..."
            packets.append(packet)
        
        return packets
    
    def generate_cryptomining_scenario(self):
        """Generate cryptomining scenario"""
        packets = []
        base_time = time.time()
        
        # Mining pool connection
        for i in range(100):
            packet = self.packet_gen.generate_ip_packet('normal', base_time + i * 30)
            packet.dst = "pool.mining.com"
            
            # Stratum protocol simulation
            tcp_layer = Mock()
            tcp_layer.dport = 3333  # Common mining port
            
            packet.__getitem__ = Mock(side_effect=lambda x: {
                'TCP': tcp_layer,
                'IP': Mock(src=packet.src, dst=packet.dst)
            }.get(str(x), Mock()))
            
            packets.append(packet)
        
        return packets


def create_test_dataset(scenario='mixed'):
    """Create a test dataset with various packet types"""
    gen = PacketGenerator()
    scenario_gen = ScenarioGenerator()
    
    if scenario == 'mixed':
        packets = []
        
        # Normal traffic (60%)
        for _ in range(600):
            packet_type = random.choice(['dns', 'http', 'https'])
            if packet_type == 'dns':
                packets.append(gen.generate_dns_packet('normal'))
            else:
                packets.append(gen.generate_http_packet('normal'))
        
        # Suspicious traffic (30%)
        for _ in range(300):
            packet_type = random.choice(['dns_suspicious', 'http_suspicious', 'c2'])
            if packet_type == 'dns_suspicious':
                packets.append(gen.generate_dns_packet(random.choice(['suspicious', 'dga'])))
            elif packet_type == 'http_suspicious':
                packets.append(gen.generate_http_packet('suspicious'))
            else:
                packets.extend(gen.generate_c2_beacon_traffic(duration=300, interval=60))
        
        # Attack scenarios (10%)
        packets.extend(scenario_gen.generate_apt_scenario()[:100])
        
        # Shuffle to simulate realistic traffic mix
        random.shuffle(packets)
        return packets
    
    elif scenario == 'apt':
        return scenario_gen.generate_apt_scenario()
    
    elif scenario == 'ransomware':
        return scenario_gen.generate_ransomware_scenario()
    
    elif scenario == 'cryptomining':
        return scenario_gen.generate_cryptomining_scenario()
    
    else:
        return []


if __name__ == "__main__":
    # Generate sample data for testing
    print("Generating test datasets...")
    
    datasets = {
        'mixed': create_test_dataset('mixed'),
        'apt': create_test_dataset('apt'),
        'ransomware': create_test_dataset('ransomware'),
        'cryptomining': create_test_dataset('cryptomining')
    }
    
    for name, packets in datasets.items():
        print(f"\n{name.upper()} scenario: {len(packets)} packets")
        print(f"Time range: {packets[0].time} - {packets[-1].time if packets else 'N/A'}")
        
        # Sample some packets
        for i, packet in enumerate(packets[:5]):
            print(f"  Packet {i}: {getattr(packet, 'src', 'N/A')} -> {getattr(packet, 'dst', 'N/A')}")