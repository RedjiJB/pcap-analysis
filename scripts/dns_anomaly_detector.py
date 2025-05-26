#!/usr/bin/env python3
"""
DNS Anomaly Detector - Find DNS tunneling and DGA domains
"""

from scapy.all import *
import math
import statistics
import argparse
from datetime import datetime

def calculate_entropy(string):
    """Calculate Shannon entropy of a string"""
    if not string:
        return 0
    
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob if p > 0])
    return entropy

def detect_dga_domains(pcap_file, entropy_threshold=3.5):
    """Detect DGA (Domain Generation Algorithm) domains"""
    packets = rdpcap(pcap_file)
    suspicious_domains = []
    
    for pkt in packets:
        if pkt.haslayer(DNSQR):
            domain = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            
            # Skip common domains
            if any(common in domain for common in ['google', 'microsoft', 'amazon', 'cloudflare']):
                continue
            
            # Calculate entropy of subdomain
            parts = domain.split('.')
            if len(parts) > 2:
                subdomain = parts[0]
                entropy = calculate_entropy(subdomain)
                
                # High entropy suggests randomness (DGA)
                if entropy > entropy_threshold:
                    suspicious_domains.append({
                        'domain': domain,
                        'entropy': entropy,
                        'length': len(subdomain),
                        'timestamp': datetime.fromtimestamp(pkt.time),
                        'src_ip': pkt[IP].src if IP in pkt else 'Unknown'
                    })
            
            # Check for unusually long domains
            if len(domain) > 50 or (len(parts) > 0 and len(parts[0]) > 30):
                suspicious_domains.append({
                    'domain': domain,
                    'reason': 'Unusually long',
                    'timestamp': datetime.fromtimestamp(pkt.time),
                    'src_ip': pkt[IP].src if IP in pkt else 'Unknown'
                })
    
    return suspicious_domains

def detect_dns_tunneling(pcap_file):
    """Detect potential DNS tunneling"""
    packets = rdpcap(pcap_file)
    dns_stats = {}
    tunneling_indicators = []
    
    for pkt in packets:
        if pkt.haslayer(DNSQR):
            src_ip = pkt[IP].src if IP in pkt else 'Unknown'
            query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            
            if src_ip not in dns_stats:
                dns_stats[src_ip] = {
                    'queries': [],
                    'query_sizes': [],
                    'unique_domains': set()
                }
            
            dns_stats[src_ip]['queries'].append(query)
            dns_stats[src_ip]['query_sizes'].append(len(query))
            dns_stats[src_ip]['unique_domains'].add(query.split('.')[-2] if len(query.split('.')) > 1 else query)
    
    # Analyze patterns
    for ip, stats in dns_stats.items():
        # High query rate
        query_rate = len(stats['queries'])
        
        # Large average query size
        avg_query_size = statistics.mean(stats['query_sizes']) if stats['query_sizes'] else 0
        
        # Many unique domains
        unique_ratio = len(stats['unique_domains']) / len(stats['queries']) if stats['queries'] else 0
        
        # DNS tunneling indicators
        if query_rate > 100 or avg_query_size > 40 or unique_ratio > 0.8:
            tunneling_indicators.append({
                'src_ip': ip,
                'query_count': query_rate,
                'avg_query_size': avg_query_size,
                'unique_domains': len(stats['unique_domains']),
                'suspicious_queries': [q for q in stats['queries'] if len(q) > 50][:5]  # Top 5
            })
    
    return tunneling_indicators

def analyze_dns_responses(pcap_file):
    """Analyze DNS responses for anomalies"""
    packets = rdpcap(pcap_file)
    anomalies = []
    
    for pkt in packets:
        if pkt.haslayer(DNSRR):
            # Check for unusual response codes
            if pkt[DNS].rcode != 0:  # Non-NOERROR response
                anomalies.append({
                    'type': 'DNS Error',
                    'rcode': pkt[DNS].rcode,
                    'query': pkt[DNSQR].qname.decode() if pkt.haslayer(DNSQR) else 'Unknown',
                    'timestamp': datetime.fromtimestamp(pkt.time)
                })
            
            # Check for suspicious IPs in responses
            if pkt[DNSRR].type == 1:  # A record
                ip = pkt[DNSRR].rdata
                # Check for private IPs in public DNS
                if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                    anomalies.append({
                        'type': 'Private IP in DNS',
                        'ip': ip,
                        'domain': pkt[DNSQR].qname.decode() if pkt.haslayer(DNSQR) else 'Unknown',
                        'timestamp': datetime.fromtimestamp(pkt.time)
                    })
    
    return anomalies

def main():
    parser = argparse.ArgumentParser(description='Detect DNS anomalies in PCAP')
    parser.add_argument('pcap', help='PCAP file to analyze')
    parser.add_argument('-e', '--entropy', type=float, default=3.5, help='Entropy threshold for DGA detection')
    
    args = parser.parse_args()
    
    print(f"[*] Analyzing DNS traffic in {args.pcap}...")
    
    # Run detections
    dga_domains = detect_dga_domains(args.pcap, args.entropy)
    dns_tunneling = detect_dns_tunneling(args.pcap)
    dns_anomalies = analyze_dns_responses(args.pcap)
    
    # Report results
    print(f"\n[+] DGA Domains Detected: {len(dga_domains)}")
    for domain in dga_domains[:10]:  # Top 10
        print(f"    - {domain['domain']} (entropy: {domain.get('entropy', 'N/A'):.2f})")
    
    print(f"\n[+] DNS Tunneling Indicators: {len(dns_tunneling)}")
    for indicator in dns_tunneling:
        print(f"    - {indicator['src_ip']}: {indicator['query_count']} queries, avg size: {indicator['avg_query_size']:.1f}")
    
    print(f"\n[+] DNS Anomalies: {len(dns_anomalies)}")
    for anomaly in dns_anomalies[:10]:
        print(f"    - {anomaly['type']}: {anomaly}")
    
    print("\n[*] Analysis complete!")

if __name__ == "__main__":
    main()