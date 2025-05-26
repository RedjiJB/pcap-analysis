#!/usr/bin/env python3
"""
Credential Extractor - Find passwords in PCAP files
"""

from scapy.all import *
import re
import base64
import argparse
from datetime import datetime

def extract_ftp_creds(pcap_file):
    """Extract FTP credentials"""
    packets = rdpcap(pcap_file)
    creds = []
    
    for pkt in packets:
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            
            # FTP USER command
            if payload.startswith('USER'):
                username = payload.split()[1].strip()
                creds.append({
                    'type': 'FTP',
                    'username': username,
                    'src_ip': pkt[IP].src if IP in pkt else 'Unknown',
                    'dst_ip': pkt[IP].dst if IP in pkt else 'Unknown',
                    'timestamp': datetime.fromtimestamp(pkt.time)
                })
            
            # FTP PASS command
            elif payload.startswith('PASS'):
                password = payload.split()[1].strip()
                if creds and creds[-1]['type'] == 'FTP':
                    creds[-1]['password'] = password
    
    return creds

def extract_http_auth(pcap_file):
    """Extract HTTP Basic Authentication"""
    packets = rdpcap(pcap_file)
    creds = []
    
    for pkt in packets:
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            
            # Look for Authorization header
            if b'Authorization: Basic' in payload:
                auth_line = payload.split(b'Authorization: Basic ')[1].split(b'\r\n')[0]
                try:
                    decoded = base64.b64decode(auth_line).decode('utf-8')
                    username, password = decoded.split(':', 1)
                    
                    creds.append({
                        'type': 'HTTP Basic Auth',
                        'username': username,
                        'password': password,
                        'src_ip': pkt[IP].src if IP in pkt else 'Unknown',
                        'dst_ip': pkt[IP].dst if IP in pkt else 'Unknown',
                        'timestamp': datetime.fromtimestamp(pkt.time)
                    })
                except:
                    pass
    
    return creds

def extract_form_data(pcap_file):
    """Extract potential form submissions"""
    packets = rdpcap(pcap_file)
    forms = []
    
    for pkt in packets:
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            
            # Look for POST data
            if 'POST' in payload and 'Content-Type: application/x-www-form-urlencoded' in payload:
                # Extract form data
                data_match = re.search(r'\r\n\r\n(.+)', payload, re.DOTALL)
                if data_match:
                    form_data = data_match.group(1)
                    
                    # Look for password fields
                    if 'password=' in form_data or 'pass=' in form_data or 'pwd=' in form_data:
                        forms.append({
                            'type': 'HTTP Form',
                            'data': form_data[:200],  # First 200 chars
                            'src_ip': pkt[IP].src if IP in pkt else 'Unknown',
                            'dst_ip': pkt[IP].dst if IP in pkt else 'Unknown',
                            'timestamp': datetime.fromtimestamp(pkt.time)
                        })
    
    return forms

def main():
    parser = argparse.ArgumentParser(description='Extract credentials from PCAP')
    parser.add_argument('pcap', help='PCAP file to analyze')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    
    args = parser.parse_args()
    
    print(f"[*] Analyzing {args.pcap} for credentials...")
    
    # Extract different credential types
    ftp_creds = extract_ftp_creds(args.pcap)
    http_creds = extract_http_auth(args.pcap)
    form_creds = extract_form_data(args.pcap)
    
    # Combine results
    all_creds = ftp_creds + http_creds + form_creds
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            f.write("# Extracted Credentials\n\n")
            for cred in all_creds:
                f.write(f"## {cred['type']}\n")
                f.write(f"- Time: {cred['timestamp']}\n")
                f.write(f"- Source: {cred.get('src_ip', 'Unknown')}\n")
                f.write(f"- Destination: {cred.get('dst_ip', 'Unknown')}\n")
                if 'username' in cred:
                    f.write(f"- Username: {cred['username']}\n")
                if 'password' in cred:
                    f.write(f"- Password: [REDACTED]\n")
                f.write("\n")
    else:
        for cred in all_creds:
            print(f"\n[+] Found {cred['type']} credential:")
            print(f"    Time: {cred['timestamp']}")
            print(f"    {cred.get('src_ip', 'Unknown')} → {cred.get('dst_ip', 'Unknown')}")
            if 'username' in cred:
                print(f"    Username: {cred['username']}")
    
    print(f"\n[*] Total credentials found: {len(all_creds)}")

if __name__ == "__main__":
    main()