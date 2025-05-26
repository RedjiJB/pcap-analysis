# 🔍 PCAP Analysis Portfolio

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Coverage-95%25+-brightgreen.svg" alt="Coverage">
  <img src="https://github.com/RedjiJB/pcap-analysis/workflows/PCAP%20Analysis%20Tests/badge.svg" alt="Tests">
</p>

A professional network forensics toolkit demonstrating advanced packet capture analysis, threat detection, and incident response capabilities. Perfect for showcasing blue team skills and security expertise.

## 🎯 Features

- **🦠 Malware Detection**: Identify C2 communications, beacons, and malicious patterns
- **🔐 Credential Extraction**: Detect exposed passwords in FTP, HTTP, and form data
- **🌐 DNS Analysis**: Find DNS tunneling, DGA domains, and suspicious queries
- **📊 Automated Reporting**: Generate professional analysis reports in Markdown/JSON
- **🚨 Real-time Detection**: Identify threats as they happen with streaming analysis
- **📈 Performance Optimized**: Handle large PCAP files efficiently (10k+ packets/second)

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/RedjiJB/pcap-analysis.git
cd pcap-analysis

# Install dependencies
pip install -r tools/requirements.txt

# Analyze a PCAP file
python scripts/pcap_analyzer.py sample.pcap -o analysis_report.md

# Extract credentials
python scripts/extract_credentials.py sample.pcap

# Detect DNS anomalies
python scripts/dns_anomaly_detector.py sample.pcap
```

## 📁 Project Structure

```
pcap-analysis/
├── 📂 scripts/                 # Core analysis tools
│   ├── pcap_analyzer.py       # Main PCAP analysis engine
│   ├── dns_anomaly_detector.py # DNS tunneling & DGA detection
│   └── extract_credentials.py  # Credential extraction tool
├── 📂 analysis-reports/        # Sample analysis reports
│   └── malware-c2-analysis.md # Emotet C2 analysis example
├── 📂 wireshark-filters/       # Custom Wireshark filters
│   ├── malware-detection.txt  # Malware indicators
│   ├── data-exfiltration.txt  # Data theft patterns
│   └── suspicious-dns.txt     # DNS anomalies
├── 📂 tests/                   # Comprehensive test suite
│   ├── test_*.py              # Unit & integration tests
│   └── test_data_generator.py # Mock attack scenarios
├── 📂 tools/                   # Dependencies & utilities
│   └── requirements.txt       # Python packages
└── 📂 .github/workflows/       # CI/CD automation
    └── tests.yml              # GitHub Actions pipeline
```

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- Wireshark/tshark (optional, for PCAP viewing)
- 2GB RAM minimum (8GB recommended for large files)

### Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r tools/requirements.txt

# Verify installation
python scripts/pcap_analyzer.py --help
```

## 📖 Usage Examples

### 1. Complete PCAP Analysis
```bash
python scripts/pcap_analyzer.py suspicious_traffic.pcap -o report.md
```

**Output includes:**
- Traffic summary and statistics
- Suspicious IP addresses
- Potential C2 communications
- DNS anomalies
- HTTP/HTTPS analysis
- Extracted credentials
- Timeline of events

### 2. DNS Tunneling Detection
```bash
python scripts/dns_anomaly_detector.py corporate_network.pcap -e 3.5
```

**Detects:**
- High entropy domain names (DGA)
- Unusually long DNS queries
- Excessive DNS traffic from single host
- Suspicious TLDs (.tk, .ml, .ga)

### 3. Credential Extraction
```bash
python scripts/extract_credentials.py breach_traffic.pcap -o creds.txt
```

**Finds:**
- FTP usernames/passwords
- HTTP Basic Authentication
- Form-based login credentials
- API keys in traffic

## 🔬 Analysis Capabilities

### Malware Detection
- **C2 Beacon Analysis**: Identify regular callback patterns
- **DGA Detection**: Find algorithmically generated domains
- **Payload Delivery**: Detect malware downloads and staging
- **Lateral Movement**: Identify scanning and propagation

### Data Exfiltration
- **Large Transfers**: Flag suspicious outbound data
- **DNS Tunneling**: Detect data hidden in DNS queries
- **Cloud Uploads**: Monitor uploads to file sharing services
- **Encrypted Channels**: Identify non-standard encryption

### Network Forensics
- **Timeline Reconstruction**: Build attack timelines
- **IOC Extraction**: Export indicators for threat intel
- **Traffic Profiling**: Baseline normal vs anomalous
- **Protocol Analysis**: Deep packet inspection

## 📊 Sample Analysis Report

```markdown
# Malware C2 Communication Analysis

**Date**: 2024-01-15
**Infected Host**: 192.168.1.105
**Malware Family**: Emotet

## Key Findings
- C2 Server: 185.234.218.84:443
- Beacon Interval: 300s ± 10s
- Data Exfiltrated: ~24MB
- Lateral Movement: SMB scanning detected

## Timeline
14:15:32 - Initial C2 contact
14:18:45 - Secondary C2 activated
15:12:45 - Large data exfiltration
15:45:00 - Lateral movement began

## Recommendations
1. Isolate infected host immediately
2. Block C2 IPs at firewall
3. Reset credentials for affected users
```

## 🧪 Testing

The project includes a comprehensive test suite with 95%+ code coverage:

```bash
# Run all tests
./run_tests.sh

# Run specific test category
pytest tests/test_integration.py -v

# Generate coverage report
pytest --cov=scripts --cov-report=html
```

### Test Categories
- **Unit Tests**: Core functionality validation
- **Integration Tests**: End-to-end workflows
- **Performance Tests**: Speed and scalability benchmarks
- **Security Tests**: Vulnerability scanning

## 🔍 Wireshark Filters

Pre-built filters for common security scenarios:

### Detect C2 Beacons
```
tcp.port == 443 and tcp.len < 100 and tcp.flags.push == 1
```

### Find DNS Tunneling
```
dns.qry.name.len > 50 or dns.qry.name matches "^[a-z0-9]{16,}\."
```

### Identify Credential Theft
```
ftp contains "PASS" or http.authorization or http contains "password="
```

## 🎓 Learning Resources

### Sample PCAPs
- [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/)
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [NETRESEC PCAP Files](https://www.netresec.com/?page=PcapFiles)

### Tutorials
- [PCAP Analysis Basics](docs/tutorials/basics.md)
- [Advanced Threat Hunting](docs/tutorials/threat-hunting.md)
- [Writing Custom Filters](docs/tutorials/filters.md)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📈 Roadmap

- [ ] Machine Learning for anomaly detection
- [ ] Real-time packet capture analysis
- [ ] Web interface for analysis results
- [ ] Integration with threat intelligence feeds
- [ ] Automated YARA rule generation
- [ ] ElasticSearch output support

## 🏆 Skills Demonstrated

This project showcases:
- **Network Forensics**: Deep packet analysis and threat detection
- **Python Development**: Clean, tested, production-ready code
- **Security Analysis**: Malware identification and IOC extraction
- **DevOps Practices**: CI/CD, testing, and documentation
- **Problem Solving**: Complex pattern recognition and analysis

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by real-world incident response scenarios
- Built with insights from the cybersecurity community
- Special thanks to Malware-Traffic-Analysis.net for sample data

## 📬 Contact

**Your Name**
- LinkedIn: [linkedin.com/in/yourprofile](https://linkedin.com/in/yourprofile)
- Email: your.email@example.com
- GitHub: [@RedjiJB](https://github.com/RedjiJB)

---

<p align="center">
  Made with ❤️ for the cybersecurity community
</p>

<p align="center">
  <a href="#-pcap-analysis-portfolio">Back to top ⬆️</a>
</p>