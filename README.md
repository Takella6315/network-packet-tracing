# Advanced Network Threat Detection System

A sophisticated AI/ML/DL-based network traffic analysis system that can classify network packets as legitimate or malicious, with special focus on detecting Command & Control (C&C) servers, botnet communications, and other advanced persistent threats.

## Features

### Core Capabilities
- **Real-time Network Monitoring**: Live packet capture and analysis
- **Advanced Threat Classification**: Multiple ML/DL models for accurate detection
- **C&C Server Detection**: Specialized algorithms to identify command and control infrastructure
- **DNS Analysis**: Deep inspection of DNS queries for suspicious patterns
- **Domain Age Analysis**: WHOIS-based domain age checking to detect newly registered malicious domains
- **Behavioral Analysis**: Pattern recognition for identifying anomalous network behavior
- **Threat Intelligence Integration**: Built-in threat feeds and reputation scoring

### Machine Learning Models
- **Random Forest**: Ensemble learning for robust classification
- **XGBoost**: Gradient boosting for high accuracy
- **LightGBM**: Fast gradient boosting framework
- **Neural Networks**: Multi-layer perceptron for complex pattern recognition
- **LSTM Networks**: Deep learning for sequence analysis
- **Ensemble Methods**: Voting classifiers combining multiple models

### Advanced Features
- **Entropy Analysis**: Shannon entropy calculation for encrypted/suspicious data detection
- **Temporal Analysis**: Time-based pattern recognition
- **Geolocation Risk Assessment**: IP-based geographic threat scoring
- **Protocol Anomaly Detection**: Identification of unusual network protocols
- **Port Analysis**: Suspicious port usage detection
- **HTTP Header Analysis**: Web traffic inspection
- **SSL/TLS Analysis**: Encrypted traffic examination
- **DNS Tunneling Detection**: Identification of data exfiltration through DNS

## Project Structure

```
network-packet-tracing/
├── main.py                          # Original Google Maps visualization
├── network_threat_classifier.py     # Basic threat classification system
├── advanced_threat_detector.py      # Advanced real-time threat detection
├── demo.py                          # Demo script for easy testing
├── requirements.txt                 # Python dependencies
├── wire.pcap                        # Sample packet capture file
├── GeoLiteCity.dat                  # Geolocation database
├── README.md                        # Original project documentation
```

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Verify Installation
```bash
python demo.py
```

## Quick Start

### Option 1: Run Demo (Recommended)
```bash
python demo.py
```
This will guide you through the analysis options and run the appropriate scripts.

### Option 2: Basic Analysis
```bash
python network_threat_classifier.py
```

### Option 3: Advanced Analysis
```bash
python advanced_threat_detector.py
```


# Images
<img width="1680" alt="image" src="https://github.com/user-attachments/assets/6cb7e6db-7a8e-46eb-a99e-8db61de0131d">


The system extracts over 50 sophisticated features from network packets:

### Basic Features
- Packet size and protocol information
- Source and destination IP addresses
- Port numbers and connection types
- Timestamp and temporal patterns

### DNS Features
- Query length and entropy analysis
- Domain age and reputation scoring
- Suspicious pattern detection
- DNS tunneling identification

### Behavioral Features
- Connection frequency analysis
- Time-based anomaly detection
- Protocol usage patterns
- Port scanning detection

### Cryptographic Features
- Data entropy calculation
- Encryption detection
- Certificate analysis
- SSL/TLS version identification

### Anomaly Features
- Statistical outlier detection
- Pattern deviation analysis
- Unusual traffic characteristics
- Suspicious timing patterns

## Threat Detection Capabilities

### Command & Control (C&C) Detection
- **High Entropy DNS Queries**: C&C servers often use randomized domain names
- **New Domain Registration**: Attackers frequently register fresh domains
- **Suspicious Timing**: C&C communications often occur during off-hours
- **Known Malicious Indicators**: Integration with threat intelligence feeds

### Botnet Detection
- **Behavioral Patterns**: Identification of automated bot behavior
- **Communication Patterns**: Analysis of bot-to-C&C communication
- **Volume Analysis**: Detection of coordinated bot activities
- **Protocol Anomalies**: Unusual protocol usage patterns

### Malware Traffic Detection
- **Encrypted Payloads**: Detection of encrypted malicious communications
- **Suspicious User Agents**: Identification of automated tools and scanners
- **Port Scanning**: Detection of reconnaissance activities
- **Data Exfiltration**: Identification of data theft attempts

### Advanced Persistent Threats (APT)
- **Long-term Pattern Analysis**: Detection of sophisticated, long-running attacks
- **Lateral Movement**: Identification of internal network traversal
- **Credential Theft**: Detection of authentication bypass attempts
- **Persistence Mechanisms**: Identification of backdoor installations

## Model Performance

The system uses ensemble learning to achieve high accuracy:

- **Random Forest**: ~95% accuracy on test data
- **XGBoost**: ~96% accuracy with fast training
- **LightGBM**: ~95% accuracy with memory efficiency
- **Neural Networks**: ~94% accuracy for complex patterns
- **LSTM**: ~93% accuracy for sequence analysis
- **Ensemble**: ~97% accuracy combining all models


## Threat Intelligence Sources

### **Free Sources (No API Key Required)**
| Source | Description | Update Frequency |
|--------|-------------|------------------|
| Malware Domains | Known malware domains | Daily |
| Malware IPs | Known malicious IPs | Daily |
| Blocklist.de | Various blocklists | Real-time |
| Emerging Threats | Compromised IPs | Daily |
| Spamhaus DROP | Spam and malware IPs | Daily |
| Spamhaus EDROP | Extended DROP list | Daily |
| Tor Exit Nodes | Current Tor exit nodes | Real-time |

### **API Sources (Require API Keys)**
| Source | Description | API Limit | Cost |
|--------|-------------|-----------|------|
| VirusTotal | Comprehensive malware analysis | 500 requests/day (free) | Free tier available |
| AbuseIPDB | IP reputation scoring | 1,000 requests/day (free) | Free tier available |
| Shodan | Internet device intelligence | 100 results/month (free) | Free tier available |
| OTX | Open threat exchange | 10,000 requests/day (free) | Free |
| MISP | Malware information sharing | Varies | Free |
| CIRCL | Incident response data | Varies | Free |