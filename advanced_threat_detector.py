import dpkt
import socket
import struct
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import dns.resolver
import dns.reversename
import whois
import requests
import json
import hashlib
import re
import threading
import time
import queue
from collections import defaultdict, Counter, deque
import warnings
warnings.filterwarnings('ignore')

# Import dynamic threat intelligence
from threat_intelligence import get_threat_intelligence_manager

# ML/DL Libraries
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, IsolationForest, VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
import xgboost as xgb
import lightgbm as lgb

# Deep Learning
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import (LSTM, Dense, Conv1D, MaxPooling1D, Dropout, 
                                   Input, Attention, Bidirectional, GRU, BatchNormalization)
from tensorflow.keras.optimizers import Adam, RMSprop
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
from tensorflow.keras.utils import to_categorical

# Network Analysis
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

class AdvancedThreatDetector:
    """
    Advanced real-time network threat detection system with sophisticated ML/DL capabilities
    """
    
    def __init__(self, pcap_file=None, real_time=False, geoip_db='GeoLiteCity.dat'):
        self.pcap_file = pcap_file
        self.real_time = real_time
        self.geoip_db = geoip_db
        self.features = []
        self.labels = []
        self.dns_cache = {}
        self.domain_age_cache = {}
        self.suspicious_domains = set()
        self.behavioral_profiles = defaultdict(list)
        self.anomaly_scores = []
        self.packet_queue = queue.Queue()
        self.is_monitoring = False
        
        # Initialize dynamic threat intelligence
        self.threat_intel = get_threat_intelligence_manager()
        
        # Advanced model ensemble
        self.models = {}
        self.scalers = {}
        self.ensemble_model = None
        
        # Real-time monitoring
        self.monitoring_thread = None
        self.alert_threshold = 0.8
        self.alert_history = deque(maxlen=1000)
        
        # Load threat intelligence and behavioral patterns
        self._load_threat_intelligence()
        self._load_behavioral_patterns()
        
    def _load_threat_intelligence(self):
        """Load comprehensive threat intelligence feeds"""
        try:
            # Update threat intelligence feeds
            print("Updating dynamic threat intelligence feeds...")
            self.threat_intel.update_all_feeds()
            
            # Get statistics
            stats = self.threat_intel.get_statistics()
            print(f"Loaded {stats['total_indicators']} threat indicators from {len(stats['by_source'])} sources")
            
            # Static threat intelligence patterns (complementary to dynamic feeds)
            self.threat_intelligence = {
                'high_risk_ports': {4444, 6666, 6667, 6668, 6669, 7000, 8080, 9999},
                'suspicious_user_agents': [
                    'curl', 'wget', 'python-requests', 'bot', 'crawler',
                    'scanner', 'exploit', 'backdoor'
                ],
                'malicious_patterns': [
                    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP in domain
                    r'[a-z0-9]{32,}',  # Long random strings
                    r'[0-9]{8,}',  # Long number sequences
                ]
            }
            
        except Exception as e:
            print(f"Warning: Could not load threat intelligence: {e}")
    
    def _load_behavioral_patterns(self):
        """Load known behavioral patterns for anomaly detection"""
        self.behavioral_patterns = {
            'normal_dns_entropy_range': (2.0, 4.5),
            'normal_packet_size_range': (64, 1500),
            'normal_connection_frequency': (1, 10),  # connections per minute
            'suspicious_time_windows': [(2, 6), (22, 24)],  # night hours
        }
    
    def extract_advanced_features(self, packet_data):
        """Extract comprehensive features for threat detection"""
        features = {}
        
        # Basic packet features
        features['packet_size'] = len(packet_data['raw_data'])
        features['protocol'] = packet_data.get('protocol', 0)
        features['src_port'] = packet_data.get('src_port', 0)
        features['dst_port'] = packet_data.get('dst_port', 0)
        features['timestamp'] = packet_data.get('timestamp', 0)
        
        # IP-based features
        src_ip = packet_data.get('src_ip', '')
        dst_ip = packet_data.get('dst_ip', '')
        
        features['is_private_src'] = self._is_private_ip(src_ip)
        features['is_private_dst'] = self._is_private_ip(dst_ip)
        features['is_known_malicious_src'] = src_ip in self.known_malicious_ips
        features['is_known_malicious_dst'] = dst_ip in self.known_malicious_ips
        
        # Advanced IP analysis
        features['ip_reputation_score'] = self._calculate_ip_reputation(src_ip, dst_ip)
        features['geolocation_risk'] = self._calculate_geolocation_risk(src_ip, dst_ip)
        
        # DNS-based features
        dns_features = self._extract_advanced_dns_features(packet_data)
        features.update(dns_features)
        
        # Temporal features
        temporal_features = self._extract_temporal_features(packet_data)
        features.update(temporal_features)
        
        # Behavioral features
        behavioral_features = self._extract_behavioral_features(packet_data)
        features.update(behavioral_features)
        
        # Network flow features
        flow_features = self._extract_flow_features(packet_data)
        features.update(flow_features)
        
        # Entropy and randomness features
        entropy_features = self._extract_entropy_features(packet_data)
        features.update(entropy_features)
        
        # HTTP-based features
        http_features = self._extract_http_features(packet_data)
        features.update(http_features)
        
        # Cryptographic features
        crypto_features = self._extract_crypto_features(packet_data)
        features.update(crypto_features)
        
        # Anomaly detection features
        anomaly_features = self._extract_anomaly_features(packet_data)
        features.update(anomaly_features)
        
        return features
    
    def _calculate_ip_reputation(self, src_ip, dst_ip):
        """Calculate IP reputation score based on various factors"""
        score = 0
        
        # Check against known malicious IPs using dynamic threat intelligence
        src_malicious, src_confidence, src_threat_level = self.threat_intel.check_ip_reputation(src_ip)
        dst_malicious, dst_confidence, dst_threat_level = self.threat_intel.check_ip_reputation(dst_ip)
        
        if src_malicious or dst_malicious:
            score += 50
        
        # Check for suspicious IP patterns
        for ip in [src_ip, dst_ip]:
            if ip:
                # Check for dynamic IP ranges (often used by attackers)
                if self._is_dynamic_ip(ip):
                    score += 20
                
                # Check for VPN/Proxy IPs (simplified check)
                if self._is_likely_vpn_ip(ip):
                    score += 15
        
        return min(score, 100)
    
    def _is_dynamic_ip(self, ip):
        """Check if IP is likely from a dynamic range"""
        try:
            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                # Check for common dynamic IP ranges
                first_octet = int(ip_parts[0])
                if first_octet in [10, 172, 192]:  # Private ranges
                    return True
                # Add more sophisticated checks here
        except:
            pass
        return False
    
    def _is_likely_vpn_ip(self, ip):
        """Simplified check for VPN/proxy IPs"""
        # This is a simplified implementation
        # In production, use a proper VPN/proxy detection service
        return False
    
    def _calculate_geolocation_risk(self, src_ip, dst_ip):
        """Calculate geolocation-based risk score"""
        risk_score = 0
        
        # Check source IP geolocation
        if src_ip:
            src_risk = self._get_country_risk_score(src_ip)
            risk_score += src_risk * 0.6
        
        # Check destination IP geolocation
        if dst_ip:
            dst_risk = self._get_country_risk_score(dst_ip)
            risk_score += dst_risk * 0.4
        
        return min(risk_score, 100)
    
    def _get_country_risk_score(self, ip):
        """Get country-based risk score for IP"""
        # Simplified country risk scoring
        # In production, use a proper geolocation service with risk data
        high_risk_countries = ['CN', 'RU', 'KP', 'IR']  # Example high-risk countries
        
        try:
            # This would integrate with a real geolocation service
            # For now, return a random score for demonstration
            return np.random.randint(0, 30)
        except:
            return 0
    
    def _extract_advanced_dns_features(self, packet_data):
        """Extract advanced DNS-based features"""
        features = {}
        
        if 'dns_query' in packet_data:
            query = packet_data['dns_query']
            features['dns_query_length'] = len(query)
            features['dns_query_entropy'] = self._calculate_entropy(query)
            features['dns_query_has_numbers'] = bool(re.search(r'\d', query))
            features['dns_query_has_hyphens'] = '-' in query
            features['dns_query_subdomain_count'] = query.count('.')
            features['dns_query_has_suspicious_pattern'] = self._has_suspicious_dns_pattern(query)
            
            # Domain age analysis
            domain_age = self._get_domain_age(query)
            features['domain_age_days'] = domain_age
            features['is_new_domain'] = domain_age < 30
            features['is_very_old_domain'] = domain_age > 3650
            
            # Domain reputation
            # Check domain reputation using dynamic threat intelligence
            domain_malicious, domain_confidence, domain_threat_level = self.threat_intel.check_domain_reputation(query)
            features['is_known_malicious_domain'] = domain_malicious
            features['domain_threat_confidence'] = domain_confidence
            features['domain_threat_level'] = self._threat_level_to_numeric(domain_threat_level)
            features['domain_reputation_score'] = self._calculate_domain_reputation(query)
            features['domain_typo_squatting_score'] = self._detect_typo_squatting(query)
            
            # DNS tunneling detection
            features['potential_dns_tunneling'] = self._detect_dns_tunneling(query)
            
        else:
            # Set default values for non-DNS packets
            for key in ['dns_query_length', 'dns_query_entropy', 'dns_query_has_numbers',
                       'dns_query_has_hyphens', 'dns_query_subdomain_count', 'dns_query_has_suspicious_pattern',
                       'domain_age_days', 'is_new_domain', 'is_very_old_domain', 'is_known_malicious_domain',
                       'domain_reputation_score', 'domain_typo_squatting_score', 'potential_dns_tunneling']:
                features[key] = 0
        
        return features
    
    def _has_suspicious_dns_pattern(self, query):
        """Check for suspicious DNS query patterns"""
        suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP in domain
            r'[a-z0-9]{32,}',  # Long random strings
            r'[0-9]{8,}',  # Long number sequences
            r'[a-z]{1,3}[0-9]{4,}',  # Short prefix + long numbers
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, query):
                return 1
        return 0
    
    def _detect_typo_squatting(self, domain):
        """Detect potential typo squatting domains"""
        # Simplified typo squatting detection
        # In production, use a proper typo squatting detection service
        common_typos = ['gogle', 'facebok', 'amazom', 'microsft']
        for typo in common_typos:
            if typo in domain.lower():
                return 1
        return 0
    
    def _detect_dns_tunneling(self, query):
        """Detect potential DNS tunneling"""
        # Check for characteristics of DNS tunneling
        if len(query) > 50:  # Very long queries
            return 1
        if query.count('.') > 5:  # Many subdomains
            return 1
        if re.search(r'[A-Za-z0-9+/=]{20,}', query):  # Base64-like encoding
            return 1
        return 0
    
    def _extract_http_features(self, packet_data):
        """Extract HTTP-based features"""
        features = {}
        
        # Check if packet contains HTTP data
        if 'http_data' in packet_data:
            http_data = packet_data['http_data']
            features['http_user_agent_length'] = len(http_data.get('user_agent', ''))
            features['http_user_agent_suspicious'] = self._is_suspicious_user_agent(http_data.get('user_agent', ''))
            features['http_method'] = http_data.get('method', '')
            features['http_response_code'] = http_data.get('response_code', 0)
            features['http_content_length'] = http_data.get('content_length', 0)
            features['http_has_suspicious_headers'] = self._has_suspicious_headers(http_data)
        else:
            features['http_user_agent_length'] = 0
            features['http_user_agent_suspicious'] = 0
            features['http_method'] = ''
            features['http_response_code'] = 0
            features['http_content_length'] = 0
            features['http_has_suspicious_headers'] = 0
        
        return features
    
    def _is_suspicious_user_agent(self, user_agent):
        """Check if user agent is suspicious"""
        if not user_agent:
            return 0
        
        suspicious_agents = self.threat_intelligence.get('suspicious_user_agents', [])
        for agent in suspicious_agents:
            if agent.lower() in user_agent.lower():
                return 1
        return 0
    
    def _has_suspicious_headers(self, http_data):
        """Check for suspicious HTTP headers"""
        suspicious_headers = ['x-forwarded-for', 'x-real-ip', 'x-originating-ip']
        headers = http_data.get('headers', {})
        
        for header in suspicious_headers:
            if header in headers:
                return 1
        return 0
    
    def _extract_crypto_features(self, packet_data):
        """Extract cryptographic features"""
        features = {}
        
        raw_data = packet_data.get('raw_data', b'')
        if raw_data:
            # Check for encrypted data characteristics
            features['data_entropy'] = self._calculate_entropy(raw_data)
            features['is_likely_encrypted'] = self._is_likely_encrypted(raw_data)
            features['has_certificate_data'] = self._has_certificate_data(raw_data)
            features['ssl_tls_version'] = self._detect_ssl_tls_version(raw_data)
        else:
            features['data_entropy'] = 0
            features['is_likely_encrypted'] = 0
            features['has_certificate_data'] = 0
            features['ssl_tls_version'] = 0
        
        return features
    
    def _is_likely_encrypted(self, data):
        """Check if data is likely encrypted"""
        if len(data) < 16:
            return 0
        
        # High entropy suggests encryption
        entropy = self._calculate_entropy(data)
        if entropy > 7.5:  # High entropy threshold
            return 1
        
        # Check for common encryption patterns
        if data.startswith(b'\x16\x03'):  # TLS handshake
            return 1
        
        return 0
    
    def _has_certificate_data(self, data):
        """Check for certificate data"""
        # Look for X.509 certificate patterns
        cert_patterns = [b'-----BEGIN CERTIFICATE-----', b'-----BEGIN RSA PRIVATE KEY-----']
        for pattern in cert_patterns:
            if pattern in data:
                return 1
        return 0
    
    def _detect_ssl_tls_version(self, data):
        """Detect SSL/TLS version"""
        if len(data) < 5:
            return 0
        
        # Check for TLS version in handshake
        if data[0] == 0x16:  # TLS handshake
            if len(data) >= 5:
                version = struct.unpack('>H', data[1:3])[0]
                if version == 0x0301:  # TLS 1.0
                    return 1
                elif version == 0x0302:  # TLS 1.1
                    return 2
                elif version == 0x0303:  # TLS 1.2
                    return 3
                elif version == 0x0304:  # TLS 1.3
                    return 4
        return 0
    
    def _extract_anomaly_features(self, packet_data):
        """Extract features for anomaly detection"""
        features = {}
        
        # Calculate anomaly scores based on behavioral patterns
        features['packet_size_anomaly'] = self._calculate_packet_size_anomaly(packet_data)
        features['timing_anomaly'] = self._calculate_timing_anomaly(packet_data)
        features['protocol_anomaly'] = self._calculate_protocol_anomaly(packet_data)
        features['port_anomaly'] = self._calculate_port_anomaly(packet_data)
        
        return features
    
    def _calculate_packet_size_anomaly(self, packet_data):
        """Calculate packet size anomaly score"""
        packet_size = len(packet_data.get('raw_data', b''))
        normal_range = self.behavioral_patterns['normal_packet_size_range']
        
        if packet_size < normal_range[0] or packet_size > normal_range[1]:
            return abs(packet_size - (normal_range[0] + normal_range[1]) / 2) / 1000
        return 0
    
    def _calculate_timing_anomaly(self, packet_data):
        """Calculate timing anomaly score"""
        timestamp = packet_data.get('timestamp', 0)
        if timestamp:
            dt = datetime.fromtimestamp(timestamp)
            hour = dt.hour
            
            # Check if packet is sent during suspicious hours
            for start_hour, end_hour in self.behavioral_patterns['suspicious_time_windows']:
                if start_hour <= hour <= end_hour:
                    return 1
        return 0
    
    def _calculate_protocol_anomaly(self, packet_data):
        """Calculate protocol anomaly score"""
        protocol = packet_data.get('protocol', 0)
        
        # Check for unusual protocols
        unusual_protocols = [47, 50, 51, 89, 112]  # GRE, ESP, AH, OSPF, LDP
        if protocol in unusual_protocols:
            return 1
        return 0
    
    def _calculate_port_anomaly(self, packet_data):
        """Calculate port anomaly score"""
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        
        # Check for suspicious ports
        suspicious_ports = self.threat_intelligence.get('high_risk_ports', set())
        if src_port in suspicious_ports or dst_port in suspicious_ports:
            return 1
        
        # Check for port scanning patterns
        if src_port > 60000 and dst_port < 1024:  # High source port to low destination port
            return 0.5
        
        return 0
    
    def build_ensemble_model(self, X_train, y_train):
        """Build advanced ensemble model"""
        print("Building advanced ensemble model...")
        
        # Individual models
        rf = RandomForestClassifier(n_estimators=200, max_depth=25, random_state=42)
        xgb_model = xgb.XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.05, random_state=42)
        lgb_model = lgb.LGBMClassifier(n_estimators=200, max_depth=8, learning_rate=0.05, random_state=42)
        svm = SVC(probability=True, random_state=42)
        lr = LogisticRegression(random_state=42, max_iter=1000)
        
        # Deep learning model
        dl_model = self._build_advanced_dl_model(X_train.shape[1])
        
        # Train deep learning model
        dl_model.fit(X_train, y_train, epochs=100, batch_size=32, validation_split=0.2, verbose=0)
        
        # Create ensemble
        self.ensemble_model = VotingClassifier([
            ('rf', rf),
            ('xgb', xgb_model),
            ('lgb', lgb_model),
            ('svm', svm),
            ('lr', lr),
            ('dl', dl_model)
        ], voting='soft')
        
        # Train ensemble
        self.ensemble_model.fit(X_train, y_train)
        
        return self.ensemble_model
    
    def _build_advanced_dl_model(self, input_dim):
        """Build advanced deep learning model"""
        model = Sequential([
            Dense(512, activation='relu', input_shape=(input_dim,)),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(256, activation='relu'),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(128, activation='relu'),
            BatchNormalization(),
            Dropout(0.2),
            
            Dense(64, activation='relu'),
            Dropout(0.2),
            
            Dense(32, activation='relu'),
            Dropout(0.1),
            
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def real_time_monitoring(self, interface='eth0'):
        """Start real-time network monitoring"""
        print(f"Starting real-time monitoring on interface {interface}...")
        self.is_monitoring = True
        
        def packet_callback(packet):
            if self.is_monitoring:
                try:
                    # Process packet in real-time
                    packet_data = self._process_realtime_packet(packet)
                    if packet_data:
                        # Extract features
                        features = self.extract_advanced_features(packet_data)
                        
                        # Predict threat level
                        if self.ensemble_model:
                            threat_score = self._predict_threat_score(features)
                            
                            # Check if alert threshold is exceeded
                            if threat_score > self.alert_threshold:
                                self._generate_alert(packet_data, threat_score)
                        
                        # Add to queue for batch processing
                        self.packet_queue.put((features, packet_data))
                        
                except Exception as e:
                    print(f"Error processing packet: {e}")
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(
            target=lambda: scapy.sniff(iface=interface, prn=packet_callback, store=0)
        )
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
    
    def _process_realtime_packet(self, packet):
        """Process packet for real-time analysis"""
        try:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                
                packet_data = {
                    'timestamp': time.time(),
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'protocol': ip_layer.proto,
                    'raw_data': bytes(packet)
                }
                
                # Extract port information
                if packet.haslayer(TCP):
                    packet_data['src_port'] = packet[TCP].sport
                    packet_data['dst_port'] = packet[TCP].dport
                elif packet.haslayer(UDP):
                    packet_data['src_port'] = packet[UDP].sport
                    packet_data['dst_port'] = packet[UDP].dport
                
                # Extract DNS information
                if packet.haslayer(DNS):
                    dns_layer = packet[DNS]
                    if dns_layer.qd:
                        packet_data['dns_query'] = dns_layer.qd.qname.decode()
                
                # Extract HTTP information
                if packet.haslayer(HTTPRequest):
                    http_layer = packet[HTTPRequest]
                    packet_data['http_data'] = {
                        'method': http_layer.Method.decode(),
                        'user_agent': http_layer.User_Agent.decode() if http_layer.User_Agent else '',
                        'headers': dict(http_layer.headers)
                    }
                
                return packet_data
        except Exception as e:
            print(f"Error processing real-time packet: {e}")
        
        return None
    
    def _predict_threat_score(self, features):
        """Predict threat score for given features"""
        if not self.ensemble_model:
            return 0.0
        
        try:
            # Convert features to array
            feature_array = np.array([list(features.values())]).reshape(1, -1)
            
            # Scale features
            if 'main' in self.scalers:
                feature_array = self.scalers['main'].transform(feature_array)
            
            # Predict probability
            threat_prob = self.ensemble_model.predict_proba(feature_array)[0][1]
            return threat_prob
        except Exception as e:
            print(f"Error predicting threat score: {e}")
            return 0.0
    
    def _generate_alert(self, packet_data, threat_score):
        """Generate security alert"""
        alert = {
            'timestamp': datetime.now(),
            'threat_score': threat_score,
            'src_ip': packet_data.get('src_ip', 'Unknown'),
            'dst_ip': packet_data.get('dst_ip', 'Unknown'),
            'protocol': packet_data.get('protocol', 0),
            'src_port': packet_data.get('src_port', 0),
            'dst_port': packet_data.get('dst_port', 0),
            'dns_query': packet_data.get('dns_query', ''),
            'alert_type': self._classify_alert_type(packet_data, threat_score)
        }
        
        self.alert_history.append(alert)
        
        print(f"\n🚨 SECURITY ALERT 🚨")
        print(f"Time: {alert['timestamp']}")
        print(f"Threat Score: {threat_score:.4f}")
        print(f"Source: {alert['src_ip']}:{alert['src_port']}")
        print(f"Destination: {alert['dst_ip']}:{alert['dst_port']}")
        print(f"Alert Type: {alert['alert_type']}")
        if alert['dns_query']:
            print(f"DNS Query: {alert['dns_query']}")
        print("-" * 50)
    
    def _classify_alert_type(self, packet_data, threat_score):
        """Classify the type of security alert"""
        if threat_score > 0.9:
            return "CRITICAL - High confidence malicious activity"
        elif threat_score > 0.8:
            return "HIGH - Likely malicious activity"
        elif threat_score > 0.6:
            return "MEDIUM - Suspicious activity detected"
        else:
            return "LOW - Potential security concern"
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=1)
        print("Real-time monitoring stopped.")
    
    def generate_comprehensive_report(self):
        """Generate comprehensive threat analysis report"""
        print("\n" + "="*80)
        print("COMPREHENSIVE ADVANCED THREAT ANALYSIS REPORT")
        print("="*80)
        
        # Basic statistics
        total_packets = len(self.features)
        malicious_packets = sum(self.labels)
        benign_packets = total_packets - malicious_packets
        
        print(f"\n📊 PACKET ANALYSIS SUMMARY:")
        print(f"  Total Packets Analyzed: {total_packets:,}")
        print(f"  Malicious Packets: {malicious_packets:,} ({malicious_packets/total_packets*100:.2f}%)")
        print(f"  Benign Packets: {benign_packets:,} ({benign_packets/total_packets*100:.2f}%)")
        
        # Alert summary
        if self.alert_history:
            print(f"\n🚨 REAL-TIME ALERTS:")
            print(f"  Total Alerts Generated: {len(self.alert_history)}")
            
            alert_types = Counter([alert['alert_type'].split(' - ')[0] for alert in self.alert_history])
            for alert_type, count in alert_types.items():
                print(f"  {alert_type}: {count}")
        
        # DNS analysis
        dns_queries = [f for f in self.features if f.get('dns_query_length', 0) > 0]
        print(f"\n🌐 DNS ANALYSIS:")
        print(f"  DNS Queries Found: {len(dns_queries):,}")
        
        if dns_queries:
            new_domains = sum(1 for f in dns_queries if f.get('is_new_domain', False))
            suspicious_domains = sum(1 for f in dns_queries if f.get('domain_reputation_score', 0) > 50)
            tunneling_attempts = sum(1 for f in dns_queries if f.get('potential_dns_tunneling', False))
            
            print(f"  New Domains (< 30 days): {new_domains}")
            print(f"  Suspicious Domains: {suspicious_domains}")
            print(f"  Potential DNS Tunneling: {tunneling_attempts}")
        
        # Security recommendations
        print(f"\n🛡️  SECURITY RECOMMENDATIONS:")
        threat_level = malicious_packets / total_packets if total_packets > 0 else 0
        
        if threat_level > 0.1:
            print("  🔴 CRITICAL THREAT LEVEL:")
            print("     - Immediate network isolation required")
            print("     - Conduct full forensic analysis")
            print("     - Update all security policies")
            print("     - Consider incident response team activation")
        elif threat_level > 0.05:
            print("  🟡 HIGH THREAT LEVEL:")
            print("     - Increase monitoring frequency")
            print("     - Review and update security configurations")
            print("     - Consider additional security tools")
            print("     - Monitor for lateral movement")
        elif threat_level > 0.01:
            print("  🟠 MEDIUM THREAT LEVEL:")
            print("     - Enhanced monitoring recommended")
            print("     - Review security logs")
            print("     - Update threat intelligence feeds")
        else:
            print("  🟢 LOW THREAT LEVEL:")
            print("     - Continue regular monitoring")
            print("     - Maintain current security posture")
            print("     - Regular security assessments recommended")
    
    def visualize_advanced_results(self):
        """Create advanced visualizations"""
        print("\nGenerating advanced visualizations...")
        
        # Set up the plotting style
        plt.style.use('seaborn-v0_8')
        fig, axes = plt.subplots(3, 3, figsize=(20, 15))
        fig.suptitle('Advanced Network Threat Analysis Dashboard', fontsize=16, fontweight='bold')
        
        # 1. Threat Distribution
        threat_counts = Counter(self.labels)
        axes[0, 0].pie([threat_counts[0], threat_counts[1]], 
                      labels=['Benign', 'Malicious'], 
                      autopct='%1.1f%%',
                      colors=['lightgreen', 'lightcoral'],
                      explode=(0, 0.1))
        axes[0, 0].set_title('Threat Distribution')
        
        # 2. Packet Size Distribution
        packet_sizes = [len(f.get('raw_data', b'')) for f in self.features]
        axes[0, 1].hist(packet_sizes, bins=50, alpha=0.7, color='skyblue', edgecolor='black')
        axes[0, 1].set_title('Packet Size Distribution')
        axes[0, 1].set_xlabel('Packet Size (bytes)')
        axes[0, 1].set_ylabel('Frequency')
        
        # 3. DNS Query Entropy
        dns_entropies = [f.get('dns_query_entropy', 0) for f in self.features if f.get('dns_query_entropy', 0) > 0]
        if dns_entropies:
            axes[0, 2].hist(dns_entropies, bins=30, alpha=0.7, color='orange', edgecolor='black')
            axes[0, 2].set_title('DNS Query Entropy Distribution')
            axes[0, 2].set_xlabel('Entropy')
            axes[0, 2].set_ylabel('Frequency')
        else:
            axes[0, 2].text(0.5, 0.5, 'No DNS queries found', ha='center', va='center', transform=axes[0, 2].transAxes)
            axes[0, 2].set_title('DNS Query Entropy Distribution')
        
        # 4. Domain Age Analysis
        domain_ages = [f.get('domain_age_days', 0) for f in self.features if f.get('domain_age_days', 0) > 0]
        if domain_ages:
            axes[1, 0].hist(domain_ages, bins=30, alpha=0.7, color='purple', edgecolor='black')
            axes[1, 0].set_title('Domain Age Distribution')
            axes[1, 0].set_xlabel('Domain Age (days)')
            axes[1, 0].set_ylabel('Frequency')
        else:
            axes[1, 0].text(0.5, 0.5, 'No domain age data', ha='center', va='center', transform=axes[1, 0].transAxes)
            axes[1, 0].set_title('Domain Age Distribution')
        
        # 5. Protocol Distribution
        protocols = [f.get('protocol', 0) for f in self.features]
        protocol_counts = Counter(protocols)
        axes[1, 1].bar(protocol_counts.keys(), protocol_counts.values(), color='lightcoral', edgecolor='black')
        axes[1, 1].set_title('Protocol Distribution')
        axes[1, 1].set_xlabel('Protocol Number')
        axes[1, 1].set_ylabel('Count')
        
        # 6. Port Analysis
        dst_ports = [f.get('dst_port', 0) for f in self.features if f.get('dst_port', 0) > 0]
        if dst_ports:
            axes[1, 2].hist(dst_ports, bins=50, alpha=0.7, color='lightblue', edgecolor='black')
            axes[1, 2].set_title('Destination Port Distribution')
            axes[1, 2].set_xlabel('Port Number')
            axes[1, 2].set_ylabel('Frequency')
        else:
            axes[1, 2].text(0.5, 0.5, 'No port data', ha='center', va='center', transform=axes[1, 2].transAxes)
            axes[1, 2].set_title('Destination Port Distribution')
        
        # 7. Threat Score Distribution
        if hasattr(self, 'ensemble_model') and self.ensemble_model:
            # Calculate threat scores for visualization
            threat_scores = []
            for features in self.features:
                score = self._predict_threat_score(features)
                threat_scores.append(score)
            
            axes[2, 0].hist(threat_scores, bins=30, alpha=0.7, color='red', edgecolor='black')
            axes[2, 0].set_title('Threat Score Distribution')
            axes[2, 0].set_xlabel('Threat Score')
            axes[2, 0].set_ylabel('Frequency')
            axes[2, 0].axvline(x=0.5, color='orange', linestyle='--', label='Alert Threshold')
            axes[2, 0].legend()
        else:
            axes[2, 0].text(0.5, 0.5, 'No threat scores available', ha='center', va='center', transform=axes[2, 0].transAxes)
            axes[2, 0].set_title('Threat Score Distribution')
        
        # 8. Temporal Analysis
        timestamps = [f.get('timestamp', 0) for f in self.features if f.get('timestamp', 0) > 0]
        if timestamps:
            hours = [datetime.fromtimestamp(ts).hour for ts in timestamps]
            hour_counts = Counter(hours)
            axes[2, 1].bar(hour_counts.keys(), hour_counts.values(), color='lightgreen', edgecolor='black')
            axes[2, 1].set_title('Traffic by Hour of Day')
            axes[2, 1].set_xlabel('Hour')
            axes[2, 1].set_ylabel('Packet Count')
        else:
            axes[2, 1].text(0.5, 0.5, 'No timestamp data', ha='center', va='center', transform=axes[2, 1].transAxes)
            axes[2, 1].set_title('Traffic by Hour of Day')
        
        # 9. Alert Timeline
        if self.alert_history:
            alert_times = [alert['timestamp'] for alert in self.alert_history]
            alert_scores = [alert['threat_score'] for alert in self.alert_history]
            
            axes[2, 2].scatter(range(len(alert_times)), alert_scores, 
                             c=alert_scores, cmap='Reds', alpha=0.7, edgecolors='black')
            axes[2, 2].set_title('Alert Timeline')
            axes[2, 2].set_xlabel('Alert Number')
            axes[2, 2].set_ylabel('Threat Score')
            axes[2, 2].axhline(y=0.8, color='orange', linestyle='--', label='High Alert Threshold')
            axes[2, 2].legend()
        else:
            axes[2, 2].text(0.5, 0.5, 'No alerts generated', ha='center', va='center', transform=axes[2, 2].transAxes)
            axes[2, 2].set_title('Alert Timeline')
        
        plt.tight_layout()
        plt.savefig('advanced_threat_analysis_dashboard.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        print("Advanced visualization saved as 'advanced_threat_analysis_dashboard.png'")
    
    def _threat_level_to_numeric(self, threat_level):
        """Convert threat level string to numeric value"""
        threat_levels = {
            'unknown': 0,
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return threat_levels.get(threat_level.lower(), 0)

def main():
    """Main function to run the advanced threat detector"""
    print("Advanced Network Threat Detection System")
    print("=" * 50)
    
    # Initialize the detector
    detector = AdvancedThreatDetector('wire.pcap')
    
    # Parse PCAP file and extract features
    X, y = detector.parse_pcap_file()
    
    if len(X) == 0:
        print("No packets could be parsed from the PCAP file.")
        return
    
    # Prepare data for machine learning
    X_train, X_test, y_train, y_test = detector.prepare_data()
    
    # Build and train ensemble model
    detector.build_ensemble_model(X_train, y_train)
    
    # Evaluate models
    detector._evaluate_models(X_test, y_test)
    
    # Detect C&C servers
    detector.detect_c2_servers()
    
    # Generate comprehensive report
    detector.generate_comprehensive_report()
    
    # Create advanced visualizations
    detector.visualize_advanced_results()
    
    print("\nAdvanced analysis complete! Check the generated report and visualizations.")
    
    # Option to start real-time monitoring
    response = input("\nWould you like to start real-time monitoring? (y/n): ")
    if response.lower() == 'y':
        try:
            detector.real_time_monitoring()
            print("Real-time monitoring started. Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                detector.stop_monitoring()
        except Exception as e:
            print(f"Error starting real-time monitoring: {e}")

if __name__ == "__main__":
    main()
