#!/usr/bin/env python3
"""
Advanced Network Traffic Threat Classification System
====================================================

This sophisticated AI/ML/DL system analyzes network packet captures to classify
traffic as legitimate or malicious, with special focus on detecting:
- Command & Control (C&C) servers
- Botnet communications
- Malware traffic patterns
- Suspicious DNS queries
- Domain age analysis
- Behavioral pattern recognition

Author: AI Assistant
Date: 2024
"""

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
from collections import defaultdict, Counter
import warnings
warnings.filterwarnings('ignore')

# Import dynamic threat intelligence
from threat_intelligence import get_threat_intelligence_manager

# ML/DL Libraries
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.neural_network import MLPClassifier
import xgboost as xgb
import lightgbm as lgb

# Deep Learning
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import LSTM, Dense, Conv1D, MaxPooling1D, Dropout, Input, Attention
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

# Network Analysis
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR

class NetworkThreatClassifier:
    """
    Advanced network threat classification system using multiple ML/DL approaches
    """
    
    def __init__(self, pcap_file, geoip_db='GeoLiteCity.dat'):
        self.pcap_file = pcap_file
        self.geoip_db = geoip_db
        self.features = []
        self.labels = []
        self.dns_cache = {}
        self.domain_age_cache = {}
        self.suspicious_domains = set()
        
        # Initialize dynamic threat intelligence
        self.threat_intel = get_threat_intelligence_manager()
        
        # Initialize models
        self.models = {}
        self.scalers = {}
        
    def _load_threat_intelligence(self):
        """Load threat intelligence from dynamic sources"""
        try:
            # Update threat intelligence feeds
            print("Updating threat intelligence feeds...")
            self.threat_intel.update_all_feeds()
            
            # Get statistics
            stats = self.threat_intel.get_statistics()
            print(f"Loaded {stats['total_indicators']} threat indicators from {len(stats['by_source'])} sources")
            
        except Exception as e:
            print(f"Warning: Could not load threat intelligence: {e}")
    
    def extract_advanced_features(self, packet_data):
        """
        Extract sophisticated features from network packets for ML classification
        """
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
        
        # Check IP reputation using dynamic threat intelligence
        src_malicious, src_confidence, src_threat_level = self.threat_intel.check_ip_reputation(src_ip)
        dst_malicious, dst_confidence, dst_threat_level = self.threat_intel.check_ip_reputation(dst_ip)
        
        features['is_known_malicious_src'] = src_malicious
        features['is_known_malicious_dst'] = dst_malicious
        features['src_threat_confidence'] = src_confidence
        features['dst_threat_confidence'] = dst_confidence
        features['src_threat_level'] = self._threat_level_to_numeric(src_threat_level)
        features['dst_threat_level'] = self._threat_level_to_numeric(dst_threat_level)
        
        # DNS-based features
        dns_features = self._extract_dns_features(packet_data)
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
        
        return features
    
    def _is_private_ip(self, ip):
        """Check if IP is private"""
        try:
            ip_obj = socket.inet_aton(ip)
            return (
                (ip_obj[0] == 10) or
                (ip_obj[0] == 172 and 16 <= ip_obj[1] <= 31) or
                (ip_obj[0] == 192 and ip_obj[1] == 168)
            )
        except:
            return False
    
    def _extract_dns_features(self, packet_data):
        """Extract DNS-related features for threat detection"""
        features = {}
        
        # Check if packet contains DNS data
        if 'dns_query' in packet_data:
            query = packet_data['dns_query']
            features['dns_query_length'] = len(query)
            features['dns_query_entropy'] = self._calculate_entropy(query)
            features['dns_query_has_numbers'] = bool(re.search(r'\d', query))
            features['dns_query_has_hyphens'] = '-' in query
            features['dns_query_subdomain_count'] = query.count('.')
            
            # Domain age analysis
            domain_age = self._get_domain_age(query)
            features['domain_age_days'] = domain_age
            features['is_new_domain'] = domain_age < 30  # Suspicious if domain is very new
            features['is_very_old_domain'] = domain_age > 3650  # 10+ years
            
            # Check domain reputation using dynamic threat intelligence
            domain_malicious, domain_confidence, domain_threat_level = self.threat_intel.check_domain_reputation(query)
            features['is_known_malicious_domain'] = domain_malicious
            features['domain_threat_confidence'] = domain_confidence
            features['domain_threat_level'] = self._threat_level_to_numeric(domain_threat_level)
            
            # Domain reputation features
            features['domain_reputation_score'] = self._calculate_domain_reputation(query)
            
        else:
            features['dns_query_length'] = 0
            features['dns_query_entropy'] = 0
            features['dns_query_has_numbers'] = False
            features['dns_query_has_hyphens'] = False
            features['dns_query_subdomain_count'] = 0
            features['domain_age_days'] = 0
            features['is_new_domain'] = False
            features['is_very_old_domain'] = False
            features['is_known_malicious_domain'] = False
            features['domain_threat_confidence'] = 0
            features['domain_threat_level'] = 0
            features['domain_reputation_score'] = 0
        
        return features
    
    def _get_domain_age(self, domain):
        """Get domain age in days using WHOIS data"""
        if domain in self.domain_age_cache:
            return self.domain_age_cache[domain]
        
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                age_days = (datetime.now() - creation_date).days
                self.domain_age_cache[domain] = age_days
                return age_days
        except:
            pass
        
        # If WHOIS fails, return a default age
        self.domain_age_cache[domain] = 365
        return 365
    
    def _calculate_domain_reputation(self, domain):
        """Calculate domain reputation score (0-100, higher = more suspicious)"""
        score = 0
        
        # Check for suspicious patterns
        if re.search(r'\d{4,}', domain):  # Many consecutive numbers
            score += 20
        if domain.count('-') > 2:  # Many hyphens
            score += 15
        if len(domain) > 50:  # Very long domain
            score += 10
        if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain):  # IP in domain
            score += 30
        
        # Check against known malicious patterns
        malicious_patterns = ['bot', 'c2', 'command', 'control', 'malware', 'trojan']
        for pattern in malicious_patterns:
            if pattern in domain.lower():
                score += 25
        
        return min(score, 100)
    
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
    
    def _extract_temporal_features(self, packet_data):
        """Extract time-based features"""
        features = {}
        
        timestamp = packet_data.get('timestamp', 0)
        if timestamp:
            dt = datetime.fromtimestamp(timestamp)
            features['hour_of_day'] = dt.hour
            features['day_of_week'] = dt.weekday()
            features['is_weekend'] = dt.weekday() >= 5
            features['is_night_time'] = dt.hour < 6 or dt.hour > 22
        else:
            features['hour_of_day'] = 12
            features['day_of_week'] = 0
            features['is_weekend'] = False
            features['is_night_time'] = False
        
        return features
    
    def _extract_behavioral_features(self, packet_data):
        """Extract behavioral pattern features"""
        features = {}
        
        # Packet size patterns
        packet_size = len(packet_data.get('raw_data', ''))
        features['packet_size_category'] = self._categorize_packet_size(packet_size)
        
        # Protocol-specific features
        protocol = packet_data.get('protocol', 0)
        features['is_tcp'] = protocol == 6
        features['is_udp'] = protocol == 17
        features['is_icmp'] = protocol == 1
        
        # Port-based features
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        features['is_well_known_port_src'] = src_port < 1024
        features['is_well_known_port_dst'] = dst_port < 1024
        features['is_ephemeral_port_src'] = 49152 <= src_port <= 65535
        features['is_ephemeral_port_dst'] = 49152 <= dst_port <= 65535
        
        return features
    
    def _categorize_packet_size(self, size):
        """Categorize packet size for behavioral analysis"""
        if size < 64:
            return 0  # Very small
        elif size < 512:
            return 1  # Small
        elif size < 1024:
            return 2  # Medium
        elif size < 1500:
            return 3  # Large
        else:
            return 4  # Very large
    
    def _extract_flow_features(self, packet_data):
        """Extract network flow features"""
        features = {}
        
        # These would be calculated across multiple packets in a flow
        # For now, we'll use single packet approximations
        features['flow_duration'] = 1  # Placeholder
        features['packets_per_second'] = 1  # Placeholder
        features['bytes_per_second'] = len(packet_data.get('raw_data', ''))
        
        return features
    
    def _extract_entropy_features(self, packet_data):
        """Extract entropy and randomness features"""
        features = {}
        
        raw_data = packet_data.get('raw_data', b'')
        if raw_data:
            features['data_entropy'] = self._calculate_entropy(raw_data)
            features['data_randomness'] = self._calculate_randomness(raw_data)
        else:
            features['data_entropy'] = 0
            features['data_randomness'] = 0
        
        return features
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        if isinstance(data, str):
            data = data.encode()
        
        # Count byte frequencies
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            probability = count / total_bytes
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _calculate_randomness(self, data):
        """Calculate randomness score of data"""
        if not data:
            return 0
        
        if isinstance(data, str):
            data = data.encode()
        
        # Simple randomness test based on byte distribution
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        # Calculate chi-square statistic
        expected_frequency = total_bytes / 256
        chi_square = sum((count - expected_frequency) ** 2 / expected_frequency 
                        for count in byte_counts.values())
        
        # Normalize to 0-1 scale
        return min(chi_square / 1000, 1.0)
    
    def parse_pcap_file(self):
        """Parse PCAP file and extract features"""
        print("Parsing PCAP file and extracting features...")
        
        with open(self.pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            
            packet_count = 0
            for timestamp, buf in pcap:
                try:
                    # Parse Ethernet frame
                    eth = dpkt.ethernet.Ethernet(buf)
                    
                    # Check if it's an IP packet
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        
                        # Extract basic packet information
                        packet_data = {
                            'timestamp': timestamp,
                            'src_ip': socket.inet_ntoa(ip.src),
                            'dst_ip': socket.inet_ntoa(ip.dst),
                            'protocol': ip.p,
                            'raw_data': buf
                        }
                        
                        # Extract port information if TCP/UDP
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            packet_data['src_port'] = ip.data.sport
                            packet_data['dst_port'] = ip.data.dport
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            packet_data['src_port'] = ip.data.sport
                            packet_data['dst_port'] = ip.data.dport
                            
                            # Check for DNS queries
                            if packet_data['dst_port'] == 53:
                                try:
                                    dns = dpkt.dns.DNS(ip.data.data)
                                    if dns.qd:
                                        packet_data['dns_query'] = dns.qd[0].name.decode()
                                except:
                                    pass
                        
                        # Extract advanced features
                        features = self.extract_advanced_features(packet_data)
                        self.features.append(features)
                        
                        # Generate synthetic labels for demonstration
                        # In production, you would use real labeled data
                        label = self._generate_synthetic_label(features)
                        self.labels.append(label)
                        
                        packet_count += 1
                        if packet_count % 1000 == 0:
                            print(f"Processed {packet_count} packets...")
                            
                except Exception as e:
                    continue
        
        print(f"Finished parsing. Processed {packet_count} packets.")
        return np.array(self.features), np.array(self.labels)
    
    def _generate_synthetic_label(self, features):
        """
        Generate synthetic labels for demonstration purposes.
        In production, use real labeled data from security experts.
        """
        # Simple heuristic-based labeling for demonstration
        score = 0
        
        # Check for suspicious features
        if features.get('is_known_malicious_src', False) or features.get('is_known_malicious_dst', False):
            score += 50
        
        if features.get('is_known_malicious_domain', False):
            score += 40
        
        if features.get('is_new_domain', False):
            score += 20
        
        if features.get('domain_reputation_score', 0) > 50:
            score += 30
        
        if features.get('is_night_time', False):
            score += 10
        
        if features.get('dns_query_entropy', 0) > 4:
            score += 15
        
        # Random component to simulate real-world uncertainty
        score += np.random.randint(0, 20)
        
        return 1 if score > 50 else 0  # 1 = malicious, 0 = benign
    
    def prepare_data(self):
        """Prepare data for machine learning"""
        print("Preparing data for machine learning...")
        
        # Convert features to DataFrame
        df = pd.DataFrame(self.features)
        
        # Handle missing values
        df = df.fillna(0)
        
        # Encode categorical variables
        categorical_columns = df.select_dtypes(include=['object']).columns
        for col in categorical_columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
        
        # Separate features and labels
        X = df.values
        y = np.array(self.labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        self.scalers['main'] = scaler
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def train_models(self, X_train, X_test, y_train, y_test):
        """Train multiple ML/DL models"""
        print("Training machine learning models...")
        
        # Random Forest
        print("Training Random Forest...")
        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42
        )
        rf.fit(X_train, y_train)
        self.models['random_forest'] = rf
        
        # XGBoost
        print("Training XGBoost...")
        xgb_model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=42
        )
        xgb_model.fit(X_train, y_train)
        self.models['xgboost'] = xgb_model
        
        # LightGBM
        print("Training LightGBM...")
        lgb_model = lgb.LGBMClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=42
        )
        lgb_model.fit(X_train, y_train)
        self.models['lightgbm'] = lgb_model
        
        # Neural Network
        print("Training Neural Network...")
        nn_model = MLPClassifier(
            hidden_layer_sizes=(100, 50, 25),
            activation='relu',
            solver='adam',
            alpha=0.001,
            learning_rate='adaptive',
            max_iter=1000,
            random_state=42
        )
        nn_model.fit(X_train, y_train)
        self.models['neural_network'] = nn_model
        
        # Deep Learning LSTM Model
        print("Training LSTM Deep Learning Model...")
        lstm_model = self._build_lstm_model(X_train.shape[1])
        lstm_model.fit(
            X_train, y_train,
            epochs=50,
            batch_size=32,
            validation_split=0.2,
            callbacks=[
                EarlyStopping(patience=10, restore_best_weights=True),
                ReduceLROnPlateau(factor=0.5, patience=5)
            ],
            verbose=0
        )
        self.models['lstm'] = lstm_model
        
        # Evaluate models
        self._evaluate_models(X_test, y_test)
    
    def _build_lstm_model(self, input_dim):
        """Build LSTM model for sequence analysis"""
        model = Sequential([
            LSTM(128, return_sequences=True, input_shape=(1, input_dim)),
            Dropout(0.3),
            LSTM(64, return_sequences=False),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def _evaluate_models(self, X_test, y_test):
        """Evaluate all trained models"""
        print("\n" + "="*50)
        print("MODEL EVALUATION RESULTS")
        print("="*50)
        
        for name, model in self.models.items():
            if name == 'lstm':
                # Reshape for LSTM
                X_test_reshaped = X_test.reshape(X_test.shape[0], 1, X_test.shape[1])
                y_pred = (model.predict(X_test_reshaped) > 0.5).astype(int).flatten()
            else:
                y_pred = model.predict(X_test)
            
            accuracy = np.mean(y_pred == y_test)
            auc_score = roc_auc_score(y_test, y_pred)
            
            print(f"\n{name.upper()}:")
            print(f"  Accuracy: {accuracy:.4f}")
            print(f"  AUC Score: {auc_score:.4f}")
            
            # Classification report
            print(f"\n  Classification Report:")
            print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
    
    def detect_c2_servers(self, threshold=0.7):
        """Detect potential Command & Control servers"""
        print(f"\nDetecting C&C servers with threshold {threshold}...")
        
        c2_candidates = []
        
        for i, features in enumerate(self.features):
            # Calculate C&C likelihood score
            c2_score = self._calculate_c2_score(features)
            
            if c2_score > threshold:
                c2_candidates.append({
                    'packet_index': i,
                    'c2_score': c2_score,
                    'features': features
                })
        
        # Sort by C&C score
        c2_candidates.sort(key=lambda x: x['c2_score'], reverse=True)
        
        print(f"Found {len(c2_candidates)} potential C&C servers")
        
        # Display top candidates
        for i, candidate in enumerate(c2_candidates[:10]):  # Top 10
            print(f"\nC&C Candidate #{i+1}:")
            print(f"  Score: {candidate['c2_score']:.4f}")
            print(f"  Packet Index: {candidate['packet_index']}")
            
            features = candidate['features']
            if 'src_ip' in features:
                print(f"  Source IP: {features['src_ip']}")
            if 'dst_ip' in features:
                print(f"  Destination IP: {features['dst_ip']}")
            if 'dns_query' in features:
                print(f"  DNS Query: {features['dns_query']}")
        
        return c2_candidates
    
    def _calculate_c2_score(self, features):
        """Calculate Command & Control server likelihood score"""
        score = 0
        
        # High entropy in DNS queries (common in C&C)
        if features.get('dns_query_entropy', 0) > 4:
            score += 0.3
        
        # New domains (C&C often use fresh domains)
        if features.get('is_new_domain', False):
            score += 0.4
        
        # Suspicious domain patterns
        if features.get('domain_reputation_score', 0) > 70:
            score += 0.3
        
        # Night-time activity (common for C&C)
        if features.get('is_night_time', False):
            score += 0.2
        
        # Known malicious indicators
        if features.get('is_known_malicious_domain', False):
            score += 0.8
        
        if features.get('is_known_malicious_src', False) or features.get('is_known_malicious_dst', False):
            score += 0.9
        
        return min(score, 1.0)
    
    def generate_threat_report(self):
        """Generate comprehensive threat analysis report"""
        print("\n" + "="*60)
        print("COMPREHENSIVE THREAT ANALYSIS REPORT")
        print("="*60)
        
        # Basic statistics
        total_packets = len(self.features)
        malicious_packets = sum(self.labels)
        benign_packets = total_packets - malicious_packets
        
        print(f"\nPACKET ANALYSIS SUMMARY:")
        print(f"  Total Packets Analyzed: {total_packets}")
        print(f"  Malicious Packets: {malicious_packets} ({malicious_packets/total_packets*100:.2f}%)")
        print(f"  Benign Packets: {benign_packets} ({benign_packets/total_packets*100:.2f}%)")
        
        # DNS analysis
        dns_queries = [f for f in self.features if f.get('dns_query_length', 0) > 0]
        print(f"\nDNS ANALYSIS:")
        print(f"  DNS Queries Found: {len(dns_queries)}")
        
        if dns_queries:
            new_domains = sum(1 for f in dns_queries if f.get('is_new_domain', False))
            suspicious_domains = sum(1 for f in dns_queries if f.get('domain_reputation_score', 0) > 50)
            
            print(f"  New Domains (< 30 days): {new_domains}")
            print(f"  Suspicious Domains: {suspicious_domains}")
        
        # C&C Detection
        c2_candidates = self.detect_c2_servers()
        print(f"\nCOMMAND & CONTROL DETECTION:")
        print(f"  Potential C&C Servers: {len(c2_candidates)}")
        
        # Recommendations
        print(f"\nSECURITY RECOMMENDATIONS:")
        if malicious_packets > total_packets * 0.1:
            print("  ⚠️  HIGH THREAT LEVEL: Significant malicious activity detected")
            print("  - Implement immediate network isolation")
            print("  - Conduct forensic analysis")
            print("  - Update security policies")
        elif malicious_packets > total_packets * 0.05:
            print("  ⚠️  MEDIUM THREAT LEVEL: Some suspicious activity detected")
            print("  - Monitor network traffic closely")
            print("  - Review security configurations")
            print("  - Consider additional monitoring tools")
        else:
            print("  ✅ LOW THREAT LEVEL: Minimal suspicious activity")
            print("  - Continue regular monitoring")
            print("  - Maintain current security posture")
    
    def visualize_results(self):
        """Create visualizations of the analysis results"""
        print("\nGenerating visualizations...")
        
        # Set up the plotting style
        plt.style.use('seaborn-v0_8')
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Network Threat Analysis Dashboard', fontsize=16, fontweight='bold')
        
        # 1. Threat Distribution
        threat_counts = Counter(self.labels)
        axes[0, 0].pie([threat_counts[0], threat_counts[1]], 
                      labels=['Benign', 'Malicious'], 
                      autopct='%1.1f%%',
                      colors=['lightgreen', 'lightcoral'])
        axes[0, 0].set_title('Threat Distribution')
        
        # 2. Packet Size Distribution
        packet_sizes = [len(f.get('raw_data', b'')) for f in self.features]
        axes[0, 1].hist(packet_sizes, bins=50, alpha=0.7, color='skyblue')
        axes[0, 1].set_title('Packet Size Distribution')
        axes[0, 1].set_xlabel('Packet Size (bytes)')
        axes[0, 1].set_ylabel('Frequency')
        
        # 3. DNS Query Entropy
        dns_entropies = [f.get('dns_query_entropy', 0) for f in self.features if f.get('dns_query_entropy', 0) > 0]
        if dns_entropies:
            axes[1, 0].hist(dns_entropies, bins=30, alpha=0.7, color='orange')
            axes[1, 0].set_title('DNS Query Entropy Distribution')
            axes[1, 0].set_xlabel('Entropy')
            axes[1, 0].set_ylabel('Frequency')
        else:
            axes[1, 0].text(0.5, 0.5, 'No DNS queries found', ha='center', va='center', transform=axes[1, 0].transAxes)
            axes[1, 0].set_title('DNS Query Entropy Distribution')
        
        # 4. Domain Age Analysis
        domain_ages = [f.get('domain_age_days', 0) for f in self.features if f.get('domain_age_days', 0) > 0]
        if domain_ages:
            axes[1, 1].hist(domain_ages, bins=30, alpha=0.7, color='purple')
            axes[1, 1].set_title('Domain Age Distribution')
            axes[1, 1].set_xlabel('Domain Age (days)')
            axes[1, 1].set_ylabel('Frequency')
        else:
            axes[1, 1].text(0.5, 0.5, 'No domain age data', ha='center', va='center', transform=axes[1, 1].transAxes)
            axes[1, 1].set_title('Domain Age Distribution')
        
        plt.tight_layout()
        plt.savefig('threat_analysis_dashboard.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        print("Visualization saved as 'threat_analysis_dashboard.png'")

def main():
    """Main function to run the network threat classifier"""
    print("Advanced Network Threat Classification System")
    print("=" * 50)
    
    # Initialize the classifier
    classifier = NetworkThreatClassifier('wire.pcap')
    
    # Parse PCAP file and extract features
    X, y = classifier.parse_pcap_file()
    
    if len(X) == 0:
        print("No packets could be parsed from the PCAP file.")
        return
    
    # Prepare data for machine learning
    X_train, X_test, y_train, y_test = classifier.prepare_data()
    
    # Train models
    classifier.train_models(X_train, X_test, y_train, y_test)
    
    # Detect C&C servers
    classifier.detect_c2_servers()
    
    # Generate comprehensive report
    classifier.generate_threat_report()
    
    # Create visualizations
    classifier.visualize_results()
    
    print("\nAnalysis complete! Check the generated report and visualizations.")

if __name__ == "__main__":
    main()
