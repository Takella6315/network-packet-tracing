#!/usr/bin/env python3
"""
Setup script for the Advanced Network Threat Detection System
============================================================

This script helps set up the environment and install all dependencies
for the network threat detection system.

Usage:
    python setup.py
"""

import subprocess
import sys
import os
import platform

def check_python_version():
    """Check if Python version is compatible"""
    print("🐍 Checking Python version...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python 3.8+ required. Current version: {version.major}.{version.minor}")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} is compatible")
    return True

def install_requirements():
    """Install required packages"""
    print("\n📦 Installing required packages...")
    
    try:
        # Upgrade pip first
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        
        # Install requirements
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        
        print("✅ All packages installed successfully!")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing packages: {e}")
        return False

def check_pcap_file():
    """Check if wire.pcap exists"""
    print("\n📁 Checking for PCAP file...")
    
    if os.path.exists('wire.pcap'):
        print("✅ wire.pcap file found!")
        return True
    else:
        print("⚠️  wire.pcap file not found.")
        print("   You can:")
        print("   1. Place your PCAP file in this directory and rename it to 'wire.pcap'")
        print("   2. Use Wireshark to capture network traffic and save as 'wire.pcap'")
        print("   3. Download a sample PCAP file for testing")
        return False

def check_geolocation_db():
    """Check if GeoLiteCity.dat exists"""
    print("\n🌍 Checking geolocation database...")
    
    if os.path.exists('GeoLiteCity.dat'):
        print("✅ GeoLiteCity.dat found!")
        return True
    else:
        print("⚠️  GeoLiteCity.dat not found.")
        print("   This file is needed for IP geolocation analysis.")
        print("   You can download it from: https://github.com/mbcc2006/GeoLiteCity-data")
        return False

def create_sample_config():
    """Create a sample configuration file"""
    print("\n⚙️  Creating sample configuration...")
    
    config_content = """# Network Threat Detection Configuration
# =====================================

# Alert thresholds (0.0 to 1.0)
ALERT_THRESHOLD = 0.8
C2_DETECTION_THRESHOLD = 0.7

# Real-time monitoring settings
MONITORING_INTERFACE = "eth0"  # Change to your network interface
SAMPLING_RATE = 1.0  # 1.0 = capture all packets

# Threat intelligence settings
ENABLE_THREAT_INTELLIGENCE = True
THREAT_FEED_UPDATE_INTERVAL = 3600  # seconds

# Logging settings
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR
LOG_FILE = "threat_detection.log"

# Model settings
MODEL_RETRAIN_INTERVAL = 86400  # seconds (24 hours)
ENSEMBLE_VOTING = "soft"  # "soft" or "hard"

# Visualization settings
GENERATE_DASHBOARDS = True
DASHBOARD_DPI = 300
SAVE_RAW_DATA = False
"""
    
    try:
        with open('config.py', 'w') as f:
            f.write(config_content)
        print("✅ Sample configuration created: config.py")
        return True
    except Exception as e:
        print(f"❌ Error creating configuration: {e}")
        return False

def run_test():
    """Run a basic test to verify installation"""
    print("\n🧪 Running installation test...")
    
    try:
        # Test basic imports
        import dpkt
        import numpy as np
        import pandas as pd
        import sklearn
        import tensorflow as tf
        import matplotlib
        import seaborn
        
        print("✅ All core libraries imported successfully!")
        
        # Test basic functionality
        from network_threat_classifier import NetworkThreatClassifier
        print("✅ Network threat classifier imported successfully!")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Test error: {e}")
        return False

def print_next_steps():
    """Print next steps for the user"""
    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Run the demo: python demo.py")
    print("2. Or run basic analysis: python network_threat_classifier.py")
    print("3. Or run advanced analysis: python advanced_threat_detector.py")
    print("\n📚 Documentation:")
    print("- Read THREAT_DETECTION_README.md for detailed usage instructions")
    print("- Check config.py for configuration options")
    print("\n🔧 Troubleshooting:")
    print("- If you encounter issues, check the troubleshooting section in the README")
    print("- Make sure you have the required permissions for network monitoring")

def main():
    """Main setup function"""
    print("🛡️  Advanced Network Threat Detection System Setup")
    print("=" * 60)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        print("\n❌ Setup failed during package installation.")
        print("Please check the error messages above and try again.")
        sys.exit(1)
    
    # Check PCAP file
    pcap_exists = check_pcap_file()
    
    # Check geolocation database
    geo_db_exists = check_geolocation_db()
    
    # Create sample configuration
    create_sample_config()
    
    # Run test
    if not run_test():
        print("\n❌ Setup test failed.")
        print("Please check the error messages above and try reinstalling packages.")
        sys.exit(1)
    
    # Print next steps
    print_next_steps()
    
    # Final status
    print(f"\n📊 Setup Status:")
    print(f"   Python: ✅ Compatible")
    print(f"   Packages: ✅ Installed")
    print(f"   PCAP file: {'✅ Found' if pcap_exists else '⚠️  Missing'}")
    print(f"   Geo DB: {'✅ Found' if geo_db_exists else '⚠️  Missing'}")
    print(f"   Configuration: ✅ Created")
    print(f"   Test: ✅ Passed")

if __name__ == "__main__":
    main()
