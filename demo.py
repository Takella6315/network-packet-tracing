

import sys
import os
from network_threat_classifier import NetworkThreatClassifier
from advanced_threat_detector import AdvancedThreatDetector

def run_basic_analysis():
    """Run basic threat analysis"""
    print("Running Basic Network Threat Analysis...")
    print("=" * 50)
    
    try:
        # Initialize basic classifier
        classifier = NetworkThreatClassifier('wire.pcap')
        
        # Parse PCAP file
        X, y = classifier.parse_pcap_file()
        
        if len(X) == 0:
            print("No packets could be parsed from wire.pcap")
            return False
        
        # Prepare data
        X_train, X_test, y_train, y_test = classifier.prepare_data()
        
        # Train models
        classifier.train_models(X_train, X_test, y_train, y_test)
        
        # Detect C&C servers
        classifier.detect_c2_servers()
        
        # Generate report
        classifier.generate_threat_report()
        
        # Create visualizations
        classifier.visualize_results()
        
        print("Basic analysis completed successfully!")
        return True
        
    except Exception as e:
        print(f"Error in basic analysis: {e}")
        return False

def run_advanced_analysis():
    """Run advanced threat analysis"""
    print("\nRunning Advanced Network Threat Analysis...")
    print("=" * 50)
    
    try:
        # Initialize advanced detector
        detector = AdvancedThreatDetector('wire.pcap')
        
        # Parse PCAP file
        X, y = detector.parse_pcap_file()
        
        if len(X) == 0:
            print("No packets could be parsed from wire.pcap")
            return False
        
        # Prepare data
        X_train, X_test, y_train, y_test = detector.prepare_data()
        
        # Build ensemble model
        detector.build_ensemble_model(X_train, y_train)
        
        # Detect C&C servers
        detector.detect_c2_servers()
        
        # Generate comprehensive report
        detector.generate_comprehensive_report()
        
        # Create advanced visualizations
        detector.visualize_advanced_results()
        
        print("Advanced analysis completed successfully!")
        return True
        
    except Exception as e:
        print(f"Error in advanced analysis: {e}")
        return False

def run_threat_intelligence_test():
    """Run threat intelligence test"""
    print("\n🛡️  Running Threat Intelligence Test...")
    print("=" * 50)
    
    try:
        from test_threat_intel import test_threat_intelligence
        test_threat_intelligence()
        print("Threat intelligence test completed successfully!")
        return True
        
    except Exception as e:
        print(f"Error in threat intelligence test: {e}")
        return False

def check_dependencies():
    """Check if all required dependencies are installed"""
    print("🔧 Checking dependencies...")
    
    required_packages = [
        'dpkt', 'scapy', 'numpy', 'pandas', 'scikit-learn',
        'tensorflow', 'matplotlib', 'seaborn', 'xgboost', 'lightgbm'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"Missing packages: {', '.join(missing_packages)}")
        print("Please install them using: pip install -r requirements.txt")
        return False
    else:
        print("All dependencies are installed!")
        return True

def check_pcap_file():
    """Check if wire.pcap file exists"""
    if not os.path.exists('wire.pcap'):
        print("wire.pcap file not found!")
        print("Please make sure wire.pcap is in the current directory.")
        return False
    else:
        print("wire.pcap file found!")
        return True

def main():
    """Main demo function"""
    print("Advanced Network Threat Detection System Demo")
    print("=" * 60)
    
    # Check dependencies
    if not check_dependencies():
        return
    
    # Check PCAP file
    if not check_pcap_file():
        return
    
    print("\nChoose analysis type:")
    print("1. Basic Analysis (faster, good for testing)")
    print("2. Advanced Analysis (comprehensive, more features)")
    print("3. Threat Intelligence Test (test dynamic threat feeds)")
    print("4. Both (recommended)")
    
    choice = input("\nEnter your choice (1/2/3/4): ").strip()
    
    if choice == '1':
        run_basic_analysis()
    elif choice == '2':
        run_advanced_analysis()
    elif choice == '3':
        run_threat_intelligence_test()
    elif choice == '4':
        print("\n🔄 Running both analyses...")
        run_basic_analysis()
        run_advanced_analysis()
    else:
        print("Invalid choice. Please run the script again and choose 1, 2, 3, or 4.")
        return
    
    print("\nDemo completed!")
    print("\nGenerated files:")
    print("- threat_analysis_dashboard.png (basic analysis visualization)")
    print("- advanced_threat_analysis_dashboard.png (advanced analysis visualization)")
    print("- Check console output for detailed threat reports")

if __name__ == "__main__":
    main()
