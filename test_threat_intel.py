#!/usr/bin/env python3
"""
Test script for Dynamic Threat Intelligence System
=================================================

This script demonstrates the dynamic threat intelligence capabilities
and shows how to use the system with real threat feeds.

Usage:
    python test_threat_intel.py
"""

import time
from threat_intelligence import ThreatIntelligenceManager

def test_threat_intelligence():
    """Test the threat intelligence system"""
    print("🛡️  Testing Dynamic Threat Intelligence System")
    print("=" * 60)
    
    # Initialize threat intelligence manager
    print("\n1. Initializing Threat Intelligence Manager...")
    ti = ThreatIntelligenceManager()
    
    # Show initial statistics
    print("\n2. Initial Statistics:")
    stats = ti.get_statistics()
    print(f"   Total Indicators: {stats['total_indicators']:,}")
    print(f"   Sources: {len(stats['by_source'])}")
    print(f"   By Type: {stats['by_type']}")
    print(f"   By Threat Level: {stats['by_threat_level']}")
    
    # Update threat feeds
    print("\n3. Updating Threat Feeds...")
    start_time = time.time()
    ti.update_all_feeds()
    update_time = time.time() - start_time
    print(f"   Update completed in {update_time:.2f} seconds")
    
    # Show updated statistics
    print("\n4. Updated Statistics:")
    stats = ti.get_statistics()
    print(f"   Total Indicators: {stats['total_indicators']:,}")
    print(f"   Sources: {len(stats['by_source'])}")
    print(f"   By Type: {stats['by_type']}")
    print(f"   By Threat Level: {stats['by_threat_level']}")
    
    # Test IP reputation checking
    print("\n5. Testing IP Reputation Checks:")
    test_ips = [
        "8.8.8.8",  # Google DNS (should be clean)
        "1.1.1.1",  # Cloudflare DNS (should be clean)
        "192.168.1.1",  # Private IP (should be clean)
        "127.0.0.1",  # Localhost (should be clean)
    ]
    
    for ip in test_ips:
        is_malicious, confidence, threat_level = ti.check_ip_reputation(ip)
        status = "🚨 MALICIOUS" if is_malicious else "✅ CLEAN"
        print(f"   {ip}: {status} (Confidence: {confidence:.2f}, Level: {threat_level})")
    
    # Test domain reputation checking
    print("\n6. Testing Domain Reputation Checks:")
    test_domains = [
        "google.com",  # Should be clean
        "microsoft.com",  # Should be clean
        "example.com",  # Should be clean
        "malicious-site.com",  # Might be flagged
    ]
    
    for domain in test_domains:
        is_malicious, confidence, threat_level = ti.check_domain_reputation(domain)
        status = "🚨 MALICIOUS" if is_malicious else "✅ CLEAN"
        print(f"   {domain}: {status} (Confidence: {confidence:.2f}, Level: {threat_level})")
    
    # Test custom indicator addition
    print("\n7. Testing Custom Indicator Addition:")
    ti.add_custom_indicator(
        value="192.168.100.100",
        indicator_type="ip",
        threat_level="high",
        description="Test malicious IP",
        tags=["test", "malicious"],
        confidence=0.9
    )
    
    # Check the custom indicator
    is_malicious, confidence, threat_level = ti.check_ip_reputation("192.168.100.100")
    status = "🚨 MALICIOUS" if is_malicious else "✅ CLEAN"
    print(f"   Custom IP 192.168.100.100: {status} (Confidence: {confidence:.2f}, Level: {threat_level})")
    
    # Show source statistics
    print("\n8. Source Statistics:")
    for source, count in stats['by_source'].items():
        print(f"   {source}: {count:,} indicators")
    
    # Show last update times
    print("\n9. Last Update Times:")
    for source, last_update in stats['last_updates'].items():
        if last_update:
            print(f"   {source}: {last_update}")
        else:
            print(f"   {source}: Never updated")
    
    print("\n✅ Threat Intelligence Test Completed Successfully!")
    
    # Show configuration status
    print("\n10. Configuration Status:")
    print(f"   Free Feeds Enabled: {len(ti.free_feeds) > 0}")
    print(f"   API Feeds Enabled: {sum(1 for config in ti.api_configs.values() if config['enabled'])}")
    print(f"   Update Interval: {ti.update_interval} seconds")
    print(f"   Database: {ti.cache_db}")

def test_real_time_updates():
    """Test real-time updates"""
    print("\n🔄 Testing Real-time Updates...")
    
    ti = ThreatIntelligenceManager(update_interval=10)  # 10 second updates for testing
    
    print("Starting background updates (will run for 30 seconds)...")
    ti.start_background_updates()
    
    # Monitor for 30 seconds
    for i in range(30):
        time.sleep(1)
        if i % 10 == 0:
            stats = ti.get_statistics()
            print(f"   {i}s: {stats['total_indicators']} indicators from {len(stats['by_source'])} sources")
    
    ti.stop_background_updates()
    print("Background updates stopped.")

def main():
    """Main test function"""
    try:
        test_threat_intelligence()
        
        # Ask if user wants to test real-time updates
        response = input("\nWould you like to test real-time updates? (y/n): ")
        if response.lower() == 'y':
            test_real_time_updates()
        
        print("\n🎉 All tests completed!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
