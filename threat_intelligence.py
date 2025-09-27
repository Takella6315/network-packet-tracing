import requests
import json
import time
import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
import threading
import logging
from dataclasses import dataclass
from urllib.parse import urljoin
import xml.etree.ElementTree as ET

# Try to import local configuration, fall back to default
try:
    from threat_intel_config_local import *
except ImportError:
    try:
        from threat_intel_config import *
    except ImportError:
        # Default configuration
        VIRUSTOTAL_API_KEY = ""
        ABUSEIPDB_API_KEY = ""
        SHODAN_API_KEY = ""
        OTX_API_KEY = ""
        UPDATE_INTERVAL = 3600
        ENABLE_FREE_FEEDS = True

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatIndicator:
    """Represents a threat indicator"""
    value: str
    indicator_type: str  # 'ip', 'domain', 'url', 'hash', 'email'
    threat_level: str    # 'low', 'medium', 'high', 'critical'
    source: str
    first_seen: datetime
    last_seen: datetime
    description: str
    tags: List[str]
    confidence: float    # 0.0 to 1.0

class ThreatIntelligenceManager:
    """
    Manages dynamic threat intelligence from multiple sources
    """
    
    def __init__(self, cache_db='threat_intel.db', update_interval=None):
        self.cache_db = cache_db
        self.update_interval = update_interval or UPDATE_INTERVAL
        self.indicators = {}
        self.last_update = {}
        self.update_thread = None
        self.is_running = False
        
        # API configurations from config file
        self.api_configs = {
            'virustotal': {
                'api_key': VIRUSTOTAL_API_KEY,
                'base_url': 'https://www.virustotal.com/vtapi/v2',
                'enabled': bool(VIRUSTOTAL_API_KEY)
            },
            'abuseipdb': {
                'api_key': ABUSEIPDB_API_KEY,
                'base_url': 'https://api.abuseipdb.com/api/v2',
                'enabled': bool(ABUSEIPDB_API_KEY)
            },
            'shodan': {
                'api_key': SHODAN_API_KEY,
                'base_url': 'https://api.shodan.io',
                'enabled': bool(SHODAN_API_KEY)
            },
            'otx': {
                'api_key': OTX_API_KEY,
                'base_url': 'https://otx.alienvault.com/api/v1',
                'enabled': bool(OTX_API_KEY)
            }
        }
        
        # Free/open source threat feeds (no API key required)
        self.free_feeds = {}
        if ENABLE_FREE_FEEDS:
            self.free_feeds = {
                'malware_domains': 'https://mirror1.malwaredomains.com/files/domains.txt',
                'malware_ips': 'https://mirror1.malwaredomains.com/files/ips.txt',
                'blocklist_de': 'https://lists.blocklist.de/lists/all.txt',
                'emerging_threats': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                'spamhaus_drop': 'https://www.spamhaus.org/drop/drop.txt',
                'spamhaus_edrop': 'https://www.spamhaus.org/drop/edrop.txt',
                'tor_exit_nodes': 'https://check.torproject.org/tor-exit-nodes.txt',
                'malware_bazaar': 'https://mb-api.abuse.ch/api/v1',
                'urlhaus': 'https://urlhaus-api.abuse.ch/v1'
            }
        
        # Initialize database
        self._init_database()
        
        # Load cached data
        self._load_cached_data()
        
        # Start background update thread
        self.start_background_updates()
    
    def _init_database(self):
        """Initialize SQLite database for caching threat intelligence"""
        try:
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()
            
            # Create indicators table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    value TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    description TEXT,
                    tags TEXT,
                    confidence REAL,
                    UNIQUE(value, source)
                )
            ''')
            
            # Create source metadata table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS source_metadata (
                    source TEXT PRIMARY KEY,
                    last_update TIMESTAMP,
                    total_indicators INTEGER,
                    status TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
    
    def _load_cached_data(self):
        """Load cached threat intelligence data from database"""
        try:
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()
            
            # Load indicators
            cursor.execute('SELECT * FROM indicators')
            rows = cursor.fetchall()
            
            for row in rows:
                indicator = ThreatIndicator(
                    value=row[1],
                    indicator_type=row[2],
                    threat_level=row[3],
                    source=row[4],
                    first_seen=datetime.fromisoformat(row[5]) if row[5] else datetime.now(),
                    last_seen=datetime.fromisoformat(row[6]) if row[6] else datetime.now(),
                    description=row[7] or '',
                    tags=json.loads(row[8]) if row[8] else [],
                    confidence=row[9] or 0.5
                )
                
                # Index by type and value
                if indicator.indicator_type not in self.indicators:
                    self.indicators[indicator.indicator_type] = {}
                
                self.indicators[indicator.indicator_type][indicator.value] = indicator
            
            # Load source metadata
            cursor.execute('SELECT * FROM source_metadata')
            rows = cursor.fetchall()
            
            for row in rows:
                self.last_update[row[0]] = datetime.fromisoformat(row[1]) if row[1] else None
            
            conn.close()
            logger.info(f"Loaded {sum(len(indicators) for indicators in self.indicators.values())} cached indicators")
            
        except Exception as e:
            logger.error(f"Error loading cached data: {e}")
    
    def start_background_updates(self):
        """Start background thread for updating threat intelligence"""
        if not self.is_running:
            self.is_running = True
            self.update_thread = threading.Thread(target=self._background_update_loop, daemon=True)
            self.update_thread.start()
            logger.info("Background threat intelligence updates started")
    
    def stop_background_updates(self):
        """Stop background updates"""
        self.is_running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
        logger.info("Background threat intelligence updates stopped")
    
    def _background_update_loop(self):
        """Background loop for updating threat intelligence"""
        while self.is_running:
            try:
                self.update_all_feeds()
                time.sleep(self.update_interval)
            except Exception as e:
                logger.error(f"Error in background update loop: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def update_all_feeds(self):
        """Update all configured threat intelligence feeds"""
        logger.info("Updating threat intelligence feeds...")
        
        # Update free feeds
        for feed_name, feed_url in self.free_feeds.items():
            try:
                self._update_free_feed(feed_name, feed_url)
            except Exception as e:
                logger.error(f"Error updating {feed_name}: {e}")
        
        # Update API-based feeds
        for api_name, config in self.api_configs.items():
            if config['enabled'] and config['api_key']:
                try:
                    self._update_api_feed(api_name, config)
                except Exception as e:
                    logger.error(f"Error updating {api_name}: {e}")
        
        logger.info("Threat intelligence update completed")
    
    def _update_free_feed(self, feed_name: str, feed_url: str):
        """Update a free threat intelligence feed"""
        try:
            response = requests.get(feed_url, timeout=30)
            response.raise_for_status()
            
            indicators = []
            lines = response.text.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse different feed formats
                if feed_name == 'malware_domains':
                    # Format: domain,type,description
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        domain = parts[0]
                        indicator_type = 'domain'
                        description = parts[2] if len(parts) > 2 else 'Malware domain'
                        threat_level = 'high'
                        tags = ['malware', 'domain']
                
                elif feed_name == 'malware_ips':
                    # Format: ip,description
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        ip = parts[0]
                        indicator_type = 'ip'
                        description = parts[1] if len(parts) > 1 else 'Malware IP'
                        threat_level = 'high'
                        tags = ['malware', 'ip']
                
                elif feed_name in ['blocklist_de', 'emerging_threats', 'spamhaus_drop', 'spamhaus_edrop']:
                    # Format: ip (one per line)
                    ip = line
                    indicator_type = 'ip'
                    description = f'Blocked IP from {feed_name}'
                    threat_level = 'medium'
                    tags = ['blocked', 'ip']
                
                elif feed_name == 'tor_exit_nodes':
                    # Format: ip (one per line)
                    ip = line
                    indicator_type = 'ip'
                    description = 'Tor exit node'
                    threat_level = 'low'
                    tags = ['tor', 'exit-node', 'ip']
                
                else:
                    # Default parsing
                    if self._is_ip(line):
                        indicator_type = 'ip'
                        threat_level = 'medium'
                        tags = ['blocked']
                    elif self._is_domain(line):
                        indicator_type = 'domain'
                        threat_level = 'medium'
                        tags = ['blocked']
                    else:
                        continue
                    
                    description = f'Threat indicator from {feed_name}'
                
                # Create indicator
                indicator = ThreatIndicator(
                    value=line,
                    indicator_type=indicator_type,
                    threat_level=threat_level,
                    source=feed_name,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    description=description,
                    tags=tags,
                    confidence=0.8
                )
                
                indicators.append(indicator)
            
            # Store indicators
            self._store_indicators(indicators)
            self.last_update[feed_name] = datetime.now()
            
            logger.info(f"Updated {feed_name}: {len(indicators)} indicators")
            
        except Exception as e:
            logger.error(f"Error updating {feed_name}: {e}")
    
    def _update_api_feed(self, api_name: str, config: Dict):
        """Update an API-based threat intelligence feed"""
        try:
            if api_name == 'virustotal':
                self._update_virustotal(config)
            elif api_name == 'abuseipdb':
                self._update_abuseipdb(config)
            elif api_name == 'shodan':
                self._update_shodan(config)
            elif api_name == 'otx':
                self._update_otx(config)
            
        except Exception as e:
            logger.error(f"Error updating {api_name}: {e}")
    
    def _update_virustotal(self, config: Dict):
        """Update VirusTotal threat intelligence"""
        # This would require a VirusTotal API key
        # For now, we'll implement a placeholder
        logger.info("VirusTotal integration requires API key")
    
    def _update_abuseipdb(self, config: Dict):
        """Update AbuseIPDB threat intelligence"""
        # This would require an AbuseIPDB API key
        logger.info("AbuseIPDB integration requires API key")
    
    def _update_shodan(self, config: Dict):
        """Update Shodan threat intelligence"""
        # This would require a Shodan API key
        logger.info("Shodan integration requires API key")
    
    def _update_otx(self, config: Dict):
        """Update OTX threat intelligence"""
        # This would require an OTX API key
        logger.info("OTX integration requires API key")
    
    def _store_indicators(self, indicators: List[ThreatIndicator]):
        """Store indicators in database"""
        try:
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()
            
            for indicator in indicators:
                cursor.execute('''
                    INSERT OR REPLACE INTO indicators 
                    (value, indicator_type, threat_level, source, first_seen, last_seen, description, tags, confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    indicator.value,
                    indicator.indicator_type,
                    indicator.threat_level,
                    indicator.source,
                    indicator.first_seen.isoformat(),
                    indicator.last_seen.isoformat(),
                    indicator.description,
                    json.dumps(indicator.tags),
                    indicator.confidence
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error storing indicators: {e}")
    
    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address"""
        try:
            parts = value.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def _is_domain(self, value: str) -> bool:
        """Check if value is a domain name"""
        return '.' in value and not value.startswith('.') and not value.endswith('.')
    
    def check_ip_reputation(self, ip: str) -> Tuple[bool, float, str]:
        """
        Check IP reputation
        
        Returns:
            (is_malicious, confidence, threat_level)
        """
        if 'ip' in self.indicators and ip in self.indicators['ip']:
            indicator = self.indicators['ip'][ip]
            return True, indicator.confidence, indicator.threat_level
        
        return False, 0.0, 'unknown'
    
    def check_domain_reputation(self, domain: str) -> Tuple[bool, float, str]:
        """
        Check domain reputation
        
        Returns:
            (is_malicious, confidence, threat_level)
        """
        if 'domain' in self.indicators and domain in self.indicators['domain']:
            indicator = self.indicators['domain'][domain]
            return True, indicator.confidence, indicator.threat_level
        
        return False, 0.0, 'unknown'
    
    def get_threat_indicators(self, indicator_type: str = None) -> List[ThreatIndicator]:
        """Get all threat indicators of a specific type"""
        if indicator_type:
            return list(self.indicators.get(indicator_type, {}).values())
        else:
            all_indicators = []
            for indicators in self.indicators.values():
                all_indicators.extend(indicators.values())
            return all_indicators
    
    def get_statistics(self) -> Dict:
        """Get threat intelligence statistics"""
        stats = {
            'total_indicators': sum(len(indicators) for indicators in self.indicators.values()),
            'by_type': {indicator_type: len(indicators) for indicator_type, indicators in self.indicators.items()},
            'by_source': {},
            'by_threat_level': {},
            'last_updates': self.last_update
        }
        
        # Count by source and threat level
        for indicators in self.indicators.values():
            for indicator in indicators.values():
                # By source
                if indicator.source not in stats['by_source']:
                    stats['by_source'][indicator.source] = 0
                stats['by_source'][indicator.source] += 1
                
                # By threat level
                if indicator.threat_level not in stats['by_threat_level']:
                    stats['by_threat_level'][indicator.threat_level] = 0
                stats['by_threat_level'][indicator.threat_level] += 1
        
        return stats
    
    def add_custom_indicator(self, value: str, indicator_type: str, threat_level: str, 
                           description: str = '', tags: List[str] = None, confidence: float = 0.5):
        """Add a custom threat indicator"""
        indicator = ThreatIndicator(
            value=value,
            indicator_type=indicator_type,
            threat_level=threat_level,
            source='custom',
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            description=description,
            tags=tags or [],
            confidence=confidence
        )
        
        if indicator_type not in self.indicators:
            self.indicators[indicator_type] = {}
        
        self.indicators[indicator_type][value] = indicator
        self._store_indicators([indicator])
        
        logger.info(f"Added custom indicator: {value} ({indicator_type})")
    
    def cleanup_old_indicators(self, days: int = 30):
        """Remove indicators older than specified days"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM indicators WHERE last_seen < ?', (cutoff_date.isoformat(),))
            deleted_count = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            # Reload data
            self.indicators.clear()
            self._load_cached_data()
            
            logger.info(f"Cleaned up {deleted_count} old indicators")
            
        except Exception as e:
            logger.error(f"Error cleaning up old indicators: {e}")

# Global instance
threat_intel = ThreatIntelligenceManager()

def get_threat_intelligence_manager() -> ThreatIntelligenceManager:
    """Get the global threat intelligence manager instance"""
    return threat_intel

if __name__ == "__main__":
    # Test the threat intelligence system
    ti = ThreatIntelligenceManager()
    
    # Update feeds
    ti.update_all_feeds()
    
    # Get statistics
    stats = ti.get_statistics()
    print("Threat Intelligence Statistics:")
    print(json.dumps(stats, indent=2, default=str))
    
    # Test IP check
    test_ip = "192.168.1.1"
    is_malicious, confidence, threat_level = ti.check_ip_reputation(test_ip)
    print(f"\nIP {test_ip}: Malicious={is_malicious}, Confidence={confidence}, Level={threat_level}")
    
    # Test domain check
    test_domain = "example.com"
    is_malicious, confidence, threat_level = ti.check_domain_reputation(test_domain)
    print(f"Domain {test_domain}: Malicious={is_malicious}, Confidence={confidence}, Level={threat_level}")
