# VirusTotal API (https://www.virustotal.com/gui/my-apikey)
VIRUSTOTAL_API_KEY = ""

# AbuseIPDB API (https://www.abuseipdb.com/account/api)
ABUSEIPDB_API_KEY = ""

# Shodan API (https://account.shodan.io/)
SHODAN_API_KEY = ""

# AlienVault OTX API (https://otx.alienvault.com/api/)
OTX_API_KEY = ""

# MISP (Malware Information Sharing Platform) API
MISP_URL = ""
MISP_API_KEY = ""

# CIRCL (Computer Incident Response Center Luxembourg) API
CIRCL_API_KEY = ""

# Custom threat feed URLs
CUSTOM_THREAT_FEEDS = {
    'custom_feed_1': '',
    'custom_feed_2': '',
}

# Update Settings
# ===============
UPDATE_INTERVAL = 3600  # seconds (1 hour)
CACHE_DURATION = 86400  # seconds (24 hours)
MAX_INDICATORS_PER_SOURCE = 100000

# Rate Limiting
# =============
RATE_LIMIT_DELAY = 1  # seconds between API calls
MAX_RETRIES = 3
TIMEOUT = 30  # seconds

# Database Settings
# ================
DATABASE_PATH = 'threat_intel.db'
CLEANUP_OLD_INDICATORS_DAYS = 30

# Logging
# =======
LOG_LEVEL = 'INFO'
LOG_FILE = 'threat_intelligence.log'

# Feature Flags
# =============
ENABLE_VIRUSTOTAL = False
ENABLE_ABUSEIPDB = False
ENABLE_SHODAN = False
ENABLE_OTX = False
ENABLE_MISP = False
ENABLE_CIRCL = False
ENABLE_FREE_FEEDS = True
ENABLE_CUSTOM_FEEDS = False

# Threat Level Mapping
# ===================
THREAT_LEVEL_MAPPING = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
    'unknown': 0
}

# Confidence Thresholds
# =====================
MIN_CONFIDENCE_THRESHOLD = 0.5
HIGH_CONFIDENCE_THRESHOLD = 0.8

# Alert Settings
# ==============
ALERT_ON_NEW_INDICATORS = True
ALERT_ON_HIGH_CONFIDENCE = True
ALERT_EMAIL = ""
ALERT_WEBHOOK_URL = ""

# Performance Settings
# ===================
MAX_CONCURRENT_REQUESTS = 5
BATCH_SIZE = 1000
MEMORY_LIMIT_MB = 512

def get_api_config():
    """Get API configuration dictionary"""
    return {
        'virustotal': {
            'api_key': VIRUSTOTAL_API_KEY,
            'enabled': ENABLE_VIRUSTOTAL and bool(VIRUSTOTAL_API_KEY)
        },
        'abuseipdb': {
            'api_key': ABUSEIPDB_API_KEY,
            'enabled': ENABLE_ABUSEIPDB and bool(ABUSEIPDB_API_KEY)
        },
        'shodan': {
            'api_key': SHODAN_API_KEY,
            'enabled': ENABLE_SHODAN and bool(SHODAN_API_KEY)
        },
        'otx': {
            'api_key': OTX_API_KEY,
            'enabled': ENABLE_OTX and bool(OTX_API_KEY)
        },
        'misp': {
            'url': MISP_URL,
            'api_key': MISP_API_KEY,
            'enabled': ENABLE_MISP and bool(MISP_URL) and bool(MISP_API_KEY)
        },
        'circl': {
            'api_key': CIRCL_API_KEY,
            'enabled': ENABLE_CIRCL and bool(CIRCL_API_KEY)
        }
    }

def get_update_settings():
    """Get update settings dictionary"""
    return {
        'update_interval': UPDATE_INTERVAL,
        'cache_duration': CACHE_DURATION,
        'max_indicators_per_source': MAX_INDICATORS_PER_SOURCE,
        'rate_limit_delay': RATE_LIMIT_DELAY,
        'max_retries': MAX_RETRIES,
        'timeout': TIMEOUT
    }

def get_database_settings():
    """Get database settings dictionary"""
    return {
        'database_path': DATABASE_PATH,
        'cleanup_old_indicators_days': CLEANUP_OLD_INDICATORS_DAYS
    }

def get_logging_settings():
    """Get logging settings dictionary"""
    return {
        'log_level': LOG_LEVEL,
        'log_file': LOG_FILE
    }

def get_feature_flags():
    """Get feature flags dictionary"""
    return {
        'enable_virustotal': ENABLE_VIRUSTOTAL,
        'enable_abuseipdb': ENABLE_ABUSEIPDB,
        'enable_shodan': ENABLE_SHODAN,
        'enable_otx': ENABLE_OTX,
        'enable_misp': ENABLE_MISP,
        'enable_circl': ENABLE_CIRCL,
        'enable_free_feeds': ENABLE_FREE_FEEDS,
        'enable_custom_feeds': ENABLE_CUSTOM_FEEDS
    }

if __name__ == "__main__":
    print("Threat Intelligence Configuration")
    print("=" * 40)
    print(f"Update Interval: {UPDATE_INTERVAL} seconds")
    print(f"Cache Duration: {CACHE_DURATION} seconds")
    print(f"Database Path: {DATABASE_PATH}")
    print(f"Log Level: {LOG_LEVEL}")
    print("\nAPI Status:")
    config = get_api_config()
    for api_name, api_config in config.items():
        status = "Enabled" if api_config['enabled'] else "Disabled"
        print(f"  {api_name}: {status}")
