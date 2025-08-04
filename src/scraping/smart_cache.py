#!/usr/bin/env python3
"""
Smart Caching System for Zero-Day Scraper
Implements multi-tier caching with intelligent TTL management
"""
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, Tuple
import pickle
import logging
from functools import lru_cache
from collections import OrderedDict
import threading

logger = logging.getLogger(__name__)


class TTLCache:
    """In-memory cache with TTL support"""
    
    def __init__(self, maxsize: int = 1000, ttl: int = 3600):
        self.maxsize = maxsize
        self.ttl = ttl
        self.cache = OrderedDict()
        self.lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired"""
        with self.lock:
            if key in self.cache:
                value, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    # Move to end (LRU)
                    self.cache.move_to_end(key)
                    return value
                else:
                    # Expired
                    del self.cache[key]
            return None
    
    def set(self, key: str, value: Any):
        """Set value in cache"""
        with self.lock:
            # Remove oldest if at capacity
            if len(self.cache) >= self.maxsize:
                self.cache.popitem(last=False)
            
            self.cache[key] = (value, time.time())
    
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()


class DiskCache:
    """Disk-based cache with TTL support"""
    
    def __init__(self, cache_dir: Path = None, ttl: int = 86400):
        self.cache_dir = cache_dir or Path("data/cache/disk")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
    
    def _get_cache_path(self, key: str) -> Path:
        """Get file path for cache key"""
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.cache"
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from disk cache"""
        cache_path = self._get_cache_path(key)
        
        if cache_path.exists():
            try:
                # Check if expired
                mtime = cache_path.stat().st_mtime
                if time.time() - mtime < self.ttl:
                    with open(cache_path, 'rb') as f:
                        return pickle.load(f)
                else:
                    # Expired - remove
                    cache_path.unlink()
            except Exception as e:
                logger.error(f"Error reading cache {key}: {e}")
        
        return None
    
    def set(self, key: str, value: Any):
        """Set value in disk cache"""
        cache_path = self._get_cache_path(key)
        
        try:
            with open(cache_path, 'wb') as f:
                pickle.dump(value, f)
            logger.error(f"Error writing cache {key}: {e}")
    
    def clear(self):
        """Clear all cache files"""
        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                cache_file.unlink()
            except:
                pass


class SmartCache:
    """
    Intelligent multi-tier caching system with adaptive TTL
    """
    
    def __init__(self, cache_dir: Path = None):
        """Initialize smart cache with multiple tiers"""
        self.cache_dir = cache_dir or Path("data/cache")
        
        # Cache tiers with different characteristics
        self.tiers = {
            'hot': TTLCache(maxsize=1000, ttl=3600),        # 1 hour - frequent access
            'warm': TTLCache(maxsize=5000, ttl=21600),      # 6 hours - moderate access
            'cold': DiskCache(self.cache_dir / 'cold', ttl=604800)  # 7 days - rare access
        }
        
        # Access tracking for tier promotion/demotion
        self.access_counts = {}
        self.access_lock = threading.Lock()
        
        # CVE criticality cache
        self.criticality_cache = TTLCache(maxsize=10000, ttl=86400)
        
        # Cache statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'tier_hits': {'hot': 0, 'warm': 0, 'cold': 0}
        }
    
    def get(self, key: str, cve_data: Dict = None) -> Optional[Any]:
        """
        Get value from cache with intelligent tier selection
        
        Args:
            key: Cache key (usually URL)
            cve_data: Optional CVE context for intelligent caching
            
        Returns:
            Cached value or None
        """
        # Track access
        self._track_access(key)
        
        # Determine appropriate tier based on context
        if cve_data:
            tier_order = self._get_tier_order(cve_data)
        else:
            tier_order = ['hot', 'warm', 'cold']
        
        # Check each tier in order
        for tier_name in tier_order:
            tier = self.tiers[tier_name]
            value = tier.get(key)
            
            if value is not None:
                self.stats['hits'] += 1
                self.stats['tier_hits'][tier_name] += 1
                
                # Promote to hotter tier if frequently accessed
                if tier_name != 'hot' and self._should_promote(key):
                    self.tiers['hot'].set(key, value)
                
                return value
        
        self.stats['misses'] += 1
        return None
    
    def set(self, key: str, value: Any, cve_data: Dict = None):
        """
        Set value in cache with intelligent tier selection
        
        Args:
            key: Cache key
            value: Value to cache
            cve_data: Optional CVE context for intelligent caching
        """
        # Determine appropriate tier
        tier_name = self._select_tier(key, cve_data)
        tier = self.tiers[tier_name]
        
        # Set in selected tier
        tier.set(key, value)
        
        # Also set in hot tier if critical
        if cve_data and self._is_critical(cve_data) and tier_name != 'hot':
            self.tiers['hot'].set(key, value)
    
    def adaptive_ttl(self, cve_data: Dict) -> int:
        """
        Calculate adaptive TTL based on CVE characteristics
        
        Args:
            cve_data: CVE information
            
        Returns:
            TTL in seconds
        """
        base_ttl = 3600  # 1 hour base
        
        # Critical CVEs get shorter TTL for fresh data
        if self._is_critical(cve_data):
            base_ttl = 900  # 15 minutes
        
        # Zero-days get very short TTL
        if self._is_likely_zero_day(cve_data):
            base_ttl = 300  # 5 minutes
        
        # Old CVEs get longer TTL
        if self._is_old_cve(cve_data):
            base_ttl = 86400  # 24 hours
        
        # Active exploitation reduces TTL
        if self._has_active_exploitation(cve_data):
            base_ttl = min(base_ttl, 1800)  # Max 30 minutes
        
        return base_ttl
    
    def invalidate(self, pattern: str = None):
        """
        Invalidate cache entries matching pattern
        
        Args:
            pattern: Optional pattern to match (invalidates all if None)
        """
        if pattern is None:
            # Clear all tiers
            for tier in self.tiers.values():
                tier.clear()
            self.access_counts.clear()
        else:
            # Would implement pattern matching invalidation
            logger.warning(f"Pattern invalidation not yet implemented: {pattern}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.stats['hits'] + self.stats['misses']
        hit_rate = self.stats['hits'] / total_requests if total_requests > 0 else 0
        
        return {
            'total_requests': total_requests,
            'hits': self.stats['hits'],
            'misses': self.stats['misses'],
            'hit_rate': hit_rate,
            'tier_distribution': self.stats['tier_hits'],
            'hot_cache_size': len(self.tiers['hot'].cache),
            'warm_cache_size': len(self.tiers['warm'].cache)
        }
    
    def _track_access(self, key: str):
        """Track access count for cache promotion"""
        with self.access_lock:
            self.access_counts[key] = self.access_counts.get(key, 0) + 1
    
    def _should_promote(self, key: str) -> bool:
        """Determine if cache entry should be promoted to hotter tier"""
        access_count = self.access_counts.get(key, 0)
        return access_count > 3  # Promote after 3 accesses
    
    def _select_tier(self, key: str, cve_data: Dict = None) -> str:
        """Select appropriate cache tier"""
        if not cve_data:
            return 'warm'  # Default tier
        
        # Critical CVEs go to hot tier
        if self._is_critical(cve_data):
            return 'hot'
        
        # Recent CVEs go to warm tier
        if self._is_recent(cve_data):
            return 'warm'
        
        # Everything else goes to cold tier
        return 'cold'
    
    def _get_tier_order(self, cve_data: Dict) -> list:
        """Get tier check order based on CVE characteristics"""
        if self._is_critical(cve_data):
            return ['hot', 'warm', 'cold']
        elif self._is_old_cve(cve_data):
            return ['cold', 'warm', 'hot']
        else:
            return ['warm', 'hot', 'cold']
    
    def _is_critical(self, cve_data: Dict) -> bool:
        """Check if CVE is critical"""
        # Check cache first
        cve_id = cve_data.get('cve_id', '')
        cached = self.criticality_cache.get(cve_id)
        if cached is not None:
            return cached
        
        # Calculate criticality
        critical = False
        
        # CISA KEV = critical
        if cve_data.get('in_cisa_kev', False):
            critical = True
        
        # High CVSS = critical
        cvss = cve_data.get('cvss_score', 0)
        if cvss >= 9.0:
            critical = True
        
        # Active exploitation = critical
        if cve_data.get('active_exploitation', False):
            critical = True
        
        # Cache result
        self.criticality_cache.set(cve_id, critical)
        return critical
    
    def _is_likely_zero_day(self, cve_data: Dict) -> bool:
        """Check if CVE is likely a zero-day"""
        indicators = 0
        
        if cve_data.get('in_cisa_kev', False):
            indicators += 1
        
        if cve_data.get('exploitation_before_patch', False):
            indicators += 1
        
        if cve_data.get('apt_association', False):
            indicators += 1
        
        return indicators >= 2
    
    def _is_recent(self, cve_data: Dict) -> bool:
        """Check if CVE is recent (within 30 days)"""
        published = cve_data.get('published_date')
        if not published:
            return True  # Assume recent if unknown
        
        try:
            pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
            return (datetime.now() - pub_date).days < 30
        except:
            return True
    
    def _is_old_cve(self, cve_data: Dict) -> bool:
        """Check if CVE is old (over 1 year)"""
        published = cve_data.get('published_date')
        if not published:
            return False
        
        try:
            pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
            return (datetime.now() - pub_date).days > 365
        except:
            return False
    
    def _has_active_exploitation(self, cve_data: Dict) -> bool:
        """Check if CVE has active exploitation"""
        return (
            cve_data.get('active_exploitation', False) or
            cve_data.get('honeypot_activity', False) or
            cve_data.get('incident_reports', 0) > 0
        )


class CacheWarmer:
    """Pre-warm cache for critical CVEs"""
    
    def __init__(self, cache: SmartCache, scraper):
        self.cache = cache
        self.scraper = scraper
    
    def warm_critical_cves(self, cve_list: list):
        """Pre-warm cache for critical CVEs"""
        logger.info(f"Warming cache for {len(cve_list)} critical CVEs")
        
        for cve_id in cve_list:
            try:
                # Scrape with high priority
                evidence = self.scraper.scrape_all_sources(cve_id)
                
                # Cache with appropriate TTL
                ttl = self.cache.adaptive_ttl(evidence)
                
                # Store in hot tier for critical CVEs
                self.cache.set(f"evidence:{cve_id}", evidence, evidence)
                
            except Exception as e:
                logger.error(f"Error warming cache for {cve_id}: {e}")
    
    def schedule_refresh(self, cve_id: str, interval: int):
        """Schedule periodic refresh for actively monitored CVEs"""
        # Would implement scheduled refresh logic
        pass


# Singleton instance
_smart_cache_instance = None


def get_smart_cache() -> SmartCache:
    """Get singleton SmartCache instance"""
    global _smart_cache_instance
    if _smart_cache_instance is None:
        _smart_cache_instance = SmartCache()
    return _smart_cache_instance


__all__ = ['SmartCache', 'TTLCache', 'DiskCache', 'CacheWarmer', 'get_smart_cache']