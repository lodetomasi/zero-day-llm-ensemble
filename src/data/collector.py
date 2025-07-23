"""
Data collector with real-time API verification for Zero-Day Detection
"""
import requests
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import pandas as pd
from pathlib import Path

from config.settings import (
    CISA_KEV_URL, NVD_API_URL, MAX_RETRIES, RETRY_DELAY,
    RATE_LIMIT_DELAY, REQUEST_TIMEOUT, DATA_DIR
)
from src.utils.logger import get_logger, api_logger

logger = get_logger(__name__)


class DataCollector:
    """Collect and verify CVE data from multiple sources"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Zero-Day-Detection-Research/1.0 (Academic Research)'
        })
        self.cache_dir = DATA_DIR / "cache"
        self.cache_dir.mkdir(exist_ok=True, parents=True)
        
        # Track API health
        self.api_status = {
            'CISA_KEV': {'available': False, 'last_check': None, 'error': None},
            'NVD': {'available': False, 'last_check': None, 'error': None}
        }
    
    def verify_apis(self) -> Dict[str, bool]:
        """Verify all APIs are accessible and returning valid data"""
        logger.info("Verifying API availability...")
        
        # Test CISA KEV
        cisa_status = self._test_cisa_api()
        self.api_status['CISA_KEV'].update({
            'available': cisa_status[0],
            'last_check': datetime.now().isoformat(),
            'error': cisa_status[1]
        })
        
        # Test NVD
        nvd_status = self._test_nvd_api()
        self.api_status['NVD'].update({
            'available': nvd_status[0],
            'last_check': datetime.now().isoformat(),
            'error': nvd_status[1]
        })
        
        # Log results
        for api, status in self.api_status.items():
            if status['available']:
                logger.info(f"✓ {api} API is available")
            else:
                logger.error(f"✗ {api} API is unavailable: {status['error']}")
        
        return {api: status['available'] for api, status in self.api_status.items()}
    
    def _test_cisa_api(self) -> Tuple[bool, Optional[str]]:
        """Test CISA KEV API"""
        try:
            response = self.session.get(CISA_KEV_URL, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if 'vulnerabilities' in data and isinstance(data['vulnerabilities'], list):
                sample_size = min(3, len(data['vulnerabilities']))
                logger.debug(f"CISA KEV API test successful. Found {len(data['vulnerabilities'])} vulnerabilities")
                
                # Verify data structure
                if sample_size > 0:
                    sample = data['vulnerabilities'][0]
                    required_fields = ['cveID', 'vendorProject', 'shortDescription']
                    if all(field in sample for field in required_fields):
                        return True, None
                    else:
                        return False, "Missing required fields in CISA data"
                
                return True, None
            else:
                return False, "Invalid CISA KEV data structure"
                
        except requests.RequestException as e:
            return False, f"Request error: {str(e)}"
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON response: {str(e)}"
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"
    
    def _test_nvd_api(self) -> Tuple[bool, Optional[str]]:
        """Test NVD API"""
        try:
            # Test with minimal parameters
            test_params = {
                'resultsPerPage': 1,
                'startIndex': 0
            }
            
            response = self.session.get(NVD_API_URL, params=test_params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if 'vulnerabilities' in data:
                logger.debug("NVD API test successful")
                return True, None
            else:
                return False, "Invalid NVD data structure"
                
        except requests.RequestException as e:
            return False, f"Request error: {str(e)}"
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON response: {str(e)}"
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"
    
    def fetch_cisa_zero_days(self, max_count: int = 100, 
                            use_cache: bool = True) -> List[Dict[str, Any]]:
        """Fetch confirmed zero-day vulnerabilities from CISA KEV"""
        logger.info(f"Fetching up to {max_count} zero-days from CISA KEV...")
        
        # Check cache first
        cache_file = self.cache_dir / "cisa_kev_data.json"
        if use_cache and cache_file.exists():
            cache_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
            if cache_age < timedelta(hours=24):
                logger.info("Using cached CISA data (less than 24 hours old)")
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)
                    return cached_data[:max_count]
        
        # Fetch fresh data
        for attempt in range(MAX_RETRIES):
            try:
                logger.debug(f"Attempt {attempt + 1}/{MAX_RETRIES} to fetch CISA data")
                api_logger.log_api_request("CISA_KEV", CISA_KEV_URL, "bulk_fetch", "DataCollector")
                
                start_time = time.time()
                response = self.session.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
                duration = time.time() - start_time
                
                response.raise_for_status()
                data = response.json()
                
                api_logger.log_api_response(
                    "CISA_KEV", 
                    {"status": "success", "count": len(data.get('vulnerabilities', []))},
                    {"total": len(response.content)},
                    duration
                )
                
                vulnerabilities = data.get('vulnerabilities', [])
                logger.info(f"Successfully fetched {len(vulnerabilities)} vulnerabilities from CISA")
                
                # Process and validate data
                processed_vulns = []
                for vuln in vulnerabilities[:max_count]:
                    processed = self._process_cisa_entry(vuln)
                    if processed:
                        processed_vulns.append(processed)
                
                # Cache the data
                if use_cache and processed_vulns:
                    with open(cache_file, 'w') as f:
                        json.dump(processed_vulns, f, indent=2)
                    logger.debug(f"Cached {len(processed_vulns)} CISA entries")
                
                return processed_vulns
                
            except Exception as e:
                api_logger.log_api_error("CISA_KEV", e, attempt + 1)
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
                else:
                    logger.error(f"Failed to fetch CISA data after {MAX_RETRIES} attempts")
                    return self._get_fallback_zero_days(max_count)
    
    def fetch_nvd_regular_cves(self, max_count: int = 100,
                              use_cache: bool = True) -> List[Dict[str, Any]]:
        """Fetch regular CVEs from NVD API"""
        logger.info(f"Fetching up to {max_count} regular CVEs from NVD...")
        
        # Check cache
        cache_file = self.cache_dir / "nvd_regular_cves.json"
        if use_cache and cache_file.exists():
            cache_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
            if cache_age < timedelta(hours=24):
                logger.info("Using cached NVD data")
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)
                    return cached_data[:max_count]
        
        regular_cves = []
        
        # Fetch from different time periods for diversity
        end_date = datetime.now()
        periods = [
            (end_date - timedelta(days=30), end_date),
            (end_date - timedelta(days=90), end_date - timedelta(days=30)),
            (end_date - timedelta(days=180), end_date - timedelta(days=90)),
            (end_date - timedelta(days=365), end_date - timedelta(days=180))
        ]
        
        for start_date, end_date in periods:
            if len(regular_cves) >= max_count:
                break
                
            batch = self._fetch_nvd_batch(
                start_date.strftime('%Y-%m-%dT00:00:00.000'),
                end_date.strftime('%Y-%m-%dT23:59:59.999'),
                results_per_page=min(50, max_count - len(regular_cves))
            )
            
            # Filter out potential zero-days
            filtered_batch = self._filter_non_zero_days(batch)
            regular_cves.extend(filtered_batch)
            
            if batch:
                time.sleep(RATE_LIMIT_DELAY)
        
        # Cache results
        if use_cache and regular_cves:
            with open(cache_file, 'w') as f:
                json.dump(regular_cves[:max_count], f, indent=2)
        
        logger.info(f"Collected {len(regular_cves[:max_count])} regular CVEs")
        return regular_cves[:max_count]
    
    def _fetch_nvd_batch(self, start_date: str, end_date: str, 
                        results_per_page: int = 50) -> List[Dict[str, Any]]:
        """Fetch a batch of CVEs from NVD"""
        params = {
            'pubStartDate': start_date,
            'pubEndDate': end_date,
            'resultsPerPage': results_per_page,
            'startIndex': 0
        }
        
        for attempt in range(MAX_RETRIES):
            try:
                api_logger.log_api_request("NVD", f"{NVD_API_URL}?{params}", "batch_fetch", "DataCollector")
                
                start_time = time.time()
                response = self.session.get(NVD_API_URL, params=params, timeout=REQUEST_TIMEOUT)
                duration = time.time() - start_time
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    api_logger.log_api_response(
                        "NVD",
                        {"status": "success", "count": len(vulnerabilities)},
                        {"total": len(response.content)},
                        duration
                    )
                    
                    processed = []
                    for vuln_wrapper in vulnerabilities:
                        processed_vuln = self._process_nvd_entry(vuln_wrapper.get('cve', {}))
                        if processed_vuln:
                            processed.append(processed_vuln)
                    
                    return processed
                    
                elif response.status_code == 403:
                    logger.warning("NVD API rate limit reached")
                    time.sleep(30)  # Wait longer for rate limit
                    
            except Exception as e:
                api_logger.log_api_error("NVD", e, attempt + 1)
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
        
        return []
    
    def _process_cisa_entry(self, vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process and validate CISA KEV entry"""
        try:
            return {
                'cve_id': vuln.get('cveID', ''),
                'vendor': vuln.get('vendorProject', 'Unknown'),
                'product': vuln.get('product', 'Unknown'),
                'vulnerability_name': vuln.get('vulnerabilityName', ''),
                'description': vuln.get('shortDescription', ''),
                'date_added': vuln.get('dateAdded', ''),
                'due_date': vuln.get('dueDate', ''),
                'required_action': vuln.get('requiredAction', ''),
                'notes': vuln.get('notes', ''),
                'is_zero_day': True,  # CISA KEV only contains confirmed zero-days
                'source': 'CISA_KEV',
                'year': int(vuln.get('cveID', 'CVE-2024-0000').split('-')[1]),
                'published_date': vuln.get('dateAdded', ''),
                'last_modified': vuln.get('dateAdded', '')
            }
        except Exception as e:
            logger.error(f"Error processing CISA entry: {e}")
            return None
    
    def _process_nvd_entry(self, cve: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process and validate NVD entry"""
        try:
            # Extract description
            descriptions = cve.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            # Extract metrics
            metrics = cve.get('metrics', {})
            cvss_data = {}
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
            
            return {
                'cve_id': cve.get('id', ''),
                'vendor': 'Various',  # NVD doesn't have structured vendor field
                'product': 'Various',
                'description': description,
                'published_date': cve.get('published', ''),
                'last_modified': cve.get('lastModified', ''),
                'cvss_score': cvss_data.get('baseScore', 0),
                'cvss_severity': cvss_data.get('baseSeverity', 'NONE'),
                'is_zero_day': False,  # Default for NVD entries
                'source': 'NVD',
                'year': int(cve.get('id', 'CVE-2024-0000').split('-')[1])
            }
        except Exception as e:
            logger.error(f"Error processing NVD entry: {e}")
            return None
    
    def _filter_non_zero_days(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter out potential zero-days from NVD data"""
        zero_day_indicators = [
            'actively exploited',
            'in the wild',
            'exploitation detected',
            'being exploited',
            'active exploitation',
            'zero-day',
            '0-day'
        ]
        
        filtered = []
        for cve in cves:
            description = cve.get('description', '').lower()
            
            # Skip if contains zero-day indicators
            if any(indicator in description for indicator in zero_day_indicators):
                logger.debug(f"Filtering out potential zero-day: {cve.get('cve_id')}")
                continue
                
            filtered.append(cve)
        
        return filtered
    
    def _get_fallback_zero_days(self, count: int) -> List[Dict[str, Any]]:
        """Fallback zero-day data for testing"""
        logger.warning("Using fallback zero-day data")
        
        fallback_data = [
            {
                'cve_id': 'CVE-2024-3400',
                'vendor': 'Palo Alto Networks',
                'product': 'PAN-OS',
                'description': 'A command injection vulnerability in Palo Alto Networks PAN-OS software enables an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.',
                'is_zero_day': True,
                'source': 'FALLBACK',
                'year': 2024
            },
            {
                'cve_id': 'CVE-2024-21762',
                'vendor': 'Fortinet',
                'product': 'FortiOS',
                'description': 'An out-of-bounds write vulnerability in FortiOS and FortiProxy SSL-VPN may allow a remote unauthenticated attacker to execute arbitrary code.',
                'is_zero_day': True,
                'source': 'FALLBACK',
                'year': 2024
            }
        ]
        
        return fallback_data[:count]
    
    def create_balanced_dataset(self, zero_day_count: int = 100,
                               regular_count: int = 100,
                               save_to_file: bool = True) -> pd.DataFrame:
        """Create a balanced dataset with verification"""
        logger.info(f"Creating balanced dataset: {zero_day_count} zero-days + {regular_count} regular CVEs")
        
        # Verify APIs first
        api_status = self.verify_apis()
        
        if not api_status['CISA_KEV']:
            logger.warning("CISA KEV API unavailable, using fallback data")
        
        if not api_status['NVD']:
            logger.warning("NVD API unavailable, dataset may be limited")
        
        # Fetch data
        zero_days = self.fetch_cisa_zero_days(zero_day_count)
        regular_cves = self.fetch_nvd_regular_cves(regular_count)
        
        # Ensure we have enough data
        actual_zero_days = len(zero_days)
        actual_regular = len(regular_cves)
        
        if actual_zero_days < zero_day_count:
            logger.warning(f"Only {actual_zero_days} zero-days available (requested {zero_day_count})")
        
        if actual_regular < regular_count:
            logger.warning(f"Only {actual_regular} regular CVEs available (requested {regular_count})")
        
        # Combine and create DataFrame
        all_data = zero_days + regular_cves
        df = pd.DataFrame(all_data)
        
        # Shuffle
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Log statistics
        logger.info(f"Dataset created:")
        logger.info(f"  Total samples: {len(df)}")
        logger.info(f"  Zero-days: {df['is_zero_day'].sum()} ({df['is_zero_day'].mean()*100:.1f}%)")
        logger.info(f"  Regular CVEs: {(~df['is_zero_day']).sum()} ({(~df['is_zero_day']).mean()*100:.1f}%)")
        logger.info(f"  Sources: {df['source'].value_counts().to_dict()}")
        
        # Save to file
        if save_to_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = DATA_DIR / f"dataset_{timestamp}.csv"
            df.to_csv(output_file, index=False)
            logger.info(f"Dataset saved to: {output_file}")
        
        return df