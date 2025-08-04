#!/usr/bin/env python3
"""
Comprehensive Zero-Day Evidence Scraper
Collects evidence from multiple sources to determine zero-day likelihood
"""
import json
import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime, timedelta
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple
import logging
from urllib.parse import quote_plus, urlparse
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ComprehensiveZeroDayScraper:
    """
    Comprehensive scraper that collects evidence from multiple sources
    to determine if a CVE was exploited as a zero-day
    """
    
    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize scraper with caching support"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Setup caching
        self.cache_dir = cache_dir or Path("data/scraping_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_expiry = timedelta(days=7)  # Cache for 7 days
        
        # Rate limiting
        self.last_request_time = {}
        self.min_delay = 1.0  # Minimum delay between requests to same domain
        
    def _get_cache_path(self, url: str) -> Path:
        """Get cache file path for a URL"""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return self.cache_dir / f"{url_hash}.json"
    
    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cache file is still valid"""
        if not cache_path.exists():
            return False
        
        # Check age
        cache_time = datetime.fromtimestamp(cache_path.stat().st_mtime)
        return datetime.now() - cache_time < self.cache_expiry
    
    def _rate_limit(self, url: str):
        """Implement rate limiting per domain"""
        domain = urlparse(url).netloc
        
        if domain in self.last_request_time:
            elapsed = time.time() - self.last_request_time[domain]
            if elapsed < self.min_delay:
                time.sleep(self.min_delay - elapsed)
        
        self.last_request_time[domain] = time.time()
    
    def _fetch_url(self, url: str, use_cache: bool = True) -> Optional[str]:
        """Fetch URL content with caching and error handling"""
        cache_path = self._get_cache_path(url)
        
        # Check cache
        if use_cache and self._is_cache_valid(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    cached_data = json.load(f)
                    return cached_data.get('content')
            except:
                pass
        
        # Rate limit
        self._rate_limit(url)
        
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                content = response.text
                
                # Cache the response
                with open(cache_path, 'w') as f:
                    json.dump({
                        'url': url,
                        'content': content,
                        'fetched_at': datetime.now().isoformat()
                    }, f)
                
                return content
            else:
                logger.warning(f"HTTP {response.status_code} for {url}")
                return None
                
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return None
    
    def scrape_all_sources(self, cve_id: str) -> Dict:
        """
        Scrape all available sources for a CVE
        Returns comprehensive evidence dictionary
        """
        logger.info(f"Starting comprehensive scrape for {cve_id}")
        
        evidence = {
            'cve_id': cve_id,
            'scraped_at': datetime.now().isoformat(),
            'sources': {},
            'indicators': {
                'exploitation_before_patch': [],
                'active_campaigns': [],
                'apt_associations': [],
                'emergency_patches': [],
                'timeline_anomalies': []
            },
            'scores': {
                'exploitation_likelihood': 0.0,
                'zero_day_confidence': 0.0,
                'evidence_quality': 0.0
            },
            'summary': ''
        }
        
        # Scrape sources in parallel
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {
                executor.submit(self.scrape_nvd_details, cve_id): 'nvd',
                executor.submit(self.scrape_cisa_kev, cve_id): 'cisa_kev',
                executor.submit(self.scrape_security_news, cve_id): 'security_news',
                executor.submit(self.scrape_github_activity, cve_id): 'github',
                executor.submit(self.scrape_exploit_databases, cve_id): 'exploit_db',
                executor.submit(self.scrape_threat_intelligence, cve_id): 'threat_intel',
                executor.submit(self.scrape_vendor_advisories, cve_id): 'vendor',
                executor.submit(self.scrape_social_media, cve_id): 'social_media',
                executor.submit(self.scrape_mitre_attack, cve_id): 'mitre_attack',
                executor.submit(self.scrape_virustotal, cve_id): 'virustotal',
                executor.submit(self.scrape_patch_timeline, cve_id): 'patch_timeline'
            }
            
            for future in as_completed(futures):
                source_name = futures[future]
                try:
                    result = future.result()
                    evidence['sources'][source_name] = result
                    
                    # Extract indicators from each source
                    self._extract_indicators(result, evidence['indicators'])
                    
                except Exception as e:
                    logger.error(f"Error scraping {source_name}: {e}")
                    evidence['sources'][source_name] = {'error': str(e)}
        
        # Calculate final scores
        evidence['scores'] = self._calculate_scores(evidence)
        evidence['summary'] = self._generate_summary(evidence)
        
        return evidence
    
    def scrape_nvd_details(self, cve_id: str) -> Dict:
        """Scrape detailed information from NVD"""
        result = {
            'found': False,
            'published_date': None,
            'last_modified': None,
            'cvss_score': None,
            'references': [],
            'cwe': [],
            'timeline_analysis': {}
        }
        
        try:
            # Use NVD API 2.0
            api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            content = self._fetch_url(api_url)
            
            if content:
                data = json.loads(content)
                if 'vulnerabilities' in data and data['vulnerabilities']:
                    vuln = data['vulnerabilities'][0]['cve']
                    
                    result['found'] = True
                    result['published_date'] = vuln.get('published')
                    result['last_modified'] = vuln.get('lastModified')
                    
                    # Extract CVSS
                    metrics = vuln.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        result['cvss_score'] = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV30' in metrics:
                        result['cvss_score'] = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                    
                    # Extract references
                    for ref in vuln.get('references', []):
                        result['references'].append({
                            'url': ref.get('url'),
                            'tags': ref.get('tags', [])
                        })
                    
                    # Timeline analysis
                    if result['published_date']:
                        pub_date = datetime.fromisoformat(result['published_date'].replace('Z', '+00:00'))
                        mod_date = datetime.fromisoformat(result['last_modified'].replace('Z', '+00:00'))
                        
                        time_diff = (mod_date - pub_date).days
                        result['timeline_analysis'] = {
                            'days_between_publish_modify': time_diff,
                            'rapid_update': time_diff < 1,  # Updated within a day suggests urgency
                            'year': pub_date.year,
                            'month': pub_date.month
                        }
                    
        except Exception as e:
            logger.error(f"NVD scraping error: {e}")
            
        return result
    
    def scrape_cisa_kev(self, cve_id: str) -> Dict:
        """Check if CVE is in CISA Known Exploited Vulnerabilities catalog"""
        result = {
            'in_kev': False,
            'date_added': None,
            'vulnerability_name': None,
            'notes': None,
            'required_action': None
        }
        
        try:
            kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            content = self._fetch_url(kev_url)
            
            if content:
                data = json.loads(content)
                for vuln in data.get('vulnerabilities', []):
                    if vuln.get('cveID') == cve_id:
                        result['in_kev'] = True
                        result['date_added'] = vuln.get('dateAdded')
                        result['vulnerability_name'] = vuln.get('vulnerabilityName')
                        result['notes'] = vuln.get('notes')
                        result['required_action'] = vuln.get('requiredAction')
                        break
                        
        except Exception as e:
            logger.error(f"CISA KEV scraping error: {e}")
            
        return result
    
    def scrape_security_news(self, cve_id: str) -> Dict:
        """Scrape security news outlets for zero-day mentions"""
        result = {
            'articles': [],
            'zero_day_mentions': 0,
            'exploitation_mentions': 0,
            'emergency_patch_mentions': 0,
            'sources_checked': []
        }
        
        # Security news sources to check
        news_sources = [
            {
                'name': 'The Hacker News',
                'search_url': f'https://thehackernews.com/search?q={cve_id}',
                'selector': 'div.body-post'
            },
            {
                'name': 'BleepingComputer',
                'search_url': f'https://www.bleepingcomputer.com/search/?q={cve_id}',
                'selector': 'div.search-result'
            },
            {
                'name': 'SecurityWeek',
                'search_url': f'https://www.securityweek.com/?s={cve_id}',
                'selector': 'article'
            },
            {
                'name': 'ZDNet Security',
                'search_url': f'https://www.zdnet.com/search/?q={cve_id}',
                'selector': 'article'
            }
        ]
        
        for source in news_sources:
            try:
                content = self._fetch_url(source['search_url'])
                if content:
                    soup = BeautifulSoup(content, 'html.parser')
                    articles = soup.select(source['selector'])[:3]  # First 3 results
                    
                    for article in articles:
                        text = article.get_text().lower()
                        
                        # Check for zero-day indicators
                        zero_day_terms = ['zero-day', '0-day', 'zero day', 'zeroday']
                        exploitation_terms = ['actively exploited', 'in the wild', 'active exploitation', 
                                            'ongoing attacks', 'under attack']
                        emergency_terms = ['emergency patch', 'out-of-band', 'urgent update', 'critical update']
                        
                        article_data = {
                            'source': source['name'],
                            'mentions_zero_day': any(term in text for term in zero_day_terms),
                            'mentions_exploitation': any(term in text for term in exploitation_terms),
                            'mentions_emergency': any(term in text for term in emergency_terms)
                        }
                        
                        if article_data['mentions_zero_day']:
                            result['zero_day_mentions'] += 1
                        if article_data['mentions_exploitation']:
                            result['exploitation_mentions'] += 1
                        if article_data['mentions_emergency']:
                            result['emergency_patch_mentions'] += 1
                            
                        result['articles'].append(article_data)
                    
                    result['sources_checked'].append(source['name'])
                    
            except Exception as e:
                logger.warning(f"Error scraping {source['name']}: {e}")
                
        return result
    
    def scrape_github_activity(self, cve_id: str) -> Dict:
        """Analyze GitHub activity related to the CVE"""
        result = {
            'poc_repositories': 0,
            'earliest_poc_date': None,
            'exploit_tools': [],
            'timeline_analysis': {},
            'stars_total': 0
        }
        
        try:
            # Search GitHub via API
            search_url = f"https://api.github.com/search/repositories?q={cve_id}+exploit+poc&sort=created&order=asc"
            
            headers = self.session.headers.copy()
            headers['Accept'] = 'application/vnd.github.v3+json'
            
            response = self.session.get(search_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                result['poc_repositories'] = data.get('total_count', 0)
                
                if data.get('items'):
                    # Analyze first repository (earliest)
                    first_repo = data['items'][0]
                    result['earliest_poc_date'] = first_repo.get('created_at')
                    
                    # Collect exploit tools
                    for repo in data['items'][:10]:  # First 10 repos
                        if any(term in repo.get('description', '').lower() 
                               for term in ['exploit', 'poc', 'rce', 'vulnerability']):
                            result['exploit_tools'].append({
                                'name': repo.get('name'),
                                'created': repo.get('created_at'),
                                'stars': repo.get('stargazers_count', 0),
                                'language': repo.get('language')
                            })
                            result['stars_total'] += repo.get('stargazers_count', 0)
                    
                    # Timeline analysis
                    if result['earliest_poc_date']:
                        poc_date = datetime.fromisoformat(result['earliest_poc_date'].replace('Z', '+00:00'))
                        result['timeline_analysis'] = {
                            'year': poc_date.year,
                            'month': poc_date.month,
                            'days_old': (datetime.now() - poc_date.replace(tzinfo=None)).days
                        }
                        
        except Exception as e:
            logger.error(f"GitHub scraping error: {e}")
            
        return result
    
    def scrape_exploit_databases(self, cve_id: str) -> Dict:
        """Check various exploit databases"""
        result = {
            'exploit_db': False,
            'metasploit': False,
            'packetstorm': False,
            'exploit_count': 0,
            'commercial_exploit': False
        }
        
        try:
            # Check Exploit-DB (via search)
            exploitdb_url = f"https://www.exploit-db.com/search?cve={cve_id}"
            content = self._fetch_url(exploitdb_url)
            if content and cve_id in content:
                result['exploit_db'] = True
                result['exploit_count'] += 1
            
            # Check Rapid7 (Metasploit)
            rapid7_url = f"https://www.rapid7.com/db/?q={cve_id}&type=metasploit"
            content = self._fetch_url(rapid7_url)
            if content and 'metasploit' in content.lower():
                result['metasploit'] = True
                result['exploit_count'] += 1
            
            # Check if commercial exploit exists (indicates high value)
            if content and any(term in content.lower() for term in ['zerodium', 'exodus', 'vupen']):
                result['commercial_exploit'] = True
                
        except Exception as e:
            logger.error(f"Exploit database scraping error: {e}")
            
        return result
    
    def scrape_threat_intelligence(self, cve_id: str) -> Dict:
        """Scrape threat intelligence sources"""
        result = {
            'apt_groups': [],
            'campaigns': [],
            'malware_families': [],
            'iocs': [],
            'threat_reports': []
        }
        
        # APT group patterns
        apt_patterns = [
            r'apt\d+', r'apt-\d+', 'lazarus', 'equation group', 'darkhydrus',
            'turla', 'sofacy', 'fancy bear', 'cozy bear', 'carbanak',
            'fin7', 'cobalt group', 'silence', 'ta505', 'emotet'
        ]
        
        # Search patterns
        campaign_patterns = [
            'operation', 'campaign', 'watering hole', 'spear phishing',
            'targeted attack', 'supply chain'
        ]
        
        try:
            # Search various threat intel sources
            search_queries = [
                f"{cve_id} APT",
                f"{cve_id} campaign",
                f"{cve_id} threat actor",
                f"{cve_id} attribution"
            ]
            
            for query in search_queries:
                # Use Google as a meta-search engine
                search_url = f"https://www.google.com/search?q={quote_plus(query)}"
                content = self._fetch_url(search_url)
                
                if content:
                    content_lower = content.lower()
                    
                    # Extract APT groups
                    for pattern in apt_patterns:
                        if re.search(pattern, content_lower):
                            if pattern not in [g.lower() for g in result['apt_groups']]:
                                result['apt_groups'].append(pattern.upper())
                    
                    # Extract campaigns
                    for pattern in campaign_patterns:
                        if pattern in content_lower:
                            # Extract context around the pattern
                            matches = re.finditer(pattern, content_lower)
                            for match in matches:
                                start = max(0, match.start() - 50)
                                end = min(len(content_lower), match.end() + 50)
                                context = content_lower[start:end]
                                
                                if context not in [c['context'] for c in result['campaigns']]:
                                    result['campaigns'].append({
                                        'type': pattern,
                                        'context': context
                                    })
                                    
        except Exception as e:
            logger.error(f"Threat intelligence scraping error: {e}")
            
        return result
    
    def scrape_vendor_advisories(self, cve_id: str) -> Dict:
        """Scrape vendor security advisories"""
        result = {
            'has_advisory': False,
            'emergency_patch': False,
            'out_of_band': False,
            'severity_rating': None,
            'patch_timeline': {}
        }
        
        # Common vendor advisory patterns
        vendor_patterns = {
            'microsoft': 'microsoft.com/security',
            'cisco': 'cisco.com/security',
            'adobe': 'helpx.adobe.com/security',
            'oracle': 'oracle.com/security-alerts',
            'vmware': 'vmware.com/security',
            'apple': 'support.apple.com/HT'
        }
        
        try:
            # Search for vendor advisories
            for vendor, pattern in vendor_patterns.items():
                search_url = f"https://www.google.com/search?q={quote_plus(cve_id + ' site:' + pattern)}"
                content = self._fetch_url(search_url)
                
                if content and pattern in content:
                    result['has_advisory'] = True
                    
                    # Check for emergency/out-of-band indicators
                    content_lower = content.lower()
                    if any(term in content_lower for term in 
                           ['out-of-band', 'emergency', 'immediate', 'critical update']):
                        result['emergency_patch'] = True
                        result['out_of_band'] = True
                        
        except Exception as e:
            logger.error(f"Vendor advisory scraping error: {e}")
            
        return result
    
    def scrape_social_media(self, cve_id: str) -> Dict:
        """Analyze social media discussions"""
        result = {
            'twitter_mentions': 0,
            'reddit_discussions': 0,
            'infosec_community_buzz': False,
            'researcher_claims': []
        }
        
        try:
            # Search Reddit
            reddit_url = f"https://www.reddit.com/search.json?q={cve_id}&sort=relevance"
            headers = self.session.headers.copy()
            headers['User-Agent'] = 'Python/Scraper 1.0'
            
            response = self.session.get(reddit_url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                posts = data.get('data', {}).get('children', [])
                
                security_subreddits = ['netsec', 'cybersecurity', 'infosec', 'blueteamsec']
                
                for post in posts:
                    post_data = post.get('data', {})
                    subreddit = post_data.get('subreddit', '').lower()
                    
                    if any(sec_sub in subreddit for sec_sub in security_subreddits):
                        result['reddit_discussions'] += 1
                        
                        # Check if discussing exploitation
                        title = post_data.get('title', '').lower()
                        if any(term in title for term in ['exploit', 'zero-day', '0day', 'in the wild']):
                            result['infosec_community_buzz'] = True
                            
        except Exception as e:
            logger.error(f"Social media scraping error: {e}")
            
        return result
    
    def scrape_mitre_attack(self, cve_id: str) -> Dict:
        """Scrape MITRE ATT&CK for technique associations"""
        result = {
            'techniques': [],
            'groups': [],
            'campaigns': [],
            'found': False
        }
        
        # Check cache first
        cache_key = f"mitre_{cve_id}"
        cached = self._get_cache(cache_key)
        if cached is not None:
            return cached
        
        try:
            # Search MITRE ATT&CK for CVE references
            search_url = f"https://attack.mitre.org/search/?q={cve_id}"
            self._rate_limit("attack.mitre.org")
            
            response = self.session.get(search_url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Look for technique associations
                techniques = soup.find_all('a', href=re.compile(r'/techniques/T\d+'))
                for tech in techniques[:5]:  # Limit to 5
                    result['techniques'].append({
                        'id': tech.get('href', '').split('/')[-1],
                        'name': tech.text.strip()
                    })
                
                # Look for group associations
                groups = soup.find_all('a', href=re.compile(r'/groups/G\d+'))
                for group in groups[:5]:
                    result['groups'].append({
                        'id': group.get('href', '').split('/')[-1],
                        'name': group.text.strip()
                    })
                
                result['found'] = bool(result['techniques'] or result['groups'])
                
        except Exception as e:
            logger.error(f"Error scraping MITRE ATT&CK: {e}")
        
        self._set_cache(cache_key, result)
        return result
    
    def scrape_virustotal(self, cve_id: str) -> Dict:
        """Check VirusTotal for malware samples referencing this CVE"""
        result = {
            'malware_samples': 0,
            'first_seen': None,
            'campaigns': [],
            'found': False
        }
        
        # Check cache
        cache_key = f"vt_{cve_id}"
        cached = self._get_cache(cache_key)
        if cached is not None:
            return cached
        
        try:
            # Search for CVE in VT (without API key, limited info)
            search_url = f"https://www.virustotal.com/gui/search/{cve_id}"
            self._rate_limit("virustotal.com")
            
            response = self.session.get(search_url, timeout=10)
            if response.status_code == 200:
                # Parse response for indicators
                content = response.text.lower()
                
                # Look for malware indicators
                if 'malware' in content or 'detection' in content:
                    result['found'] = True
                    # Extract sample count if visible
                    sample_match = re.search(r'(\d+)\s*samples?', content)
                    if sample_match:
                        result['malware_samples'] = int(sample_match.group(1))
                
        except Exception as e:
            logger.error(f"Error checking VirusTotal: {e}")
        
        self._set_cache(cache_key, result)
        return result
    
    def scrape_patch_timeline(self, cve_id: str) -> Dict:
        """Analyze patch timeline vs exploitation timeline"""
        result = {
            'disclosure_date': None,
            'patch_date': None,
            'first_exploit_date': None,
            'days_to_patch': None,
            'exploited_before_patch': False,
            'patch_urgency': 'unknown'
        }
        
        # Check cache
        cache_key = f"timeline_{cve_id}"
        cached = self._get_cache(cache_key)
        if cached is not None:
            return cached
        
        try:
            # Get dates from existing scraped data
            if hasattr(self, '_last_nvd_data'):
                nvd_data = self._last_nvd_data
            else:
                nvd_data = {}
            
            if nvd_data.get('published_date'):
                result['disclosure_date'] = nvd_data['published_date']
            
            # Calculate timeline metrics
            if result['disclosure_date']:
                # Look for patch urgency indicators
                result['patch_urgency'] = 'normal'
                
                # Check CISA KEV for exploitation timeline
                kev_data = self.scrape_cisa_kev(cve_id)
                if kev_data.get('in_kev'):
                    result['exploited_before_patch'] = True
                    result['patch_urgency'] = 'emergency'
                
        except Exception as e:
            logger.error(f"Error analyzing patch timeline: {e}")
        
        self._set_cache(cache_key, result)
        return result
    
    def _extract_indicators(self, source_data: Dict, indicators: Dict):
        """Extract zero-day indicators from source data"""
        
        # Check for exploitation before patch
        if source_data.get('in_kev'):  # CISA KEV listing is strong indicator
            indicators['exploitation_before_patch'].append({
                'source': 'CISA KEV',
                'confidence': 0.9
            })
        
        # Check patch timeline for pre-patch exploitation
        if source_data.get('exploited_before_patch'):
            indicators['exploitation_before_patch'].append({
                'source': 'timeline_analysis',
                'confidence': 0.85
            })
        
        # Check for APT associations
        apt_groups = source_data.get('apt_groups', [])
        for apt in apt_groups:
            indicators['apt_associations'].append({
                'group': apt,
                'source': 'threat_intel'
            })
        
        # Check MITRE ATT&CK groups
        mitre_groups = source_data.get('groups', [])
        for group in mitre_groups:
            indicators['apt_associations'].append({
                'group': group.get('name', 'Unknown'),
                'source': 'mitre_attack'
            })
        
        # Check for emergency patches
        if source_data.get('emergency_patch') or source_data.get('out_of_band'):
            indicators['emergency_patches'].append({
                'source': 'vendor_advisory',
                'type': 'out-of-band' if source_data.get('out_of_band') else 'emergency'
            })
        
        # Check patch urgency from timeline
        if source_data.get('patch_urgency') == 'emergency':
            indicators['emergency_patches'].append({
                'source': 'patch_timeline',
                'type': 'emergency'
            })
        
        # Check timeline anomalies
        if source_data.get('timeline_analysis', {}).get('rapid_update'):
            indicators['timeline_anomalies'].append({
                'type': 'rapid_nvd_update',
                'details': 'Updated within 24 hours of publication'
            })
        
        # Check for malware samples
        if source_data.get('malware_samples', 0) > 0:
            indicators['active_campaigns'].append({
                'source': 'virustotal',
                'details': f"{source_data['malware_samples']} malware samples found"
            })
    
    def _calculate_scores(self, evidence: Dict) -> Dict:
        """Calculate confidence scores based on all evidence"""
        scores = {
            'exploitation_likelihood': 0.5,  # Start neutral
            'zero_day_confidence': 0.3,  # Start LOW - require evidence to prove zero-day
            'evidence_quality': 0.0
        }
        
        # Factor 1: CISA KEV listing (indicates exploitation, but NOT necessarily zero-day)
        if evidence['sources'].get('cisa_kev', {}).get('in_kev'):
            scores['exploitation_likelihood'] += 0.3
            # CISA KEV alone does NOT prove zero-day - many are added after disclosure
            scores['zero_day_confidence'] += 0.05  # Reduced from 0.2
        
        # Factor 2: Security news coverage (CRITICAL for zero-day detection)
        news = evidence['sources'].get('security_news', {})
        if news.get('zero_day_mentions', 0) > 0:
            # News explicitly mentioning zero-day is strong evidence
            scores['zero_day_confidence'] += 0.2 * min(news['zero_day_mentions'], 3)
        if news.get('exploitation_mentions', 0) > 0:
            scores['exploitation_likelihood'] += 0.1 * min(news['exploitation_mentions'], 3)
        
        # Factor 3: APT associations (strong zero-day indicator)
        apt_count = len(evidence['indicators']['apt_associations'])
        if apt_count > 0:
            scores['zero_day_confidence'] += 0.2 * min(apt_count, 2)  # Increased
            scores['exploitation_likelihood'] += 0.1
        
        # Factor 3b: MITRE ATT&CK associations
        mitre = evidence['sources'].get('mitre_attack', {})
        if mitre.get('found'):
            if mitre.get('groups'):
                scores['zero_day_confidence'] += 0.15
            if mitre.get('techniques'):
                scores['exploitation_likelihood'] += 0.1
        
        # Factor 4: Emergency patches
        if evidence['indicators']['emergency_patches']:
            scores['zero_day_confidence'] += 0.1
        
        # Factor 5: Exploit availability timeline
        github = evidence['sources'].get('github', {})
        poc_count = github.get('poc_repositories', 0)
        if poc_count > 20:  # Many PoCs strongly suggest NOT zero-day
            scores['zero_day_confidence'] -= 0.3  # Strong penalty
        elif poc_count > 10:
            scores['zero_day_confidence'] -= 0.15
        
        # Factor 6: Vendor advisory timing
        vendor = evidence['sources'].get('vendor', {})
        if vendor.get('out_of_band'):
            # Out-of-band patch suggests urgency, but check disclosure type
            if vendor.get('disclosure_type') == 'coordinated':
                # Coordinated disclosure = NOT zero-day
                scores['zero_day_confidence'] -= 0.2
            else:
                scores['zero_day_confidence'] += 0.1
        
        # Factor 7: Patch timeline analysis
        timeline = evidence['sources'].get('patch_timeline', {})
        if timeline.get('exploited_before_patch'):
            scores['zero_day_confidence'] += 0.25  # Strong evidence
            scores['exploitation_likelihood'] += 0.2
        if timeline.get('days_to_patch') is not None and timeline['days_to_patch'] < 7:
            scores['zero_day_confidence'] += 0.1  # Emergency patching
        
        # Factor 8: Malware samples (VirusTotal)
        vt = evidence['sources'].get('virustotal', {})
        if vt.get('malware_samples', 0) > 0:
            scores['exploitation_likelihood'] += 0.15
            if vt['malware_samples'] > 10:
                scores['zero_day_confidence'] += 0.1
        
        # Normalize scores
        for key in scores:
            scores[key] = max(0.0, min(1.0, scores[key]))
        
        # Calculate evidence quality
        sources_with_data = sum(1 for s in evidence['sources'].values() 
                               if s and not s.get('error'))
        scores['evidence_quality'] = sources_with_data / len(evidence['sources'])
        
        return scores
    
    def _generate_summary(self, evidence: Dict) -> str:
        """Generate human-readable summary of findings"""
        scores = evidence['scores']
        indicators = evidence['indicators']
        
        summary_parts = []
        
        # Overall assessment
        if scores['zero_day_confidence'] >= 0.7:
            summary_parts.append("HIGH CONFIDENCE: This appears to be a zero-day vulnerability.")
        elif scores['zero_day_confidence'] >= 0.5:
            summary_parts.append("MODERATE CONFIDENCE: This may have been a zero-day vulnerability.")
        else:
            summary_parts.append("LOW CONFIDENCE: This does not appear to be a zero-day vulnerability.")
        
        # Key evidence
        if evidence['sources'].get('cisa_kev', {}).get('in_kev'):
            summary_parts.append("• Listed in CISA Known Exploited Vulnerabilities catalog")
        
        if indicators['apt_associations']:
            groups = ', '.join([a['group'] for a in indicators['apt_associations']])
            summary_parts.append(f"• Associated with APT groups: {groups}")
        
        if indicators['emergency_patches']:
            summary_parts.append("• Vendor issued emergency/out-of-band patches")
        
        news = evidence['sources'].get('security_news', {})
        if news.get('zero_day_mentions', 0) > 0:
            summary_parts.append(f"• {news['zero_day_mentions']} security articles mention zero-day exploitation")
        
        return '\n'.join(summary_parts)


def create_cve_report(cve_id: str, output_dir: Optional[Path] = None) -> Path:
    """
    Create a comprehensive report for a CVE
    Returns path to the report file
    """
    output_dir = output_dir or Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    scraper = ComprehensiveZeroDayScraper()
    evidence = scraper.scrape_all_sources(cve_id)
    
    # Save JSON report
    report_path = output_dir / f"{cve_id}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, 'w') as f:
        json.dump(evidence, f, indent=2)
    
    # Create markdown summary
    md_path = output_dir / f"{cve_id}_summary.md"
    with open(md_path, 'w') as f:
        f.write(f"# Zero-Day Analysis Report: {cve_id}\n\n")
        f.write(f"**Generated**: {evidence['scraped_at']}\n\n")
        
        f.write("## Summary\n\n")
        f.write(evidence['summary'] + "\n\n")
        
        f.write("## Confidence Scores\n\n")
        scores = evidence['scores']
        f.write(f"- **Zero-Day Confidence**: {scores['zero_day_confidence']:.1%}\n")
        f.write(f"- **Exploitation Likelihood**: {scores['exploitation_likelihood']:.1%}\n")
        f.write(f"- **Evidence Quality**: {scores['evidence_quality']:.1%}\n\n")
        
        f.write("## Key Indicators\n\n")
        
        if evidence['indicators']['exploitation_before_patch']:
            f.write("### Exploitation Before Patch\n")
            for ind in evidence['indicators']['exploitation_before_patch']:
                f.write(f"- {ind['source']} (confidence: {ind['confidence']})\n")
            f.write("\n")
        
        if evidence['indicators']['apt_associations']:
            f.write("### APT Associations\n")
            for ind in evidence['indicators']['apt_associations']:
                f.write(f"- {ind['group']}\n")
            f.write("\n")
        
        f.write("## Data Sources\n\n")
        for source, data in evidence['sources'].items():
            if data and not data.get('error'):
                f.write(f"- ✓ {source}\n")
            else:
                f.write(f"- ✗ {source}\n")
    
    logger.info(f"Report saved to {report_path}")
    logger.info(f"Summary saved to {md_path}")
    
    return report_path


if __name__ == "__main__":
    # Test with a known CVE
    import sys
    
    if len(sys.argv) > 1:
        cve_id = sys.argv[1]
    else:
        cve_id = "CVE-2023-23397"  # Microsoft Outlook zero-day
    
    print(f"Analyzing {cve_id}...")
    report_path = create_cve_report(cve_id)
    print(f"\nReport saved to: {report_path}")
