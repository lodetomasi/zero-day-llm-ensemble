#!/usr/bin/env python3
"""
Turbo Zero-Day Evidence Scraper using Scrapy
High-performance parallel scraping with backward compatibility
"""
import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Any
import multiprocessing

# Scrapy imports
try:
    import scrapy
    from scrapy.crawler import CrawlerProcess, CrawlerRunner
    from twisted.internet import reactor, defer
    from scrapy.utils.log import configure_logging
    from bs4 import BeautifulSoup
    SCRAPY_AVAILABLE = True
except ImportError:
    SCRAPY_AVAILABLE = False
    logging.warning("Scrapy not installed. Falling back to requests-based scraping.")

# Import the original scraper for fallback
from .comprehensive_scraper import ComprehensiveZeroDayScraper

# BeautifulSoup for parsing
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

# Suppress verbose logging
logging.getLogger('scrapy').setLevel(logging.ERROR)
logging.getLogger('twisted').setLevel(logging.ERROR)
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


class TurboZeroDayScraper(ComprehensiveZeroDayScraper):
    """
    High-performance scraper using Scrapy for parallel requests
    Falls back to comprehensive scraper if Scrapy is not available
    """
    
    def __init__(self, cache_dir: Optional[Path] = None, turbo_mode: bool = True):
        """
        Initialize turbo scraper
        
        Args:
            cache_dir: Directory for caching responses
            turbo_mode: Use Scrapy if available (default: True)
        """
        super().__init__(cache_dir)
        self.turbo_mode = turbo_mode and SCRAPY_AVAILABLE
        
        if self.turbo_mode:
            # Configure Scrapy logging
            configure_logging({'LOG_LEVEL': 'WARNING'})
            
            # Scrapy settings for maximum performance
            self.scrapy_settings = {
                'USER_AGENT': self.session.headers['User-Agent'],
                'ROBOTSTXT_OBEY': False,
                'CONCURRENT_REQUESTS': 100,
                'CONCURRENT_REQUESTS_PER_DOMAIN': 16,
                'DOWNLOAD_DELAY': 0,
                'COOKIES_ENABLED': False,
                'TELNETCONSOLE_ENABLED': False,
                'RETRY_TIMES': 2,
                'DOWNLOAD_TIMEOUT': 15,
                'AUTOTHROTTLE_ENABLED': True,
                'AUTOTHROTTLE_TARGET_CONCURRENCY': 50.0,
                'HTTPCACHE_ENABLED': True,
                'HTTPCACHE_DIR': str(self.cache_dir / 'scrapy_cache'),
                'HTTPCACHE_EXPIRATION_SECS': int(self.cache_expiry.total_seconds()),
            }
    
    def scrape_all_sources(self, cve_id: str) -> Dict:
        """
        Scrape all sources - uses Scrapy if available, otherwise falls back
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Dictionary with all scraped data
        """
        if not self.turbo_mode:
            # Fallback to original implementation
            # logger.info(f"Using standard scraper for {cve_id}")
            return super().scrape_all_sources(cve_id)
        
        # logger.info(f"Using TURBO scraper for {cve_id}")
        start_time = time.time()
        
        # Run the Scrapy crawler
        raw_results = self._run_scrapy_crawler(cve_id)
        
        # Format results to match expected structure
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
        
        # Process and format each source result
        for source, data in raw_results.items():
            if source == 'nvd':
                evidence['sources']['nvd'] = self._format_nvd_result(data, cve_id)
            elif source == 'cisa_kev':
                evidence['sources']['cisa_kev'] = self._format_cisa_result(data, cve_id)
            elif source == 'github':
                evidence['sources']['github'] = self._format_github_result(data)
            elif source == 'exploitdb':
                evidence['sources']['exploit_db'] = self._format_exploitdb_result(data)
            else:
                # Store other results as-is
                evidence['sources'][source] = data
        
        # Calculate scores
        self._calculate_scores(evidence)
        
        elapsed = time.time() - start_time
        # logger.info(f"Turbo scraping completed in {elapsed:.2f}s for {cve_id}")
        
        return evidence
    
    def scrape_all_sources_enhanced(self, cve_id: str) -> Dict:
        """
        Enhanced scraping method - delegates to scrape_all_sources
        Maintains compatibility with EnhancedZeroDayScraper interface
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Dictionary with all scraped data
        """
        # For TurboScraper, enhanced and regular are the same
        # We already scrape all sources in parallel
        return self.scrape_all_sources(cve_id)
    
    def _run_scrapy_crawler(self, cve_id: str) -> Dict:
        """
        Run Scrapy crawler to fetch all sources in parallel
        """
        # Use multiprocessing to run Scrapy in a separate process
        # This avoids reactor already running issues
        manager = multiprocessing.Manager()
        results_dict = manager.dict()
        
        process = multiprocessing.Process(
            target=self._scrapy_process_target,
            args=(cve_id, results_dict)
        )
        
        process.start()
        process.join(timeout=60)  # 60 second timeout
        
        if process.is_alive():
            process.terminate()
            process.join()
            logger.warning("Scrapy process timed out")
            return {}
        
        # Convert managed dict to regular dict
        return dict(results_dict)
    
    def _scrapy_process_target(self, cve_id: str, results_dict: dict):
        """
        Target function for the Scrapy process
        """
        # Create and configure the spider
        process = CrawlerProcess(self.scrapy_settings)
        
        # Define the spider
        class CVETurboSpider(scrapy.Spider):
            name = 'cve_turbo'
            
            def __init__(self, cve_id, scraper_instance, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.cve_id = cve_id
                self.scraper = scraper_instance
                self.results = {}
            
            def start_requests(self):
                """Generate all requests in parallel"""
                # Build all URLs to scrape
                url_map = self._build_url_map()
                
                for source, url in url_map.items():
                    yield scrapy.Request(
                        url,
                        callback=self.parse_source,
                        meta={'source': source, 'cve_id': self.cve_id},
                        errback=self.handle_error,
                        dont_filter=True
                    )
            
            def _build_url_map(self) -> Dict[str, str]:
                """Build mapping of source to URL"""
                cve_id = self.cve_id
                return {
                    'nvd': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                    'cisa_kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
                    'github': f'https://api.github.com/search/code?q={cve_id}+extension:py+extension:c+extension:cpp',
                    'exploitdb': f'https://www.exploit-db.com/search?cve={cve_id}',
                    'google_search': f'https://www.google.com/search?q="{cve_id}"+exploit+poc+-site:nvd.nist.gov',
                    'news_search': f'https://www.google.com/search?q="{cve_id}"+news+security+-site:nvd.nist.gov&tbm=nws',
                    'reddit': f'https://www.reddit.com/search.json?q={cve_id}&sort=relevance',
                    'twitter_search': f'https://nitter.net/search?q={cve_id}',
                }
            
            def parse_source(self, response):
                """Parse response based on source"""
                source = response.meta['source']
                
                try:
                    if source == 'nvd':
                        self.results[source] = self._parse_nvd(response)
                    elif source == 'cisa_kev':
                        self.results[source] = self._parse_cisa(response)
                    elif source == 'github':
                        self.results[source] = self._parse_github(response)
                    elif source == 'exploitdb':
                        self.results[source] = self._parse_exploitdb(response)
                    elif source in ['google_search', 'news_search']:
                        self.results[source] = self._parse_google(response)
                    elif source == 'reddit':
                        self.results[source] = self._parse_reddit(response)
                    else:
                        self.results[source] = {'html': response.text[:5000]}
                except Exception as e:
                    logger.error(f"Error parsing {source}: {str(e)}")
                    self.results[source] = {'error': str(e)}
            
            def _parse_nvd(self, response):
                """Parse NVD response"""
                return {
                    'status': 'success',
                    'content': response.text,
                    'url': response.url
                }
            
            def _parse_cisa(self, response):
                """Parse CISA KEV JSON"""
                try:
                    data = json.loads(response.text)
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    # Check if our CVE is in the list
                    for vuln in vulnerabilities:
                        if vuln.get('cveID') == self.cve_id:
                            return {
                                'found': True,
                                'data': vuln,
                                'date_added': vuln.get('dateAdded')
                            }
                    
                    return {'found': False}
                except:
                    return {'error': 'Failed to parse CISA data'}
            
            def _parse_github(self, response):
                """Parse GitHub API response"""
                try:
                    data = json.loads(response.text)
                    return {
                        'total_count': data.get('total_count', 0),
                        'items': data.get('items', [])[:10]  # First 10 results
                    }
                except:
                    return {'error': 'Failed to parse GitHub data'}
            
            def _parse_exploitdb(self, response):
                """Parse ExploitDB search results"""
                soup = BeautifulSoup(response.text, 'html.parser')
                exploits = []
                
                # Find exploit entries
                for row in soup.find_all('tr', class_='exploittable'):
                    title_elem = row.find('td', class_='exploittitle')
                    date_elem = row.find('td', class_='date')
                    platform_elem = row.find('td', class_='platform')
                    
                    exploit = {
                        'title': title_elem.text.strip() if title_elem else None,
                        'date': date_elem.text.strip() if date_elem else None,
                        'platform': platform_elem.text.strip() if platform_elem else None
                    }
                    if exploit['title']:
                        exploits.append(exploit)
                
                return {
                    'count': len(exploits),
                    'exploits': exploits
                }
            
            def _parse_google(self, response):
                """Parse Google search results"""
                soup = BeautifulSoup(response.text, 'html.parser')
                results = []
                
                for g in soup.find_all('div', class_='g'):
                    title = g.find('h3')
                    link = g.find('a')
                    snippet = g.find('span', class_='st')
                    
                    if title and link:
                        results.append({
                            'title': title.text,
                            'url': link.get('href', ''),
                            'snippet': snippet.text if snippet else ''
                        })
                
                return {
                    'count': len(results),
                    'results': results[:10]  # First 10 results
                }
            
            def _parse_reddit(self, response):
                """Parse Reddit JSON response"""
                try:
                    data = json.loads(response.text)
                    posts = []
                    
                    for child in data.get('data', {}).get('children', []):
                        post = child.get('data', {})
                        posts.append({
                            'title': post.get('title'),
                            'score': post.get('score'),
                            'created': post.get('created_utc'),
                            'subreddit': post.get('subreddit'),
                            'url': post.get('url')
                        })
                    
                    return {
                        'count': len(posts),
                        'posts': posts[:10]
                    }
                except:
                    return {'error': 'Failed to parse Reddit data'}
            
            def handle_error(self, failure):
                """Handle request failures"""
                source = failure.request.meta['source']
                logger.error(f"Failed to fetch {source}: {failure.value}")
                self.results[source] = {
                    'error': str(failure.value),
                    'status': 'failed'
                }
            
            def closed(self, reason):
                """Called when spider closes"""
                # logger.info(f"Spider closed: {reason}")
                # Store results in the shared dictionary
                for key, value in self.results.items():
                    results_dict[key] = value
        
        # Start the crawler
        process.crawl(CVETurboSpider, cve_id=cve_id, scraper_instance=self)
        process.start()
    
    async def scrape_all_sources_async(self, cve_id: str) -> Dict:
        """
        Async version for when reactor is already running
        """
        if not self.turbo_mode:
            return super().scrape_all_sources(cve_id)
        
        runner = CrawlerRunner(self.scrapy_settings)
        
        # Import spider class from above
        from types import ModuleType
        module = ModuleType('temp_module')
        exec(compile(open(__file__).read(), __file__, 'exec'), module.__dict__)
        CVETurboSpider = module.CVETurboSpider
        
        await runner.crawl(CVETurboSpider, cve_id=cve_id, scraper_instance=self)
        
        spider = list(runner.crawlers)[0].spider
        return spider.results
    
    def _format_nvd_result(self, data: Dict, cve_id: str) -> Dict:
        """Format NVD result to match expected structure"""
        if not data or data.get('error'):
            return {'error': data.get('error', 'Failed to fetch NVD data')}
        
        # Parse the HTML content if available
        content = data.get('content', '')
        result = {
            'cve_id': cve_id,
            'description': 'No description available',
            'cvss_score': 0.0,
            'severity': 'UNKNOWN',
            'published_date': None,
            'last_modified': None,
            'vendor': 'Unknown',
            'product': 'Unknown'
        }
        
        # Try to extract info from HTML
        if content:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract description
            desc_elem = soup.find('p', {'data-testid': 'vuln-description'})
            if desc_elem:
                result['description'] = desc_elem.text.strip()
            
            # Extract CVSS score
            cvss_elem = soup.find('a', {'data-testid': 'vuln-cvss3-panel-score'})
            if cvss_elem:
                try:
                    result['cvss_score'] = float(cvss_elem.text.strip())
                except:
                    pass
        
        return result
    
    def _format_cisa_result(self, data: Dict, cve_id: str) -> Dict:
        """Format CISA KEV result"""
        if not data or data.get('error'):
            return {'in_kev': False}
        
        if data.get('found'):
            vuln_data = data.get('data', {})
            return {
                'in_kev': True,
                'date_added': vuln_data.get('dateAdded'),
                'due_date': vuln_data.get('dueDate'),
                'product': vuln_data.get('product'),
                'vendor': vuln_data.get('vendorProject'),
                'vulnerability_name': vuln_data.get('vulnerabilityName'),
                'required_action': vuln_data.get('requiredAction')
            }
        
        return {'in_kev': False}
    
    def _format_github_result(self, data: Dict) -> Dict:
        """Format GitHub result"""
        if not data or data.get('error'):
            return {'total_count': 0, 'items': []}
        
        return {
            'total_count': data.get('total_count', 0),
            'items': data.get('items', [])
        }
    
    def _format_exploitdb_result(self, data: Dict) -> Dict:
        """Format ExploitDB result"""
        if not data or data.get('error'):
            return {'count': 0, 'exploits': []}
        
        return {
            'count': data.get('count', 0),
            'exploits': data.get('exploits', [])
        }
    
    def _calculate_scores(self, evidence: Dict):
        """Calculate exploitation likelihood and other scores"""
        scores = evidence['scores']
        sources = evidence['sources']
        
        # Evidence quality based on successful sources
        successful_sources = sum(1 for s in sources.values() 
                               if s and not s.get('error'))
        scores['evidence_quality'] = min(successful_sources / 10, 1.0)
        
        # Exploitation likelihood
        likelihood = 0.0
        
        # CISA KEV is strong indicator
        if sources.get('cisa_kev', {}).get('found'):
            likelihood += 0.4
        
        # GitHub activity
        github_count = sources.get('github', {}).get('total_count', 0)
        if github_count > 10:
            likelihood += 0.2
        elif github_count > 0:
            likelihood += 0.1
        
        # ExploitDB presence
        if sources.get('exploit_db', {}).get('count', 0) > 0:
            likelihood += 0.3
        
        scores['exploitation_likelihood'] = min(likelihood, 1.0)
        scores['zero_day_confidence'] = scores['exploitation_likelihood'] * scores['evidence_quality']


# Convenience function for testing
def benchmark_scrapers(cve_id: str = "CVE-2024-3400"):
    """
    Benchmark turbo vs standard scraper
    """
    import time
    
    print(f"\nBenchmarking scrapers for {cve_id}")
    print("-" * 50)
    
    # Test standard scraper
    standard_scraper = ComprehensiveZeroDayScraper()
    start = time.time()
    standard_results = standard_scraper.scrape_all_sources(cve_id)
    standard_time = time.time() - start
    
    print(f"Standard scraper: {standard_time:.2f}s")
    print(f"Sources scraped: {len(standard_results)}")
    
    # Test turbo scraper
    if SCRAPY_AVAILABLE:
        turbo_scraper = TurboZeroDayScraper()
        start = time.time()
        turbo_results = turbo_scraper.scrape_all_sources(cve_id)
        turbo_time = time.time() - start
        
        print(f"\nTurbo scraper: {turbo_time:.2f}s")
        print(f"Sources scraped: {len(turbo_results)}")
        print(f"Speedup: {standard_time/turbo_time:.1f}x")
    else:
        print("\nScrapy not available - install with: pip install scrapy")


if __name__ == "__main__":
    benchmark_scrapers()