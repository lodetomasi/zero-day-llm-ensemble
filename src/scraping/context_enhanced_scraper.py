#!/usr/bin/env python3
"""
Context-Enhanced Zero-Day Evidence Scraper
Extends the enhanced scraper with massive context collection for better LLM performance
"""
import json
import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime, timedelta
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple, Any
import logging
from urllib.parse import quote_plus, urlparse
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import feedparser
from collections import defaultdict
import numpy as np

from .enhanced_scraper import EnhancedZeroDayScraper

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ContextEnhancedScraper(EnhancedZeroDayScraper):
    """
    Scraper that collects massive amounts of context for LLMs
    """
    
    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize context-enhanced scraper"""
        super().__init__(cache_dir)
        
        # Additional headers for accessing more sources
        self.doc_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityResearchBot/1.0)'
        }
        
        # GitHub API headers
        self.github_headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'ZeroDay-Research-Bot/1.0'
        }
        
        # NVD headers
        self.nvd_headers = {
            'Accept': 'application/json',
            'User-Agent': 'ZeroDay-Research-Bot/1.0'
        }
    
    def _apply_rate_limit(self, domain: str = None):
        """Apply rate limiting between requests"""
        # Simple rate limiting - wait 0.5 seconds between requests
        time.sleep(0.5)
    
    def _make_request(self, url: str, headers: Optional[Dict] = None, timeout: int = 10) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
        try:
            # Use provided headers or default
            if headers is None:
                headers = self.doc_headers
            
            # Apply rate limiting
            domain = urlparse(url).netloc
            self._apply_rate_limit(domain)
            
            # Make request
            response = requests.get(url, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                return response
            else:
                logger.debug(f"Non-200 status code {response.status_code} for {url}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error for {url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching {url}: {e}")
            return None
        
    def scrape_all_sources_context_enhanced(self, cve_id: str) -> Dict:
        """
        Enhanced scraping with massive context collection
        """
        logger.info(f"Starting context-enhanced scrape for {cve_id}")
        
        # Get base + enhanced evidence
        evidence = super().scrape_all_sources_enhanced(cve_id)
        
        # Add massive context
        context_sources = self._scrape_extended_context(cve_id, evidence)
        evidence['extended_context'] = context_sources
        
        # Extract product/vendor info for targeted searches
        product_info = self._extract_product_info(evidence)
        
        # Add product-specific context
        if product_info:
            evidence['product_context'] = self._scrape_product_context(product_info)
        
        # Calculate enhanced scores with context
        evidence['scores'] = self._calculate_context_aware_scores(evidence)
        
        return evidence
    
    def _scrape_extended_context(self, cve_id: str, base_evidence: Dict) -> Dict:
        """Scrape additional context sources"""
        context_sources = {}
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {
                # Documentation and guides
                executor.submit(self.scrape_documentation, cve_id): 'documentation',
                executor.submit(self.scrape_configuration_examples, cve_id): 'configurations',
                executor.submit(self.scrape_deployment_guides, cve_id): 'deployment_guides',
                
                # Code and technical details
                executor.submit(self.scrape_code_repositories, cve_id): 'code_analysis',
                executor.submit(self.scrape_patch_analysis, cve_id): 'patch_details',
                # executor.submit(self.scrape_related_commits, cve_id): 'related_commits',  # TODO: implement
                
                # Discussions and analysis
                executor.submit(self.scrape_full_discussions, cve_id): 'full_discussions',
                executor.submit(self.scrape_technical_blogs, cve_id): 'technical_blogs',
                executor.submit(self.scrape_security_advisories, cve_id): 'security_advisories',
                
                # Historical context
                executor.submit(self.scrape_historical_vulnerabilities, cve_id): 'historical_vulns',
                executor.submit(self.scrape_attack_patterns, cve_id): 'attack_patterns',
                executor.submit(self.scrape_mitigation_strategies, cve_id): 'mitigations',
                
                # Real-world data
                executor.submit(self.scrape_exploit_tutorials, cve_id): 'exploit_tutorials',
                executor.submit(self.scrape_incident_reports, cve_id): 'incident_analysis',
                executor.submit(self.scrape_forensic_data, cve_id): 'forensic_evidence'
            }
            
            for future in as_completed(futures):
                source_name = futures[future]
                try:
                    result = future.result()
                    context_sources[source_name] = result
                except Exception as e:
                    logger.error(f"Error scraping {source_name}: {e}")
                    context_sources[source_name] = {'error': str(e)}
        
        return context_sources
    
    def scrape_documentation(self, cve_id: str) -> Dict:
        """Scrape official documentation and manuals"""
        result = {
            'official_docs': [],
            'man_pages': [],
            'api_docs': [],
            'wiki_pages': [],
            'total_pages': 0
        }
        
        # Extract product name from CVE description
        product = self._extract_product_name(cve_id)
        if not product:
            return result
        
        # Official documentation sites
        doc_sites = [
            f"https://docs.{product}.com",
            f"https://{product}.readthedocs.io",
            f"https://wiki.{product}.org",
            f"https://help.{product}.com"
        ]
        
        for site in doc_sites:
            try:
                # Search for vulnerability-related docs
                search_url = f"{site}/search?q={cve_id}+vulnerability+security"
                response = self._make_request(search_url)
                if response and response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract documentation snippets
                    doc_snippets = []
                    for item in soup.find_all(['div', 'article', 'section'], limit=5):
                        text = item.get_text(strip=True)[:500]
                        if text:
                            doc_snippets.append(text)
                    
                    if doc_snippets:
                        result['official_docs'].extend(doc_snippets)
                        result['total_pages'] += len(doc_snippets)
            except:
                continue
        
        # Man pages
        try:
            man_url = f"https://man7.org/linux/man-pages/search.html?q={product}"
            response = self._make_request(man_url)
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                man_entries = soup.find_all('div', class_='manual-text', limit=3)
                result['man_pages'] = [entry.get_text(strip=True)[:1000] for entry in man_entries]
        except:
            pass
        
        return result
    
    def scrape_configuration_examples(self, cve_id: str) -> Dict:
        """Scrape configuration files and examples"""
        result = {
            'config_examples': [],
            'docker_configs': [],
            'k8s_manifests': [],
            'terraform_modules': [],
            'ansible_playbooks': []
        }
        
        # GitHub search for configs
        try:
            # Search for configuration files
            search_queries = [
                f"{cve_id} filename:config",
                f"{cve_id} filename:dockerfile",
                f"{cve_id} filename:values.yaml",
                f"{cve_id} extension:tf",
                f"{cve_id} extension:yml ansible"
            ]
            
            for query in search_queries:
                url = f"https://api.github.com/search/code?q={quote_plus(query)}&per_page=5"
                response = self._make_request(url, headers=self.github_headers)
                
                if response and response.status_code == 200:
                    data = response.json()
                    for item in data.get('items', [])[:3]:
                        # Get file content
                        content_url = item.get('url')
                        if content_url:
                            content_resp = self._make_request(content_url, headers=self.github_headers)
                            if content_resp and content_resp.status_code == 200:
                                file_data = content_resp.json()
                                content = file_data.get('content', '')
                                if content:
                                    # Decode base64
                                    import base64
                                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                                    
                                    # Categorize by type
                                    if 'dockerfile' in item['name'].lower():
                                        result['docker_configs'].append(decoded[:1000])
                                    elif '.yaml' in item['name'] or '.yml' in item['name']:
                                        if 'ansible' in decoded.lower():
                                            result['ansible_playbooks'].append(decoded[:1000])
                                        else:
                                            result['k8s_manifests'].append(decoded[:1000])
                                    elif '.tf' in item['name']:
                                        result['terraform_modules'].append(decoded[:1000])
                                    else:
                                        result['config_examples'].append(decoded[:1000])
        except Exception as e:
            logger.error(f"Error scraping configs: {e}")
        
        return result
    
    def scrape_code_repositories(self, cve_id: str) -> Dict:
        """Scrape code examples and vulnerable code patterns"""
        result = {
            'vulnerable_code_snippets': [],
            'patched_code_snippets': [],
            'poc_implementations': [],
            'code_patterns': [],
            'affected_functions': []
        }
        
        try:
            # Search for vulnerable code
            queries = [
                f"{cve_id} vulnerable code",
                f"{cve_id} proof of concept",
                f"{cve_id} exploit code",
                f"{cve_id} patch fix"
            ]
            
            for query in queries:
                url = f"https://api.github.com/search/code?q={quote_plus(query)}&per_page=10"
                response = self._make_request(url, headers=self.github_headers)
                
                if response and response.status_code == 200:
                    data = response.json()
                    
                    for item in data.get('items', [])[:5]:
                        repo = item.get('repository', {})
                        file_path = item.get('path', '')
                        
                        # Get file content
                        content_url = item.get('url')
                        if content_url:
                            content_resp = self._make_request(content_url, headers=self.github_headers)
                            if content_resp and content_resp.status_code == 200:
                                file_data = content_resp.json()
                                content = file_data.get('content', '')
                                
                                if content:
                                    import base64
                                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                                    
                                    # Extract relevant code sections (up to 2000 chars)
                                    code_snippet = {
                                        'repo': repo.get('full_name', 'unknown'),
                                        'file': file_path,
                                        'code': decoded[:2000],
                                        'language': item.get('language', 'unknown')
                                    }
                                    
                                    # Categorize
                                    if 'poc' in query or 'exploit' in query:
                                        result['poc_implementations'].append(code_snippet)
                                    elif 'patch' in query or 'fix' in query:
                                        result['patched_code_snippets'].append(code_snippet)
                                    else:
                                        result['vulnerable_code_snippets'].append(code_snippet)
        except Exception as e:
            logger.error(f"Error scraping code: {e}")
        
        return result
    
    def scrape_full_discussions(self, cve_id: str) -> Dict:
        """Scrape complete discussion threads from multiple sources"""
        result = {
            'stackoverflow_threads': [],
            'reddit_discussions': [],
            'hackernews_threads': [],
            'forum_posts': [],
            'mailing_lists': [],
            'total_comments': 0
        }
        
        # Stack Overflow
        try:
            so_url = f"https://api.stackexchange.com/2.3/search/advanced?q={cve_id}&site=stackoverflow&filter=withbody"
            response = self._make_request(so_url)
            if response and response.status_code == 200:
                data = response.json()
                for item in data.get('items', [])[:3]:
                    thread = {
                        'title': item.get('title', ''),
                        'body': item.get('body', ''),
                        'answers': item.get('answer_count', 0),
                        'score': item.get('score', 0),
                        'link': item.get('link', '')
                    }
                    
                    # Get answers if any
                    if item.get('question_id'):
                        answer_url = f"https://api.stackexchange.com/2.3/questions/{item['question_id']}/answers?site=stackoverflow&filter=withbody"
                        answer_resp = self._make_request(answer_url)
                        if answer_resp and answer_resp.status_code == 200:
                            answer_data = answer_resp.json()
                            thread['answer_bodies'] = [a.get('body', '')[:1000] for a in answer_data.get('items', [])[:5]]
                            result['total_comments'] += len(thread['answer_bodies'])
                    
                    result['stackoverflow_threads'].append(thread)
        except:
            pass
        
        # Reddit discussions
        try:
            reddit_url = f"https://www.reddit.com/search.json?q={cve_id}&sort=relevance&limit=10"
            response = self._make_request(reddit_url, headers={'User-Agent': 'SecurityBot 1.0'})
            if response and response.status_code == 200:
                data = response.json()
                for post in data.get('data', {}).get('children', [])[:5]:
                    post_data = post.get('data', {})
                    
                    thread = {
                        'title': post_data.get('title', ''),
                        'body': post_data.get('selftext', ''),
                        'subreddit': post_data.get('subreddit', ''),
                        'score': post_data.get('score', 0),
                        'num_comments': post_data.get('num_comments', 0),
                        'url': f"https://reddit.com{post_data.get('permalink', '')}"
                    }
                    
                    # Get comments
                    if post_data.get('permalink'):
                        comment_url = f"https://www.reddit.com{post_data['permalink']}.json"
                        comment_resp = self._make_request(comment_url, headers={'User-Agent': 'SecurityBot 1.0'})
                        if comment_resp and comment_resp.status_code == 200:
                            comment_data = comment_resp.json()
                            if len(comment_data) > 1:
                                comments = []
                                for comment in comment_data[1].get('data', {}).get('children', [])[:10]:
                                    comment_body = comment.get('data', {}).get('body', '')
                                    if comment_body:
                                        comments.append(comment_body[:500])
                                thread['top_comments'] = comments
                                result['total_comments'] += len(comments)
                    
                    result['reddit_discussions'].append(thread)
        except:
            pass
        
        # Security mailing lists
        try:
            # OSS Security
            oss_url = f"https://www.openwall.com/lists/oss-security/search?q={cve_id}"
            response = self._make_request(oss_url)
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                messages = soup.find_all('div', class_='message', limit=5)
                
                for msg in messages:
                    post = {
                        'subject': msg.find('h3').get_text(strip=True) if msg.find('h3') else '',
                        'body': msg.find('pre').get_text(strip=True)[:2000] if msg.find('pre') else '',
                        'date': msg.find('span', class_='date').get_text(strip=True) if msg.find('span', class_='date') else ''
                    }
                    result['mailing_lists'].append(post)
        except:
            pass
        
        return result
    
    def scrape_technical_blogs(self, cve_id: str) -> Dict:
        """Scrape detailed technical blog posts and analyses"""
        result = {
            'blog_posts': [],
            'technical_analyses': [],
            'research_papers': [],
            'vendor_blogs': []
        }
        
        # Technical blog sites
        blog_sites = [
            "https://blog.qualys.com",
            "https://www.mandiant.com/resources/blog",
            "https://www.crowdstrike.com/blog",
            "https://blog.talosintelligence.com",
            "https://www.sentinelone.com/blog",
            "https://research.checkpoint.com",
            "https://securelist.com",
            "https://blog.rapid7.com"
        ]
        
        for site in blog_sites:
            try:
                search_url = f"{site}/search?q={cve_id}"
                response = self._make_request(search_url)
                if response and response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract blog posts
                    articles = soup.find_all(['article', 'div'], class_=re.compile('post|article|entry'), limit=3)
                    
                    for article in articles:
                        post = {
                            'source': site,
                            'title': article.find(['h1', 'h2', 'h3']).get_text(strip=True) if article.find(['h1', 'h2', 'h3']) else '',
                            'content': article.get_text(strip=True)[:3000],
                            'date': article.find(['time', 'span'], class_=re.compile('date|time')).get_text(strip=True) if article.find(['time', 'span'], class_=re.compile('date|time')) else ''
                        }
                        result['blog_posts'].append(post)
            except:
                continue
        
        return result
    
    def scrape_patch_analysis(self, cve_id: str) -> Dict:
        """Analyze patches and fixes in detail"""
        result = {
            'patch_commits': [],
            'diff_analysis': [],
            'fix_description': '',
            'affected_files': [],
            'lines_changed': 0
        }
        
        # Search for patch commits
        try:
            url = f"https://api.github.com/search/commits?q={cve_id}+fix&per_page=5"
            response = self._make_request(url, headers={**self.github_headers, 'Accept': 'application/vnd.github.cloak-preview'})
            
            if response and response.status_code == 200:
                data = response.json()
                
                for item in data.get('items', [])[:3]:
                    commit = item.get('commit', {})
                    
                    # Get detailed commit info
                    commit_url = item.get('url')
                    if commit_url:
                        commit_resp = self._make_request(commit_url, headers=self.github_headers)
                        if commit_resp and commit_resp.status_code == 200:
                            commit_data = commit_resp.json()
                            
                            patch_info = {
                                'sha': item.get('sha', ''),
                                'message': commit.get('message', ''),
                                'author': commit.get('author', {}).get('name', ''),
                                'date': commit.get('author', {}).get('date', ''),
                                'files_changed': len(commit_data.get('files', [])),
                                'additions': commit_data.get('stats', {}).get('additions', 0),
                                'deletions': commit_data.get('stats', {}).get('deletions', 0)
                            }
                            
                            # Get diff for each file
                            diffs = []
                            for file in commit_data.get('files', [])[:5]:
                                diff = {
                                    'filename': file.get('filename', ''),
                                    'status': file.get('status', ''),
                                    'additions': file.get('additions', 0),
                                    'deletions': file.get('deletions', 0),
                                    'patch': file.get('patch', '')[:1000]  # First 1000 chars of patch
                                }
                                diffs.append(diff)
                                result['affected_files'].append(file.get('filename', ''))
                            
                            patch_info['diffs'] = diffs
                            result['patch_commits'].append(patch_info)
                            result['lines_changed'] += patch_info['additions'] + patch_info['deletions']
        except Exception as e:
            logger.error(f"Error analyzing patches: {e}")
        
        return result
    
    def scrape_historical_vulnerabilities(self, cve_id: str) -> Dict:
        """Get historical context of similar vulnerabilities"""
        result = {
            'similar_cves': [],
            'vendor_history': [],
            'product_timeline': [],
            'vulnerability_trends': {}
        }
        
        # Extract product/vendor from CVE
        product_info = self._extract_product_info_from_cve(cve_id)
        if not product_info:
            return result
        
        vendor = product_info.get('vendor', '')
        product = product_info.get('product', '')
        
        # Search for similar CVEs
        try:
            # NVD search for same product
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={vendor}+{product}"
            response = self._make_request(nvd_url, headers=self.nvd_headers)
            
            if response and response.status_code == 200:
                data = response.json()
                
                for vuln in data.get('vulnerabilities', [])[:20]:
                    cve = vuln.get('cve', {})
                    cve_id_hist = cve.get('id', '')
                    
                    if cve_id_hist != cve_id:  # Skip current CVE
                        similar = {
                            'cve_id': cve_id_hist,
                            'description': cve.get('descriptions', [{}])[0].get('value', ''),
                            'published': cve.get('published', ''),
                            'severity': vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0),
                            'cwe': [w.get('description', [{}])[0].get('value', '') for w in cve.get('weaknesses', [])]
                        }
                        result['similar_cves'].append(similar)
                
                # Analyze trends
                if result['similar_cves']:
                    # Group by year
                    years = {}
                    for cve in result['similar_cves']:
                        year = cve['published'][:4] if cve['published'] else 'unknown'
                        years[year] = years.get(year, 0) + 1
                    
                    result['vulnerability_trends'] = {
                        'by_year': years,
                        'total_historical': len(result['similar_cves']),
                        'average_severity': np.mean([c['severity'] for c in result['similar_cves'] if c['severity'] > 0])
                    }
        except:
            pass
        
        return result
    
    def scrape_exploit_tutorials(self, cve_id: str) -> Dict:
        """Scrape exploit tutorials and walkthroughs"""
        result = {
            'tutorials': [],
            'video_references': [],
            'step_by_step_guides': [],
            'tools_required': []
        }
        
        # Search for tutorials
        try:
            # YouTube search
            yt_url = f"https://www.youtube.com/results?search_query={cve_id}+exploit+tutorial"
            response = self._make_request(yt_url)
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract video info (titles and descriptions)
                scripts = soup.find_all('script')
                for script in scripts:
                    if 'var ytInitialData' in str(script):
                        # Extract JSON data
                        import re
                        json_str = re.search(r'var ytInitialData = ({.*?});', str(script))
                        if json_str:
                            try:
                                import json
                                yt_data = json.loads(json_str.group(1))
                                # Navigate through the complex structure to find video renderers
                                # This is simplified - actual implementation would need proper parsing
                                result['video_references'].append({
                                    'platform': 'YouTube',
                                    'query': f"{cve_id} exploit tutorial",
                                    'note': 'Video tutorials available'
                                })
                            except:
                                pass
        except:
            pass
        
        # Search for written tutorials
        tutorial_sites = [
            "https://www.exploit-db.com",
            "https://github.com",
            "https://medium.com"
        ]
        
        for site in tutorial_sites:
            try:
                if 'github' in site:
                    # GitHub search
                    url = f"https://api.github.com/search/repositories?q={cve_id}+tutorial+exploit&per_page=5"
                    response = self._make_request(url, headers=self.github_headers)
                    if response and response.status_code == 200:
                        data = response.json()
                        for repo in data.get('items', [])[:3]:
                            # Get README
                            readme_url = f"https://api.github.com/repos/{repo['full_name']}/readme"
                            readme_resp = self._make_request(readme_url, headers=self.github_headers)
                            if readme_resp and readme_resp.status_code == 200:
                                readme_data = readme_resp.json()
                                content = readme_data.get('content', '')
                                if content:
                                    import base64
                                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                                    result['tutorials'].append({
                                        'source': f"GitHub: {repo['full_name']}",
                                        'content': decoded[:2000],
                                        'stars': repo.get('stargazers_count', 0)
                                    })
            except:
                continue
        
        return result
    
    def scrape_deployment_guides(self, cve_id: str) -> Dict:
        """Scrape deployment and setup guides"""
        result = {
            'deployment_docs': [],
            'architecture_diagrams': [],
            'best_practices': [],
            'common_configs': []
        }
        
        # Extract product info
        product = self._extract_product_name(cve_id)
        if not product:
            return result
        
        # Search for deployment guides
        deployment_queries = [
            f"{product} deployment guide",
            f"{product} installation tutorial",
            f"{product} architecture",
            f"{product} best practices security"
        ]
        
        for query in deployment_queries:
            try:
                # General web search simulation (would need proper search API)
                # For now, search GitHub wikis
                url = f"https://api.github.com/search/repositories?q={quote_plus(query)}+in:description&per_page=3"
                response = self._make_request(url, headers=self.github_headers)
                
                if response and response.status_code == 200:
                    data = response.json()
                    for repo in data.get('items', [])[:2]:
                        # Check for wiki
                        if repo.get('has_wiki'):
                            result['deployment_docs'].append({
                                'source': f"GitHub Wiki: {repo['full_name']}",
                                'description': repo.get('description', ''),
                                'url': f"https://github.com/{repo['full_name']}/wiki"
                            })
            except:
                continue
        
        return result
    
    def scrape_attack_patterns(self, cve_id: str) -> Dict:
        """Scrape common attack patterns and methodologies"""
        result = {
            'attack_vectors': [],
            'ttps': [],  # Tactics, Techniques, Procedures
            'iocs': [],  # Indicators of Compromise
            'detection_rules': []
        }
        
        # MITRE ATT&CK patterns
        try:
            # Search for related techniques
            attack_url = "https://attack.mitre.org/tactics/enterprise/"
            response = self._make_request(attack_url)
            if response and response.status_code == 200:
                # Extract relevant attack patterns
                # This is simplified - actual implementation would parse ATT&CK framework
                result['ttps'].append({
                    'framework': 'MITRE ATT&CK',
                    'reference': cve_id,
                    'note': 'Check ATT&CK framework for related techniques'
                })
        except:
            pass
        
        # Search for IOCs
        try:
            # GitHub search for IOCs
            url = f"https://api.github.com/search/code?q={cve_id}+IOC+indicators&per_page=5"
            response = self._make_request(url, headers=self.github_headers)
            
            if response and response.status_code == 200:
                data = response.json()
                for item in data.get('items', [])[:3]:
                    result['iocs'].append({
                        'source': item.get('repository', {}).get('full_name', ''),
                        'file': item.get('path', ''),
                        'type': 'potential IOCs available'
                    })
        except:
            pass
        
        # Detection rules (Sigma, Yara, Snort)
        rule_queries = [
            f"{cve_id} sigma rule",
            f"{cve_id} yara rule",
            f"{cve_id} snort signature"
        ]
        
        for query in rule_queries:
            try:
                url = f"https://api.github.com/search/code?q={quote_plus(query)}&per_page=3"
                response = self._make_request(url, headers=self.github_headers)
                
                if response and response.status_code == 200:
                    data = response.json()
                    for item in data.get('items', [])[:2]:
                        result['detection_rules'].append({
                            'type': query.split()[-2],  # sigma/yara/snort
                            'source': item.get('repository', {}).get('full_name', ''),
                            'file': item.get('path', '')
                        })
            except:
                continue
        
        return result
    
    def scrape_mitigation_strategies(self, cve_id: str) -> Dict:
        """Scrape mitigation and remediation strategies"""
        result = {
            'official_mitigations': [],
            'workarounds': [],
            'security_controls': [],
            'patch_alternatives': []
        }
        
        # Search for mitigation guides
        mitigation_queries = [
            f"{cve_id} mitigation",
            f"{cve_id} workaround",
            f"{cve_id} remediation",
            f"{cve_id} security controls"
        ]
        
        for query in mitigation_queries:
            try:
                # Search various sources
                url = f"https://www.google.com/search?q={quote_plus(query)}"
                response = self._make_request(url)
                if response and response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract search result snippets
                    snippets = soup.find_all('div', class_='VwiC3b', limit=3)
                    for snippet in snippets:
                        text = snippet.get_text(strip=True)
                        if text and len(text) > 50:
                            if 'mitigation' in query:
                                result['official_mitigations'].append(text[:500])
                            elif 'workaround' in query:
                                result['workarounds'].append(text[:500])
                            elif 'control' in query:
                                result['security_controls'].append(text[:500])
            except:
                continue
        
        return result
    
    def scrape_security_advisories(self, cve_id: str) -> Dict:
        """Scrape detailed security advisories from multiple sources"""
        result = {
            'vendor_advisories': [],
            'cert_advisories': [],
            'researcher_advisories': [],
            'aggregated_intel': []
        }
        
        # Vendor security pages
        vendor_urls = [
            f"https://security.microsoft.com/search?query={cve_id}",
            f"https://security.apache.org/search?q={cve_id}",
            f"https://www.oracle.com/security-alerts/search.html?q={cve_id}",
            f"https://security.redhat.com/search?q={cve_id}"
        ]
        
        for url in vendor_urls:
            try:
                response = self._make_request(url)
                if response and response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract advisory content
                    advisories = soup.find_all(['div', 'article'], class_=re.compile('advisory|alert|bulletin'), limit=2)
                    for advisory in advisories:
                        content = advisory.get_text(strip=True)[:1500]
                        if content:
                            result['vendor_advisories'].append({
                                'source': urlparse(url).netloc,
                                'content': content
                            })
            except:
                continue
        
        return result
    
    def scrape_incident_reports(self, cve_id: str) -> Dict:
        """Scrape real incident reports and case studies"""
        result = {
            'incident_reports': [],
            'case_studies': [],
            'breach_analysis': [],
            'lessons_learned': []
        }
        
        # Search for incident reports
        try:
            # This would typically search incident databases
            # For now, simulate with GitHub search
            url = f"https://api.github.com/search/repositories?q={cve_id}+incident+report+analysis&per_page=5"
            response = self._make_request(url, headers=self.github_headers)
            
            if response and response.status_code == 200:
                data = response.json()
                for repo in data.get('items', [])[:3]:
                    result['incident_reports'].append({
                        'source': repo['full_name'],
                        'description': repo.get('description', ''),
                        'stars': repo.get('stargazers_count', 0)
                    })
        except:
            pass
        
        return result
    
    def scrape_forensic_data(self, cve_id: str) -> Dict:
        """Scrape forensic analysis and evidence"""
        result = {
            'forensic_artifacts': [],
            'log_patterns': [],
            'memory_indicators': [],
            'network_signatures': []
        }
        
        # Search for forensic indicators
        forensic_queries = [
            f"{cve_id} forensic artifacts",
            f"{cve_id} log analysis",
            f"{cve_id} memory forensics",
            f"{cve_id} network indicators"
        ]
        
        for query in forensic_queries:
            try:
                url = f"https://api.github.com/search/code?q={quote_plus(query)}&per_page=3"
                response = self._make_request(url, headers=self.github_headers)
                
                if response and response.status_code == 200:
                    data = response.json()
                    for item in data.get('items', [])[:2]:
                        forensic_item = {
                            'type': query.split()[-2],
                            'source': item.get('repository', {}).get('full_name', ''),
                            'file': item.get('path', '')
                        }
                        
                        if 'artifact' in query:
                            result['forensic_artifacts'].append(forensic_item)
                        elif 'log' in query:
                            result['log_patterns'].append(forensic_item)
                        elif 'memory' in query:
                            result['memory_indicators'].append(forensic_item)
                        elif 'network' in query:
                            result['network_signatures'].append(forensic_item)
            except:
                continue
        
        return result
    
    def _extract_product_info(self, evidence: Dict) -> Optional[Dict]:
        """Extract product and vendor information from evidence"""
        nvd_data = evidence.get('sources', {}).get('nvd', {})
        if nvd_data:
            # Parse from references or description
            # This is simplified - actual implementation would be more sophisticated
            return {
                'vendor': 'unknown',
                'product': 'unknown',
                'version': 'unknown'
            }
        return None
    
    def _extract_product_name(self, cve_id: str) -> Optional[str]:
        """Extract product name from CVE ID or description"""
        # Try to get from cached NVD data first
        cache_key = f"nvd_{cve_id}"
        cached = self._get_cache(cache_key)
        
        if cached and isinstance(cached, dict):
            # Try to extract from description
            descriptions = cached.get('vulnerabilities', [{}])[0].get('cve', {}).get('descriptions', [])
            if descriptions:
                desc = descriptions[0].get('value', '').lower()
                # Simple heuristic - extract product name
                # This is very simplified - real implementation would be more sophisticated
                if 'apache' in desc:
                    return 'apache'
                elif 'microsoft' in desc:
                    return 'microsoft'
                elif 'linux' in desc:
                    return 'linux'
                elif 'cisco' in desc:
                    return 'cisco'
                # Add more patterns as needed
        
        return 'software'  # Generic fallback
    
    def _extract_product_info_from_cve(self, cve_id: str) -> Optional[Dict]:
        """Extract product info from CVE data"""
        # Would query NVD API or use cached data
        return {'vendor': 'unknown', 'product': 'unknown'}
    
    def _scrape_product_context(self, product_info: Dict) -> Dict:
        """Get product-specific context"""
        result = {
            'product_documentation': [],
            'known_deployments': [],
            'common_integrations': [],
            'security_history': []
        }
        
        # Would search for product-specific information
        return result
    
    def _calculate_context_aware_scores(self, evidence: Dict) -> Dict:
        """Calculate scores considering extended context"""
        base_scores = evidence.get('scores', {})
        
        # Boost scores based on context richness
        context = evidence.get('extended_context', {})
        
        # Calculate context quality
        context_quality = 0.0
        if context:
            # Code analysis available
            if context.get('code_analysis', {}).get('vulnerable_code_snippets'):
                context_quality += 0.1
            
            # Patch analysis available
            if context.get('patch_details', {}).get('patch_commits'):
                context_quality += 0.1
            
            # Rich discussions
            if context.get('full_discussions', {}).get('total_comments', 0) > 10:
                context_quality += 0.1
            
            # Historical context
            if context.get('historical_vulns', {}).get('similar_cves'):
                context_quality += 0.05
            
            # Exploit tutorials
            if context.get('exploit_tutorials', {}).get('tutorials'):
                context_quality += 0.15
        
        # Adjust scores
        base_scores['context_richness'] = min(1.0, context_quality)
        base_scores['evidence_quality'] = min(1.0, base_scores.get('evidence_quality', 0) + context_quality * 0.5)
        
        return base_scores


# Export the context-enhanced scraper
__all__ = ['ContextEnhancedScraper']