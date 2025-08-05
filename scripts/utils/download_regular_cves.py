#!/usr/bin/env python3
"""
Download regular (non zero-day) CVEs from various sources
Focus on responsibly disclosed vulnerabilities
"""
import json
import requests
import random
from datetime import datetime, timedelta
from pathlib import Path
import time

class RegularCVEDownloader:
    def __init__(self):
        self.cve_database = {}
        self.known_zero_days = set()
        
        # Load CISA KEV to exclude known zero-days
        self._load_known_zero_days()
        
    def _load_known_zero_days(self):
        """Load CISA KEV CVEs to exclude them"""
        try:
            # Try to load from existing data
            if Path('data/additional_cves.json').exists():
                with open('data/additional_cves.json', 'r') as f:
                    data = json.load(f)
                    self.known_zero_days = {k for k, v in data.items() if v.get('is_zero_day', False)}
                    print(f"📋 Loaded {len(self.known_zero_days)} known zero-days to exclude")
        except:
            pass
    
    def download_old_cves(self, start_year=2020, end_year=2022, count_per_year=100):
        """Download older CVEs (likely to be regular disclosures)"""
        print(f"📥 Downloading older CVEs ({start_year}-{end_year})...")
        
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        for year in range(start_year, end_year + 1):
            print(f"  📅 Year {year}...")
            
            # Search for CVEs from this year
            params = {
                'pubStartDate': f'{year}-01-01T00:00:00.000',
                'pubEndDate': f'{year}-12-31T23:59:59.999',
                'resultsPerPage': count_per_year
            }
            
            try:
                response = requests.get(base_url, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    added = 0
                    for vuln in vulnerabilities:
                        cve_data = vuln.get('cve', {})
                        cve_id = cve_data.get('id')
                        
                        # Skip if it's a known zero-day
                        if cve_id and cve_id not in self.known_zero_days:
                            # Check for responsible disclosure indicators
                            description = self._get_description(cve_data).lower()
                            
                            # Look for responsible disclosure patterns
                            responsible_disclosure = any([
                                'reported by' in description,
                                'discovered by' in description,
                                'found by' in description,
                                'credit' in description,
                                'researcher' in description,
                                'responsible disclosure' in description,
                                'coordinated disclosure' in description,
                                'bug bounty' in description
                            ])
                            
                            self.cve_database[cve_id] = {
                                'is_zero_day': False,  # Regular CVE
                                'description': self._get_description(cve_data),
                                'source': 'NVD',
                                'year': year,
                                'cvss_score': self._get_cvss_score(cve_data),
                                'published': cve_data.get('published', ''),
                                'evidence': 'Responsible disclosure' if responsible_disclosure else 'Regular disclosure',
                                'has_disclosure_credit': responsible_disclosure
                            }
                            added += 1
                    
                    print(f"    ✅ Added {added} regular CVEs from {year}")
                else:
                    print(f"    ❌ Error: {response.status_code}")
            except Exception as e:
                print(f"    ❌ Error: {str(e)}")
            
            # Rate limit
            time.sleep(2)
    
    def download_patched_before_disclosure(self, days_back=180):
        """Download CVEs that were patched before public disclosure"""
        print(f"📥 Downloading CVEs patched before disclosure (last {days_back} days)...")
        
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Get CVEs from the specified period
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            'lastModStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
            'lastModEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
            'resultsPerPage': 200
        }
        
        try:
            response = requests.get(base_url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                added = 0
                for vuln in vulnerabilities:
                    cve_data = vuln.get('cve', {})
                    cve_id = cve_data.get('id')
                    
                    if cve_id and cve_id not in self.known_zero_days:
                        # Check timeline
                        published = cve_data.get('published', '')
                        modified = cve_data.get('lastModified', '')
                        
                        # If modified significantly before published, likely patched first
                        try:
                            pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                            mod_date = datetime.fromisoformat(modified.replace('Z', '+00:00'))
                            
                            # This heuristic isn't perfect but helps identify regular disclosures
                            if (pub_date - mod_date).days < 0:  # Modified before published
                                self.cve_database[cve_id] = {
                                    'is_zero_day': False,
                                    'description': self._get_description(cve_data),
                                    'source': 'NVD',
                                    'cvss_score': self._get_cvss_score(cve_data),
                                    'published': published,
                                    'modified': modified,
                                    'evidence': 'Patched before public disclosure'
                                }
                                added += 1
                        except:
                            pass
                
                print(f"  ✅ Added {added} CVEs patched before disclosure")
            else:
                print(f"  ❌ Error: {response.status_code}")
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
    
    def download_low_severity_cves(self, count=200):
        """Download low/medium severity CVEs (rarely zero-days)"""
        print(f"📥 Downloading low/medium severity CVEs...")
        
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Recent CVEs with lower severity
        end_date = datetime.now()
        start_date = end_date - timedelta(days=90)
        
        params = {
            'cvssV3Severity': 'LOW,MEDIUM',
            'lastModStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
            'lastModEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
            'resultsPerPage': count
        }
        
        try:
            response = requests.get(base_url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                added = 0
                for vuln in vulnerabilities:
                    cve_data = vuln.get('cve', {})
                    cve_id = cve_data.get('id')
                    
                    if cve_id and cve_id not in self.known_zero_days and cve_id not in self.cve_database:
                        cvss = self._get_cvss_score(cve_data)
                        
                        self.cve_database[cve_id] = {
                            'is_zero_day': False,
                            'description': self._get_description(cve_data),
                            'source': 'NVD',
                            'cvss_score': cvss,
                            'severity': 'LOW' if cvss < 4.0 else 'MEDIUM',
                            'published': cve_data.get('published', ''),
                            'evidence': 'Low/medium severity - unlikely zero-day'
                        }
                        added += 1
                
                print(f"  ✅ Added {added} low/medium severity CVEs")
            else:
                print(f"  ❌ Error: {response.status_code}")
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
    
    def generate_synthetic_regular_cves(self, count=500):
        """Generate synthetic regular CVEs for testing"""
        print(f"📥 Generating {count} synthetic regular CVEs...")
        
        vendors = ['Microsoft', 'Adobe', 'Oracle', 'IBM', 'Cisco', 'VMware', 'Apache', 'Linux', 'Google', 'Mozilla']
        products = ['Office', 'Reader', 'Java', 'WebSphere', 'IOS', 'vSphere', 'Struts', 'Kernel', 'Chrome', 'Firefox']
        vuln_types = ['Buffer Overflow', 'SQL Injection', 'XSS', 'Path Traversal', 'Authentication Bypass', 
                      'Privilege Escalation', 'Memory Corruption', 'Use After Free', 'Integer Overflow']
        
        researchers = ['Security Researcher', 'Google Project Zero', 'Trend Micro Zero Day Initiative',
                       'Qualys Research Team', 'Rapid7', 'Tenable Research', 'Check Point Research',
                       'CrowdStrike Intelligence', 'FireEye Mandiant', 'Palo Alto Networks Unit 42']
        
        for i in range(count):
            year = random.choice([2021, 2022, 2023, 2024])
            cve_num = random.randint(10000, 90000)
            cve_id = f"CVE-{year}-{cve_num}"
            
            if cve_id not in self.known_zero_days and cve_id not in self.cve_database:
                vendor = random.choice(vendors)
                product = random.choice(products)
                vuln_type = random.choice(vuln_types)
                researcher = random.choice(researchers)
                
                # Generate realistic CVSS scores (mostly medium)
                cvss = round(random.triangular(3.0, 7.9, 5.5), 1)
                
                self.cve_database[cve_id] = {
                    'is_zero_day': False,
                    'description': f"{vuln_type} in {vendor} {product}",
                    'source': 'Synthetic',
                    'vendor': vendor,
                    'product': product,
                    'vulnerability_type': vuln_type,
                    'cvss_score': cvss,
                    'severity': 'LOW' if cvss < 4.0 else ('MEDIUM' if cvss < 7.0 else 'HIGH'),
                    'evidence': f'Responsibly disclosed by {researcher}',
                    'researcher_credit': researcher,
                    'disclosure_type': 'Coordinated Disclosure',
                    'published': f'{year}-{random.randint(1,12):02d}-{random.randint(1,28):02d}'
                }
        
        print(f"  ✅ Generated {count} synthetic regular CVEs")
    
    def _get_description(self, cve_data):
        """Extract description from CVE data"""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', 'No description available')
        return 'No description available'
    
    def _get_cvss_score(self, cve_data):
        """Extract CVSS score from CVE data"""
        metrics = cve_data.get('metrics', {})
        
        # Try CVSS v3.1 first
        cvss_v31 = metrics.get('cvssMetricV31', [])
        if cvss_v31:
            return cvss_v31[0].get('cvssData', {}).get('baseScore', 0)
        
        # Try CVSS v3.0
        cvss_v30 = metrics.get('cvssMetricV30', [])
        if cvss_v30:
            return cvss_v30[0].get('cvssData', {}).get('baseScore', 0)
        
        # Try CVSS v2
        cvss_v2 = metrics.get('cvssMetricV2', [])
        if cvss_v2:
            return cvss_v2[0].get('cvssData', {}).get('baseScore', 0)
        
        return 5.0  # Default medium score
    
    def save_dataset(self, filename='regular_cves.json'):
        """Save the regular CVEs"""
        output_path = Path('data') / filename
        output_path.parent.mkdir(exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.cve_database, f, indent=2)
        
        print(f"\n✅ Saved {len(self.cve_database)} regular CVEs to {output_path}")
        
        return output_path
    
    def merge_and_balance(self):
        """Merge with existing data and create balanced dataset"""
        # Load existing full dataset
        full_data_path = Path('data/full_dataset.json')
        if full_data_path.exists():
            with open(full_data_path, 'r') as f:
                full_data = json.load(f)
            
            # Add our regular CVEs
            for cve_id, data in self.cve_database.items():
                if cve_id not in full_data:
                    full_data[cve_id] = data
            
            # Save updated full dataset
            with open(full_data_path, 'w') as f:
                json.dump(full_data, f, indent=2)
            
            # Count
            zero_days = sum(1 for v in full_data.values() if v.get('is_zero_day', False))
            regular = sum(1 for v in full_data.values() if not v.get('is_zero_day', False))
            
            print(f"\n📊 Updated full dataset:")
            print(f"   Total: {len(full_data)} CVEs")
            print(f"   Zero-days: {zero_days}")
            print(f"   Regular: {regular}")
            print(f"   Balance: {zero_days/len(full_data)*100:.1f}% zero-days, {regular/len(full_data)*100:.1f}% regular")
            
            # Create new balanced datasets
            print("\n🔄 Creating balanced datasets...")
            
            # Separate types
            all_zero_days = {k: v for k, v in full_data.items() if v.get('is_zero_day', False)}
            all_regular = {k: v for k, v in full_data.items() if not v.get('is_zero_day', False)}
            
            # Create balanced datasets of various sizes
            for size in [100, 200, 500, 1000]:
                per_type = size // 2
                if len(all_regular) >= per_type and len(all_zero_days) >= per_type:
                    balanced = {}
                    balanced.update(dict(random.sample(list(all_zero_days.items()), per_type)))
                    balanced.update(dict(random.sample(list(all_regular.items()), per_type)))
                    
                    output_path = Path('data') / f'balanced_dataset_{size}.json'
                    with open(output_path, 'w') as f:
                        json.dump(balanced, f, indent=2)
                    
                    print(f"   ✅ Created {output_path} ({len(balanced)} CVEs)")


def main():
    """Download regular CVEs"""
    print("🚀 Regular CVE Downloader - Finding Non Zero-Day CVEs\n")
    
    downloader = RegularCVEDownloader()
    
    # 1. Download older CVEs (2020-2022) - likely regular disclosures
    downloader.download_old_cves(start_year=2020, end_year=2022, count_per_year=50)
    
    # 2. Download low/medium severity CVEs
    downloader.download_low_severity_cves(count=200)
    
    # 3. Download CVEs patched before disclosure
    downloader.download_patched_before_disclosure(days_back=180)
    
    # 4. Generate synthetic regular CVEs for testing
    downloader.generate_synthetic_regular_cves(count=500)
    
    # 5. Save the regular CVEs
    downloader.save_dataset()
    
    # 6. Merge and create balanced datasets
    downloader.merge_and_balance()
    
    print("\n✅ Complete! You now have balanced datasets for testing.")


if __name__ == "__main__":
    main()