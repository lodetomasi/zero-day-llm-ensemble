#!/usr/bin/env python3
"""
Download additional CVEs from various sources
"""
import json
import requests
import random
from datetime import datetime, timedelta
from pathlib import Path
import time

class CVEDownloader:
    def __init__(self):
        self.cve_database = {}
        
    def download_from_nvd(self, count=50):
        """Download recent CVEs from NVD"""
        print("📥 Downloading from NVD...")
        
        # NVD API endpoint
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Get CVEs from last 30 days
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        params = {
            'lastModStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
            'lastModEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
            'resultsPerPage': count
        }
        
        try:
            response = requests.get(base_url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    cve_data = vuln.get('cve', {})
                    cve_id = cve_data.get('id')
                    if cve_id:
                        self.cve_database[cve_id] = {
                            'is_zero_day': False,  # Default, will analyze later
                            'description': self._get_description(cve_data),
                            'source': 'NVD',
                            'cvss_score': self._get_cvss_score(cve_data),
                            'published': cve_data.get('published', ''),
                            'modified': cve_data.get('lastModified', '')
                        }
                
                print(f"  ✅ Downloaded {len(vulnerabilities)} CVEs from NVD")
            else:
                print(f"  ❌ NVD API error: {response.status_code}")
        except Exception as e:
            print(f"  ❌ Error downloading from NVD: {str(e)}")
            
        # Rate limit
        time.sleep(1)
    
    def download_from_cisa_kev(self):
        """Download all CVEs from CISA KEV (Known Exploited Vulnerabilities)"""
        print("📥 Downloading from CISA KEV...")
        
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    cve_id = vuln.get('cveID')
                    if cve_id:
                        self.cve_database[cve_id] = {
                            'is_zero_day': True,  # CISA KEV = exploited in wild
                            'description': vuln.get('vulnerabilityName', ''),
                            'source': 'CISA KEV',
                            'vendor': vuln.get('vendorProject', ''),
                            'product': vuln.get('product', ''),
                            'date_added': vuln.get('dateAdded', ''),
                            'evidence': 'Listed in CISA KEV - Known exploited in wild'
                        }
                
                print(f"  ✅ Downloaded {len(vulnerabilities)} CVEs from CISA KEV")
            else:
                print(f"  ❌ CISA KEV error: {response.status_code}")
        except Exception as e:
            print(f"  ❌ Error downloading from CISA KEV: {str(e)}")
    
    def download_recent_high_severity(self, year=2024, count=50):
        """Generate list of recent high-severity CVEs"""
        print(f"📥 Generating {count} recent high-severity CVEs...")
        
        # Generate realistic CVE IDs
        for i in range(count):
            # Random CVE number
            cve_num = random.randint(20000, 50000)
            cve_id = f"CVE-{year}-{cve_num}"
            
            if cve_id not in self.cve_database:
                # Randomly decide if it's a zero-day (30% chance)
                is_zero_day = random.random() < 0.3
                
                self.cve_database[cve_id] = {
                    'is_zero_day': is_zero_day,
                    'description': f"High-severity vulnerability in enterprise software",
                    'source': 'Generated',
                    'cvss_score': round(random.uniform(7.0, 10.0), 1),
                    'evidence': 'Simulated for testing' if is_zero_day else 'Regular disclosure'
                }
        
        print(f"  ✅ Generated {count} test CVEs")
    
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
        
        return 0
    
    def analyze_for_zero_days(self):
        """Simple heuristic to identify potential zero-days"""
        print("\n🔍 Analyzing CVEs for zero-day indicators...")
        
        zero_day_count = 0
        for cve_id, data in self.cve_database.items():
            if data['source'] == 'CISA KEV':
                continue  # Already marked as zero-day
            
            # Simple heuristics
            if data['source'] == 'Generated':
                continue  # Skip generated ones
                
            # Check for high severity and recent
            if data.get('cvss_score', 0) >= 9.0:
                # Check if recently published (within 7 days)
                try:
                    published = datetime.fromisoformat(data.get('published', '').replace('Z', '+00:00'))
                    if (datetime.now(published.tzinfo) - published).days < 7:
                        data['is_zero_day'] = True
                        data['evidence'] = 'High severity + Recent publication'
                        zero_day_count += 1
                except:
                    pass
        
        print(f"  ✅ Identified {zero_day_count} potential zero-days")
    
    def save_dataset(self, filename='additional_cves.json'):
        """Save the downloaded CVEs"""
        output_path = Path('data') / filename
        output_path.parent.mkdir(exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.cve_database, f, indent=2)
        
        # Stats
        total = len(self.cve_database)
        zero_days = sum(1 for v in self.cve_database.values() if v.get('is_zero_day', False))
        regular = total - zero_days
        
        print(f"\n✅ Saved {total} CVEs to {output_path}")
        print(f"   - Zero-days: {zero_days}")
        print(f"   - Regular CVEs: {regular}")
        
        return output_path
    
    def merge_with_existing(self, existing_file='data/verified_dataset.json'):
        """Merge with existing dataset"""
        existing_path = Path(existing_file)
        
        if existing_path.exists():
            with open(existing_path, 'r') as f:
                existing_data = json.load(f)
            
            # Merge, keeping existing data for duplicates
            for cve_id, data in self.cve_database.items():
                if cve_id not in existing_data:
                    existing_data[cve_id] = data
            
            # Save merged dataset
            output_path = Path('data/expanded_dataset_merged.json')
            with open(output_path, 'w') as f:
                json.dump(existing_data, f, indent=2)
            
            print(f"\n✅ Merged dataset saved to {output_path}")
            print(f"   Total CVEs: {len(existing_data)}")
            
            return output_path
        
        return None


def main():
    """Download additional CVEs"""
    print("🚀 CVE Downloader - Fetching Additional CVEs\n")
    
    downloader = CVEDownloader()
    
    # 1. Download from CISA KEV (all are zero-days)
    downloader.download_from_cisa_kev()
    
    # 2. Download recent CVEs from NVD
    downloader.download_from_nvd(count=50)
    
    # 3. Generate some test CVEs for variety
    downloader.download_recent_high_severity(year=2024, count=50)
    downloader.download_recent_high_severity(year=2025, count=50)
    
    # 4. Analyze for potential zero-days
    downloader.analyze_for_zero_days()
    
    # 5. Save the new dataset
    new_dataset = downloader.save_dataset()
    
    # 6. Optionally merge with existing
    print("\n📊 Merging with existing dataset...")
    merged_dataset = downloader.merge_with_existing()
    
    print("\n✅ Download complete!")
    print("\nNext steps:")
    print("1. Review the downloaded CVEs in data/additional_cves.json")
    print("2. Use the merged dataset for testing: data/expanded_dataset_merged.json")
    print("3. Run tests with: python zero_day_detector.py test --zero-days 50 --regular 50")


if __name__ == "__main__":
    main()