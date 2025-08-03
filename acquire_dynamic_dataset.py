#!/usr/bin/env python3
"""
Acquire dynamic dataset by scraping real data from multiple sources
This creates a dataset with actual scraped evidence for each CVE
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

import json
import time
from datetime import datetime
from src.scraping.comprehensive_scraper import ComprehensiveZeroDayScraper
from create_extended_dataset import EXTENDED_DATASET
from mixed_cve_list import MIXED_CVE_LIST
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def acquire_dataset(cve_list=None, limit=10, save_raw=True, use_mixed=False):
    """
    Acquire dataset by scraping real data for CVEs
    
    Args:
        cve_list: List of CVEs to scrape (if None, uses EXTENDED_DATASET)
        limit: Maximum number of CVEs to process
        save_raw: Save raw scraped data
    """
    # Initialize scraper
    scraper = ComprehensiveZeroDayScraper()
    
    # Get CVE list
    if cve_list is None:
        if use_mixed:
            # Use mixed list of zero-days and regular CVEs
            cve_list = MIXED_CVE_LIST[:limit]
            # Create ground truth (first 25 are zero-days)
            ground_truth = {}
            for i, cve in enumerate(MIXED_CVE_LIST):
                ground_truth[cve] = {"is_zero_day": i < 25}
        else:
            # Use CVEs from extended dataset
            cve_list = list(EXTENDED_DATASET.keys())[:limit]
            ground_truth = EXTENDED_DATASET
    else:
        ground_truth = {cve: None for cve in cve_list}
    
    print(f"🌐 Acquiring Dynamic Dataset")
    print(f"=" * 60)
    print(f"CVEs to process: {len(cve_list)}")
    print(f"Sources: NVD, CISA KEV, GitHub, News, ExploitDB, etc.")
    print(f"=" * 60)
    
    # Results storage
    dataset = {
        "metadata": {
            "created": datetime.now().isoformat(),
            "total_cves": len(cve_list),
            "sources": [
                "NVD", "CISA KEV", "Security News", "GitHub",
                "ExploitDB", "Threat Intel", "Vendor Advisories", "Social Media"
            ]
        },
        "cves": {}
    }
    
    # Process each CVE
    for i, cve_id in enumerate(cve_list):
        print(f"\n[{i+1}/{len(cve_list)}] Processing {cve_id}...")
        
        try:
            # Scrape all sources
            evidence = scraper.scrape_all_sources(cve_id)
            
            # Create dataset entry
            entry = {
                "cve_id": cve_id,
                "ground_truth": ground_truth.get(cve_id, {}).get("is_zero_day") if cve_id in ground_truth else None,
                "description": ground_truth.get(cve_id, {}).get("description", "Unknown"),
                "scraped_evidence": {
                    "sources": evidence.get("sources", {}),
                    "indicators": evidence.get("indicators", {}),
                    "scores": evidence.get("scores", {}),
                    "timeline": extract_timeline(evidence),
                    "key_facts": extract_key_facts(evidence)
                },
                "scraped_at": evidence.get("scraped_at", datetime.now().isoformat())
            }
            
            dataset["cves"][cve_id] = entry
            
            # Show summary
            print(f"  ✅ Scraped successfully")
            print(f"     - CISA KEV: {evidence['sources'].get('cisa_kev', {}).get('listed', False)}")
            print(f"     - GitHub PoCs: {evidence['sources'].get('github', {}).get('total_repos', 0)}")
            print(f"     - News mentions: {evidence['sources'].get('news', {}).get('total_articles', 0)}")
            print(f"     - Exploitation evidence: {bool(evidence['indicators'].get('exploitation_before_patch', []))}")
            
            # Save raw data if requested
            if save_raw:
                raw_file = Path(f"data/raw_evidence/{cve_id}_raw.json")
                raw_file.parent.mkdir(parents=True, exist_ok=True)
                with open(raw_file, 'w') as f:
                    json.dump(evidence, f, indent=2)
            
            # Rate limiting
            time.sleep(2)  # Be respectful to APIs
            
        except Exception as e:
            logger.error(f"Error processing {cve_id}: {str(e)}")
            dataset["cves"][cve_id] = {
                "cve_id": cve_id,
                "error": str(e),
                "scraped_at": datetime.now().isoformat()
            }
    
    # Calculate statistics
    dataset["metadata"]["statistics"] = calculate_statistics(dataset)
    
    # Save dataset
    output_file = Path("data/dynamic_dataset.json")
    output_file.parent.mkdir(exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"\n✅ Dataset acquired and saved to {output_file}")
    print(f"\nStatistics:")
    stats = dataset["metadata"]["statistics"]
    print(f"  - Successfully scraped: {stats['successful']}")
    print(f"  - Failed: {stats['failed']}")
    print(f"  - With CISA KEV: {stats['with_cisa_kev']}")
    print(f"  - With GitHub PoCs: {stats['with_github_pocs']}")
    print(f"  - With exploitation evidence: {stats['with_exploitation_evidence']}")
    
    return dataset


def extract_timeline(evidence):
    """Extract key timeline events from evidence"""
    timeline = []
    
    # NVD publication
    if 'nvd' in evidence['sources'] and evidence['sources']['nvd'].get('published_date'):
        timeline.append({
            "date": evidence['sources']['nvd']['published_date'],
            "event": "CVE Published",
            "source": "NVD"
        })
    
    # CISA KEV addition
    if 'cisa_kev' in evidence['sources'] and evidence['sources']['cisa_kev'].get('date_added'):
        timeline.append({
            "date": evidence['sources']['cisa_kev']['date_added'],
            "event": "Added to CISA KEV",
            "source": "CISA"
        })
    
    # First PoC
    if 'github' in evidence['sources'] and evidence['sources']['github'].get('earliest_poc'):
        timeline.append({
            "date": evidence['sources']['github']['earliest_poc'],
            "event": "First Public PoC",
            "source": "GitHub"
        })
    
    # Sort by date
    timeline.sort(key=lambda x: x['date'] if x['date'] else '9999-99-99')
    
    return timeline


def extract_key_facts(evidence):
    """Extract key facts from evidence"""
    facts = []
    
    # CVSS Score
    if 'nvd' in evidence['sources'] and evidence['sources']['nvd'].get('cvss_score'):
        facts.append(f"CVSS Score: {evidence['sources']['nvd']['cvss_score']}")
    
    # CISA KEV
    if evidence['sources'].get('cisa_kev', {}).get('listed'):
        facts.append("Listed in CISA Known Exploited Vulnerabilities")
    
    # Exploitation
    if evidence['indicators'].get('exploitation_before_patch'):
        facts.append("Exploitation detected before patch available")
    
    # APT associations
    apt_groups = evidence['indicators'].get('apt_associations', [])
    if apt_groups:
        facts.append(f"Associated with APT groups: {', '.join(apt_groups)}")
    
    # Emergency patches
    if evidence['indicators'].get('emergency_patches'):
        facts.append("Emergency/out-of-band patches released")
    
    return facts


def calculate_statistics(dataset):
    """Calculate dataset statistics"""
    stats = {
        "total": len(dataset["cves"]),
        "successful": 0,
        "failed": 0,
        "with_cisa_kev": 0,
        "with_github_pocs": 0,
        "with_exploitation_evidence": 0,
        "with_news_mentions": 0
    }
    
    for cve_id, data in dataset["cves"].items():
        if "error" in data:
            stats["failed"] += 1
        else:
            stats["successful"] += 1
            
            # Check various indicators
            evidence = data.get("scraped_evidence", {})
            
            if evidence.get("sources", {}).get("cisa_kev", {}).get("listed"):
                stats["with_cisa_kev"] += 1
            
            if evidence.get("sources", {}).get("github", {}).get("total_repos", 0) > 0:
                stats["with_github_pocs"] += 1
            
            if evidence.get("indicators", {}).get("exploitation_before_patch"):
                stats["with_exploitation_evidence"] += 1
            
            if evidence.get("sources", {}).get("news", {}).get("total_articles", 0) > 0:
                stats["with_news_mentions"] += 1
    
    return stats


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Acquire dynamic dataset through web scraping")
    parser.add_argument("--limit", type=int, default=10, help="Number of CVEs to process (default: 10)")
    parser.add_argument("--cve-list", nargs="+", help="Specific CVEs to process")
    parser.add_argument("--no-raw", action="store_true", help="Don't save raw evidence files")
    parser.add_argument("--mixed", action="store_true", help="Use mixed list of zero-days and regular CVEs")
    
    args = parser.parse_args()
    
    # Run acquisition
    dataset = acquire_dataset(
        cve_list=args.cve_list,
        limit=args.limit,
        save_raw=not args.no_raw,
        use_mixed=args.mixed
    )