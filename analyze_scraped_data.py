#!/usr/bin/env python3
"""
Analyze scraped raw evidence data
"""
import json
import os
from pathlib import Path
from collections import defaultdict
import pandas as pd

def analyze_raw_evidence():
    """Analyze all raw evidence files"""
    raw_dir = Path("data/raw_evidence")
    
    stats = {
        "total_files": 0,
        "with_cisa_kev": 0,
        "with_nvd": 0,
        "with_cvss_10": 0,
        "with_github_pocs": 0,
        "with_exploit_db": 0,
        "with_news_mentions": 0,
        "with_emergency_patch": 0,
        "by_year": defaultdict(int),
        "cve_details": []
    }
    
    # Process each raw file
    for file_path in raw_dir.glob("*_raw.json"):
        stats["total_files"] += 1
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        cve_id = data.get("cve_id", file_path.stem.replace("_raw", ""))
        sources = data.get("sources", {})
        
        # Extract key information
        cve_info = {
            "cve_id": cve_id,
            "year": cve_id.split("-")[1] if "-" in cve_id else "Unknown",
            "cisa_kev": sources.get("cisa_kev", {}).get("in_kev", False),
            "cvss_score": sources.get("nvd", {}).get("cvss_score", 0),
            "github_pocs": sources.get("github", {}).get("poc_repositories", 0),
            "exploit_db": sources.get("exploit_db", {}).get("exploit_count", 0),
            "news_articles": len(sources.get("security_news", {}).get("articles", [])),
            "emergency_patch": sources.get("vendor", {}).get("emergency_patch", False),
            "zero_day_confidence": data.get("scores", {}).get("zero_day_confidence", 0),
            "exploitation_indicators": len(data.get("indicators", {}).get("exploitation_before_patch", []))
        }
        
        stats["cve_details"].append(cve_info)
        
        # Update counters
        if cve_info["cisa_kev"]:
            stats["with_cisa_kev"] += 1
        if sources.get("nvd", {}).get("found"):
            stats["with_nvd"] += 1
        if cve_info["cvss_score"] == 10.0:
            stats["with_cvss_10"] += 1
        if cve_info["github_pocs"] > 0:
            stats["with_github_pocs"] += 1
        if cve_info["exploit_db"] > 0:
            stats["with_exploit_db"] += 1
        if cve_info["news_articles"] > 0:
            stats["with_news_mentions"] += 1
        if cve_info["emergency_patch"]:
            stats["with_emergency_patch"] += 1
        
        stats["by_year"][cve_info["year"]] += 1
    
    return stats

def print_analysis(stats):
    """Print analysis results"""
    print("🔍 Scraped Data Analysis")
    print("=" * 60)
    print(f"\n📊 Overall Statistics:")
    print(f"  Total CVEs scraped: {stats['total_files']}")
    print(f"  With CISA KEV listing: {stats['with_cisa_kev']} ({stats['with_cisa_kev']/stats['total_files']*100:.1f}%)")
    print(f"  With NVD data: {stats['with_nvd']} ({stats['with_nvd']/stats['total_files']*100:.1f}%)")
    print(f"  With CVSS 10.0: {stats['with_cvss_10']} ({stats['with_cvss_10']/stats['total_files']*100:.1f}%)")
    print(f"  With GitHub PoCs: {stats['with_github_pocs']} ({stats['with_github_pocs']/stats['total_files']*100:.1f}%)")
    print(f"  With ExploitDB: {stats['with_exploit_db']} ({stats['with_exploit_db']/stats['total_files']*100:.1f}%)")
    print(f"  With news coverage: {stats['with_news_mentions']} ({stats['with_news_mentions']/stats['total_files']*100:.1f}%)")
    print(f"  With emergency patches: {stats['with_emergency_patch']} ({stats['with_emergency_patch']/stats['total_files']*100:.1f}%)")
    
    print(f"\n📅 By Year:")
    for year in sorted(stats['by_year'].keys()):
        print(f"  {year}: {stats['by_year'][year]} CVEs")
    
    # Top CVEs by zero-day confidence
    df = pd.DataFrame(stats['cve_details'])
    df_sorted = df.sort_values('zero_day_confidence', ascending=False)
    
    print(f"\n🎯 Top 10 by Zero-Day Confidence:")
    for idx, row in df_sorted.head(10).iterrows():
        indicators = []
        if row['cisa_kev']:
            indicators.append("CISA KEV")
        if row['cvss_score'] == 10.0:
            indicators.append("CVSS 10")
        if row['emergency_patch']:
            indicators.append("Emergency Patch")
        if row['exploitation_indicators'] > 0:
            indicators.append(f"{row['exploitation_indicators']} exploit indicators")
            
        print(f"  {row['cve_id']}: {row['zero_day_confidence']:.2%} - {', '.join(indicators)}")
    
    # CVEs with most evidence
    print(f"\n📚 CVEs with Most Evidence:")
    df['evidence_count'] = (
        df['cisa_kev'].astype(int) + 
        (df['github_pocs'] > 0).astype(int) + 
        (df['exploit_db'] > 0).astype(int) + 
        (df['news_articles'] > 0).astype(int) + 
        df['emergency_patch'].astype(int) +
        (df['exploitation_indicators'] > 0).astype(int)
    )
    
    for idx, row in df.sort_values('evidence_count', ascending=False).head(10).iterrows():
        evidence = []
        if row['cisa_kev']:
            evidence.append("CISA")
        if row['github_pocs'] > 0:
            evidence.append(f"GitHub({row['github_pocs']})")
        if row['exploit_db'] > 0:
            evidence.append(f"ExploitDB({row['exploit_db']})")
        if row['news_articles'] > 0:
            evidence.append(f"News({row['news_articles']})")
            
        print(f"  {row['cve_id']}: {row['evidence_count']} sources - {', '.join(evidence)}")
    
    # Save detailed results
    df.to_csv('data/scraped_analysis.csv', index=False)
    print(f"\n💾 Detailed results saved to data/scraped_analysis.csv")

if __name__ == "__main__":
    stats = analyze_raw_evidence()
    print_analysis(stats)