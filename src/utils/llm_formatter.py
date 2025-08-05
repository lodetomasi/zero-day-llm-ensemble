#!/usr/bin/env python3
"""
LLM Data Formatter
Formats scraped data optimally for LLM consumption
"""
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import re


class LLMDataFormatter:
    """
    Formats scraped web data into clean, structured formats for LLM analysis
    """
    
    @staticmethod
    def format_for_llm(scraped_data: Dict[str, Any], cve_id: str) -> str:
        """
        Convert scraped data into optimized format for LLM processing
        
        Args:
            scraped_data: Raw scraped data from all sources
            cve_id: CVE identifier
            
        Returns:
            Formatted string optimized for LLM consumption
        """
        sections = []
        
        # Header
        sections.append(f"# CVE Analysis: {cve_id}")
        sections.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        
        # NVD Data
        if 'nvd' in scraped_data and scraped_data['nvd']:
            sections.append("## Official NVD Information")
            nvd_data = scraped_data['nvd']
            if isinstance(nvd_data, dict):
                if 'description' in nvd_data:
                    sections.append(f"**Description**: {nvd_data['description']}")
                if 'cvss_score' in nvd_data:
                    sections.append(f"**CVSS Score**: {nvd_data['cvss_score']}")
                if 'published_date' in nvd_data:
                    sections.append(f"**Published**: {nvd_data['published_date']}")
            sections.append("")
        
        # CISA KEV Status
        if 'cisa_kev' in scraped_data:
            sections.append("## CISA Known Exploited Status")
            kev_data = scraped_data['cisa_kev']
            if isinstance(kev_data, dict):
                if kev_data.get('found'):
                    sections.append("✅ **Listed in CISA KEV**")
                    if 'date_added' in kev_data:
                        sections.append(f"Date Added: {kev_data['date_added']}")
                    if 'data' in kev_data:
                        vuln_data = kev_data['data']
                        if 'vendorProject' in vuln_data:
                            sections.append(f"Vendor: {vuln_data['vendorProject']}")
                        if 'product' in vuln_data:
                            sections.append(f"Product: {vuln_data['product']}")
                else:
                    sections.append("❌ Not found in CISA KEV")
            sections.append("")
        
        # GitHub PoCs
        if 'github' in scraped_data:
            sections.append("## GitHub Activity")
            github_data = scraped_data['github']
            if isinstance(github_data, dict):
                total_count = github_data.get('total_count', 0)
                sections.append(f"**Total repositories/code**: {total_count}")
                
                if total_count > 0 and 'items' in github_data:
                    sections.append("\n### Sample Code References:")
                    for item in github_data['items'][:5]:  # First 5
                        if isinstance(item, dict):
                            repo = item.get('repository', {})
                            sections.append(f"- {repo.get('full_name', 'Unknown')}: {item.get('path', '')}")
            sections.append("")
        
        # ExploitDB
        if 'exploitdb' in scraped_data:
            sections.append("## ExploitDB Entries")
            exploit_data = scraped_data['exploitdb']
            if isinstance(exploit_data, dict):
                count = exploit_data.get('count', 0)
                sections.append(f"**Total exploits**: {count}")
                
                if count > 0 and 'exploits' in exploit_data:
                    sections.append("\n### Available Exploits:")
                    for exploit in exploit_data['exploits'][:5]:
                        if isinstance(exploit, dict):
                            title = exploit.get('title', 'Unknown')
                            date = exploit.get('date', 'Unknown')
                            platform = exploit.get('platform', 'Unknown')
                            sections.append(f"- {title} ({platform}) - {date}")
            sections.append("")
        
        # Security News
        if 'news_search' in scraped_data:
            sections.append("## Security News Coverage")
            news_data = scraped_data['news_search']
            if isinstance(news_data, dict):
                count = news_data.get('count', 0)
                sections.append(f"**News articles found**: {count}")
                
                if count > 0 and 'results' in news_data:
                    sections.append("\n### Recent Headlines:")
                    for article in news_data['results'][:5]:
                        if isinstance(article, dict):
                            title = article.get('title', 'Unknown')
                            sections.append(f"- {title}")
            sections.append("")
        
        # Social Media Activity
        if 'reddit' in scraped_data:
            sections.append("## Social Media Discussion")
            reddit_data = scraped_data['reddit']
            if isinstance(reddit_data, dict):
                count = reddit_data.get('count', 0)
                if count > 0:
                    sections.append(f"**Reddit posts**: {count}")
                    if 'posts' in reddit_data:
                        high_score_posts = [p for p in reddit_data['posts'] if p.get('score', 0) > 10]
                        if high_score_posts:
                            sections.append(f"High-engagement posts: {len(high_score_posts)}")
            sections.append("")
        
        # Summary for LLM
        sections.append("## Key Indicators Summary")
        sections.append("Based on the collected evidence, analyze:")
        sections.append("1. Is this vulnerability being actively exploited in the wild?")
        sections.append("2. Was this a zero-day (exploited before patch available)?")
        sections.append("3. What is the timeline of disclosure vs exploitation?")
        sections.append("4. Are there working exploits publicly available?")
        sections.append("5. What is the overall threat level?")
        
        return "\n".join(sections)
    
    @staticmethod
    def format_as_json(scraped_data: Dict[str, Any], cve_id: str) -> str:
        """
        Format data as structured JSON for LLM processing
        """
        structured_data = {
            "cve_id": cve_id,
            "analysis_timestamp": datetime.now().isoformat(),
            "evidence": {},
            "indicators": {
                "has_cisa_kev": False,
                "has_public_exploits": False,
                "has_github_pocs": False,
                "has_news_coverage": False,
                "has_social_discussion": False
            }
        }
        
        # Process each source
        if 'cisa_kev' in scraped_data:
            structured_data["indicators"]["has_cisa_kev"] = scraped_data['cisa_kev'].get('found', False)
            structured_data["evidence"]["cisa_kev"] = scraped_data['cisa_kev']
        
        if 'github' in scraped_data:
            count = scraped_data['github'].get('total_count', 0)
            structured_data["indicators"]["has_github_pocs"] = count > 0
            structured_data["evidence"]["github_activity"] = {
                "repository_count": count,
                "has_exploit_code": count > 5  # Heuristic
            }
        
        if 'exploitdb' in scraped_data:
            count = scraped_data['exploitdb'].get('count', 0)
            structured_data["indicators"]["has_public_exploits"] = count > 0
            structured_data["evidence"]["exploit_availability"] = {
                "exploitdb_count": count
            }
        
        if 'news_search' in scraped_data:
            count = scraped_data['news_search'].get('count', 0)
            structured_data["indicators"]["has_news_coverage"] = count > 0
            structured_data["evidence"]["media_coverage"] = {
                "article_count": count
            }
        
        return json.dumps(structured_data, indent=2)
    
    @staticmethod
    def create_concise_summary(scraped_data: Dict[str, Any]) -> str:
        """
        Create a concise summary for quick LLM analysis
        """
        summary_points = []
        
        # CISA KEV
        if scraped_data.get('cisa_kev', {}).get('found'):
            date_added = scraped_data['cisa_kev'].get('date_added', 'Unknown')
            summary_points.append(f"CISA KEV: Listed ({date_added})")
        else:
            summary_points.append("CISA KEV: Not listed")
        
        # GitHub
        github_count = scraped_data.get('github', {}).get('total_count', 0)
        summary_points.append(f"GitHub: {github_count} results")
        
        # ExploitDB
        exploit_count = scraped_data.get('exploitdb', {}).get('count', 0)
        summary_points.append(f"ExploitDB: {exploit_count} exploits")
        
        # News
        news_count = scraped_data.get('news_search', {}).get('count', 0)
        summary_points.append(f"News: {news_count} articles")
        
        return " | ".join(summary_points)