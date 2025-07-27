"""
Enhanced temporal analysis for better zero-day detection
"""
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import re

class TemporalAnalyzer:
    """Analyze temporal relationships between vulnerability events"""
    
    def analyze_timeline(self, evidence: Dict) -> Dict:
        """
        Analyze timeline to determine if exploitation happened before disclosure
        """
        timeline = {
            'is_zero_day': False,
            'confidence': 0.0,  # Start at zero - require evidence
            'timeline_events': [],
            'key_dates': {},
            'analysis': ''
        }
        
        # Extract key dates
        cve_id = evidence.get('cve_id', '')
        year = self._extract_cve_year(cve_id)
        
        # CISA KEV dates
        kev_data = evidence.get('sources', {}).get('cisa_kev', {})
        if kev_data.get('in_kev'):
            date_added = self._parse_date(kev_data.get('date_added'))
            if date_added:
                timeline['key_dates']['kev_added'] = date_added
                timeline['timeline_events'].append({
                    'date': date_added,
                    'event': 'Added to CISA KEV',
                    'significance': 'high'
                })
        
        # NVD publication date
        nvd_data = evidence.get('sources', {}).get('nvd', {})
        pub_date = self._parse_date(nvd_data.get('published_date'))
        if pub_date:
            timeline['key_dates']['nvd_published'] = pub_date
            timeline['timeline_events'].append({
                'date': pub_date,
                'event': 'CVE published in NVD',
                'significance': 'medium'
            })
        
        # GitHub PoC dates
        github_data = evidence.get('sources', {}).get('github', {})
        first_poc = self._parse_date(github_data.get('first_poc_date'))
        if first_poc:
            timeline['key_dates']['first_poc'] = first_poc
            timeline['timeline_events'].append({
                'date': first_poc,
                'event': 'First public PoC on GitHub',
                'significance': 'high'
            })
        
        # Analyze timeline patterns
        timeline = self._analyze_patterns(timeline, evidence)
        
        # Sort events chronologically
        timeline['timeline_events'].sort(key=lambda x: x['date'])
        
        return timeline
    
    def _analyze_patterns(self, timeline: Dict, evidence: Dict) -> Dict:
        """Analyze timeline patterns to detect zero-day indicators"""
        
        # Pattern 1: KEV added very close to or before NVD publication
        kev_date = timeline['key_dates'].get('kev_added')
        nvd_date = timeline['key_dates'].get('nvd_published')
        
        if kev_date and nvd_date:
            days_diff = (kev_date - nvd_date).days
            if days_diff <= 1:  # Same day or next day
                timeline['confidence'] += 0.4
                timeline['analysis'] += "KEV listing on disclosure day suggests pre-existing exploitation. "
            elif days_diff <= 7:  # Within a week
                timeline['confidence'] += 0.1  # Weak signal
                timeline['analysis'] += "KEV listing within a week of disclosure. "
            elif days_diff < 0:  # KEV before NVD
                timeline['confidence'] += 0.6
                timeline['is_zero_day'] = True
                timeline['analysis'] += "KEV listing BEFORE public disclosure - strong zero-day indicator! "
        
        # Pattern 2: Emergency patches (weak signal by itself)
        if evidence.get('indicators', {}).get('emergency_patches'):
            timeline['confidence'] += 0.1  # Reduced from 0.2
            timeline['analysis'] += "Emergency patches released. "
        
        # Pattern 3: News explicitly mentioning zero-day (strong signal)
        news_data = evidence.get('sources', {}).get('security_news', {})
        zero_day_mentions = news_data.get('zero_day_mentions', 0)
        if zero_day_mentions >= 3:
            timeline['confidence'] += 0.4  # Multiple sources = strong
            timeline['analysis'] += f"{zero_day_mentions} articles explicitly mention zero-day exploitation. "
        elif zero_day_mentions > 0:
            timeline['confidence'] += 0.2
            timeline['analysis'] += f"{zero_day_mentions} article(s) mention zero-day. "
        
        # Pattern 4: APT associations
        apt_groups = evidence.get('indicators', {}).get('apt_associations', [])
        if apt_groups:
            timeline['confidence'] += 0.15
            timeline['analysis'] += f"Associated with APT groups known for zero-day usage. "
        
        # Pattern 5: Rapid PoC development
        poc_date = timeline['key_dates'].get('first_poc')
        if poc_date and nvd_date:
            poc_days = (poc_date - nvd_date).days
            if poc_days <= 1:  # PoC same day or next day
                timeline['confidence'] += 0.1
                timeline['analysis'] += "Very rapid PoC development suggests prior knowledge. "
        
        # Negative indicators (penalize likely false positives)
        github_data = evidence.get('sources', {}).get('github', {})
        poc_count = github_data.get('poc_count', 0)
        if poc_count > 50:  # Massive PoC availability
            timeline['confidence'] -= 0.4  # Strong penalty
            timeline['analysis'] += f"{poc_count} PoCs found - suggests NOT a zero-day. "
        elif poc_count > 20:
            timeline['confidence'] -= 0.2
            timeline['analysis'] += f"{poc_count} PoCs found - likely not zero-day. "
        
        # Final determination
        if timeline['confidence'] >= 0.5:
            timeline['is_zero_day'] = True
        
        # Cap confidence at 1.0
        timeline['confidence'] = min(1.0, max(0.0, timeline['confidence']))
        
        return timeline
    
    def _extract_cve_year(self, cve_id: str) -> Optional[int]:
        """Extract year from CVE ID"""
        match = re.match(r'CVE-(\d{4})-\d+', cve_id)
        if match:
            return int(match.group(1))
        return None
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse various date formats"""
        if not date_str:
            return None
        
        # Common date formats
        formats = [
            '%Y-%m-%d',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y/%m/%d',
            '%d/%m/%Y',
            '%B %d, %Y',
            '%b %d, %Y'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str.split('+')[0].split('.')[0], fmt)
            except:
                continue
        
        return None
    
    def generate_timeline_summary(self, timeline: Dict) -> str:
        """Generate human-readable timeline summary"""
        summary = []
        
        if timeline['is_zero_day']:
            summary.append("🚨 ZERO-DAY DETECTED based on timeline analysis")
        else:
            summary.append("ℹ️ No strong zero-day indicators in timeline")
        
        summary.append(f"Confidence: {timeline['confidence']:.0%}")
        summary.append("")
        
        if timeline['timeline_events']:
            summary.append("Key Events:")
            for event in timeline['timeline_events']:
                date_str = event['date'].strftime('%Y-%m-%d')
                summary.append(f"  • {date_str}: {event['event']}")
        
        if timeline['analysis']:
            summary.append("")
            summary.append("Analysis:")
            summary.append(timeline['analysis'])
        
        return '\n'.join(summary)