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
            'confidence': 0.0,
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
            if days_diff <= 7:  # KEV within a week of disclosure
                timeline['confidence'] += 0.3
                timeline['analysis'] += "KEV listing very close to disclosure suggests active exploitation. "
            elif days_diff < 0:  # KEV before NVD
                timeline['confidence'] += 0.5
                timeline['is_zero_day'] = True
                timeline['analysis'] += "KEV listing BEFORE public disclosure - strong zero-day indicator! "
        
        # Pattern 2: Emergency patches
        if evidence.get('indicators', {}).get('emergency_patches'):
            timeline['confidence'] += 0.2
            timeline['analysis'] += "Emergency patches suggest exploitation pressure. "
        
        # Pattern 3: News mentions before official disclosure
        news_data = evidence.get('sources', {}).get('security_news', {})
        if news_data.get('zero_day_mentions', 0) > 0:
            timeline['confidence'] += 0.2
            timeline['analysis'] += f"{news_data['zero_day_mentions']} articles mention zero-day exploitation. "
        
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
        
        # Negative indicators
        github_data = evidence.get('sources', {}).get('github', {})
        if github_data.get('poc_count', 0) > 50:  # Too many PoCs
            timeline['confidence'] -= 0.2
            timeline['analysis'] += "Large number of PoCs suggests NOT a zero-day (widely known). "
        
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