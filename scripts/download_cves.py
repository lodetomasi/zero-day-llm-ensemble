#!/usr/bin/env python3
"""
Script semplice per scaricare dati di CVE specifiche
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

import json
import time
from src.scraping.comprehensive_scraper import ComprehensiveZeroDayScraper

def download_cves(cve_list, output_file="downloaded_cves.json"):
    """
    Scarica dati per una lista di CVE
    
    Args:
        cve_list: Lista di CVE da scaricare
        output_file: File dove salvare i risultati
    """
    scraper = ComprehensiveZeroDayScraper()
    results = {}
    
    print(f"📥 Downloading data for {len(cve_list)} CVEs...")
    
    for i, cve_id in enumerate(cve_list, 1):
        print(f"\n[{i}/{len(cve_list)}] Scraping {cve_id}...")
        
        try:
            # Scarica tutti i dati disponibili
            evidence = scraper.scrape_all_sources(cve_id)
            
            # Estrai informazioni chiave
            nvd_data = evidence.get('sources', {}).get('nvd', {})
            cisa_kev = evidence.get('sources', {}).get('cisa_kev', {})
            
            results[cve_id] = {
                'description': nvd_data.get('description', 'No description'),
                'cvss_score': nvd_data.get('cvss_v3_score', 0),
                'published_date': nvd_data.get('published_date', ''),
                'in_cisa_kev': bool(cisa_kev),
                'kev_date_added': cisa_kev.get('dateAdded', '') if cisa_kev else '',
                'sources_found': len([s for s in evidence.get('sources', {}).values() if s]),
                'raw_evidence': evidence  # Tutti i dati grezzi
            }
            
            print(f"   ✅ Found data from {results[cve_id]['sources_found']} sources")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
            results[cve_id] = {'error': str(e)}
        
        # Pausa per evitare rate limiting
        if i < len(cve_list):
            time.sleep(2)
    
    # Salva risultati
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✅ Results saved to {output_file}")
    print(f"   - Successful: {len([r for r in results.values() if 'error' not in r])}")
    print(f"   - Failed: {len([r for r in results.values() if 'error' in r])}")

if __name__ == "__main__":
    # Esempio di utilizzo
    cves_to_download = [
        "CVE-2024-6387",  # OpenSSH regreSSHion
        "CVE-2024-3094",  # XZ Utils backdoor
        "CVE-2024-38063", # Windows TCP/IP
        "CVE-2023-46604", # Apache ActiveMQ
        "CVE-2023-28121", # WooCommerce
    ]
    
    # Puoi anche passare CVE da linea di comando
    if len(sys.argv) > 1:
        cves_to_download = sys.argv[1:]
    
    download_cves(cves_to_download)