#!/usr/bin/env python3
"""Create visualizations from existing results"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

# Import the visualization function from the complete test
from run_complete_test import create_visualizations

def main():
    # Find the latest results file
    results_dir = Path('results')
    result_files = list(results_dir.glob('complete_test_*.json'))
    
    if not result_files:
        print("❌ No results files found!")
        return
    
    # Get the most recent file
    latest_file = max(result_files, key=lambda x: x.stat().st_mtime)
    print(f"📊 Creating visualizations for: {latest_file.name}")
    
    # Create visualizations
    create_visualizations(latest_file, results_dir)
    
    print("\n✅ Visualizations created successfully!")

if __name__ == "__main__":
    main()