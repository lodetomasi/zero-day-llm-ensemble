#!/usr/bin/env python3
"""
Create ML baselines for comparison with LLM ensemble
"""
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import cross_val_score, StratifiedKFold
import pandas as pd
from pathlib import Path

def load_features_from_cache():
    """Load pre-extracted features from detection cache"""
    cache_file = Path('cache/detection_cache.json')
    if not cache_file.exists():
        raise FileNotFoundError("Run detection first to generate features")
    
    with open(cache_file, 'r') as f:
        cache = json.load(f)
    
    features = []
    labels = []
    cve_ids = []
    
    for cve_id, data in cache.items():
        # Extract key features
        feat_vector = [
            float(data['evidence_summary']['cisa_kev']),
            data['evidence_summary']['apt_groups'],
            data['evidence_summary']['poc_repositories'],
            data['evidence_summary']['news_mentions'],
            float(data['evidence_summary']['exploitation_evidence']),
            data['detection_score'],
            data['confidence'],
            len(data['key_indicators']),
            data['agent_consensus']
        ]
        
        features.append(feat_vector)
        labels.append(int(data['is_zero_day']))
        cve_ids.append(cve_id)
    
    return np.array(features), np.array(labels), cve_ids

def run_ml_baselines():
    """Run multiple ML baselines and compare"""
    print("🤖 Running ML Baselines for Comparison")
    print("="*60)
    
    # Load features
    X, y, cve_ids = load_features_from_cache()
    print(f"Loaded {len(X)} samples with {X.shape[1]} features")
    
    # Define baselines
    baselines = {
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
        'SVM (RBF)': SVC(kernel='rbf', random_state=42),
        'Logistic Regression': LogisticRegression(random_state=42)
    }
    
    # 5-fold cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    results = {}
    
    for name, model in baselines.items():
        print(f"\n📊 Testing {name}...")
        
        # Cross-validation scores
        cv_scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy')
        cv_f1 = cross_val_score(model, X, y, cv=cv, scoring='f1')
        cv_precision = cross_val_score(model, X, y, cv=cv, scoring='precision')
        cv_recall = cross_val_score(model, X, y, cv=cv, scoring='recall')
        
        # Train on full dataset for final metrics
        model.fit(X, y)
        y_pred = model.predict(X)
        
        results[name] = {
            'accuracy': {
                'mean': cv_scores.mean(),
                'std': cv_scores.std(),
                'scores': cv_scores.tolist()
            },
            'f1_score': {
                'mean': cv_f1.mean(),
                'std': cv_f1.std()
            },
            'precision': {
                'mean': cv_precision.mean(),
                'std': cv_precision.std()
            },
            'recall': {
                'mean': cv_recall.mean(),
                'std': cv_recall.std()
            },
            'full_accuracy': accuracy_score(y, y_pred),
            'full_f1': f1_score(y, y_pred)
        }
        
        print(f"  Accuracy: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
        print(f"  F1-Score: {cv_f1.mean():.3f} ± {cv_f1.std():.3f}")
        print(f"  Precision: {cv_precision.mean():.3f} ± {cv_precision.std():.3f}")
        print(f"  Recall: {cv_recall.mean():.3f} ± {cv_recall.std():.3f}")
    
    # Feature importance for Random Forest
    rf = baselines['Random Forest']
    rf.fit(X, y)
    
    feature_names = [
        'CISA_KEV', 'APT_Groups', 'PoC_Count', 'News_Mentions',
        'Exploitation_Evidence', 'Detection_Score', 'Confidence',
        'Key_Indicators_Count', 'Agent_Consensus'
    ]
    
    importance = pd.DataFrame({
        'feature': feature_names,
        'importance': rf.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\n🔍 Feature Importance (Random Forest):")
    for _, row in importance.iterrows():
        print(f"  {row['feature']}: {row['importance']:.3f}")
    
    # Save results
    with open('ml_baseline_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n📊 Comparison with LLM Ensemble:")
    print("  LLM Ensemble: 80.0% accuracy, 86.4% F1")
    print(f"  Best ML Baseline: {max(r['accuracy']['mean'] for r in results.values()):.1%} accuracy")
    
    return results

def statistical_significance_test():
    """Test statistical significance of LLM ensemble vs baselines"""
    from scipy import stats
    
    # LLM ensemble results (from your test)
    llm_accuracy = 0.80
    llm_correct = 24
    n_samples = 30
    
    # Test against random baseline (50%)
    p_value_random = stats.binomtest(llm_correct, n_samples, 0.5, alternative='greater').pvalue
    
    print("\n📈 Statistical Significance Tests:")
    print(f"  H0: System performs at random (50%)")
    print(f"  p-value: {p_value_random:.4f}")
    print(f"  Significant: {'Yes' if p_value_random < 0.05 else 'No'}")
    
    # McNemar's test would require paired predictions
    # This would compare LLM vs best ML baseline on same samples

if __name__ == "__main__":
    results = run_ml_baselines()
    statistical_significance_test()