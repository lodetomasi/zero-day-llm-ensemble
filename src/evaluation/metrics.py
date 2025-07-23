"""
Evaluation metrics for Zero-Day Detection System
"""
import numpy as np
from typing import Dict, Any, List, Tuple, Optional
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score,
    precision_recall_curve, roc_curve, average_precision_score
)

from src.utils.logger import get_logger

logger = get_logger(__name__)


class MetricsCalculator:
    """Calculate and track evaluation metrics"""
    
    def __init__(self):
        self.results_history = []
    
    def calculate_metrics(self, y_true: np.ndarray, y_pred: np.ndarray,
                         y_prob: Optional[np.ndarray] = None,
                         prefix: str = "") -> Dict[str, float]:
        """
        Calculate comprehensive metrics
        
        Args:
            y_true: True labels
            y_pred: Binary predictions
            y_prob: Probability predictions
            prefix: Prefix for metric names
            
        Returns:
            Dictionary of metrics
        """
        metrics = {}
        
        # Basic metrics
        metrics[f'{prefix}accuracy'] = accuracy_score(y_true, y_pred)
        metrics[f'{prefix}precision'] = precision_score(y_true, y_pred, zero_division=0)
        metrics[f'{prefix}recall'] = recall_score(y_true, y_pred, zero_division=0)
        metrics[f'{prefix}f1'] = f1_score(y_true, y_pred, zero_division=0)
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        metrics[f'{prefix}true_negatives'] = int(cm[0, 0])
        metrics[f'{prefix}false_positives'] = int(cm[0, 1])
        metrics[f'{prefix}false_negatives'] = int(cm[1, 0])
        metrics[f'{prefix}true_positives'] = int(cm[1, 1])
        
        # Additional metrics
        metrics[f'{prefix}specificity'] = cm[0, 0] / (cm[0, 0] + cm[0, 1]) if (cm[0, 0] + cm[0, 1]) > 0 else 0
        metrics[f'{prefix}balanced_accuracy'] = (metrics[f'{prefix}recall'] + metrics[f'{prefix}specificity']) / 2
        
        # Probabilistic metrics if available
        if y_prob is not None:
            try:
                metrics[f'{prefix}roc_auc'] = roc_auc_score(y_true, y_prob)
                metrics[f'{prefix}average_precision'] = average_precision_score(y_true, y_prob)
            except ValueError as e:
                logger.warning(f"Could not calculate ROC AUC: {e}")
                metrics[f'{prefix}roc_auc'] = None
                metrics[f'{prefix}average_precision'] = None
        
        # Store results
        self.results_history.append({
            'y_true': y_true,
            'y_pred': y_pred,
            'y_prob': y_prob,
            'metrics': metrics,
            'prefix': prefix
        })
        
        return metrics
    
    def calculate_per_class_metrics(self, y_true: np.ndarray, y_pred: np.ndarray,
                                   class_names: List[str] = None) -> Dict[str, Any]:
        """Calculate per-class metrics"""
        if class_names is None:
            class_names = ['Regular CVE', 'Zero-Day']
        
        report = classification_report(y_true, y_pred, 
                                     target_names=class_names,
                                     output_dict=True,
                                     zero_division=0)
        
        return report
    
    def calculate_confidence_metrics(self, predictions: List[Dict[str, Any]],
                                   y_true: np.ndarray) -> Dict[str, float]:
        """Calculate metrics related to prediction confidence"""
        confidences = np.array([p.get('confidence', 0.5) for p in predictions])
        y_pred = np.array([int(p.get('prediction', 0.5) > 0.5) for p in predictions])
        
        # Separate correct and incorrect predictions
        correct_mask = y_pred == y_true
        incorrect_mask = ~correct_mask
        
        metrics = {
            'mean_confidence': np.mean(confidences),
            'std_confidence': np.std(confidences),
            'mean_confidence_correct': np.mean(confidences[correct_mask]) if np.any(correct_mask) else 0,
            'mean_confidence_incorrect': np.mean(confidences[incorrect_mask]) if np.any(incorrect_mask) else 0,
            'confidence_accuracy_correlation': np.corrcoef(confidences, correct_mask.astype(float))[0, 1] if len(confidences) > 1 else 0
        }
        
        # Calibration metrics
        calibration_error = self._calculate_calibration_error(
            y_true, y_pred, confidences
        )
        metrics.update(calibration_error)
        
        return metrics
    
    def _calculate_calibration_error(self, y_true: np.ndarray, 
                                   y_pred: np.ndarray,
                                   confidences: np.ndarray,
                                   n_bins: int = 10) -> Dict[str, float]:
        """Calculate expected calibration error"""
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        bin_lowers = bin_boundaries[:-1]
        bin_uppers = bin_boundaries[1:]
        
        ece = 0
        mce = 0
        
        for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
            in_bin = (confidences > bin_lower) & (confidences <= bin_upper)
            prop_in_bin = in_bin.mean()
            
            if prop_in_bin > 0:
                accuracy_in_bin = (y_pred[in_bin] == y_true[in_bin]).mean()
                avg_confidence_in_bin = confidences[in_bin].mean()
                
                calibration_error = abs(avg_confidence_in_bin - accuracy_in_bin)
                ece += prop_in_bin * calibration_error
                mce = max(mce, calibration_error)
        
        return {
            'expected_calibration_error': ece,
            'maximum_calibration_error': mce
        }
    
    def calculate_temporal_metrics(self, predictions_df) -> Dict[str, Any]:
        """Calculate metrics over time periods"""
        if 'year' not in predictions_df.columns:
            return {}
        
        temporal_metrics = {}
        
        for year in sorted(predictions_df['year'].unique()):
            year_mask = predictions_df['year'] == year
            year_data = predictions_df[year_mask]
            
            if len(year_data) > 0:
                y_true = year_data['true_label'].values
                y_pred = year_data['prediction'].values > 0.5
                
                year_metrics = self.calculate_metrics(
                    y_true, y_pred, prefix=f'year_{year}_'
                )
                temporal_metrics[f'year_{year}'] = year_metrics
        
        return temporal_metrics
    
    def get_curves(self, y_true: np.ndarray, y_prob: np.ndarray) -> Dict[str, Any]:
        """Get ROC and PR curves data"""
        curves = {}
        
        # ROC curve
        fpr, tpr, roc_thresholds = roc_curve(y_true, y_prob)
        curves['roc'] = {
            'fpr': fpr.tolist(),
            'tpr': tpr.tolist(),
            'thresholds': roc_thresholds.tolist(),
            'auc': roc_auc_score(y_true, y_prob)
        }
        
        # Precision-Recall curve
        precision, recall, pr_thresholds = precision_recall_curve(y_true, y_prob)
        curves['pr'] = {
            'precision': precision.tolist(),
            'recall': recall.tolist(),
            'thresholds': pr_thresholds.tolist(),
            'auc': average_precision_score(y_true, y_prob)
        }
        
        return curves