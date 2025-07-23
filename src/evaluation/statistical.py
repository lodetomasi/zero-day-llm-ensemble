"""
Statistical testing for Zero-Day Detection System
"""
import numpy as np
from typing import Dict, Any, List, Tuple, Optional
from scipy import stats
from statsmodels.stats.contingency_tables import mcnemar
import pandas as pd

from src.utils.logger import get_logger

logger = get_logger(__name__)


class StatisticalTester:
    """Advanced statistical testing for model comparison"""
    
    def __init__(self, confidence_level: float = 0.95):
        self.confidence_level = confidence_level
        self.significance_level = 1 - confidence_level
    
    def mcnemar_test(self, y_true: np.ndarray, pred1: np.ndarray, 
                     pred2: np.ndarray) -> Dict[str, Any]:
        """
        McNemar's test for comparing two classifiers
        
        Args:
            y_true: True labels
            pred1: Predictions from model 1
            pred2: Predictions from model 2
            
        Returns:
            Test results including p-value and interpretation
        """
        # Create contingency table
        correct1 = (pred1 == y_true)
        correct2 = (pred2 == y_true)
        
        # McNemar's contingency table
        both_wrong = np.sum(~correct1 & ~correct2)
        model1_right_model2_wrong = np.sum(correct1 & ~correct2)
        model1_wrong_model2_right = np.sum(~correct1 & correct2)
        both_right = np.sum(correct1 & correct2)
        
        contingency_table = np.array([
            [both_right, model1_right_model2_wrong],
            [model1_wrong_model2_right, both_wrong]
        ])
        
        # Perform test
        result = mcnemar(contingency_table, exact=True)
        
        # Interpret results
        significant = result.pvalue < self.significance_level
        
        # Effect size (odds ratio)
        if model1_wrong_model2_right > 0:
            odds_ratio = model1_right_model2_wrong / model1_wrong_model2_right
        else:
            odds_ratio = np.inf if model1_right_model2_wrong > 0 else 1.0
        
        return {
            'statistic': result.statistic,
            'p_value': result.pvalue,
            'significant': significant,
            'significance_level': self.significance_level,
            'contingency_table': contingency_table.tolist(),
            'odds_ratio': odds_ratio,
            'interpretation': self._interpret_mcnemar(result.pvalue, odds_ratio)
        }
    
    def _interpret_mcnemar(self, p_value: float, odds_ratio: float) -> str:
        """Interpret McNemar test results"""
        if p_value >= self.significance_level:
            return "No significant difference between models"
        else:
            if odds_ratio > 1:
                return f"Model 1 significantly better (OR={odds_ratio:.2f})"
            elif odds_ratio < 1:
                return f"Model 2 significantly better (OR={1/odds_ratio:.2f})"
            else:
                return "Models are significantly different but equally good"
    
    def cochrans_q_test(self, y_true: np.ndarray, 
                       predictions: Dict[str, np.ndarray]) -> Dict[str, Any]:
        """
        Cochran's Q test for comparing multiple classifiers
        
        Args:
            y_true: True labels
            predictions: Dictionary of model predictions
            
        Returns:
            Test results
        """
        # Create binary success matrix
        models = list(predictions.keys())
        n_samples = len(y_true)
        n_models = len(models)
        
        success_matrix = np.zeros((n_samples, n_models))
        for i, model in enumerate(models):
            success_matrix[:, i] = (predictions[model] == y_true).astype(int)
        
        # Calculate Cochran's Q statistic
        row_sums = np.sum(success_matrix, axis=1)
        col_sums = np.sum(success_matrix, axis=0)
        
        # Remove rows where all models agree
        disagreement_mask = (row_sums > 0) & (row_sums < n_models)
        filtered_matrix = success_matrix[disagreement_mask]
        
        if len(filtered_matrix) == 0:
            return {
                'statistic': 0,
                'p_value': 1.0,
                'significant': False,
                'interpretation': "All models agree on all samples"
            }
        
        # Calculate Q statistic
        k = n_models
        N = len(filtered_matrix)
        col_sums_filtered = np.sum(filtered_matrix, axis=0)
        row_sums_filtered = np.sum(filtered_matrix, axis=1)
        
        numerator = (k - 1) * (k * np.sum(col_sums_filtered**2) - np.sum(col_sums_filtered)**2)
        denominator = k * np.sum(row_sums_filtered) - np.sum(row_sums_filtered**2)
        
        if denominator == 0:
            Q = 0
        else:
            Q = numerator / denominator
        
        # Calculate p-value (chi-square distribution with k-1 degrees of freedom)
        p_value = 1 - stats.chi2.cdf(Q, df=k-1)
        
        return {
            'statistic': Q,
            'p_value': p_value,
            'degrees_of_freedom': k - 1,
            'significant': p_value < self.significance_level,
            'n_models': n_models,
            'n_samples_with_disagreement': len(filtered_matrix),
            'model_accuracies': {model: np.mean(predictions[model] == y_true) 
                               for model in models}
        }
    
    def bootstrap_confidence_interval(self, y_true: np.ndarray, 
                                    y_pred: np.ndarray,
                                    metric_func,
                                    n_bootstrap: int = 1000) -> Dict[str, float]:
        """
        Calculate bootstrap confidence interval for a metric
        
        Args:
            y_true: True labels
            y_pred: Predictions
            metric_func: Function to calculate metric
            n_bootstrap: Number of bootstrap iterations
            
        Returns:
            Confidence interval and statistics
        """
        n_samples = len(y_true)
        bootstrap_scores = []
        
        # Original metric
        original_score = metric_func(y_true, y_pred)
        
        # Bootstrap resampling
        for _ in range(n_bootstrap):
            indices = np.random.choice(n_samples, n_samples, replace=True)
            y_true_boot = y_true[indices]
            y_pred_boot = y_pred[indices]
            
            try:
                score = metric_func(y_true_boot, y_pred_boot)
                bootstrap_scores.append(score)
            except:
                # Skip if metric calculation fails (e.g., all one class)
                continue
        
        bootstrap_scores = np.array(bootstrap_scores)
        
        # Calculate percentiles
        alpha = 1 - self.confidence_level
        lower_percentile = (alpha / 2) * 100
        upper_percentile = (1 - alpha / 2) * 100
        
        return {
            'original_score': original_score,
            'mean': np.mean(bootstrap_scores),
            'std': np.std(bootstrap_scores),
            'lower_ci': np.percentile(bootstrap_scores, lower_percentile),
            'upper_ci': np.percentile(bootstrap_scores, upper_percentile),
            'confidence_level': self.confidence_level,
            'n_bootstrap': len(bootstrap_scores)
        }
    
    def permutation_test(self, y_true: np.ndarray, pred1: np.ndarray,
                        pred2: np.ndarray, metric_func,
                        n_permutations: int = 1000) -> Dict[str, Any]:
        """
        Permutation test for comparing two models
        
        Args:
            y_true: True labels
            pred1: Predictions from model 1
            pred2: Predictions from model 2
            metric_func: Metric function (e.g., f1_score)
            n_permutations: Number of permutations
            
        Returns:
            Test results
        """
        # Calculate original difference
        score1 = metric_func(y_true, pred1)
        score2 = metric_func(y_true, pred2)
        original_diff = score1 - score2
        
        # Permutation test
        permuted_diffs = []
        n_samples = len(y_true)
        
        for _ in range(n_permutations):
            # Randomly swap predictions between models
            swap_mask = np.random.randint(0, 2, size=n_samples).astype(bool)
            
            perm_pred1 = np.where(swap_mask, pred2, pred1)
            perm_pred2 = np.where(swap_mask, pred1, pred2)
            
            perm_score1 = metric_func(y_true, perm_pred1)
            perm_score2 = metric_func(y_true, perm_pred2)
            permuted_diffs.append(perm_score1 - perm_score2)
        
        permuted_diffs = np.array(permuted_diffs)
        
        # Calculate p-value
        if original_diff > 0:
            p_value = np.mean(permuted_diffs >= original_diff)
        else:
            p_value = np.mean(permuted_diffs <= original_diff)
        
        # Two-tailed test
        p_value_two_tailed = 2 * min(p_value, 1 - p_value)
        
        return {
            'score1': score1,
            'score2': score2,
            'original_difference': original_diff,
            'p_value': p_value_two_tailed,
            'significant': p_value_two_tailed < self.significance_level,
            'permuted_mean': np.mean(permuted_diffs),
            'permuted_std': np.std(permuted_diffs),
            'effect_size': original_diff / np.std(permuted_diffs) if np.std(permuted_diffs) > 0 else 0
        }
    
    def delong_roc_test(self, y_true: np.ndarray, prob1: np.ndarray,
                       prob2: np.ndarray) -> Dict[str, Any]:
        """
        DeLong test for comparing ROC AUC scores
        
        Args:
            y_true: True labels
            prob1: Probability predictions from model 1
            prob2: Probability predictions from model 2
            
        Returns:
            Test results
        """
        # Calculate AUC scores
        from sklearn.metrics import roc_auc_score
        auc1 = roc_auc_score(y_true, prob1)
        auc2 = roc_auc_score(y_true, prob2)
        
        # DeLong's test implementation
        n_samples = len(y_true)
        n_pos = np.sum(y_true == 1)
        n_neg = np.sum(y_true == 0)
        
        # Calculate placement values
        V10 = np.zeros(n_samples)
        V01 = np.zeros(n_samples)
        
        for i in range(n_samples):
            if y_true[i] == 1:
                V10[i] = np.sum(prob1[i] > prob1[y_true == 0]) / n_neg
                V01[i] = np.sum(prob2[i] > prob2[y_true == 0]) / n_neg
            else:
                V10[i] = np.sum(prob1[i] >= prob1[y_true == 1]) / n_pos
                V01[i] = np.sum(prob2[i] >= prob2[y_true == 1]) / n_pos
        
        # Compute covariance matrix
        S10 = np.cov(V10[y_true == 1]) / n_pos + np.cov(V10[y_true == 0]) / n_neg
        S01 = np.cov(V01[y_true == 1]) / n_pos + np.cov(V01[y_true == 0]) / n_neg
        S10_01 = np.cov(V10[y_true == 1], V01[y_true == 1])[0, 1] / n_pos + \
                 np.cov(V10[y_true == 0], V01[y_true == 0])[0, 1] / n_neg
        
        # Standard error
        se = np.sqrt(S10 + S01 - 2 * S10_01)
        
        # Z-statistic
        if se > 0:
            z = (auc1 - auc2) / se
            p_value = 2 * (1 - stats.norm.cdf(abs(z)))
        else:
            z = 0
            p_value = 1.0
        
        return {
            'auc1': auc1,
            'auc2': auc2,
            'difference': auc1 - auc2,
            'standard_error': se,
            'z_statistic': z,
            'p_value': p_value,
            'significant': p_value < self.significance_level
        }
    
    def friedman_test(self, results_matrix: np.ndarray,
                     model_names: List[str]) -> Dict[str, Any]:
        """
        Friedman test for comparing multiple models across multiple datasets
        
        Args:
            results_matrix: Shape (n_datasets, n_models) with performance scores
            model_names: List of model names
            
        Returns:
            Test results
        """
        n_datasets, n_models = results_matrix.shape
        
        # Rank models for each dataset
        ranks = np.zeros_like(results_matrix)
        for i in range(n_datasets):
            ranks[i] = stats.rankdata(-results_matrix[i])  # Negative for descending order
        
        # Calculate average ranks
        avg_ranks = np.mean(ranks, axis=0)
        
        # Friedman statistic
        chi2_stat = 12 * n_datasets / (n_models * (n_models + 1)) * \
                    (np.sum(avg_ranks**2) - n_models * (n_models + 1)**2 / 4)
        
        # Improved Friedman statistic (Iman-Davenport)
        F_stat = (n_datasets - 1) * chi2_stat / (n_datasets * (n_models - 1) - chi2_stat)
        
        # p-values
        p_value_chi2 = 1 - stats.chi2.cdf(chi2_stat, df=n_models-1)
        p_value_f = 1 - stats.f.cdf(F_stat, dfn=n_models-1, dfd=(n_models-1)*(n_datasets-1))
        
        return {
            'chi2_statistic': chi2_stat,
            'f_statistic': F_stat,
            'p_value': p_value_f,
            'significant': p_value_f < self.significance_level,
            'average_ranks': {name: rank for name, rank in zip(model_names, avg_ranks)},
            'best_model': model_names[np.argmin(avg_ranks)]
        }