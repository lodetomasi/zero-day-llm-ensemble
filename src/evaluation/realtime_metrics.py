"""
Real-time metrics tracking for Zero-Day Detection System
Provides live precision, recall, F1-score and confusion matrix updates
"""
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import numpy as np
from collections import defaultdict
from dataclasses import dataclass, field
import json
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PredictionMetrics:
    """Holds real-time metrics for predictions"""
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    
    # Per-source metrics
    source_metrics: Dict[str, Dict[str, int]] = field(default_factory=lambda: defaultdict(
        lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    ))
    
    # Per-agent metrics
    agent_metrics: Dict[str, Dict[str, int]] = field(default_factory=lambda: defaultdict(
        lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    ))
    
    # Confidence tracking
    confidence_scores: List[float] = field(default_factory=list)
    prediction_times: List[float] = field(default_factory=list)
    
    # History for temporal analysis
    prediction_history: List[Dict] = field(default_factory=list)
    
    @property
    def total_predictions(self) -> int:
        return self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
    
    @property
    def precision(self) -> float:
        """Calculate precision (positive predictive value)"""
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)
    
    @property
    def recall(self) -> float:
        """Calculate recall (sensitivity, true positive rate)"""
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)
    
    @property
    def f1_score(self) -> float:
        """Calculate F1 score (harmonic mean of precision and recall)"""
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)
    
    @property
    def accuracy(self) -> float:
        """Calculate overall accuracy"""
        if self.total_predictions == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / self.total_predictions
    
    @property
    def specificity(self) -> float:
        """Calculate specificity (true negative rate)"""
        if self.true_negatives + self.false_positives == 0:
            return 0.0
        return self.true_negatives / (self.true_negatives + self.false_positives)
    
    @property
    def balanced_accuracy(self) -> float:
        """Calculate balanced accuracy (average of sensitivity and specificity)"""
        return (self.recall + self.specificity) / 2
    
    def get_confusion_matrix(self) -> np.ndarray:
        """Return confusion matrix as numpy array"""
        return np.array([
            [self.true_negatives, self.false_positives],
            [self.false_negatives, self.true_positives]
        ])
    
    def get_source_metrics(self, source: str) -> Dict[str, float]:
        """Get metrics for a specific source (CISA_KEV or NVD)"""
        metrics = self.source_metrics[source]
        tp, fp, tn, fn = metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]
        
        total = tp + fp + tn + fn
        if total == 0:
            return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "accuracy": 0.0}
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / total
        
        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
            "total": total
        }


class RealtimeMetricsTracker:
    """Tracks and displays real-time metrics during analysis"""
    
    def __init__(self, display_interval: int = 5):
        """
        Initialize metrics tracker
        
        Args:
            display_interval: How often to display metrics (in predictions)
        """
        self.metrics = PredictionMetrics()
        self.display_interval = display_interval
        self.start_time = time.time()
        self.last_display_time = time.time()
        
        # Terminal display settings
        self.use_color = True
        self.clear_screen = False
        
        logger.info("Initialized real-time metrics tracker")
    
    def update(self, cve_id: str, actual: bool, predicted: bool, 
              confidence: float, source: str, 
              agent_predictions: Optional[Dict[str, float]] = None,
              prediction_time: float = 0.0):
        """
        Update metrics with a new prediction
        
        Args:
            cve_id: CVE identifier
            actual: True if actually zero-day
            predicted: True if predicted as zero-day
            confidence: Prediction confidence
            source: Data source (CISA_KEV or NVD)
            agent_predictions: Individual agent predictions
            prediction_time: Time taken for prediction
        """
        # Update confusion matrix
        if actual and predicted:
            self.metrics.true_positives += 1
            self.metrics.source_metrics[source]["tp"] += 1
        elif actual and not predicted:
            self.metrics.false_negatives += 1
            self.metrics.source_metrics[source]["fn"] += 1
        elif not actual and predicted:
            self.metrics.false_positives += 1
            self.metrics.source_metrics[source]["fp"] += 1
        else:
            self.metrics.true_negatives += 1
            self.metrics.source_metrics[source]["tn"] += 1
        
        # Track confidence and time
        self.metrics.confidence_scores.append(confidence)
        self.metrics.prediction_times.append(prediction_time)
        
        # Update agent-specific metrics if provided
        if agent_predictions:
            for agent, pred in agent_predictions.items():
                agent_predicted = pred > 0.5
                if actual and agent_predicted:
                    self.metrics.agent_metrics[agent]["tp"] += 1
                elif actual and not agent_predicted:
                    self.metrics.agent_metrics[agent]["fn"] += 1
                elif not actual and agent_predicted:
                    self.metrics.agent_metrics[agent]["fp"] += 1
                else:
                    self.metrics.agent_metrics[agent]["tn"] += 1
        
        # Add to history
        self.metrics.prediction_history.append({
            "timestamp": datetime.now().isoformat(),
            "cve_id": cve_id,
            "actual": actual,
            "predicted": predicted,
            "confidence": confidence,
            "source": source,
            "correct": actual == predicted
        })
        
        # Display if interval reached
        if self.metrics.total_predictions % self.display_interval == 0:
            self.display_metrics()
    
    def display_metrics(self, force: bool = False):
        """Display current metrics in a formatted way"""
        if not force and time.time() - self.last_display_time < 1.0:
            return
        
        self.last_display_time = time.time()
        elapsed = time.time() - self.start_time
        
        # ANSI color codes
        GREEN = '\033[92m' if self.use_color else ''
        RED = '\033[91m' if self.use_color else ''
        YELLOW = '\033[93m' if self.use_color else ''
        BLUE = '\033[94m' if self.use_color else ''
        BOLD = '\033[1m' if self.use_color else ''
        RESET = '\033[0m' if self.use_color else ''
        
        # Clear screen if enabled
        if self.clear_screen:
            print('\033[2J\033[H')
        
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{BOLD}🎯 REAL-TIME ZERO-DAY DETECTION METRICS{RESET}")
        print(f"{BOLD}{'='*60}{RESET}")
        
        # Overall metrics
        print(f"\n{BOLD}📊 Overall Performance ({self.metrics.total_predictions} predictions):{RESET}")
        print(f"  Accuracy:  {self._format_metric(self.metrics.accuracy)}")
        print(f"  Precision: {self._format_metric(self.metrics.precision)}")
        print(f"  Recall:    {self._format_metric(self.metrics.recall)}")
        print(f"  F1-Score:  {self._format_metric(self.metrics.f1_score)}")
        
        # Confusion Matrix
        cm = self.metrics.get_confusion_matrix()
        print(f"\n{BOLD}🔍 Confusion Matrix:{RESET}")
        print(f"                 Predicted")
        print(f"              Regular  Zero-day")
        print(f"  Actual Regular  {cm[0,0]:4d}     {cm[0,1]:4d}")
        print(f"       Zero-day  {cm[1,0]:4d}     {cm[1,1]:4d}")
        
        # Per-source metrics
        print(f"\n{BOLD}📍 Performance by Source:{RESET}")
        for source in ["CISA_KEV", "NVD"]:
            metrics = self.metrics.get_source_metrics(source)
            if metrics.get("total", 0) > 0:
                print(f"\n  {source}:")
                print(f"    Samples:   {metrics['total']}")
                print(f"    Accuracy:  {self._format_metric(metrics['accuracy'])}")
                print(f"    Precision: {self._format_metric(metrics['precision'])}")
                print(f"    Recall:    {self._format_metric(metrics['recall'])}")
        
        # Performance stats
        if self.metrics.prediction_times:
            avg_time = np.mean(self.metrics.prediction_times)
            avg_conf = np.mean(self.metrics.confidence_scores)
            print(f"\n{BOLD}⚡ Performance Stats:{RESET}")
            print(f"  Avg prediction time: {avg_time:.1f}s")
            print(f"  Avg confidence:      {avg_conf:.1%}")
            print(f"  Predictions/min:     {(60 * self.metrics.total_predictions / elapsed):.1f}")
        
        # Recent trend (last 10 predictions)
        if len(self.metrics.prediction_history) >= 10:
            recent = self.metrics.prediction_history[-10:]
            recent_correct = sum(1 for p in recent if p["correct"])
            print(f"\n{BOLD}📈 Recent Trend (last 10):{RESET}")
            print(f"  Accuracy: {recent_correct/10:.1%}")
            
        print(f"\n{BOLD}{'='*60}{RESET}\n")
    
    def _format_metric(self, value: float) -> str:
        """Format metric with color coding"""
        if not self.use_color:
            return f"{value:6.1%}"
        
        if value >= 0.9:
            color = '\033[92m'  # Green
        elif value >= 0.7:
            color = '\033[93m'  # Yellow
        else:
            color = '\033[91m'  # Red
        
        return f"{color}{value:6.1%}\033[0m"
    
    def get_agent_rankings(self) -> List[Tuple[str, Dict[str, float]]]:
        """Get agent performance rankings"""
        rankings = []
        
        for agent, metrics in self.metrics.agent_metrics.items():
            tp, fp, tn, fn = metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]
            total = tp + fp + tn + fn
            
            if total > 0:
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
                accuracy = (tp + tn) / total
                
                rankings.append((agent, {
                    "accuracy": accuracy,
                    "precision": precision,
                    "recall": recall,
                    "f1": f1,
                    "total": total
                }))
        
        # Sort by F1 score
        rankings.sort(key=lambda x: x[1]["f1"], reverse=True)
        return rankings
    
    def save_metrics(self, filepath: Path):
        """Save metrics to file"""
        metrics_data = {
            "timestamp": datetime.now().isoformat(),
            "overall": {
                "total_predictions": self.metrics.total_predictions,
                "accuracy": self.metrics.accuracy,
                "precision": self.metrics.precision,
                "recall": self.metrics.recall,
                "f1_score": self.metrics.f1_score,
                "confusion_matrix": self.metrics.get_confusion_matrix().tolist()
            },
            "by_source": {
                source: self.metrics.get_source_metrics(source)
                for source in ["CISA_KEV", "NVD"]
            },
            "agent_rankings": [
                {"agent": agent, "metrics": metrics}
                for agent, metrics in self.get_agent_rankings()
            ],
            "history": self.metrics.prediction_history[-100:]  # Last 100 predictions
        }
        
        with open(filepath, 'w') as f:
            json.dump(metrics_data, f, indent=2)
        
        logger.info(f"Saved metrics to {filepath}")
    
    def final_report(self):
        """Display final comprehensive report"""
        self.display_metrics(force=True)
        
        # Agent rankings
        BOLD = '\033[1m' if self.use_color else ''
        RESET = '\033[0m' if self.use_color else ''
        
        print(f"\n{BOLD}🏆 Agent Performance Rankings:{RESET}")
        for i, (agent, metrics) in enumerate(self.get_agent_rankings(), 1):
            print(f"\n  {i}. {agent}")
            print(f"     F1-Score:  {metrics['f1']:.1%}")
            print(f"     Precision: {metrics['precision']:.1%}")
            print(f"     Recall:    {metrics['recall']:.1%}")