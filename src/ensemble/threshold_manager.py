"""
Dynamic threshold management for zero-day classification
"""
from typing import Dict, Any
import numpy as np
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ThresholdManager:
    """Manage dynamic thresholds based on source and confidence"""
    
    def __init__(self):
        # Uniform threshold to avoid source bias
        self.base_threshold = 0.5  # Standard threshold
        self.thresholds = {
            'CISA_KEV': {
                'base': self.base_threshold,
                'high_confidence': self.base_threshold - 0.1,
                'adjustment_factor': 1.0  # No adjustment
            },
            'NVD': {
                'base': self.base_threshold,
                'high_confidence': self.base_threshold - 0.1,
                'adjustment_factor': 1.0  # No adjustment
            },
            'MANUAL': {
                'base': self.base_threshold,
                'high_confidence': self.base_threshold - 0.1,
                'adjustment_factor': 1.0  # No adjustment
            }
        }
        
        # Confidence thresholds
        self.confidence_levels = {
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4
        }
    
    def get_threshold(self, source: str, confidence: float) -> float:
        """Get dynamic threshold based on source and confidence"""
        source_config = self.thresholds.get(source, self.thresholds['MANUAL'])
        
        if confidence >= self.confidence_levels['high']:
            return source_config['high_confidence']
        else:
            return source_config['base']
    
    def adjust_prediction(self, prediction: float, source: str, 
                         confidence: float, agent_agreement: float = None) -> float:
        """Adjust prediction based on source and other factors"""
        source_config = self.thresholds.get(source, self.thresholds['MANUAL'])
        adjusted = prediction
        
        # DISABLED: Source-specific adjustments to avoid bias
        # The model should classify based on content, not source
        # adjusted = prediction
        
        logger.debug(f"Threshold adjustment: {source} {prediction:.3f} -> {adjusted:.3f} "
                    f"(conf: {confidence:.3f})")
        
        return adjusted
    
    def classify(self, prediction: float, source: str, confidence: float) -> Dict[str, Any]:
        """Classify based on dynamic threshold"""
        threshold = self.get_threshold(source, confidence)
        is_zero_day = prediction >= threshold
        
        # Calculate classification confidence
        distance_from_threshold = abs(prediction - threshold)
        classification_confidence = min(distance_from_threshold * 2, 1.0) * confidence
        
        return {
            'is_zero_day': is_zero_day,
            'threshold_used': threshold,
            'classification_confidence': classification_confidence,
            'margin': prediction - threshold
        }