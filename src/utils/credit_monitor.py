"""
Monitor API credits and track exhausted models
"""
import time
from typing import Set, Dict, Any
from datetime import datetime, timedelta


class CreditMonitor:
    """Track models with exhausted credits"""
    
    def __init__(self):
        self.exhausted_models: Dict[str, datetime] = {}
        self.retry_after = timedelta(hours=1)  # Retry after 1 hour
        
    def mark_exhausted(self, model_id: str):
        """Mark a model as having exhausted credits"""
        self.exhausted_models[model_id] = datetime.now()
        
    def is_available(self, model_id: str) -> bool:
        """Check if a model is available (not exhausted or retry time passed)"""
        if model_id not in self.exhausted_models:
            return True
            
        exhausted_time = self.exhausted_models[model_id]
        if datetime.now() - exhausted_time > self.retry_after:
            # Retry time has passed, remove from exhausted list
            del self.exhausted_models[model_id]
            return True
            
        return False
    
    def get_exhausted_models(self) -> Set[str]:
        """Get set of currently exhausted models"""
        # Clean up old entries
        current_time = datetime.now()
        to_remove = []
        
        for model_id, exhausted_time in self.exhausted_models.items():
            if current_time - exhausted_time > self.retry_after:
                to_remove.append(model_id)
                
        for model_id in to_remove:
            del self.exhausted_models[model_id]
            
        return set(self.exhausted_models.keys())


# Global credit monitor instance
credit_monitor = CreditMonitor()