"""
Advanced logging system for Zero-Day Detection
"""
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import json
from logging.handlers import RotatingFileHandler

from config.settings import LOGS_DIR, DEBUG_MODE, VERBOSE_LOGGING


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)


class APICallLogger:
    """Logger specifically for API calls with detailed debugging"""
    
    def __init__(self, logger_name: str = "api_calls"):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)
        
        # Create logs directory if it doesn't exist
        LOGS_DIR.mkdir(exist_ok=True)
        
        # File handler for API calls
        api_log_file = LOGS_DIR / f"api_calls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = RotatingFileHandler(
            api_log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        
        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO if not VERBOSE_LOGGING else logging.DEBUG)
        console_formatter = ColoredFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def log_api_request(self, model: str, prompt: str, cve_id: str, agent: str):
        """Log API request details"""
        self.logger.info(f"API Request - Agent: {agent}, Model: {model}, CVE: {cve_id}")
        if DEBUG_MODE:
            self.logger.debug(f"Prompt preview: {prompt[:200]}...")
    
    def log_api_response(self, model: str, response: Dict[str, Any], 
                        tokens: Dict[str, int], duration: float):
        """Log API response details"""
        self.logger.info(
            f"API Response - Model: {model}, "
            f"Tokens: {tokens.get('total_tokens', 'N/A')}, "
            f"Duration: {duration:.2f}s"
        )
        if DEBUG_MODE:
            self.logger.debug(f"Response: {json.dumps(response, indent=2)}")
            self.logger.debug(f"Token usage: {json.dumps(tokens, indent=2)}")
    
    def log_api_error(self, model: str, error: Exception, attempt: int):
        """Log API errors"""
        self.logger.error(
            f"API Error - Model: {model}, Attempt: {attempt}, "
            f"Error: {type(error).__name__}: {str(error)}"
        )


class ExperimentLogger:
    """Logger for experiment tracking and results"""
    
    def __init__(self, experiment_name: str):
        self.experiment_name = experiment_name
        self.logger = logging.getLogger(f"experiment.{experiment_name}")
        self.logger.setLevel(logging.DEBUG)
        
        # Create experiment log file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = LOGS_DIR / f"experiment_{experiment_name}_{timestamp}.log"
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Also log to console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(ColoredFormatter(
            '%(levelname)s - %(message)s'
        ))
        self.logger.addHandler(console_handler)
        
        # Results tracking
        self.results = {
            'experiment_name': experiment_name,
            'start_time': datetime.now().isoformat(),
            'parameters': {},
            'metrics': {},
            'predictions': []
        }
    
    def log_parameters(self, params: Dict[str, Any]):
        """Log experiment parameters"""
        self.results['parameters'] = params
        self.logger.info(f"Experiment parameters: {json.dumps(params, indent=2)}")
    
    def log_prediction(self, cve_id: str, true_label: int, prediction: float, 
                      agent_predictions: Dict[str, float], confidence: float):
        """Log individual prediction"""
        pred_data = {
            'cve_id': cve_id,
            'true_label': true_label,
            'prediction': prediction,
            'binary_prediction': int(prediction > 0.5),
            'confidence': confidence,
            'agent_predictions': agent_predictions,
            'timestamp': datetime.now().isoformat()
        }
        self.results['predictions'].append(pred_data)
        
        if DEBUG_MODE:
            self.logger.debug(f"Prediction: {json.dumps(pred_data, indent=2)}")
    
    def log_metrics(self, metrics: Dict[str, float]):
        """Log evaluation metrics"""
        self.results['metrics'] = metrics
        self.logger.info("Evaluation Metrics:")
        for metric, value in metrics.items():
            self.logger.info(f"  {metric}: {value:.4f}")
    
    def save_results(self):
        """Save all results to file"""
        self.results['end_time'] = datetime.now().isoformat()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_file = LOGS_DIR / f"results_{self.experiment_name}_{timestamp}.json"
        
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.logger.info(f"Results saved to: {results_file}")
        return results_file


# Global logger instances
api_logger = APICallLogger()
experiment_logger = None


def setup_experiment_logger(experiment_name: str) -> ExperimentLogger:
    """Setup experiment logger"""
    global experiment_logger
    experiment_logger = ExperimentLogger(experiment_name)
    return experiment_logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance"""
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        logger.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = ColoredFormatter(
            '%(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    return logger