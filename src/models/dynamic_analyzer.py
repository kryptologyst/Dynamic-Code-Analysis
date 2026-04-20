"""
Dynamic Code Analysis Module

This module provides comprehensive dynamic analysis capabilities for Python code,
including execution monitoring, security pattern detection, and vulnerability assessment.
"""

import time
import traceback
import psutil
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import logging
import json
import numpy as np
import pandas as pd
from pathlib import Path
import warnings

# Set up deterministic seeding
np.random.seed(42)
import random
random.seed(42)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dynamic_analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Security risk levels for detected patterns."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisType(Enum):
    """Types of dynamic analysis performed."""
    PERFORMANCE = "performance"
    SECURITY = "security"
    MEMORY = "memory"
    EXCEPTION = "exception"
    API_CALL = "api_call"


@dataclass
class ExecutionMetrics:
    """Metrics collected during function execution."""
    function_name: str
    execution_time: float
    memory_usage: float
    cpu_usage: float
    exception_occurred: bool
    exception_type: Optional[str] = None
    exception_message: Optional[str] = None
    security_issues: List[Dict[str, Any]] = field(default_factory=list)
    api_calls: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class SecurityPattern:
    """Represents a detected security pattern."""
    pattern_type: str
    severity: SecurityLevel
    description: str
    line_number: Optional[int] = None
    evidence: Optional[str] = None


class DynamicAnalyzer:
    """
    Advanced dynamic code analyzer with security and performance monitoring.
    
    This class provides comprehensive runtime analysis including:
    - Execution time and resource monitoring
    - Security pattern detection
    - Memory leak detection
    - API call tracking
    - Exception analysis
    """
    
    def __init__(self, 
                 enable_memory_monitoring: bool = True,
                 enable_security_scanning: bool = True,
                 enable_api_tracking: bool = True,
                 memory_threshold_mb: float = 100.0,
                 execution_timeout: float = 30.0):
        """
        Initialize the dynamic analyzer.
        
        Args:
            enable_memory_monitoring: Enable memory usage tracking
            enable_security_scanning: Enable security pattern detection
            enable_api_tracking: Enable API call monitoring
            memory_threshold_mb: Memory usage threshold in MB
            execution_timeout: Maximum execution time in seconds
        """
        self.enable_memory_monitoring = enable_memory_monitoring
        self.enable_security_scanning = enable_security_scanning
        self.enable_api_tracking = enable_api_tracking
        self.memory_threshold_mb = memory_threshold_mb
        self.execution_timeout = execution_timeout
        
        self.execution_history: List[ExecutionMetrics] = []
        self.security_patterns: List[SecurityPattern] = []
        
        # Security patterns to detect
        self.dangerous_functions = {
            'eval', 'exec', 'compile', '__import__', 'open', 'file',
            'input', 'raw_input', 'os.system', 'subprocess.call',
            'pickle.loads', 'marshal.loads', 'shelve.open'
        }
        
        self.suspicious_patterns = {
            'password': SecurityLevel.HIGH,
            'secret': SecurityLevel.HIGH,
            'token': SecurityLevel.MEDIUM,
            'key': SecurityLevel.MEDIUM,
            'admin': SecurityLevel.MEDIUM,
            'root': SecurityLevel.HIGH,
            'sudo': SecurityLevel.HIGH
        }
    
    def analyze_function(self, func: Callable) -> Callable:
        """
        Decorator to analyze function execution with comprehensive monitoring.
        
        Args:
            func: Function to analyze
            
        Returns:
            Wrapped function with analysis capabilities
        """
        def wrapper(*args, **kwargs) -> Any:
            process = psutil.Process()
            start_memory = process.memory_info().rss / 1024 / 1024  # MB
            start_cpu = process.cpu_percent()
            start_time = time.time()
            
            exception_occurred = False
            exception_type = None
            exception_message = None
            security_issues = []
            api_calls = []
            
            logger.info(f"[ANALYZING] Function: {func.__name__}")
            
            try:
                # Monitor execution with timeout
                result = self._execute_with_timeout(func, args, kwargs)
                
                # Check for security patterns in function name and arguments
                if self.enable_security_scanning:
                    security_issues = self._detect_security_patterns(
                        func.__name__, str(args), str(kwargs)
                    )
                
                # Track API calls if enabled
                if self.enable_api_tracking:
                    api_calls = self._track_api_calls(func, args, kwargs)
                
            except Exception as e:
                exception_occurred = True
                exception_type = type(e).__name__
                exception_message = str(e)
                logger.error(f"[ERROR] Exception in {func.__name__}: {exception_type} - {exception_message}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                raise
            
            finally:
                # Collect final metrics
                end_time = time.time()
                end_memory = process.memory_info().rss / 1024 / 1024  # MB
                end_cpu = process.cpu_percent()
                
                execution_time = end_time - start_time
                memory_usage = end_memory - start_memory
                
                # Create metrics object
                metrics = ExecutionMetrics(
                    function_name=func.__name__,
                    execution_time=execution_time,
                    memory_usage=memory_usage,
                    cpu_usage=end_cpu - start_cpu,
                    exception_occurred=exception_occurred,
                    exception_type=exception_type,
                    exception_message=exception_message,
                    security_issues=security_issues,
                    api_calls=api_calls
                )
                
                self.execution_history.append(metrics)
                
                # Log results
                self._log_execution_results(metrics)
                
                # Check for memory leaks
                if self.enable_memory_monitoring and memory_usage > self.memory_threshold_mb:
                    logger.warning(f"[MEMORY LEAK] {func.__name__} used {memory_usage:.2f}MB")
            
            return result
        
        return wrapper
    
    def _execute_with_timeout(self, func: Callable, args: tuple, kwargs: dict) -> Any:
        """Execute function with timeout protection."""
        result = [None]
        exception = [None]
        
        def target():
            try:
                result[0] = func(*args, **kwargs)
            except Exception as e:
                exception[0] = e
        
        thread = threading.Thread(target=target)
        thread.daemon = True
        thread.start()
        thread.join(timeout=self.execution_timeout)
        
        if thread.is_alive():
            raise TimeoutError(f"Function {func.__name__} exceeded timeout of {self.execution_timeout}s")
        
        if exception[0]:
            raise exception[0]
        
        return result[0]
    
    def _detect_security_patterns(self, func_name: str, args_str: str, kwargs_str: str) -> List[Dict[str, Any]]:
        """Detect potential security issues in function execution."""
        issues = []
        text_to_scan = f"{func_name} {args_str} {kwargs_str}".lower()
        
        # Check for dangerous function calls
        for dangerous_func in self.dangerous_functions:
            if dangerous_func in text_to_scan:
                issues.append({
                    'type': 'dangerous_function',
                    'function': dangerous_func,
                    'severity': SecurityLevel.HIGH.value,
                    'description': f"Dangerous function '{dangerous_func}' detected"
                })
        
        # Check for suspicious patterns
        for pattern, severity in self.suspicious_patterns.items():
            if pattern in text_to_scan:
                issues.append({
                    'type': 'suspicious_pattern',
                    'pattern': pattern,
                    'severity': severity.value,
                    'description': f"Suspicious pattern '{pattern}' detected"
                })
        
        return issues
    
    def _track_api_calls(self, func: Callable, args: tuple, kwargs: dict) -> List[str]:
        """Track API calls made during function execution."""
        # This is a simplified implementation
        # In a real scenario, you'd use more sophisticated tracing
        api_calls = []
        
        # Check for common API patterns
        func_name = func.__name__.lower()
        if any(keyword in func_name for keyword in ['http', 'request', 'api', 'url', 'fetch']):
            api_calls.append(f"potential_api_call:{func_name}")
        
        return api_calls
    
    def _log_execution_results(self, metrics: ExecutionMetrics) -> None:
        """Log execution results with appropriate detail level."""
        status = "ERROR" if metrics.exception_occurred else "OK"
        logger.info(f"[{status}] {metrics.function_name} - "
                   f"Time: {metrics.execution_time:.4f}s, "
                   f"Memory: {metrics.memory_usage:.2f}MB")
        
        if metrics.security_issues:
            for issue in metrics.security_issues:
                logger.warning(f"[SECURITY] {issue['description']} (Severity: {issue['severity']})")
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of all executions."""
        if not self.execution_history:
            return {"message": "No executions recorded"}
        
        df = pd.DataFrame([
            {
                'function': m.function_name,
                'execution_time': m.execution_time,
                'memory_usage': m.memory_usage,
                'cpu_usage': m.cpu_usage,
                'exception_occurred': m.exception_occurred,
                'security_issues_count': len(m.security_issues),
                'api_calls_count': len(m.api_calls)
            }
            for m in self.execution_history
        ])
        
        summary = {
            'total_executions': len(self.execution_history),
            'total_functions': df['function'].nunique(),
            'average_execution_time': df['execution_time'].mean(),
            'total_memory_usage': df['memory_usage'].sum(),
            'exception_rate': df['exception_occurred'].mean(),
            'security_issues_total': df['security_issues_count'].sum(),
            'functions_with_issues': df[df['security_issues_count'] > 0]['function'].unique().tolist(),
            'performance_stats': {
                'min_execution_time': df['execution_time'].min(),
                'max_execution_time': df['execution_time'].max(),
                'std_execution_time': df['execution_time'].std()
            }
        }
        
        return summary
    
    def export_results(self, filepath: Union[str, Path]) -> None:
        """Export analysis results to JSON file."""
        def convert_numpy(obj):
            """Convert numpy types to Python native types for JSON serialization."""
            if isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {key: convert_numpy(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [convert_numpy(item) for item in obj]
            else:
                return obj
        
        results = {
            'execution_history': [
                {
                    'function_name': m.function_name,
                    'execution_time': float(m.execution_time),
                    'memory_usage': float(m.memory_usage),
                    'cpu_usage': float(m.cpu_usage),
                    'exception_occurred': bool(m.exception_occurred),
                    'exception_type': m.exception_type,
                    'exception_message': m.exception_message,
                    'security_issues': m.security_issues,
                    'api_calls': m.api_calls,
                    'timestamp': float(m.timestamp)
                }
                for m in self.execution_history
            ],
            'summary': convert_numpy(self.get_execution_summary())
        }
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Results exported to {filepath}")


# Convenience function for easy usage
def analyze(func: Callable) -> Callable:
    """
    Convenience decorator for dynamic analysis.
    
    Args:
        func: Function to analyze
        
    Returns:
        Analyzed function
    """
    analyzer = DynamicAnalyzer()
    return analyzer.analyze_function(func)


# Example usage and testing functions
if __name__ == "__main__":
    # Create analyzer instance
    analyzer = DynamicAnalyzer()
    
    # Example functions for testing
    @analyzer.analyze_function
    def safe_function(x: int) -> int:
        """A safe function that performs simple arithmetic."""
        time.sleep(0.1)
        return x * 2
    
    @analyzer.analyze_function
    def risky_function(y: int) -> float:
        """A risky function that may cause exceptions."""
        time.sleep(0.05)
        if y == 0:
            raise ValueError("Division by zero not allowed")
        return 10 / y
    
    @analyzer.analyze_function
    def memory_intensive_function(size: int) -> List[int]:
        """A function that uses significant memory."""
        time.sleep(0.1)
        return list(range(size))
    
    @analyzer.analyze_function
    def suspicious_function(password: str) -> str:
        """A function with suspicious patterns."""
        time.sleep(0.1)
        return f"Processing password: {password[:3]}***"
    
    # Run test cases
    print("Running dynamic analysis tests...")
    
    try:
        safe_function(10)
        risky_function(5)
        risky_function(0)  # This will cause an exception
    except ValueError as e:
        print(f"Caught expected exception: {e}")
    
    memory_intensive_function(10000)
    suspicious_function("secret123")
    
    # Display results
    print("\n" + "="*50)
    print("EXECUTION SUMMARY")
    print("="*50)
    summary = analyzer.get_execution_summary()
    for key, value in summary.items():
        print(f"{key}: {value}")
    
    # Export results
    analyzer.export_results("analysis_results.json")
    print("\nAnalysis complete! Results saved to analysis_results.json")
