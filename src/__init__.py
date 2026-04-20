"""
Dynamic Code Analysis Package

A comprehensive dynamic code analysis framework for security assessment and code quality evaluation.
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"
__email__ = "research@example.com"

from .models.dynamic_analyzer import DynamicAnalyzer, analyze
from .eval.evaluator import DynamicAnalysisEvaluator
from .data.pipeline import DataPipeline
from .defenses.explainability import ExplainabilityEngine

__all__ = [
    "DynamicAnalyzer",
    "analyze", 
    "DynamicAnalysisEvaluator",
    "DataPipeline",
    "ExplainabilityEngine"
]
