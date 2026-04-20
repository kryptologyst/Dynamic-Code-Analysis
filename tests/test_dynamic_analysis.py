"""
Test suite for Dynamic Code Analysis

This module contains comprehensive tests for the dynamic analysis system.
"""

import pytest
import sys
from pathlib import Path
import tempfile
import json
import pandas as pd

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent / "src"))

from models.dynamic_analyzer import DynamicAnalyzer, ExecutionMetrics
from eval.evaluator import DynamicAnalysisEvaluator
from data.pipeline import DataPipeline, SyntheticDataGenerator
from defenses.explainability import ExplainabilityEngine, RuleBasedExplainer


class TestDynamicAnalyzer:
    """Test cases for DynamicAnalyzer."""
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = DynamicAnalyzer()
        assert analyzer.enable_memory_monitoring is True
        assert analyzer.enable_security_scanning is True
        assert analyzer.memory_threshold_mb == 100.0
    
    def test_function_analysis(self):
        """Test basic function analysis."""
        analyzer = DynamicAnalyzer()
        
        @analyzer.analyze_function
        def test_function(x):
            return x * 2
        
        result = test_function(5)
        assert result == 10
        assert len(analyzer.execution_history) == 1
        
        execution = analyzer.execution_history[0]
        assert execution.function_name == "test_function"
        assert execution.execution_time > 0
        assert execution.exception_occurred is False
    
    def test_exception_handling(self):
        """Test exception handling in analysis."""
        analyzer = DynamicAnalyzer()
        
        @analyzer.analyze_function
        def error_function():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            error_function()
        
        assert len(analyzer.execution_history) == 1
        execution = analyzer.execution_history[0]
        assert execution.exception_occurred is True
        assert execution.exception_type == "ValueError"
    
    def test_security_pattern_detection(self):
        """Test security pattern detection."""
        analyzer = DynamicAnalyzer()
        
        @analyzer.analyze_function
        def suspicious_function(password):
            return f"Processing password: {password}"
        
        suspicious_function("secret123")
        
        execution = analyzer.execution_history[0]
        assert len(execution.security_issues) > 0
        assert any(issue['type'] == 'suspicious_pattern' for issue in execution.security_issues)
    
    def test_export_results(self):
        """Test results export functionality."""
        analyzer = DynamicAnalyzer()
        
        @analyzer.analyze_function
        def test_function(x):
            return x * 2
        
        test_function(5)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            analyzer.export_results(temp_path)
            
            with open(temp_path, 'r') as f:
                results = json.load(f)
            
            assert 'execution_history' in results
            assert 'summary' in results
            assert len(results['execution_history']) == 1
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestEvaluator:
    """Test cases for DynamicAnalysisEvaluator."""
    
    def test_evaluator_initialization(self):
        """Test evaluator initialization."""
        evaluator = DynamicAnalysisEvaluator()
        assert evaluator.results_data is None
        assert evaluator.metrics_df is None
    
    def test_results_loading(self):
        """Test results loading functionality."""
        evaluator = DynamicAnalysisEvaluator()
        
        # Create test results
        test_results = {
            'execution_history': [
                {
                    'function_name': 'test_func',
                    'execution_time': 0.1,
                    'memory_usage': 10.0,
                    'cpu_usage': 20.0,
                    'exception_occurred': False,
                    'security_issues': [],
                    'api_calls': [],
                    'timestamp': 1234567890
                }
            ]
        }
        
        evaluator.results_data = test_results
        df = evaluator.prepare_dataframe()
        
        assert len(df) == 1
        assert df.iloc[0]['function_name'] == 'test_func'
        assert df.iloc[0]['execution_time'] == 0.1
    
    def test_performance_metrics(self):
        """Test performance metrics calculation."""
        evaluator = DynamicAnalysisEvaluator()
        
        test_results = {
            'execution_history': [
                {
                    'function_name': 'test_func',
                    'execution_time': 0.1,
                    'memory_usage': 10.0,
                    'cpu_usage': 20.0,
                    'exception_occurred': False,
                    'security_issues': [],
                    'api_calls': [],
                    'timestamp': 1234567890
                }
            ]
        }
        
        evaluator.results_data = test_results
        evaluator.prepare_dataframe()
        metrics = evaluator.calculate_performance_metrics()
        
        assert 'avg_execution_time' in metrics
        assert 'avg_memory_usage' in metrics
        assert metrics['avg_execution_time'] == 0.1


class TestDataPipeline:
    """Test cases for DataPipeline."""
    
    def test_pipeline_initialization(self):
        """Test pipeline initialization."""
        pipeline = DataPipeline()
        assert pipeline.synthetic_generator is not None
        assert pipeline.real_processor is not None
    
    def test_synthetic_data_generation(self):
        """Test synthetic data generation."""
        generator = SyntheticDataGenerator(num_functions=10)
        functions = generator.generate_functions()
        
        assert len(functions) == 10
        assert all(hasattr(func, 'name') for func in functions)
        assert all(hasattr(func, 'code') for func in functions)
        assert all(hasattr(func, 'risk_level') for func in functions)
    
    def test_execution_dataset_creation(self):
        """Test execution dataset creation."""
        pipeline = DataPipeline()
        pipeline.generate_synthetic_data()
        
        dataset = pipeline.create_execution_dataset(num_executions=50)
        
        assert len(dataset) == 50
        assert 'function_name' in dataset.columns
        assert 'execution_time' in dataset.columns
        assert 'memory_usage' in dataset.columns
        assert 'exception_occurred' in dataset.columns


class TestExplainability:
    """Test cases for ExplainabilityEngine."""
    
    def test_rule_explainer_initialization(self):
        """Test rule explainer initialization."""
        explainer = RuleBasedExplainer()
        assert len(explainer.rules) > 0
        assert all(hasattr(rule, 'rule_id') for rule in explainer.rules)
    
    def test_rule_evaluation(self):
        """Test rule evaluation."""
        explainer = RuleBasedExplainer()
        
        execution_data = {
            'execution_time': 2.0,
            'memory_usage': 150.0,
            'exception_occurred': True,
            'security_issues_count': 1
        }
        
        explanations = explainer.explain_execution(execution_data)
        assert len(explanations) > 0
        
        # Should detect high execution time and exception
        rule_ids = [exp.rule_id for exp in explanations]
        assert 'execution_time_high' in rule_ids or 'exception_occurred' in rule_ids
    
    def test_explainability_engine(self):
        """Test main explainability engine."""
        engine = ExplainabilityEngine()
        
        execution_data = {
            'function_name': 'test_func',
            'execution_time': 1.5,
            'memory_usage': 120.0,
            'cpu_usage': 80.0,
            'exception_occurred': False,
            'security_issues_count': 0,
            'complexity': 15
        }
        
        explanations = engine.explain_execution(execution_data)
        assert 'rule_based' in explanations
        assert 'summary' in explanations['rule_based']


class TestIntegration:
    """Integration tests."""
    
    def test_end_to_end_analysis(self):
        """Test complete end-to-end analysis workflow."""
        # Initialize components
        analyzer = DynamicAnalyzer()
        evaluator = DynamicAnalysisEvaluator()
        explainer = ExplainabilityEngine()
        
        # Run analysis
        @analyzer.analyze_function
        def test_function(x):
            if x == 0:
                raise ValueError("Division by zero")
            return 10 / x
        
        # Test normal execution
        result = test_function(5)
        assert result == 2.0
        
        # Test exception
        with pytest.raises(ValueError):
            test_function(0)
        
        # Verify analysis results
        assert len(analyzer.execution_history) == 2
        
        # Test evaluation
        results_data = {
            'execution_history': [
                {
                    'function_name': exec.function_name,
                    'execution_time': exec.execution_time,
                    'memory_usage': exec.memory_usage,
                    'cpu_usage': exec.cpu_usage,
                    'exception_occurred': exec.exception_occurred,
                    'exception_type': exec.exception_type,
                    'exception_message': exec.exception_message,
                    'security_issues': exec.security_issues,
                    'api_calls': exec.api_calls,
                    'timestamp': exec.timestamp
                }
                for exec in analyzer.execution_history
            ]
        }
        
        evaluator.results_data = results_data
        evaluator.prepare_dataframe()
        
        performance_metrics = evaluator.calculate_performance_metrics()
        security_assessment = evaluator.calculate_security_metrics()
        
        assert 'avg_execution_time' in performance_metrics
        assert 'total_vulnerabilities' in security_assessment.__dict__
        
        # Test explainability
        for execution in analyzer.execution_history:
            explanation = explainer.explain_execution({
                'function_name': execution.function_name,
                'execution_time': execution.execution_time,
                'memory_usage': execution.memory_usage,
                'cpu_usage': execution.cpu_usage,
                'exception_occurred': execution.exception_occurred,
                'security_issues_count': len(execution.security_issues),
                'complexity': 10
            })
            assert 'rule_based' in explanation


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
