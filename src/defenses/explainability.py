"""
Explainability Module for Dynamic Code Analysis

This module provides explainability features including SHAP analysis, rule-based evidence,
and execution trace analysis to help understand dynamic analysis results.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import json
import logging

# Optional SHAP import (will be handled gracefully if not available)
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    logging.warning("SHAP not available. Install with: pip install shap")

logger = logging.getLogger(__name__)


@dataclass
class ExplanationRule:
    """Represents an explanation rule."""
    rule_id: str
    condition: str
    description: str
    severity: str
    confidence: float
    evidence: List[str]


@dataclass
class ExecutionTrace:
    """Represents an execution trace."""
    function_name: str
    execution_time: float
    memory_usage: float
    cpu_usage: float
    exception_occurred: bool
    security_issues: List[Dict[str, Any]]
    trace_points: List[Dict[str, Any]]


class RuleBasedExplainer:
    """Rule-based explainer for dynamic analysis results."""
    
    def __init__(self):
        """Initialize the rule-based explainer."""
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self) -> List[ExplanationRule]:
        """Initialize explanation rules."""
        rules = [
            ExplanationRule(
                rule_id="execution_time_high",
                condition="execution_time > 1.0",
                description="Function execution time exceeds 1 second",
                severity="medium",
                confidence=0.8,
                evidence=["High execution time may indicate performance issues"]
            ),
            ExplanationRule(
                rule_id="memory_usage_high",
                condition="memory_usage > 100",
                description="Function uses more than 100MB of memory",
                severity="high",
                confidence=0.9,
                evidence=["High memory usage may indicate memory leaks or inefficient algorithms"]
            ),
            ExplanationRule(
                rule_id="exception_occurred",
                condition="exception_occurred == True",
                description="Function raised an exception during execution",
                severity="critical",
                confidence=1.0,
                evidence=["Exception indicates potential runtime errors"]
            ),
            ExplanationRule(
                rule_id="security_issues_present",
                condition="security_issues_count > 0",
                description="Function contains security-related patterns",
                severity="high",
                confidence=0.85,
                evidence=["Security patterns detected in function execution"]
            ),
            ExplanationRule(
                rule_id="cpu_usage_high",
                condition="cpu_usage > 80",
                description="Function uses more than 80% CPU",
                severity="medium",
                confidence=0.7,
                evidence=["High CPU usage may indicate computational bottlenecks"]
            ),
            ExplanationRule(
                rule_id="complexity_high",
                condition="complexity > 20",
                description="Function has high cyclomatic complexity",
                severity="medium",
                confidence=0.75,
                evidence=["High complexity makes code harder to maintain and debug"]
            )
        ]
        return rules
    
    def explain_execution(self, execution_data: Dict[str, Any]) -> List[ExplanationRule]:
        """Generate explanations for a single execution."""
        explanations = []
        
        for rule in self.rules:
            if self._evaluate_rule(rule, execution_data):
                explanations.append(rule)
        
        return explanations
    
    def _evaluate_rule(self, rule: ExplanationRule, data: Dict[str, Any]) -> bool:
        """Evaluate if a rule applies to the given data."""
        try:
            # Simple rule evaluation using eval (in production, use a proper rule engine)
            # This is safe because we control the rule conditions
            return eval(rule.condition, {"__builtins__": {}}, data)
        except Exception as e:
            logger.warning(f"Error evaluating rule {rule.rule_id}: {e}")
            return False
    
    def generate_explanation_summary(self, explanations: List[ExplanationRule]) -> Dict[str, Any]:
        """Generate a summary of explanations."""
        if not explanations:
            return {"message": "No issues detected"}
        
        summary = {
            "total_issues": len(explanations),
            "critical_issues": len([e for e in explanations if e.severity == "critical"]),
            "high_issues": len([e for e in explanations if e.severity == "high"]),
            "medium_issues": len([e for e in explanations if e.severity == "medium"]),
            "low_issues": len([e for e in explanations if e.severity == "low"]),
            "average_confidence": np.mean([e.confidence for e in explanations]),
            "issues_by_type": {}
        }
        
        # Group issues by type
        for explanation in explanations:
            issue_type = explanation.description.split()[0].lower()
            if issue_type not in summary["issues_by_type"]:
                summary["issues_by_type"][issue_type] = 0
            summary["issues_by_type"][issue_type] += 1
        
        return summary


class SHAPExplainer:
    """SHAP-based explainer for dynamic analysis results."""
    
    def __init__(self):
        """Initialize the SHAP explainer."""
        self.explainer = None
        self.model = None
        self.feature_names = None
    
    def prepare_model(self, X: pd.DataFrame, y: pd.Series) -> None:
        """Prepare a simple model for SHAP explanation."""
        if not SHAP_AVAILABLE:
            logger.warning("SHAP not available. Skipping SHAP analysis.")
            return
        
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        
        # Prepare features
        self.feature_names = list(X.columns)
        
        # Train a simple model
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Create SHAP explainer
        self.explainer = shap.TreeExplainer(self.model)
        
        logger.info("SHAP model prepared successfully")
    
    def explain_prediction(self, X: pd.DataFrame) -> Optional[Dict[str, Any]]:
        """Explain predictions using SHAP values."""
        if not SHAP_AVAILABLE or self.explainer is None:
            return None
        
        try:
            # Calculate SHAP values
            shap_values = self.explainer.shap_values(X)
            
            # Get feature importance
            feature_importance = np.abs(shap_values).mean(axis=0)
            
            # Create explanation
            explanation = {
                "shap_values": shap_values.tolist(),
                "feature_importance": dict(zip(self.feature_names, feature_importance)),
                "top_features": sorted(
                    zip(self.feature_names, feature_importance),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]
            }
            
            return explanation
        
        except Exception as e:
            logger.error(f"Error in SHAP explanation: {e}")
            return None
    
    def create_shap_plots(self, X: pd.DataFrame, output_dir: str = "assets") -> None:
        """Create SHAP visualization plots."""
        if not SHAP_AVAILABLE or self.explainer is None:
            logger.warning("SHAP not available. Skipping SHAP plots.")
            return
        
        try:
            output_path = Path(output_dir)
            output_path.mkdir(exist_ok=True)
            
            # Calculate SHAP values
            shap_values = self.explainer.shap_values(X)
            
            # Summary plot
            plt.figure(figsize=(10, 8))
            shap.summary_plot(shap_values, X, show=False)
            plt.title("SHAP Summary Plot")
            plt.tight_layout()
            plt.savefig(output_path / "shap_summary.png", dpi=300, bbox_inches='tight')
            plt.close()
            
            # Waterfall plot for first prediction
            if len(X) > 0:
                plt.figure(figsize=(10, 6))
                shap.waterfall_plot(
                    self.explainer.expected_value,
                    shap_values[0],
                    X.iloc[0],
                    show=False
                )
                plt.title("SHAP Waterfall Plot - First Prediction")
                plt.tight_layout()
                plt.savefig(output_path / "shap_waterfall.png", dpi=300, bbox_inches='tight')
                plt.close()
            
            logger.info(f"SHAP plots saved to {output_path}")
        
        except Exception as e:
            logger.error(f"Error creating SHAP plots: {e}")


class ExecutionTraceAnalyzer:
    """Analyzer for execution traces."""
    
    def __init__(self):
        """Initialize the execution trace analyzer."""
        self.traces: List[ExecutionTrace] = []
    
    def add_trace(self, trace: ExecutionTrace) -> None:
        """Add an execution trace."""
        self.traces.append(trace)
    
    def analyze_trace_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in execution traces."""
        if not self.traces:
            return {"message": "No traces available"}
        
        # Convert traces to DataFrame for analysis
        trace_data = []
        for trace in self.traces:
            trace_data.append({
                'function_name': trace.function_name,
                'execution_time': trace.execution_time,
                'memory_usage': trace.memory_usage,
                'cpu_usage': trace.cpu_usage,
                'exception_occurred': trace.exception_occurred,
                'security_issues_count': len(trace.security_issues)
            })
        
        df = pd.DataFrame(trace_data)
        
        # Analyze patterns
        patterns = {
            "total_traces": len(self.traces),
            "unique_functions": df['function_name'].nunique(),
            "exception_rate": df['exception_occurred'].mean(),
            "avg_execution_time": df['execution_time'].mean(),
            "avg_memory_usage": df['memory_usage'].mean(),
            "avg_cpu_usage": df['cpu_usage'].mean(),
            "security_issues_rate": (df['security_issues_count'] > 0).mean(),
            "performance_correlation": df[['execution_time', 'memory_usage', 'cpu_usage']].corr().to_dict(),
            "function_performance": df.groupby('function_name').agg({
                'execution_time': ['mean', 'std', 'max'],
                'memory_usage': ['mean', 'std', 'max'],
                'exception_occurred': 'mean'
            }).to_dict()
        }
        
        return patterns
    
    def identify_anomalies(self, threshold: float = 2.0) -> List[Dict[str, Any]]:
        """Identify anomalous execution traces."""
        if not self.traces:
            return []
        
        anomalies = []
        
        # Convert to DataFrame
        trace_data = []
        for trace in self.traces:
            trace_data.append({
                'function_name': trace.function_name,
                'execution_time': trace.execution_time,
                'memory_usage': trace.memory_usage,
                'cpu_usage': trace.cpu_usage,
                'exception_occurred': trace.exception_occurred,
                'security_issues_count': len(trace.security_issues)
            })
        
        df = pd.DataFrame(trace_data)
        
        # Identify outliers using Z-score
        numeric_columns = ['execution_time', 'memory_usage', 'cpu_usage']
        
        for col in numeric_columns:
            z_scores = np.abs((df[col] - df[col].mean()) / df[col].std())
            outliers = df[z_scores > threshold]
            
            for _, row in outliers.iterrows():
                anomalies.append({
                    'type': f'{col}_outlier',
                    'function_name': row['function_name'],
                    'value': row[col],
                    'z_score': z_scores[row.name],
                    'description': f'{col} is {z_scores[row.name]:.2f} standard deviations from mean'
                })
        
        return anomalies
    
    def generate_trace_report(self) -> Dict[str, Any]:
        """Generate a comprehensive trace report."""
        patterns = self.analyze_trace_patterns()
        anomalies = self.identify_anomalies()
        
        report = {
            "trace_patterns": patterns,
            "anomalies": anomalies,
            "summary": {
                "total_traces": len(self.traces),
                "anomaly_count": len(anomalies),
                "anomaly_rate": len(anomalies) / len(self.traces) if self.traces else 0
            }
        }
        
        return report


class ExplainabilityEngine:
    """Main explainability engine that combines all explanation methods."""
    
    def __init__(self):
        """Initialize the explainability engine."""
        self.rule_explainer = RuleBasedExplainer()
        self.shap_explainer = SHAPExplainer()
        self.trace_analyzer = ExecutionTraceAnalyzer()
    
    def explain_execution(self, execution_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive explanation for a single execution."""
        explanations = {}
        
        # Rule-based explanations
        rule_explanations = self.rule_explainer.explain_execution(execution_data)
        explanations["rule_based"] = {
            "explanations": [
                {
                    "rule_id": rule.rule_id,
                    "description": rule.description,
                    "severity": rule.severity,
                    "confidence": rule.confidence,
                    "evidence": rule.evidence
                }
                for rule in rule_explanations
            ],
            "summary": self.rule_explainer.generate_explanation_summary(rule_explanations)
        }
        
        # Add execution trace
        trace = ExecutionTrace(
            function_name=execution_data.get('function_name', 'unknown'),
            execution_time=execution_data.get('execution_time', 0),
            memory_usage=execution_data.get('memory_usage', 0),
            cpu_usage=execution_data.get('cpu_usage', 0),
            exception_occurred=execution_data.get('exception_occurred', False),
            security_issues=execution_data.get('security_issues', []),
            trace_points=[]
        )
        
        self.trace_analyzer.add_trace(trace)
        
        return explanations
    
    def explain_dataset(self, df: pd.DataFrame, target_column: str = 'is_risky') -> Dict[str, Any]:
        """Generate explanations for an entire dataset."""
        explanations = {}
        
        # Prepare features for SHAP
        feature_columns = [col for col in df.columns if col != target_column]
        X = df[feature_columns]
        y = df[target_column] if target_column in df.columns else pd.Series([0] * len(df))
        
        # SHAP explanations
        if SHAP_AVAILABLE:
            self.shap_explainer.prepare_model(X, y)
            shap_explanation = self.shap_explainer.explain_prediction(X)
            if shap_explanation:
                explanations["shap"] = shap_explanation
        
        # Trace analysis
        trace_report = self.trace_analyzer.generate_trace_report()
        explanations["trace_analysis"] = trace_report
        
        # Rule-based explanations for each execution
        rule_explanations = []
        for _, row in df.iterrows():
            execution_data = row.to_dict()
            rule_explanation = self.rule_explainer.explain_execution(execution_data)
            rule_explanations.extend(rule_explanation)
        
        explanations["rule_based_summary"] = self.rule_explainer.generate_explanation_summary(rule_explanations)
        
        return explanations
    
    def create_explanation_visualizations(self, explanations: Dict[str, Any], output_dir: str = "assets") -> None:
        """Create visualizations for explanations."""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Rule-based explanation visualization
        if "rule_based_summary" in explanations:
            summary = explanations["rule_based_summary"]
            
            if summary.get("total_issues", 0) > 0:
                # Issue severity distribution
                plt.figure(figsize=(10, 6))
                severities = ["critical", "high", "medium", "low"]
                counts = [
                    summary.get("critical_issues", 0),
                    summary.get("high_issues", 0),
                    summary.get("medium_issues", 0),
                    summary.get("low_issues", 0)
                ]
                
                colors = ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                plt.bar(severities, counts, color=colors)
                plt.title("Issue Distribution by Severity")
                plt.xlabel("Severity")
                plt.ylabel("Count")
                plt.tight_layout()
                plt.savefig(output_path / "issue_severity_distribution.png", dpi=300, bbox_inches='tight')
                plt.close()
        
        # SHAP visualizations
        if SHAP_AVAILABLE and "shap" in explanations:
            self.shap_explainer.create_shap_plots(
                pd.DataFrame(explanations["shap"]["shap_values"]),
                output_dir
            )
        
        logger.info(f"Explanation visualizations saved to {output_path}")
    
    def export_explanations(self, explanations: Dict[str, Any], filepath: str) -> None:
        """Export explanations to JSON file."""
        # Convert numpy arrays and other non-serializable types for JSON serialization
        def convert_for_json(obj):
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, tuple):
                return list(obj)  # Convert tuples to lists
            elif isinstance(obj, dict):
                return {str(key): convert_for_json(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [convert_for_json(item) for item in obj]
            elif hasattr(obj, '__dict__'):
                return convert_for_json(obj.__dict__)
            else:
                return obj
        
        explanations_serializable = convert_for_json(explanations)
        
        with open(filepath, 'w') as f:
            json.dump(explanations_serializable, f, indent=2)
        
        logger.info(f"Explanations exported to {filepath}")


# Example usage
if __name__ == "__main__":
    # Initialize explainability engine
    engine = ExplainabilityEngine()
    
    # Example execution data
    execution_data = {
        'function_name': 'risky_function',
        'execution_time': 2.5,
        'memory_usage': 150.0,
        'cpu_usage': 85.0,
        'exception_occurred': True,
        'security_issues_count': 2,
        'complexity': 25
    }
    
    # Generate explanations
    explanations = engine.explain_execution(execution_data)
    
    print("Explanations generated:")
    print(json.dumps(explanations, indent=2))
    
    # Example with dataset
    df = pd.DataFrame([
        {'execution_time': 0.1, 'memory_usage': 10, 'cpu_usage': 20, 'is_risky': 0},
        {'execution_time': 2.0, 'memory_usage': 200, 'cpu_usage': 90, 'is_risky': 1},
        {'execution_time': 0.5, 'memory_usage': 50, 'cpu_usage': 40, 'is_risky': 0}
    ])
    
    dataset_explanations = engine.explain_dataset(df)
    print("\nDataset explanations generated")
    
    # Export explanations
    engine.export_explanations(dataset_explanations, "explanations.json")
    print("Explanations exported to explanations.json")
