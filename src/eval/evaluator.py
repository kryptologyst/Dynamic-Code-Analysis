"""
Evaluation Module for Dynamic Code Analysis

This module provides comprehensive evaluation metrics and analysis capabilities
for dynamic code analysis results, including security assessment and performance metrics.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    precision_recall_curve, roc_curve, confusion_matrix
)
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class EvaluationMetrics:
    """Container for evaluation metrics."""
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    auc_pr: float
    false_positive_rate: float
    true_positive_rate: float
    accuracy: float
    specificity: float
    sensitivity: float


@dataclass
class SecurityAssessment:
    """Security assessment results."""
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    vulnerability_density: float
    security_score: float


class DynamicAnalysisEvaluator:
    """
    Evaluator for dynamic code analysis results.
    
    Provides comprehensive evaluation including:
    - Performance metrics (execution time, memory usage)
    - Security metrics (vulnerability detection, risk assessment)
    - Statistical analysis and benchmarking
    - Visualization capabilities
    """
    
    def __init__(self, results_data: Optional[Dict[str, Any]] = None):
        """
        Initialize the evaluator.
        
        Args:
            results_data: Analysis results data from DynamicAnalyzer
        """
        self.results_data = results_data
        self.metrics_df: Optional[pd.DataFrame] = None
        self.evaluation_results: Dict[str, Any] = {}
        
    def load_results(self, filepath: str) -> None:
        """Load analysis results from JSON file."""
        with open(filepath, 'r') as f:
            self.results_data = json.load(f)
        logger.info(f"Loaded results from {filepath}")
    
    def prepare_dataframe(self) -> pd.DataFrame:
        """Convert results to pandas DataFrame for analysis."""
        if not self.results_data:
            raise ValueError("No results data available. Load results first.")
        
        execution_history = self.results_data.get('execution_history', [])
        
        data = []
        for execution in execution_history:
            row = {
                'function_name': execution['function_name'],
                'execution_time': execution['execution_time'],
                'memory_usage': execution['memory_usage'],
                'cpu_usage': execution['cpu_usage'],
                'exception_occurred': execution['exception_occurred'],
                'exception_type': execution.get('exception_type'),
                'security_issues_count': len(execution.get('security_issues', [])),
                'api_calls_count': len(execution.get('api_calls', [])),
                'timestamp': execution['timestamp'],
                'has_security_issues': len(execution.get('security_issues', [])) > 0,
                'is_risky': execution['exception_occurred'] or len(execution.get('security_issues', [])) > 0
            }
            
            # Add individual security issue details
            for i, issue in enumerate(execution.get('security_issues', [])):
                row[f'security_issue_{i}_type'] = issue.get('type')
                row[f'security_issue_{i}_severity'] = issue.get('severity')
            
            data.append(row)
        
        self.metrics_df = pd.DataFrame(data)
        return self.metrics_df
    
    def calculate_performance_metrics(self) -> Dict[str, float]:
        """Calculate performance-related metrics."""
        if self.metrics_df is None:
            self.prepare_dataframe()
        
        df = self.metrics_df
        
        performance_metrics = {
            'avg_execution_time': df['execution_time'].mean(),
            'median_execution_time': df['execution_time'].median(),
            'std_execution_time': df['execution_time'].std(),
            'max_execution_time': df['execution_time'].max(),
            'min_execution_time': df['execution_time'].min(),
            'avg_memory_usage': df['memory_usage'].mean(),
            'max_memory_usage': df['memory_usage'].max(),
            'avg_cpu_usage': df['cpu_usage'].mean(),
            'max_cpu_usage': df['cpu_usage'].max(),
            'execution_time_percentile_95': df['execution_time'].quantile(0.95),
            'execution_time_percentile_99': df['execution_time'].quantile(0.99),
            'memory_usage_percentile_95': df['memory_usage'].quantile(0.95),
            'memory_usage_percentile_99': df['memory_usage'].quantile(0.99)
        }
        
        return performance_metrics
    
    def calculate_security_metrics(self) -> SecurityAssessment:
        """Calculate security-related metrics."""
        if self.metrics_df is None:
            self.prepare_dataframe()
        
        df = self.metrics_df
        
        # Count vulnerabilities by severity
        total_vulnerabilities = df['security_issues_count'].sum()
        
        # Analyze individual security issues
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for _, row in df.iterrows():
            for i in range(5):  # Check up to 5 security issues per function
                severity_col = f'security_issue_{i}_severity'
                if severity_col in row and pd.notna(row[severity_col]):
                    severity = row[severity_col]
                    if severity == 'critical':
                        critical_count += 1
                    elif severity == 'high':
                        high_count += 1
                    elif severity == 'medium':
                        medium_count += 1
                    elif severity == 'low':
                        low_count += 1
        
        # Calculate vulnerability density (issues per function)
        total_functions = df['function_name'].nunique()
        vulnerability_density = total_vulnerabilities / total_functions if total_functions > 0 else 0
        
        # Calculate security score (0-100, higher is better)
        # Penalize based on severity and frequency
        security_score = max(0, 100 - (
            critical_count * 25 +
            high_count * 15 +
            medium_count * 10 +
            low_count * 5
        ))
        
        return SecurityAssessment(
            total_vulnerabilities=total_vulnerabilities,
            critical_vulnerabilities=critical_count,
            high_vulnerabilities=high_count,
            medium_vulnerabilities=medium_count,
            low_vulnerabilities=low_count,
            vulnerability_density=vulnerability_density,
            security_score=security_score
        )
    
    def calculate_detection_metrics(self) -> EvaluationMetrics:
        """Calculate detection performance metrics."""
        if self.metrics_df is None:
            self.prepare_dataframe()
        
        df = self.metrics_df
        
        # Use 'is_risky' as ground truth for risky functions
        y_true = df['is_risky'].astype(int)
        
        # Use execution time as a proxy for risk score (longer execution = higher risk)
        # Normalize execution time to 0-1 range
        execution_time_normalized = (df['execution_time'] - df['execution_time'].min()) / (
            df['execution_time'].max() - df['execution_time'].min()
        )
        
        # Combine execution time and security issues for risk score
        risk_score = execution_time_normalized + df['security_issues_count'] * 0.1
        risk_score = np.clip(risk_score, 0, 1)
        
        # Calculate metrics
        precision = precision_score(y_true, (risk_score > 0.5).astype(int), zero_division=0)
        recall = recall_score(y_true, (risk_score > 0.5).astype(int), zero_division=0)
        f1 = f1_score(y_true, (risk_score > 0.5).astype(int), zero_division=0)
        
        # Calculate AUC metrics
        try:
            auc_roc = roc_auc_score(y_true, risk_score)
        except ValueError:
            auc_roc = 0.5  # Default for cases with only one class
        
        try:
            precision_curve, recall_curve, _ = precision_recall_curve(y_true, risk_score)
            auc_pr = np.trapz(precision_curve, recall_curve)
        except ValueError:
            auc_pr = 0.0
        
        # Calculate confusion matrix metrics
        y_pred = (risk_score > 0.5).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        true_positive_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        return EvaluationMetrics(
            precision=precision,
            recall=recall,
            f1_score=f1,
            auc_roc=auc_roc,
            auc_pr=auc_pr,
            false_positive_rate=false_positive_rate,
            true_positive_rate=true_positive_rate,
            accuracy=accuracy,
            specificity=specificity,
            sensitivity=sensitivity
        )
    
    def generate_leaderboard(self) -> pd.DataFrame:
        """Generate a leaderboard of functions ranked by risk."""
        if self.metrics_df is None:
            self.prepare_dataframe()
        
        df = self.metrics_df
        
        # Calculate risk score for each function
        function_stats = df.groupby('function_name').agg({
            'execution_time': ['mean', 'max', 'std'],
            'memory_usage': ['mean', 'max'],
            'security_issues_count': ['sum', 'mean'],
            'exception_occurred': 'sum',
            'is_risky': 'sum'
        }).round(4)
        
        # Flatten column names
        function_stats.columns = ['_'.join(col).strip() for col in function_stats.columns]
        
        # Calculate composite risk score
        function_stats['risk_score'] = (
            function_stats['execution_time_mean'] * 0.3 +
            function_stats['memory_usage_mean'] * 0.2 +
            function_stats['security_issues_count_sum'] * 0.3 +
            function_stats['exception_occurred_sum'] * 0.2
        )
        
        # Sort by risk score (descending)
        leaderboard = function_stats.sort_values('risk_score', ascending=False)
        
        return leaderboard
    
    def create_visualizations(self, output_dir: str = "assets") -> None:
        """Create comprehensive visualizations of analysis results."""
        if self.metrics_df is None:
            self.prepare_dataframe()
        
        df = self.metrics_df
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8')
        
        # 1. Execution Time Distribution
        plt.figure(figsize=(12, 8))
        plt.subplot(2, 2, 1)
        plt.hist(df['execution_time'], bins=30, alpha=0.7, edgecolor='black')
        plt.title('Execution Time Distribution')
        plt.xlabel('Execution Time (seconds)')
        plt.ylabel('Frequency')
        
        # 2. Memory Usage vs Execution Time
        plt.subplot(2, 2, 2)
        scatter = plt.scatter(df['execution_time'], df['memory_usage'], 
                             c=df['security_issues_count'], cmap='Reds', alpha=0.6)
        plt.colorbar(scatter, label='Security Issues Count')
        plt.title('Memory Usage vs Execution Time')
        plt.xlabel('Execution Time (seconds)')
        plt.ylabel('Memory Usage (MB)')
        
        # 3. Security Issues by Function
        plt.subplot(2, 2, 3)
        security_by_function = df.groupby('function_name')['security_issues_count'].sum().sort_values(ascending=True)
        security_by_function.plot(kind='barh')
        plt.title('Security Issues by Function')
        plt.xlabel('Total Security Issues')
        
        # 4. Exception Rate by Function
        plt.subplot(2, 2, 4)
        exception_rate = df.groupby('function_name')['exception_occurred'].mean().sort_values(ascending=True)
        exception_rate.plot(kind='barh', color='orange')
        plt.title('Exception Rate by Function')
        plt.xlabel('Exception Rate')
        
        plt.tight_layout()
        plt.savefig(output_path / 'analysis_overview.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 5. ROC Curve
        plt.figure(figsize=(8, 6))
        y_true = df['is_risky'].astype(int)
        execution_time_normalized = (df['execution_time'] - df['execution_time'].min()) / (
            df['execution_time'].max() - df['execution_time'].min()
        )
        risk_score = execution_time_normalized + df['security_issues_count'] * 0.1
        risk_score = np.clip(risk_score, 0, 1)
        
        fpr, tpr, _ = roc_curve(y_true, risk_score)
        auc_score = roc_auc_score(y_true, risk_score)
        
        plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {auc_score:.3f})')
        plt.plot([0, 1], [0, 1], 'k--', label='Random Classifier')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curve for Risk Detection')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.savefig(output_path / 'roc_curve.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 6. Precision-Recall Curve
        plt.figure(figsize=(8, 6))
        precision, recall, _ = precision_recall_curve(y_true, risk_score)
        auc_pr = np.trapz(precision, recall)
        
        plt.plot(recall, precision, label=f'PR Curve (AUC = {auc_pr:.3f})')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve for Risk Detection')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.savefig(output_path / 'precision_recall_curve.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Visualizations saved to {output_path}")
    
    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate a comprehensive evaluation report."""
        if self.metrics_df is None:
            self.prepare_dataframe()
        
        # Calculate all metrics
        performance_metrics = self.calculate_performance_metrics()
        security_assessment = self.calculate_security_metrics()
        detection_metrics = self.calculate_detection_metrics()
        leaderboard = self.generate_leaderboard()
        
        # Compile comprehensive report
        report = {
            'summary': {
                'total_executions': len(self.metrics_df),
                'total_functions': self.metrics_df['function_name'].nunique(),
                'analysis_period': {
                    'start': self.metrics_df['timestamp'].min(),
                    'end': self.metrics_df['timestamp'].max()
                }
            },
            'performance_metrics': performance_metrics,
            'security_assessment': {
                'total_vulnerabilities': security_assessment.total_vulnerabilities,
                'critical_vulnerabilities': security_assessment.critical_vulnerabilities,
                'high_vulnerabilities': security_assessment.high_vulnerabilities,
                'medium_vulnerabilities': security_assessment.medium_vulnerabilities,
                'low_vulnerabilities': security_assessment.low_vulnerabilities,
                'vulnerability_density': security_assessment.vulnerability_density,
                'security_score': security_assessment.security_score
            },
            'detection_metrics': {
                'precision': detection_metrics.precision,
                'recall': detection_metrics.recall,
                'f1_score': detection_metrics.f1_score,
                'auc_roc': detection_metrics.auc_roc,
                'auc_pr': detection_metrics.auc_pr,
                'accuracy': detection_metrics.accuracy,
                'specificity': detection_metrics.specificity,
                'sensitivity': detection_metrics.sensitivity,
                'false_positive_rate': detection_metrics.false_positive_rate,
                'true_positive_rate': detection_metrics.true_positive_rate
            },
            'leaderboard': leaderboard.to_dict('index'),
            'recommendations': self._generate_recommendations(security_assessment, detection_metrics)
        }
        
        return report
    
    def _generate_recommendations(self, security_assessment: SecurityAssessment, 
                                detection_metrics: EvaluationMetrics) -> List[str]:
        """Generate actionable recommendations based on analysis results."""
        recommendations = []
        
        # Security recommendations
        if security_assessment.critical_vulnerabilities > 0:
            recommendations.append(
                f"CRITICAL: Address {security_assessment.critical_vulnerabilities} critical vulnerabilities immediately"
            )
        
        if security_assessment.security_score < 70:
            recommendations.append(
                "Security score is below acceptable threshold. Review and fix security issues"
            )
        
        # Performance recommendations
        if detection_metrics.precision < 0.8:
            recommendations.append(
                "Low precision indicates high false positive rate. Refine detection criteria"
            )
        
        if detection_metrics.recall < 0.7:
            recommendations.append(
                "Low recall indicates missed risky functions. Improve detection sensitivity"
            )
        
        # General recommendations
        if security_assessment.vulnerability_density > 2.0:
            recommendations.append(
                "High vulnerability density suggests need for code review and security training"
            )
        
        if not recommendations:
            recommendations.append("Analysis shows good security posture. Continue monitoring.")
        
        return recommendations
    
    def export_report(self, filepath: str) -> None:
        """Export comprehensive report to JSON file."""
        report = self.generate_comprehensive_report()
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Comprehensive report exported to {filepath}")


# Example usage
if __name__ == "__main__":
    # This would typically be used with actual analysis results
    evaluator = DynamicAnalysisEvaluator()
    
    # Example of how to use with results file
    # evaluator.load_results("analysis_results.json")
    # evaluator.prepare_dataframe()
    # report = evaluator.generate_comprehensive_report()
    # evaluator.create_visualizations()
    # evaluator.export_report("evaluation_report.json")
    
    print("Dynamic Analysis Evaluator ready for use")
