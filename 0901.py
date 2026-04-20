#!/usr/bin/env python3
"""
Dynamic Code Analysis - Modernized Implementation

This is the main entry point for the modernized dynamic code analysis system.
The original simple implementation has been replaced with a comprehensive
security-focused dynamic analysis framework.

For the full implementation, see the src/ directory structure.
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent / "src"))

from src.models.dynamic_analyzer import DynamicAnalyzer
from src.eval.evaluator import DynamicAnalysisEvaluator
from src.data.pipeline import DataPipeline
from src.defenses.explainability import ExplainabilityEngine

def main():
    """Main function demonstrating the modernized dynamic analysis system."""
    print("=" * 60)
    print("DYNAMIC CODE ANALYSIS - MODERNIZED IMPLEMENTATION")
    print("=" * 60)
    print()
    print("This is a research and educational demonstration of dynamic code analysis.")
    print("The original simple implementation has been modernized with:")
    print("• Advanced security pattern detection")
    print("• Memory and performance monitoring")
    print("• Comprehensive evaluation metrics")
    print("• Explainability features")
    print("• Interactive web demo")
    print()
    
    # Initialize components
    analyzer = DynamicAnalyzer()
    evaluator = DynamicAnalysisEvaluator()
    pipeline = DataPipeline()
    explainer = ExplainabilityEngine()
    
    print("Initializing dynamic analysis system...")
    
    # Generate synthetic test data
    print("Generating synthetic test functions...")
    functions = pipeline.generate_synthetic_data()
    
    # Create execution dataset
    print("Creating execution dataset...")
    dataset = pipeline.create_execution_dataset(num_executions=100)
    
    # Run analysis on sample functions
    print("Running dynamic analysis on sample functions...")
    
    @analyzer.analyze_function
    def safe_function(x: int) -> int:
        """A safe function that performs simple arithmetic."""
        import time
        time.sleep(0.1)
        return x * 2
    
    @analyzer.analyze_function
    def risky_function(y: int) -> float:
        """A risky function that may cause exceptions."""
        import time
        time.sleep(0.05)
        if y == 0:
            raise ValueError("Division by zero not allowed")
        return 10 / y
    
    @analyzer.analyze_function
    def memory_intensive_function(size: int) -> list:
        """A function that uses significant memory."""
        import time
        time.sleep(0.1)
        return list(range(size))
    
    @analyzer.analyze_function
    def suspicious_function(password: str) -> str:
        """A function with suspicious patterns."""
        import time
        time.sleep(0.1)
        return f"Processing password: {password[:3]}***"
    
    # Execute test functions
    try:
        safe_function(10)
        risky_function(5)
        risky_function(0)  # This will cause an exception
    except ValueError as e:
        print(f"Caught expected exception: {e}")
    
    memory_intensive_function(10000)
    suspicious_function("secret123")
    
    # Generate comprehensive analysis
    print("\nGenerating comprehensive analysis...")
    
    # Get execution summary
    summary = analyzer.get_execution_summary()
    print("\nEXECUTION SUMMARY:")
    print("-" * 30)
    for key, value in summary.items():
        if isinstance(value, dict):
            print(f"{key}:")
            for sub_key, sub_value in value.items():
                print(f"  {sub_key}: {sub_value}")
        else:
            print(f"{key}: {value}")
    
    # Export results
    analyzer.export_results("analysis_results.json")
    print("\nAnalysis results exported to analysis_results.json")
    
    # Generate explanations
    print("\nGenerating explanations...")
    for execution in analyzer.execution_history:
        explanation = explainer.explain_execution({
            'function_name': execution.function_name,
            'execution_time': execution.execution_time,
            'memory_usage': execution.memory_usage,
            'cpu_usage': execution.cpu_usage,
            'exception_occurred': execution.exception_occurred,
            'security_issues_count': len(execution.security_issues),
            'complexity': 10  # Default complexity
        })
    
    # Export explanations
    explainer.export_explanations(explainer.trace_analyzer.generate_trace_report(), "explanations.json")
    print("Explanations exported to explanations.json")
    
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)
    print()
    print("Next steps:")
    print("1. Run the Streamlit demo: streamlit run demo/streamlit_demo.py")
    print("2. View generated visualizations in the assets/ directory")
    print("3. Review analysis_results.json and explanations.json")
    print("4. Explore the comprehensive evaluation metrics")
    print()
    print("For more information, see the README.md file.")

if __name__ == "__main__":
    main()

