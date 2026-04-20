"""
Streamlit Demo for Dynamic Code Analysis

Interactive web application for demonstrating dynamic code analysis capabilities.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import time
import sys
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from models.dynamic_analyzer import DynamicAnalyzer, analyze
from eval.evaluator import DynamicAnalysisEvaluator

# Page configuration
st.set_page_config(
    page_title="Dynamic Code Analysis Demo",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
        margin: 0.5rem 0;
    }
    .warning-card {
        background-color: #fff3cd;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #ffc107;
        margin: 0.5rem 0;
    }
    .danger-card {
        background-color: #f8d7da;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #dc3545;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

def main():
    """Main application function."""
    
    # Header
    st.markdown('<h1 class="main-header">🔍 Dynamic Code Analysis Demo</h1>', unsafe_allow_html=True)
    
    # Disclaimer
    st.markdown("""
    <div class="warning-card">
    <strong>⚠️ Disclaimer:</strong> This is a research and educational demonstration of dynamic code analysis techniques. 
    This tool is designed for defensive security research and code quality assessment only. 
    It should not be used for malicious purposes or production security operations without proper validation.
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.header("Configuration")
        
        # Analysis settings
        st.subheader("Analysis Settings")
        enable_memory = st.checkbox("Enable Memory Monitoring", value=True)
        enable_security = st.checkbox("Enable Security Scanning", value=True)
        enable_api = st.checkbox("Enable API Tracking", value=True)
        memory_threshold = st.slider("Memory Threshold (MB)", 10, 500, 100)
        execution_timeout = st.slider("Execution Timeout (seconds)", 5, 60, 30)
        
        st.subheader("Demo Functions")
        st.markdown("""
        The demo includes several test functions:
        - **Safe Function**: Simple arithmetic operations
        - **Risky Function**: May cause exceptions
        - **Memory Intensive**: Uses significant memory
        - **Suspicious Function**: Contains security patterns
        """)
    
    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs(["Live Analysis", "Results Dashboard", "Security Assessment", "Performance Metrics"])
    
    with tab1:
        live_analysis_tab(enable_memory, enable_security, enable_api, memory_threshold, execution_timeout)
    
    with tab2:
        results_dashboard_tab()
    
    with tab3:
        security_assessment_tab()
    
    with tab4:
        performance_metrics_tab()


def live_analysis_tab(enable_memory, enable_security, enable_api, memory_threshold, execution_timeout):
    """Live analysis demonstration tab."""
    
    st.header("Live Dynamic Analysis")
    
    # Initialize analyzer
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = DynamicAnalyzer(
            enable_memory_monitoring=enable_memory,
            enable_security_scanning=enable_security,
            enable_api_tracking=enable_api,
            memory_threshold_mb=memory_threshold,
            execution_timeout=execution_timeout
        )
    
    # Update analyzer settings
    st.session_state.analyzer.enable_memory_monitoring = enable_memory
    st.session_state.analyzer.enable_security_scanning = enable_security
    st.session_state.analyzer.enable_api_tracking = enable_api
    st.session_state.analyzer.memory_threshold_mb = memory_threshold
    st.session_state.analyzer.execution_timeout = execution_timeout
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Test Functions")
        
        # Function execution controls
        col1_1, col1_2, col1_3, col1_4 = st.columns(4)
        
        with col1_1:
            if st.button("Run Safe Function", type="primary"):
                with st.spinner("Executing safe function..."):
                    @st.session_state.analyzer.analyze_function
                    def safe_function(x):
                        time.sleep(0.1)
                        return x * 2
                    
                    result = safe_function(10)
                    st.success(f"Result: {result}")
        
        with col1_2:
            if st.button("Run Risky Function"):
                with st.spinner("Executing risky function..."):
                    @st.session_state.analyzer.analyze_function
                    def risky_function(y):
                        time.sleep(0.05)
                        if y == 0:
                            raise ValueError("Division by zero not allowed")
                        return 10 / y
                    
                    try:
                        result = risky_function(5)
                        st.success(f"Result: {result}")
                    except ValueError as e:
                        st.error(f"Exception caught: {e}")
        
        with col1_3:
            if st.button("Run Memory Intensive"):
                with st.spinner("Executing memory intensive function..."):
                    @st.session_state.analyzer.analyze_function
                    def memory_intensive_function(size):
                        time.sleep(0.1)
                        return list(range(size))
                    
                    result = memory_intensive_function(10000)
                    st.success(f"Generated list with {len(result)} elements")
        
        with col1_4:
            if st.button("Run Suspicious Function"):
                with st.spinner("Executing suspicious function..."):
                    @st.session_state.analyzer.analyze_function
                    def suspicious_function(password):
                        time.sleep(0.1)
                        return f"Processing password: {password[:3]}***"
                    
                    result = suspicious_function("secret123")
                    st.warning(f"Result: {result}")
        
        # Clear results button
        if st.button("Clear All Results", type="secondary"):
            st.session_state.analyzer.execution_history = []
            st.success("Results cleared!")
    
    with col2:
        st.subheader("Live Metrics")
        
        if st.session_state.analyzer.execution_history:
            latest = st.session_state.analyzer.execution_history[-1]
            
            st.metric("Function", latest.function_name)
            st.metric("Execution Time", f"{latest.execution_time:.4f}s")
            st.metric("Memory Usage", f"{latest.memory_usage:.2f}MB")
            st.metric("CPU Usage", f"{latest.cpu_usage:.1f}%")
            
            if latest.exception_occurred:
                st.error(f"Exception: {latest.exception_type}")
            else:
                st.success("No exceptions")
            
            if latest.security_issues:
                st.warning(f"Security Issues: {len(latest.security_issues)}")
                for issue in latest.security_issues:
                    st.write(f"- {issue['description']} ({issue['severity']})")
            else:
                st.success("No security issues")
        else:
            st.info("No executions yet. Run some test functions!")


def results_dashboard_tab():
    """Results dashboard tab."""
    
    st.header("Analysis Results Dashboard")
    
    if 'analyzer' not in st.session_state or not st.session_state.analyzer.execution_history:
        st.info("No analysis results available. Please run some functions in the Live Analysis tab.")
        return
    
    analyzer = st.session_state.analyzer
    
    # Summary metrics
    summary = analyzer.get_execution_summary()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Executions", summary['total_executions'])
    
    with col2:
        st.metric("Functions Analyzed", summary['total_functions'])
    
    with col3:
        st.metric("Exception Rate", f"{summary['exception_rate']:.1%}")
    
    with col4:
        st.metric("Security Issues", summary['security_issues_total'])
    
    # Detailed results table
    st.subheader("Execution History")
    
    if analyzer.execution_history:
        # Convert to DataFrame for display
        data = []
        for execution in analyzer.execution_history:
            data.append({
                'Function': execution.function_name,
                'Execution Time (s)': f"{execution.execution_time:.4f}",
                'Memory Usage (MB)': f"{execution.memory_usage:.2f}",
                'CPU Usage (%)': f"{execution.cpu_usage:.1f}",
                'Exception': "Yes" if execution.exception_occurred else "No",
                'Exception Type': execution.exception_type or "N/A",
                'Security Issues': len(execution.security_issues),
                'API Calls': len(execution.api_calls),
                'Timestamp': pd.to_datetime(execution.timestamp, unit='s').strftime('%H:%M:%S')
            })
        
        df = pd.DataFrame(data)
        st.dataframe(df, use_container_width=True)
        
        # Export functionality
        if st.button("Export Results"):
            analyzer.export_results("streamlit_results.json")
            st.success("Results exported to streamlit_results.json")
    
    # Performance visualization
    st.subheader("Performance Visualization")
    
    if analyzer.execution_history:
        # Create performance charts
        exec_data = pd.DataFrame([
            {
                'Function': exec.function_name,
                'Execution Time': exec.execution_time,
                'Memory Usage': exec.memory_usage,
                'CPU Usage': exec.cpu_usage,
                'Security Issues': len(exec.security_issues)
            }
            for exec in analyzer.execution_history
        ])
        
        # Execution time over time
        fig_time = px.line(
            exec_data, 
            x=range(len(exec_data)), 
            y='Execution Time',
            title='Execution Time Over Time',
            labels={'x': 'Execution Number', 'y': 'Time (seconds)'}
        )
        st.plotly_chart(fig_time, use_container_width=True)
        
        # Memory usage scatter plot
        fig_memory = px.scatter(
            exec_data,
            x='Execution Time',
            y='Memory Usage',
            color='Security Issues',
            hover_data=['Function'],
            title='Memory Usage vs Execution Time',
            labels={'Execution Time': 'Time (seconds)', 'Memory Usage': 'Memory (MB)'}
        )
        st.plotly_chart(fig_memory, use_container_width=True)


def security_assessment_tab():
    """Security assessment tab."""
    
    st.header("Security Assessment")
    
    if 'analyzer' not in st.session_state or not st.session_state.analyzer.execution_history:
        st.info("No analysis results available. Please run some functions in the Live Analysis tab.")
        return
    
    analyzer = st.session_state.analyzer
    
    # Create evaluator and load results
    evaluator = DynamicAnalysisEvaluator()
    
    # Convert analyzer results to evaluator format
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
    
    try:
        evaluator.prepare_dataframe()
        security_assessment = evaluator.calculate_security_metrics()
        
        # Security metrics display
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Vulnerabilities", security_assessment.total_vulnerabilities)
            st.metric("Critical Issues", security_assessment.critical_vulnerabilities)
        
        with col2:
            st.metric("High Issues", security_assessment.high_vulnerabilities)
            st.metric("Medium Issues", security_assessment.medium_vulnerabilities)
        
        with col3:
            st.metric("Low Issues", security_assessment.low_vulnerabilities)
            st.metric("Security Score", f"{security_assessment.security_score:.1f}/100")
        
        # Security score visualization
        fig_score = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = security_assessment.security_score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Security Score"},
            delta = {'reference': 80},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "green"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        
        fig_score.update_layout(height=400)
        st.plotly_chart(fig_score, use_container_width=True)
        
        # Vulnerability breakdown
        if security_assessment.total_vulnerabilities > 0:
            vulnerability_data = {
                'Severity': ['Critical', 'High', 'Medium', 'Low'],
                'Count': [
                    security_assessment.critical_vulnerabilities,
                    security_assessment.high_vulnerabilities,
                    security_assessment.medium_vulnerabilities,
                    security_assessment.low_vulnerabilities
                ]
            }
            
            fig_vuln = px.pie(
                values=vulnerability_data['Count'],
                names=vulnerability_data['Severity'],
                title="Vulnerability Distribution by Severity",
                color_discrete_map={
                    'Critical': '#dc3545',
                    'High': '#fd7e14',
                    'Medium': '#ffc107',
                    'Low': '#28a745'
                }
            )
            st.plotly_chart(fig_vuln, use_container_width=True)
        
        # Detailed security issues
        st.subheader("Detailed Security Issues")
        
        all_issues = []
        for exec in analyzer.execution_history:
            for issue in exec.security_issues:
                all_issues.append({
                    'Function': exec.function_name,
                    'Type': issue['type'],
                    'Severity': issue['severity'],
                    'Description': issue['description']
                })
        
        if all_issues:
            issues_df = pd.DataFrame(all_issues)
            st.dataframe(issues_df, use_container_width=True)
        else:
            st.success("No security issues detected!")
    
    except Exception as e:
        st.error(f"Error in security assessment: {e}")


def performance_metrics_tab():
    """Performance metrics tab."""
    
    st.header("Performance Metrics")
    
    if 'analyzer' not in st.session_state or not st.session_state.analyzer.execution_history:
        st.info("No analysis results available. Please run some functions in the Live Analysis tab.")
        return
    
    analyzer = st.session_state.analyzer
    
    # Create evaluator and load results
    evaluator = DynamicAnalysisEvaluator()
    
    # Convert analyzer results to evaluator format
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
    
    try:
        evaluator.prepare_dataframe()
        performance_metrics = evaluator.calculate_performance_metrics()
        detection_metrics = evaluator.calculate_detection_metrics()
        
        # Performance metrics display
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Avg Execution Time", f"{performance_metrics['avg_execution_time']:.4f}s")
            st.metric("Max Execution Time", f"{performance_metrics['max_execution_time']:.4f}s")
        
        with col2:
            st.metric("Avg Memory Usage", f"{performance_metrics['avg_memory_usage']:.2f}MB")
            st.metric("Max Memory Usage", f"{performance_metrics['max_memory_usage']:.2f}MB")
        
        with col3:
            st.metric("Avg CPU Usage", f"{performance_metrics['avg_cpu_usage']:.1f}%")
            st.metric("Max CPU Usage", f"{performance_metrics['max_cpu_usage']:.1f}%")
        
        with col4:
            st.metric("95th Percentile Time", f"{performance_metrics['execution_time_percentile_95']:.4f}s")
            st.metric("99th Percentile Time", f"{performance_metrics['execution_time_percentile_99']:.4f}s")
        
        # Detection metrics
        st.subheader("Detection Performance")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Precision", f"{detection_metrics.precision:.3f}")
            st.metric("Recall", f"{detection_metrics.recall:.3f}")
        
        with col2:
            st.metric("F1 Score", f"{detection_metrics.f1_score:.3f}")
            st.metric("Accuracy", f"{detection_metrics.accuracy:.3f}")
        
        with col3:
            st.metric("AUC ROC", f"{detection_metrics.auc_roc:.3f}")
            st.metric("AUC PR", f"{detection_metrics.auc_pr:.3f}")
        
        with col4:
            st.metric("Specificity", f"{detection_metrics.specificity:.3f}")
            st.metric("Sensitivity", f"{detection_metrics.sensitivity:.3f}")
        
        # Performance trends
        st.subheader("Performance Trends")
        
        exec_data = pd.DataFrame([
            {
                'Execution': i,
                'Function': exec.function_name,
                'Execution Time': exec.execution_time,
                'Memory Usage': exec.memory_usage,
                'CPU Usage': exec.cpu_usage
            }
            for i, exec in enumerate(analyzer.execution_history)
        ])
        
        # Multi-line chart for performance trends
        fig_trends = make_subplots(
            rows=2, cols=1,
            subplot_titles=('Execution Time Trend', 'Memory Usage Trend'),
            vertical_spacing=0.1
        )
        
        fig_trends.add_trace(
            go.Scatter(x=exec_data['Execution'], y=exec_data['Execution Time'], 
                      mode='lines+markers', name='Execution Time'),
            row=1, col=1
        )
        
        fig_trends.add_trace(
            go.Scatter(x=exec_data['Execution'], y=exec_data['Memory Usage'], 
                      mode='lines+markers', name='Memory Usage'),
            row=2, col=1
        )
        
        fig_trends.update_layout(height=600, showlegend=True)
        fig_trends.update_xaxes(title_text="Execution Number")
        fig_trends.update_yaxes(title_text="Time (seconds)", row=1, col=1)
        fig_trends.update_yaxes(title_text="Memory (MB)", row=2, col=1)
        
        st.plotly_chart(fig_trends, use_container_width=True)
        
        # Function performance comparison
        st.subheader("Function Performance Comparison")
        
        function_stats = exec_data.groupby('Function').agg({
            'Execution Time': ['mean', 'std', 'min', 'max'],
            'Memory Usage': ['mean', 'std', 'min', 'max'],
            'CPU Usage': ['mean', 'std', 'min', 'max']
        }).round(4)
        
        function_stats.columns = ['_'.join(col).strip() for col in function_stats.columns]
        
        # Display function comparison table
        st.dataframe(function_stats, use_container_width=True)
    
    except Exception as e:
        st.error(f"Error in performance metrics: {e}")


if __name__ == "__main__":
    main()
