"""
Data Pipeline Module for Dynamic Code Analysis

This module provides data generation, processing, and management capabilities
for dynamic code analysis, including synthetic data generation and real code processing.
"""

import os
import ast
import random
import time
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import pandas as pd
import numpy as np
from dataclasses import dataclass
import json
import logging

logger = logging.getLogger(__name__)

# Set deterministic seeding
np.random.seed(42)
random.seed(42)


@dataclass
class CodeFunction:
    """Represents a code function with metadata."""
    name: str
    code: str
    complexity: int
    has_exceptions: bool
    has_security_issues: bool
    estimated_execution_time: float
    estimated_memory_usage: float
    risk_level: str  # low, medium, high, critical


class SyntheticDataGenerator:
    """Generates synthetic code functions for testing dynamic analysis."""
    
    def __init__(self, num_functions: int = 100):
        """
        Initialize the synthetic data generator.
        
        Args:
            num_functions: Number of synthetic functions to generate
        """
        self.num_functions = num_functions
        self.functions: List[CodeFunction] = []
        
        # Templates for different types of functions
        self.function_templates = {
            'safe': [
                "def {name}(x):\n    return x * 2",
                "def {name}(a, b):\n    return a + b",
                "def {name}(items):\n    return sum(items)",
                "def {name}(text):\n    return text.upper()",
                "def {name}(numbers):\n    return max(numbers)"
            ],
            'risky': [
                "def {name}(x):\n    return 10 / x",
                "def {name}(items):\n    return items[10]",
                "def {name}(text):\n    return text.split()[5]",
                "def {name}(data):\n    return data['missing_key']",
                "def {name}(x):\n    if x == 0:\n        raise ValueError('Division by zero')"
            ],
            'memory_intensive': [
                "def {name}(size):\n    return list(range(size))",
                "def {name}(n):\n    return [i**2 for i in range(n)]",
                "def {name}(size):\n    data = []\n    for i in range(size):\n        data.append(i * 2)\n    return data",
                "def {name}(n):\n    matrix = []\n    for i in range(n):\n        matrix.append([0] * n)\n    return matrix"
            ],
            'suspicious': [
                "def {name}(password):\n    return f'Processing password: {{password[:3]}}***'",
                "def {name}(secret_key):\n    return f'Using secret: {{secret_key}}'",
                "def {name}(admin_token):\n    return f'Admin token: {{admin_token}}'",
                "def {name}(user_input):\n    return eval(user_input)",
                "def {name}(command):\n    return os.system(command)"
            ]
        }
    
    def generate_functions(self) -> List[CodeFunction]:
        """Generate synthetic functions for testing."""
        logger.info(f"Generating {self.num_functions} synthetic functions")
        
        functions = []
        
        # Generate different types of functions
        safe_count = int(self.num_functions * 0.4)
        risky_count = int(self.num_functions * 0.3)
        memory_count = int(self.num_functions * 0.2)
        suspicious_count = self.num_functions - safe_count - risky_count - memory_count
        
        # Generate safe functions
        for i in range(safe_count):
            func = self._generate_function('safe', i)
            functions.append(func)
        
        # Generate risky functions
        for i in range(risky_count):
            func = self._generate_function('risky', i)
            functions.append(func)
        
        # Generate memory intensive functions
        for i in range(memory_count):
            func = self._generate_function('memory_intensive', i)
            functions.append(func)
        
        # Generate suspicious functions
        for i in range(suspicious_count):
            func = self._generate_function('suspicious', i)
            functions.append(func)
        
        self.functions = functions
        logger.info(f"Generated {len(functions)} functions")
        return functions
    
    def _generate_function(self, func_type: str, index: int) -> CodeFunction:
        """Generate a single function of the specified type."""
        template = random.choice(self.function_templates[func_type])
        name = f"{func_type}_function_{index}"
        code = template.format(name=name)
        
        # Calculate complexity (simple heuristic)
        complexity = len(code.split('\n'))
        
        # Determine characteristics based on type
        has_exceptions = func_type in ['risky', 'suspicious']
        has_security_issues = func_type == 'suspicious'
        
        # Estimate execution time and memory usage
        if func_type == 'memory_intensive':
            estimated_execution_time = random.uniform(0.1, 2.0)
            estimated_memory_usage = random.uniform(50, 500)
        elif func_type == 'risky':
            estimated_execution_time = random.uniform(0.01, 0.5)
            estimated_memory_usage = random.uniform(1, 50)
        else:
            estimated_execution_time = random.uniform(0.01, 0.2)
            estimated_memory_usage = random.uniform(1, 20)
        
        # Determine risk level
        if func_type == 'suspicious':
            risk_level = 'critical'
        elif func_type == 'risky':
            risk_level = 'high'
        elif func_type == 'memory_intensive':
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return CodeFunction(
            name=name,
            code=code,
            complexity=complexity,
            has_exceptions=has_exceptions,
            has_security_issues=has_security_issues,
            estimated_execution_time=estimated_execution_time,
            estimated_memory_usage=estimated_memory_usage,
            risk_level=risk_level
        )
    
    def export_functions(self, filepath: str) -> None:
        """Export generated functions to JSON file."""
        functions_data = []
        for func in self.functions:
            functions_data.append({
                'name': func.name,
                'code': func.code,
                'complexity': func.complexity,
                'has_exceptions': func.has_exceptions,
                'has_security_issues': func.has_security_issues,
                'estimated_execution_time': func.estimated_execution_time,
                'estimated_memory_usage': func.estimated_memory_usage,
                'risk_level': func.risk_level
            })
        
        with open(filepath, 'w') as f:
            json.dump(functions_data, f, indent=2)
        
        logger.info(f"Exported {len(functions_data)} functions to {filepath}")


class RealCodeProcessor:
    """Processes real Python code files for dynamic analysis."""
    
    def __init__(self, source_directory: str = "src/"):
        """
        Initialize the real code processor.
        
        Args:
            source_directory: Directory containing Python source files
        """
        self.source_directory = Path(source_directory)
        self.functions: List[CodeFunction] = []
        
    def discover_functions(self, file_extensions: List[str] = [".py"]) -> List[CodeFunction]:
        """Discover functions in Python files."""
        logger.info(f"Discovering functions in {self.source_directory}")
        
        functions = []
        
        for file_path in self.source_directory.rglob("*"):
            if file_path.suffix in file_extensions:
                try:
                    file_functions = self._extract_functions_from_file(file_path)
                    functions.extend(file_functions)
                except Exception as e:
                    logger.warning(f"Error processing {file_path}: {e}")
        
        self.functions = functions
        logger.info(f"Discovered {len(functions)} functions")
        return functions
    
    def _extract_functions_from_file(self, file_path: Path) -> List[CodeFunction]:
        """Extract functions from a single Python file."""
        functions = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func = self._analyze_function_node(node, content, file_path)
                    if func:
                        functions.append(func)
        
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
        
        return functions
    
    def _analyze_function_node(self, node: ast.FunctionDef, content: str, file_path: Path) -> Optional[CodeFunction]:
        """Analyze an AST function node to extract metadata."""
        try:
            # Get function code
            lines = content.split('\n')
            start_line = node.lineno - 1
            end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line + 10
            
            func_code = '\n'.join(lines[start_line:end_line])
            
            # Calculate complexity (simple heuristic)
            complexity = len(func_code.split('\n'))
            
            # Check for potential exceptions
            has_exceptions = self._has_potential_exceptions(node)
            
            # Check for security issues
            has_security_issues = self._has_security_issues(node, func_code)
            
            # Estimate execution characteristics
            estimated_execution_time = self._estimate_execution_time(node, func_code)
            estimated_memory_usage = self._estimate_memory_usage(node, func_code)
            
            # Determine risk level
            risk_level = self._determine_risk_level(has_exceptions, has_security_issues, complexity)
            
            return CodeFunction(
                name=f"{file_path.stem}.{node.name}",
                code=func_code,
                complexity=complexity,
                has_exceptions=has_exceptions,
                has_security_issues=has_security_issues,
                estimated_execution_time=estimated_execution_time,
                estimated_memory_usage=estimated_memory_usage,
                risk_level=risk_level
            )
        
        except Exception as e:
            logger.warning(f"Error analyzing function {node.name}: {e}")
            return None
    
    def _has_potential_exceptions(self, node: ast.FunctionDef) -> bool:
        """Check if function has potential for exceptions."""
        dangerous_operations = [
            ast.Div, ast.FloorDiv, ast.Mod,  # Division operations
            ast.Subscript,  # Indexing
            ast.Attribute,  # Attribute access
            ast.Call  # Function calls
        ]
        
        for child in ast.walk(node):
            if isinstance(child, tuple(dangerous_operations)):
                return True
        
        return False
    
    def _has_security_issues(self, node: ast.FunctionDef, code: str) -> bool:
        """Check if function has potential security issues."""
        suspicious_patterns = [
            'eval', 'exec', 'compile', '__import__',
            'password', 'secret', 'token', 'key',
            'admin', 'root', 'sudo'
        ]
        
        code_lower = code.lower()
        return any(pattern in code_lower for pattern in suspicious_patterns)
    
    def _estimate_execution_time(self, node: ast.FunctionDef, code: str) -> float:
        """Estimate execution time based on function characteristics."""
        # Simple heuristic based on code length and complexity
        base_time = 0.01
        complexity_factor = len(code.split('\n')) * 0.001
        loop_factor = code.count('for') * 0.01 + code.count('while') * 0.01
        
        return base_time + complexity_factor + loop_factor
    
    def _estimate_memory_usage(self, node: ast.FunctionDef, code: str) -> float:
        """Estimate memory usage based on function characteristics."""
        # Simple heuristic based on data structures
        base_memory = 1.0
        list_factor = code.count('list(') * 10 + code.count('[]') * 5
        dict_factor = code.count('dict(') * 5 + code.count('{}') * 3
        
        return base_memory + list_factor + dict_factor
    
    def _determine_risk_level(self, has_exceptions: bool, has_security_issues: bool, complexity: int) -> str:
        """Determine risk level based on function characteristics."""
        if has_security_issues:
            return 'critical'
        elif has_exceptions and complexity > 10:
            return 'high'
        elif has_exceptions or complexity > 20:
            return 'medium'
        else:
            return 'low'


class DataPipeline:
    """Main data pipeline for managing code analysis data."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the data pipeline.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.synthetic_generator = SyntheticDataGenerator(
            num_functions=self.config.get('num_functions', 100)
        )
        self.real_processor = RealCodeProcessor(
            source_directory=self.config.get('source_directory', 'src/')
        )
        self.functions: List[CodeFunction] = []
    
    def generate_synthetic_data(self) -> List[CodeFunction]:
        """Generate synthetic functions for testing."""
        logger.info("Generating synthetic data")
        functions = self.synthetic_generator.generate_functions()
        self.functions.extend(functions)
        return functions
    
    def process_real_code(self, file_extensions: List[str] = [".py"]) -> List[CodeFunction]:
        """Process real code files."""
        logger.info("Processing real code files")
        functions = self.real_processor.discover_functions(file_extensions)
        self.functions.extend(functions)
        return functions
    
    def create_execution_dataset(self, num_executions: int = 1000) -> pd.DataFrame:
        """Create a dataset of function executions for analysis."""
        logger.info(f"Creating execution dataset with {num_executions} executions")
        
        if not self.functions:
            logger.warning("No functions available. Generating synthetic data.")
            self.generate_synthetic_data()
        
        executions = []
        
        for _ in range(num_executions):
            func = random.choice(self.functions)
            
            # Simulate execution characteristics
            execution_time = np.random.normal(
                func.estimated_execution_time, 
                func.estimated_execution_time * 0.1
            )
            execution_time = max(0.001, execution_time)  # Ensure positive
            
            memory_usage = np.random.normal(
                func.estimated_memory_usage,
                func.estimated_memory_usage * 0.2
            )
            memory_usage = max(0.1, memory_usage)  # Ensure positive
            
            cpu_usage = np.random.uniform(0, 100)
            
            # Simulate exceptions
            exception_occurred = func.has_exceptions and np.random.random() < 0.1
            
            # Simulate security issues
            security_issues_count = len(func.code.split()) if func.has_security_issues else 0
            
            execution = {
                'function_name': func.name,
                'execution_time': execution_time,
                'memory_usage': memory_usage,
                'cpu_usage': cpu_usage,
                'exception_occurred': exception_occurred,
                'exception_type': 'ValueError' if exception_occurred else None,
                'security_issues_count': security_issues_count,
                'complexity': func.complexity,
                'risk_level': func.risk_level,
                'timestamp': time.time() + np.random.uniform(-3600, 0)  # Last hour
            }
            
            executions.append(execution)
        
        df = pd.DataFrame(executions)
        logger.info(f"Created dataset with {len(df)} executions")
        return df
    
    def export_dataset(self, df: pd.DataFrame, filepath: str) -> None:
        """Export dataset to CSV file."""
        df.to_csv(filepath, index=False)
        logger.info(f"Dataset exported to {filepath}")
    
    def get_function_statistics(self) -> Dict[str, Any]:
        """Get statistics about available functions."""
        if not self.functions:
            return {"message": "No functions available"}
        
        df = pd.DataFrame([
            {
                'name': func.name,
                'complexity': func.complexity,
                'has_exceptions': func.has_exceptions,
                'has_security_issues': func.has_security_issues,
                'risk_level': func.risk_level
            }
            for func in self.functions
        ])
        
        stats = {
            'total_functions': len(self.functions),
            'functions_with_exceptions': df['has_exceptions'].sum(),
            'functions_with_security_issues': df['has_security_issues'].sum(),
            'average_complexity': df['complexity'].mean(),
            'risk_level_distribution': df['risk_level'].value_counts().to_dict()
        }
        
        return stats


# Example usage
if __name__ == "__main__":
    # Initialize data pipeline
    pipeline = DataPipeline()
    
    # Generate synthetic data
    synthetic_functions = pipeline.generate_synthetic_data()
    
    # Create execution dataset
    dataset = pipeline.create_execution_dataset(num_executions=500)
    
    # Export results
    pipeline.export_dataset(dataset, "synthetic_executions.csv")
    
    # Get statistics
    stats = pipeline.get_function_statistics()
    print("Function Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print(f"\nDataset created with {len(dataset)} executions")
    print(f"Columns: {list(dataset.columns)}")
