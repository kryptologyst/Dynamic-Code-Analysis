#!/usr/bin/env python3
"""
Run Dynamic Code Analysis Demo

This script provides easy access to the dynamic code analysis demo.
"""

import subprocess
import sys
from pathlib import Path

def main():
    """Main function to run the demo."""
    print("Dynamic Code Analysis Demo")
    print("=" * 40)
    print()
    print("Choose an option:")
    print("1. Run main analysis script")
    print("2. Launch Streamlit web demo")
    print("3. Run tests")
    print("4. Exit")
    print()
    
    while True:
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == "1":
            print("\nRunning main analysis script...")
            subprocess.run([sys.executable, "0901.py"])
            break
            
        elif choice == "2":
            print("\nLaunching Streamlit demo...")
            print("The demo will open in your web browser.")
            print("Press Ctrl+C to stop the demo.")
            try:
                subprocess.run(["streamlit", "run", "demo/streamlit_demo.py"])
            except KeyboardInterrupt:
                print("\nDemo stopped.")
            except FileNotFoundError:
                print("Error: Streamlit not found. Please install it with: pip install streamlit")
            break
            
        elif choice == "3":
            print("\nRunning tests...")
            try:
                subprocess.run([sys.executable, "-m", "pytest", "tests/", "-v"])
            except FileNotFoundError:
                print("Error: pytest not found. Please install it with: pip install pytest")
            break
            
        elif choice == "4":
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()
