#!/usr/bin/env python3
"""
Setup script for BoltVulnScanner
"""
import os
import sys
import subprocess
import platform

def check_python_version():
    """Check if Python 3.11+ is installed"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 11):
        print(f"Python 3.11+ is required. You have Python {version.major}.{version.minor}.{version.micro}")
        return False
    return True

def install_requirements():
    """Install required packages"""
    try:
        # Check if pip is available
        subprocess.run([sys.executable, "-m", "pip", "--version"], 
                      check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("pip is not installed. Please install pip first.")
        return False
        
    # Install main requirements
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                      check=True)
        print("Main requirements installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install main requirements: {e}")
        return False
        
    # Ask user if they want optional requirements
    response = input("Do you want to install optional requirements for PDF reports and headless browser support? (y/N): ")
    if response.lower() in ['y', 'yes']:
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements-optional.txt"], 
                          check=True)
            print("Optional requirements installed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install optional requirements: {e}")
            return False
            
    return True

def setup_environment():
    """Setup the environment for BoltVulnScanner"""
    print("Setting up BoltVulnScanner...")
    print(f"Python version: {sys.version}")
    print(f"Platform: {platform.platform()}")
    
    # Check Python version
    if not check_python_version():
        return False
        
    # Install requirements
    if not install_requirements():
        return False
        
    # Create reports directory if it doesn't exist
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        print(f"Created {reports_dir} directory")
        
    # Create creds.yaml from example if it doesn't exist
    if not os.path.exists("creds.yaml") and os.path.exists("creds.example.yaml"):
        with open("creds.example.yaml", "r") as src, open("creds.yaml", "w") as dst:
            dst.write(src.read())
        print("Created creds.yaml from example")
        
    print("\nSetup completed successfully!")
    print("\nTo run BoltVulnScanner:")
    print("  - CLI: python -m boltvuln.cli --help")
    print("  - Web UI: streamlit run src/boltvuln/streamlit_app.py")
    print("\nFor Docker usage:")
    print("  - Build: docker build -t boltvulnscanner .")
    print("  - Run: docker run --rm -v $(pwd)/reports:/app/reports boltvulnscanner scan --target http://example.com")
    
    return True

if __name__ == "__main__":
    success = setup_environment()
    sys.exit(0 if success else 1)