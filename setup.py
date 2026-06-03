#!/usr/bin/env python3
"""
Itzraven - AI-Powered Security Testing Platform
Setup configuration
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="itzraven-security",
    version="2.0.0",
    description="AI-Powered Security Testing Platform - See Everything. Miss Nothing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Itzraven Security Team",
    author_email="security@itzraven.dev",
    url="https://github.com/iamaworker-github/itzraven",
    packages=find_packages(exclude=["tests", "docs", "examples"]),
    include_package_data=True,
    package_data={
        "itzraven.ui": ["*.tcss"],
        "itzraven.ui.strix_style": ["*.tcss"],
    },
    python_requires=">=3.8",
    install_requires=[
        "textual>=0.47.0",
        "rich>=13.7.0",
        "aiohttp>=3.9.0",
        "httpx>=0.26.0",
        "websockets>=12.0",
        "dnspython>=2.4.0",
        "openai>=1.12.0",
        "anthropic>=0.18.0",
        "playwright>=1.41.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.1.0",
        "PyJWT>=2.8.0",
        "cryptography>=42.0.0",
        "pyyaml>=6.0.0",
        "python-dotenv>=1.0.0",
        "tenacity>=8.2.0",
        "cachetools>=5.3.0",
        "psutil>=5.9.0",
        "click>=8.1.0",
        "pydantic>=2.5.0",
        "pydantic-settings>=2.1.0",
        "opentelemetry-api>=1.22.0",
        "opentelemetry-sdk>=1.22.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-asyncio>=0.23.0",
            "black>=24.0.0",
            "mypy>=1.8.0",
            "pydantic>=2.5.0",
            "pydantic-settings>=2.1.0",
        ],
        "medusa": [
            "medusa-security>=2026.5.0",
        ],
        "redis": [
            "redis>=5.0.0",
        ],
        "ml": [
            "scikit-learn>=1.3.0",
            "numpy>=1.24.0",
        ],
        "observability": [
            "opentelemetry-api>=1.22.0",
            "opentelemetry-sdk>=1.22.0",
        ],
        "web": [
            "fastapi>=0.136.0",
            "uvicorn>=0.48.0",
        ],
        "all": [
            "medusa-security>=2026.5.0",
            "redis>=5.0.0",
            "scikit-learn>=1.3.0",
            "numpy>=1.24.0",
            "pydantic>=2.5.0",
            "pydantic-settings>=2.1.0",
            "opentelemetry-api>=1.22.0",
            "opentelemetry-sdk>=1.22.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "itzraven=itzraven.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="security pentesting vulnerability-scanner ai-security",
)
