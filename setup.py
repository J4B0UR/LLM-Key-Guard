#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="llm-key-guard",
    version="1.0.0",
    author="Gabriel Jabour",
    description="Security tool to detect and validate AI API keys",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gjabour/llm-key-guard",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Environment :: Console",
        "Operating System :: OS Independent",
        "Natural Language :: English",
        "Typing :: Typed",
    ],
    python_requires=">=3.8",
    install_requires=[
        "typer>=0.12.0",
        "rich>=10.0.0",
        "requests>=2.25.0",
        "tqdm>=4.60.0",
        "pyyaml>=5.1",
        "gitpython>=3.1.0",
        "gitignore_parser>=0.1.12",
        "python-dotenv>=0.19.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "pytest-cov>=2.12.0",
            "black>=21.5b2",
            "isort>=5.9.1",
            "flake8>=3.9.2",
            "mypy>=0.910",
            "pre-commit>=2.13.0",
            "build>=0.10.0",
            "twine>=4.0.0",
        ],
        "all": [
            "pytest>=6.0.0",
            "pytest-cov>=2.12.0",
            "black>=21.5b2",
            "isort>=5.9.1",
            "flake8>=3.9.2",
            "mypy>=0.910",
            "pre-commit>=2.13.0",
            "build>=0.10.0",
            "twine>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "llm-key-guard=llm_key_guard.cli:main",
        ],
    },
    project_urls={
        "Bug Tracker": "https://github.com/gjabour/llm-key-guard/issues",
        "Documentation": "https://github.com/gjabour/llm-key-guard#readme",
        "Source Code": "https://github.com/gjabour/llm-key-guard",
    },
) 