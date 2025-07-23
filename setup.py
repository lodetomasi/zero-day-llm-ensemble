"""
Setup script for Zero-Day Detection System
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="zero-day-llm-ensemble",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Zero-Day Detection using Multi-Agent LLM Ensemble with Thompson Sampling",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/zero-day-llm-ensemble",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.21.0",
        "pandas>=1.3.0",
        "scikit-learn>=1.0.0",
        "scipy>=1.7.0",
        "statsmodels>=0.13.0",
        "requests>=2.26.0",
        "matplotlib>=3.4.0",
        "seaborn>=0.11.0",
        "pyyaml>=5.4.0",
    ],
    entry_points={
        "console_scripts": [
            "zero-day-detect=experiments.run_experiment:main",
        ],
    },
)