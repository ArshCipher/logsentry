from setuptools import setup, find_packages

setup(
    name="logsentry",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "aiofiles>=23.2.1",
        "geoip2>=4.8.0",
        "scikit-learn>=1.5.2",
        "pandas>=2.2.3",
        "sqlalchemy>=2.0.35",
        "typer>=0.12.5",
        "watchdog>=5.0.3",
        "plotly>=5.24.1",
        "python-iptables>=1.0.1",
        "uvloop>=0.20.0",
    ],
    entry_points={
        "console_scripts": [
            "logsentry=logsentry.cli:app",
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="Real-time log analyzer for suspicious login attempts",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/logsentry",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
)