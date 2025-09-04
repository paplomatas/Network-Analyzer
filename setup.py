from setuptools import setup, find_packages

setup(
    name="network_analyzer",
    version="0.1.0",
    packages=find_packages(where="."),
    package_dir={"": "."},
    install_requires=[
        "scapy>=2.4.5",
        "matplotlib>=3.5.1",
        "pandas>=1.4.1",
        "numpy>=1.22.2",
        "plotly>=5.6.0",
        "networkx>=2.8.0",
        "dash>=2.3.0",
        "flask>=2.0.3",
        "sqlalchemy>=1.4.31",
        "scikit-learn>=1.0.2",
        "tqdm>=4.62.3",
        "pyshark",
        "pyqt5",
        "psycopg2",
        "pyyaml",
        "wheel",
        "setuptools"
    ],
    entry_points={
        'console_scripts': [
            'network-analyzer=network_analyzer.main:main',
        ],
    },
    author="Network Security Team",
    description="A network packet analyzer for monitoring, visualization, and security analysis",
    keywords="network, security, packet analysis, visualization",
    python_requires=">=3.7",
)
