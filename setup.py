from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="snypshark",
    version="0.1.0",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "snypshark=analyzer.cli:main",
        ],
    },
    author="Joseph Leon",
    author_email="joscalion04@gmail.com",
    description="PCAP network traffic analyzer for forensics and security investigation",
    keywords="pcap analysis network security forensics pandas",
    python_requires=">=3.8",
)
