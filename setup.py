from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name="snypshark-analyzer",
    version="1.0.0",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "snypshark=main:main",
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="Advanced network traffic analysis tool for cybersecurity",
    keywords="pcap analysis network cybersecurity pandas",
    python_requires=">=3.8",
)