"""
Snypshark — PCAP network traffic analyzer.
"""

__version__ = "0.1.0"
__author__ = "Joseph Leon"
__email__ = "joscalion04@gmail.com"

from .analytics.pandas_analyzer import PandasAnalyzer
from .core.analyzer import PCAPAnalyzer
from .ui.cli_interface import InteractiveMenu

__all__ = ["PCAPAnalyzer", "PandasAnalyzer", "InteractiveMenu"]
