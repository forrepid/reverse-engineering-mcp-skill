"""Safe, evidence-oriented reverse-engineering primitives."""

from .analyzers import StaticAnalyzer
from .models import AnalysisResult, Finding

__all__ = ["AnalysisResult", "Finding", "StaticAnalyzer"]
__version__ = "0.5.0"
