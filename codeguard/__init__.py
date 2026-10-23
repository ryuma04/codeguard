"""CodeGuard: real-time pre-execution safety layer for LLM-generated code."""
from .engine import analyze
from .guard import codeguard, CodeGuardBlocked

__all__ = ["analyze", "codeguard", "CodeGuardBlocked"]
