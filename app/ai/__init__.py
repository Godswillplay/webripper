"""
WebRipper Recon 5.0 AI Subsystem.
Local 4B/8B model integration, Ollama manager, and autonomous pentest agent.
"""

from .client import OllamaClient
from .setup import AISetupManager, RECOMMENDED_MODELS
from .tools import AgentToolbox
from .agent import AIAgent

__all__ = [
    "OllamaClient",
    "AISetupManager",
    "RECOMMENDED_MODELS",
    "AgentToolbox",
    "AIAgent",
]

