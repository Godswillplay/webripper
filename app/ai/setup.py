"""
Model setup guide and recommendations for WebRipper Recon AI.
Recommends high-performance 4B–8B parameter uncensored & coding models.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional
from .client import OllamaClient


RECOMMENDED_MODELS: List[Dict[str, str]] = [
    {
        "name": "dolphin3-cyber:8b",
        "alias": "hf.co/bartowski/Dolphin3-Cyber-8B-GGUF:Q4_K_M",
        "size": "8B (~4.9 GB, Q4_K_M)",
        "desc": "Primary Choice: Cognitive Computations' specialized cybersecurity model. Zero-refusal, expert offensive security analysis, exploit drafting, reverse engineering, and attack chain correlation.",
        "pull_cmd": "ollama run hf.co/bartowski/Dolphin3-Cyber-8B-GGUF:Q4_K_M",
        "recommended": True,
    },
    {
        "name": "qwen2.5-coder:7b",
        "alias": "qwen2.5-coder:7b",
        "size": "7B (~4.7 GB)",
        "desc": "Secondary Choice: Top-tier coding model. Outstanding at JavaScript deobfuscation, sourcemap analysis, and finding logic flaws.",
        "pull_cmd": "ollama pull qwen2.5-coder:7b",
        "recommended": True,
    },
    {
        "name": "llama3-abliterated:latest",
        "alias": "llama3-abliterated:latest",
        "size": "8B (~4.9 GB)",
        "desc": "Uncensored / abliterated Llama-3. Zero refusal on exploit analysis, vulnerability verification, and PoC crafting.",
        "pull_cmd": "ollama pull llama3-abliterated:latest",
        "recommended": False,
    },
    {
        "name": "dolphin-llama3:8b",
        "alias": "dolphin-llama3:8b",
        "size": "8B (~4.9 GB)",
        "desc": "Eric Hartford's uncensored Dolphin agent model. Great multi-tool execution and reasoning capabilities.",
        "pull_cmd": "ollama pull dolphin-llama3:8b",
        "recommended": False,
    },
    {
        "name": "mistral:7b",
        "alias": "mistral:7b",
        "size": "7B (~4.1 GB)",
        "desc": "Fast, lightweight model for high-speed triage, CVSS scoring, and rapid executive report generation.",
        "pull_cmd": "ollama pull mistral:7b",
        "recommended": False,
    },
]


OLLAMA_INSTALL_GUIDE = """
### How to Set Up Dolphin3-Cyber-8B-GGUF for WebRipper Recon

1. **Option A: Pull via Ollama (Easiest)**
   Ollama natively supports pulling GGUF models directly from Hugging Face!
   Open terminal or PowerShell and run:
   ```bash
   ollama run hf.co/bartowski/Dolphin3-Cyber-8B-GGUF:Q4_K_M
   ```
   *(Or click "Pull Recommended Model" directly inside WebRipper)*

2. **Option B: Import Local GGUF File into Ollama**
   If you already downloaded `Dolphin3-Cyber-8B-Q4_K_M.gguf`:
   1. Create a file named `Modelfile` in the folder containing the `.gguf`:
      ```dockerfile
      FROM ./Dolphin3-Cyber-8B-Q4_K_M.gguf
      TEMPLATE \"\"\"<|im_start|>system
      {{ .System }}<|im_end|>
      <|im_start|>user
      {{ .Prompt }}<|im_end|>
      <|im_start|>assistant
      \"\"\"
      PARAMETER stop \"<|im_start|>\"
      PARAMETER stop \"<|im_end|>\"
      ```
   2. Run: `ollama create dolphin3-cyber:8b -f Modelfile`

3. **Option C: Use with LM Studio / llama.cpp / LocalAI**
   - Load `Dolphin3-Cyber-8B-GGUF` into LM Studio.
   - Start the local inference server on `http://127.0.0.1:1234/v1`.
   - Set endpoint in WebRipper settings to `http://127.0.0.1:1234/v1`.
"""


def detect_ollama_binary() -> Optional[str]:
    """Find installed ollama executable on system."""
    import shutil
    bin_path = shutil.which("ollama")
    if bin_path:
        return bin_path
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    prog_files = os.environ.get("ProgramFiles", "")
    candidates = [
        os.path.join(local_app_data, "Programs", "Ollama", "ollama.exe"),
        os.path.join(prog_files, "Ollama", "ollama.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


class AISetupManager:
    """Manages AI runtime status, recommendations, and setup helpers."""

    def __init__(self, base_url: str = "http://127.0.0.1:11434"):
        self.client = OllamaClient(base_url=base_url)

    def get_status(self) -> Dict[str, any]:
        """Check AI status and return installed vs recommended models."""
        running = self.client.is_server_running()
        installed_models = self.client.list_models() if running else []

        has_recommended = False
        for inst in installed_models:
            inst_lower = inst.lower()
            if any(rec["name"].lower() in inst_lower or "dolphin3-cyber" in inst_lower for rec in RECOMMENDED_MODELS):
                has_recommended = True
                break

        return {
            "server_running": running,
            "ollama_installed": detect_ollama_binary() is not None,
            "base_url": self.client.base_url,
            "installed_models": installed_models,
            "has_recommended": has_recommended,
            "recommended": RECOMMENDED_MODELS,
            "guide": OLLAMA_INSTALL_GUIDE,
        }

