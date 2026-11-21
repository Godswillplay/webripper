"""
Universal Local LLM Client for WebRipper Recon.
Communicates with Ollama (native API) or any OpenAI-compatible local endpoint
(LM Studio, llama.cpp, LocalAI, vLLM).
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Generator, List, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen


class OllamaClient:
    """High-speed synchronous and streaming client for Ollama and OpenAI-compatible local APIs."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "dolphin3-cyber:8b",
        timeout: int = 120,
        api_key: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.api_key = api_key

    @property
    def is_ollama(self) -> bool:
        """Check if base_url is an Ollama endpoint or OpenAI-compatible endpoint."""
        if "/v1" in self.base_url:
            return False
        if ":11434" in self.base_url or "ollama" in self.base_url.lower():
            return True
        # Common local OpenAI-compatible inference ports (LM Studio, vLLM, text-generation-webui)
        if any(port in self.base_url for port in (":1234", ":8000", ":5000", ":8081")):
            return False
        return True

    def set_base_url(self, base_url: str) -> None:
        """Update base URL for Ollama / OpenAI-compatible endpoint."""
        self.base_url = base_url.rstrip("/")

    def ping(self, timeout: float = 2.0) -> tuple[bool, float, str]:
        """
        Ping the local LLM server and return (is_online, latency_ms, status_message).
        """
        import time
        start = time.perf_counter()
        try:
            if self.is_ollama:
                req = Request(f"{self.base_url}/api/tags", headers={"User-Agent": "WebRipper-AI"})
            else:
                req = Request(f"{self.base_url}/models", headers={"User-Agent": "WebRipper-AI"})

            with urlopen(req, timeout=timeout) as resp:
                latency = (time.perf_counter() - start) * 1000.0
                if resp.status == 200:
                    return (True, latency, f"ONLINE // {latency:.1f}MS")
                return (False, latency, f"HTTP {resp.status}")
        except Exception as exc:
            latency = (time.perf_counter() - start) * 1000.0
            # Simplify common Windows socket errors
            err = str(exc)
            if "10061" in err or "refused" in err.lower():
                err = "CONNECTION REFUSED (OLLAMA NOT RUNNING)"
            elif "timed out" in err.lower():
                err = "CONNECTION TIMED OUT"
            return (False, latency, err)

    def is_server_running(self, timeout: float = 2.0) -> bool:
        """Check if the local LLM server is up and responding."""
        try:
            if self.is_ollama:
                req = Request(f"{self.base_url}/api/tags", headers={"User-Agent": "WebRipper-AI"})
            else:
                req = Request(f"{self.base_url}/models", headers={"User-Agent": "WebRipper-AI"})

            with urlopen(req, timeout=timeout) as resp:
                return resp.status == 200
        except Exception:
            return False

    def list_models(self, timeout: float = 3.0) -> List[str]:
        """List all models currently installed in the local runtime."""
        models: List[str] = []
        try:
            if self.is_ollama:
                req = Request(f"{self.base_url}/api/tags", headers={"User-Agent": "WebRipper-AI"})
                with urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    for m in data.get("models", []):
                        name = m.get("name", "")
                        if name:
                            models.append(name)
            else:
                req = Request(f"{self.base_url}/models", headers={"User-Agent": "WebRipper-AI"})
                with urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    for m in data.get("data", []):
                        mid = m.get("id", "")
                        if mid:
                            models.append(mid)
        except Exception:
            pass
        return models

    def pull_model(
        self,
        model_name: str,
        progress_cb: Optional[Callable[[str, int], None]] = None,
    ) -> bool:
        """Pull a model via Ollama REST API with streaming progress."""
        if not self.is_ollama:
            return False

        # Map friendly name to HF repository alias if needed
        actual_model = model_name
        if model_name.lower() in ("dolphin3-cyber:8b", "dolphin3-cyber"):
            actual_model = "hf.co/bartowski/Dolphin3-Cyber-8B-GGUF:Q4_K_M"

        cb = progress_cb or (lambda msg, pct: None)
        cb(f"Starting download of {model_name}...", 0)

        url = f"{self.base_url}/api/pull"
        payload = json.dumps({"name": actual_model, "stream": True}).encode("utf-8")
        req = Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "WebRipper-AI"},
            method="POST",
        )

        try:
            with urlopen(req, timeout=1800) as resp:  # 30 minute timeout for large downloads
                for line in resp:
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line.decode("utf-8", errors="ignore"))
                        if "error" in chunk:
                            cb(f"Error pulling model: {chunk['error']}", 0)
                            return False

                        status = chunk.get("status", "")
                        total = chunk.get("total", 0)
                        completed = chunk.get("completed", 0)

                        pct = 0
                        if total > 0:
                            pct = min(100, int((completed / total) * 100))
                            msg = f"{status}: {completed // (1024*1024)}MB / {total // (1024*1024)}MB ({pct}%)"
                        else:
                            msg = status

                        cb(msg, pct)
                        if status == "success":
                            cb(f"Model {model_name} pulled successfully!", 100)
                            return True
                    except Exception:
                        continue
            return False
        except Exception as exc:
            cb(f"Failed to pull model: {exc}", 0)
            return False

    def chat(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
    ) -> str:
        """Send chat messages and return the assistant response string."""
        formatted_messages = []
        if system_prompt:
            formatted_messages.append({"role": "system", "content": system_prompt})
        formatted_messages.extend(messages)

        req_headers = {"Content-Type": "application/json", "User-Agent": "WebRipper-AI"}
        if self.api_key:
            req_headers["Authorization"] = f"Bearer {self.api_key}"

        if self.is_ollama:
            url = f"{self.base_url}/api/chat"
            payload = json.dumps({
                "model": self.model,
                "messages": formatted_messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_ctx": 8192,
                },
            }).encode("utf-8")
        else:
            endpoint = "/chat/completions" if self.base_url.endswith("/v1") else "/v1/chat/completions"
            url = f"{self.base_url}{endpoint}"
            payload = json.dumps({
                "model": self.model,
                "messages": formatted_messages,
                "temperature": temperature,
                "max_tokens": 4096,
                "top_p": 0.9,
            }).encode("utf-8")

        req = Request(
            url,
            data=payload,
            headers=req_headers,
            method="POST",
        )

        with urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if self.is_ollama:
                return (data.get("message") or {}).get("content", "")
            else:
                choices = data.get("choices", [])
                if choices:
                    return (choices[0].get("message") or {}).get("content", "")
                return ""

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
    ) -> str:
        """Single prompt completion method for Ollama and OpenAI-compatible endpoints."""
        if self.is_ollama:
            url = f"{self.base_url}/api/generate"
            payload = json.dumps({
                "model": self.model,
                "prompt": prompt,
                "system": system_prompt or "",
                "stream": False,
                "options": {"temperature": temperature},
            }).encode("utf-8")
        else:
            return self.chat([{"role": "user", "content": prompt}], system_prompt=system_prompt, temperature=temperature)

        req_headers = {"Content-Type": "application/json", "User-Agent": "WebRipper-AI"}
        if self.api_key:
            req_headers["Authorization"] = f"Bearer {self.api_key}"

        req = Request(url, data=payload, headers=req_headers, method="POST")
        with urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            return data.get("response", "")

