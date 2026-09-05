"""Thin client for llama-server. Greedy, seeded, prompt cache off: the decoding configuration is part
of a proposal's provenance, so it is fixed here and recorded, never left to server defaults."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

DECODING = {"temperature": 0.0, "top_k": 1, "top_p": 1.0, "min_p": 0.0, "seed": 0, "cache_prompt": False,
            "repeat_penalty": 1.0, "presence_penalty": 0.0, "frequency_penalty": 0.0}


class ServerError(RuntimeError):
    pass


@dataclass
class Completion:
    text: str
    prompt_tokens: int
    predicted_tokens: int
    wall_ms: float
    server_timings: dict = field(default_factory=dict)
    finish_reason: str = ""


class LlamaClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8080", timeout_s: float = 3600.0):
        self.base = base_url.rstrip("/")
        self.timeout = timeout_s

    def _get(self, path: str) -> dict:
        with urllib.request.urlopen(f"{self.base}{path}", timeout=self.timeout) as r:
            return json.load(r)

    def _post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(f"{self.base}{path}", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            raise ServerError(f"{path}: HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:2000]}") from None

    def wait_ready(self, seconds: float = 900.0) -> None:
        t0 = time.time()
        while time.time() - t0 < seconds:
            try:
                h = self._get("/health")
                if h.get("status") == "ok":
                    return
            except Exception:  # noqa: BLE001 - server not up yet
                pass
            time.sleep(2)
        raise ServerError("llama-server not ready")

    def props(self) -> dict:
        return self._get("/props")

    def chat(self, system: str, user: str, schema: dict, max_tokens: int = 2048, enable_thinking: bool = False) -> Completion:
        body = {"messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "response_format": {"type": "json_object", "schema": schema},
                "max_tokens": max_tokens, "chat_template_kwargs": {"enable_thinking": enable_thinking}, **DECODING}
        t0 = time.perf_counter()
        r = self._post("/v1/chat/completions", body)
        wall = (time.perf_counter() - t0) * 1000
        ch = r["choices"][0]
        text = ch["message"].get("content") or ""
        usage = r.get("usage", {})
        return Completion(text, usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0), wall, r.get("timings", {}), ch.get("finish_reason", ""))

    def grammar_compiles(self, schema: dict) -> tuple[bool, str]:
        """Ask the server to build the grammar for a schema with a zero-token request. A converter
        failure comes back as HTTP 400 with the converter's message — the measurement the projection
        experiment needs."""
        body = {"messages": [{"role": "user", "content": "{"}], "response_format": {"type": "json_object", "schema": schema},
                "max_tokens": 1, **DECODING}
        try:
            self._post("/v1/chat/completions", body)
            return True, ""
        except ServerError as e:
            return False, str(e)
