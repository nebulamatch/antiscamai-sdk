"""
AntiScam AI Python SDK – Core Client
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import httpx

logger = logging.getLogger("antiscamai")

URL_PATTERN = re.compile(r"https?://[^\s\"'\]\)>]+", re.IGNORECASE)


# ─── Config ───────────────────────────────────────────────────────────────────

@dataclass
class AntiScamConfig:
    api_key: str
    """Your SDK API key."""

    endpoint: str = "http://localhost:5000"
    """Base URL of your AntiScam AI instance."""

    mode: str = "block"
    """Operating mode: 'block' | 'flag' | 'monitor'."""

    timeout_ms: int = 3000
    """Max milliseconds to wait for AI response."""

    on_error: str = "allow"
    """Fallback when AI service is unreachable: 'allow' | 'block'."""

    exclude_paths: List[str] = field(default_factory=lambda: ["/health", "/metrics"])
    """URL prefixes to skip entirely."""

    inspect_methods: List[str] = field(default_factory=lambda: ["POST", "PUT", "PATCH"])
    """HTTP methods to inspect (others are passed through)."""

    on_threat: Optional[Callable] = None
    """Async callback invoked on every threat detection."""


# ─── Models ───────────────────────────────────────────────────────────────────

@dataclass
class ThreatDetail:
    type: str        # TEXT | URL | BEHAVIORAL | IMAGE
    category: str
    score: float
    confidence: float
    explanation: str


@dataclass
class InspectRequest:
    body_raw: Optional[str] = None
    body_text: Optional[str] = None
    extracted_urls: Optional[List[str]] = None
    headers: Optional[Dict[str, str]] = None
    source_ip: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    user_id: Optional[str] = None
    mode: Optional[str] = None
    metadata: Optional[Dict[str, str]] = None


@dataclass
class InspectResponse:
    request_id: str
    threat_score: float
    risk_level: str   # MINIMAL | LOW | MEDIUM | HIGH | CRITICAL
    decision: str     # allow | flag | block
    should_block: bool
    threats: List[ThreatDetail]
    processed_at: str
    model_version: str


# ─── Client ───────────────────────────────────────────────────────────────────

class AntiScamClient:
    """HTTP client that talks to the AntiScam AI gateway."""

    def __init__(self, config: AntiScamConfig) -> None:
        if not config.api_key:
            raise ValueError("[AntiScamAI] api_key is required")
        self._config = config
        self._endpoint = config.endpoint.rstrip("/")
        self._timeout = config.timeout_ms / 1000.0

    async def inspect(self, request: InspectRequest) -> InspectResponse:
        """Send request snapshot to AI gateway. Always returns a response (never raises)."""
        payload = {
            "bodyText": request.body_text,
            "bodyRaw": request.body_raw,
            "extractedUrls": request.extracted_urls or [],
            "headers": request.headers or {},
            "sourceIp": request.source_ip,
            "endpoint": request.endpoint,
            "method": request.method,
            "userId": request.user_id,
            "mode": request.mode or self._config.mode,
            "metadata": request.metadata or {},
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._endpoint}/sdk/v1/inspect",
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-AntiScam-Key": self._config.api_key,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                return _parse_response(data)

        except Exception as exc:
            logger.warning("[AntiScamAI] Inspection failed: %s – falling back to: %s", exc, self._config.on_error)
            return _fallback(self._config.on_error)

    def inspect_sync(self, request: InspectRequest) -> InspectResponse:
        """Synchronous version for Django / Flask."""
        payload = {
            "bodyText": request.body_text,
            "bodyRaw": request.body_raw,
            "extractedUrls": request.extracted_urls or [],
            "headers": request.headers or {},
            "sourceIp": request.source_ip,
            "endpoint": request.endpoint,
            "method": request.method,
            "userId": request.user_id,
            "mode": request.mode or self._config.mode,
            "metadata": request.metadata or {},
        }

        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(
                    f"{self._endpoint}/sdk/v1/inspect",
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-AntiScam-Key": self._config.api_key,
                    },
                )
                resp.raise_for_status()
                return _parse_response(resp.json())
        except Exception as exc:
            logger.warning("[AntiScamAI] Inspection failed: %s – falling back to: %s", exc, self._config.on_error)
            return _fallback(self._config.on_error)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def extract_urls(text: str) -> List[str]:
    return list(set(URL_PATTERN.findall(text)))


def flatten_to_text(obj: Any, max_depth: int = 5, _depth: int = 0) -> str:
    if _depth > max_depth:
        return ""
    if isinstance(obj, str) and len(obj) > 2:
        return obj
    if isinstance(obj, (list, tuple)):
        return " ".join(flatten_to_text(v, max_depth, _depth + 1) for v in obj)
    if isinstance(obj, dict):
        return " ".join(flatten_to_text(v, max_depth, _depth + 1) for v in obj.values())
    return ""


def read_body(raw: Any) -> tuple[str, List[str]]:
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
        except Exception:
            return "", []
    if isinstance(raw, str):
        text = raw
    elif isinstance(raw, dict):
        text = flatten_to_text(raw)
    else:
        text = ""
    return text, extract_urls(text)


def _parse_response(data: Dict[str, Any]) -> InspectResponse:
    threats = [
        ThreatDetail(
            type=t.get("type", ""),
            category=t.get("category", ""),
            score=t.get("score", 0),
            confidence=t.get("confidence", 0),
            explanation=t.get("explanation", ""),
        )
        for t in data.get("threats", [])
    ]
    return InspectResponse(
        request_id=data.get("requestId", ""),
        threat_score=data.get("threatScore", 0),
        risk_level=data.get("riskLevel", "MINIMAL"),
        decision=data.get("decision", "allow"),
        should_block=data.get("shouldBlock", False),
        threats=threats,
        processed_at=data.get("processedAt", ""),
        model_version=data.get("modelVersion", ""),
    )


def _fallback(on_error: str) -> InspectResponse:
    blocked = on_error == "block"
    return InspectResponse(
        request_id="error-fallback",
        threat_score=0,
        risk_level="MINIMAL",
        decision="block" if blocked else "allow",
        should_block=blocked,
        threats=[],
        processed_at="",
        model_version="unknown",
    )
