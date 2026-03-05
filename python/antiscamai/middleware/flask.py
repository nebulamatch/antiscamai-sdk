"""
AntiScam AI – Flask middleware (using before_request hook)
"""
from __future__ import annotations

import json
import logging
from functools import wraps
from typing import Callable

from flask import Flask, Request, g, jsonify, request

from ..client import AntiScamClient, AntiScamConfig, InspectRequest, read_body

logger = logging.getLogger("antiscamai")


def antiscam_flask(
    app: Flask,
    api_key: str,
    *,
    endpoint: str = "http://localhost:5000",
    mode: str = "block",
    exclude_paths: list[str] | None = None,
    inspect_methods: list[str] | None = None,
    **kwargs,
) -> None:
    """
    Register AntiScam AI middleware on a Flask application.

    Usage::

        from flask import Flask
        from antiscamai.middleware.flask import antiscam_flask

        app = Flask(__name__)
        antiscam_flask(app, api_key="YOUR_KEY")
    """
    config = AntiScamConfig(
        api_key=api_key,
        endpoint=endpoint,
        mode=mode,
        exclude_paths=exclude_paths or ["/health", "/metrics"],
        inspect_methods=inspect_methods or ["POST", "PUT", "PATCH"],
        **kwargs,
    )
    client = AntiScamClient(config)

    @app.before_request
    def _antiscam_before():
        method = request.method.upper()

        if any(request.path.startswith(p) for p in config.exclude_paths):
            return
        if method not in [m.upper() for m in config.inspect_methods]:
            return

        raw = request.get_data(as_text=False)
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = raw

        text, urls = read_body(parsed)

        safe_headers = {}
        for h in ["User-Agent", "Referer", "X-Forwarded-For", "Origin"]:
            val = request.headers.get(h)
            if val:
                safe_headers[h.lower()] = val

        try:
            result = client.inspect_sync(
                InspectRequest(
                    body_text=text[:4000],
                    extracted_urls=urls[:10],
                    headers=safe_headers,
                    source_ip=request.remote_addr,
                    endpoint=f"{method} {request.path}",
                    method=method,
                )
            )
            g.antiscam = result

            if result.should_block:
                return (
                    jsonify({
                        "error": "Request blocked by AntiScam AI",
                        "requestId": result.request_id,
                        "riskLevel": result.risk_level,
                        "reason": result.threats[0].explanation if result.threats else "Suspicious content",
                    }),
                    403,
                )

        except Exception as exc:
            logger.warning("[AntiScamAI] Middleware error (non-fatal): %s", exc)

    @app.after_request
    def _antiscam_after(response):
        result = getattr(g, "antiscam", None)
        if result and result.decision == "flag":
            response.headers["X-AntiScam-Flag"] = "true"
            response.headers["X-AntiScam-Score"] = str(result.threat_score)
        return response
