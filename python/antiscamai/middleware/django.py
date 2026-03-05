"""
AntiScam AI – Django middleware
"""
from __future__ import annotations

import json
import logging

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse

from ..client import AntiScamClient, AntiScamConfig, InspectRequest, read_body

logger = logging.getLogger("antiscamai")


class AntiScamDjangoMiddleware:
    """
    Django WSGI/ASGI middleware for AntiScam AI request inspection.

    Add to settings.py::

        ANTISCAMAI = {
            "API_KEY": "YOUR_KEY",
            "MODE": "block",            # block | flag | monitor
            "ENDPOINT": "http://localhost:5000",
            "EXCLUDE_PATHS": ["/health/", "/static/"],
            "INSPECT_METHODS": ["POST", "PUT", "PATCH"],
        }

        MIDDLEWARE = [
            ...
            "antiscamai.middleware.django.AntiScamDjangoMiddleware",
        ]
    """

    def __init__(self, get_response):
        self.get_response = get_response
        cfg = getattr(settings, "ANTISCAMAI", {})
        config = AntiScamConfig(
            api_key=cfg.get("API_KEY", ""),
            endpoint=cfg.get("ENDPOINT", "http://localhost:5000"),
            mode=cfg.get("MODE", "block"),
            exclude_paths=cfg.get("EXCLUDE_PATHS", ["/health/", "/static/", "/favicon.ico"]),
            inspect_methods=cfg.get("INSPECT_METHODS", ["POST", "PUT", "PATCH"]),
        )
        self._client = AntiScamClient(config)
        self._config = config

    def __call__(self, request: HttpRequest) -> HttpResponse:
        method = request.method.upper() if request.method else "GET"

        should_skip = (
            any(request.path.startswith(p) for p in self._config.exclude_paths)
            or method not in [m.upper() for m in self._config.inspect_methods]
        )

        if not should_skip:
            try:
                raw_body = request.body
                try:
                    parsed = json.loads(raw_body)
                except Exception:
                    parsed = raw_body

                text, urls = read_body(parsed)

                safe_headers = {}
                for h in ["HTTP_USER_AGENT", "HTTP_REFERER", "HTTP_X_FORWARDED_FOR", "HTTP_ORIGIN"]:
                    val = request.META.get(h)
                    if val:
                        safe_headers[h.replace("HTTP_", "").replace("_", "-").lower()] = val

                result = self._client.inspect_sync(
                    InspectRequest(
                        body_text=text[:4000],
                        extracted_urls=urls[:10],
                        headers=safe_headers,
                        source_ip=request.META.get("REMOTE_ADDR"),
                        endpoint=f"{method} {request.path}",
                        method=method,
                        user_id=str(request.user.pk) if hasattr(request, "user") and request.user.is_authenticated else None,
                    )
                )

                request.antiscam = result  # type: ignore[attr-defined]

                if result.should_block:
                    return JsonResponse(
                        {
                            "error": "Request blocked by AntiScam AI",
                            "requestId": result.request_id,
                            "riskLevel": result.risk_level,
                            "reason": result.threats[0].explanation if result.threats else "Suspicious content",
                        },
                        status=403,
                    )

            except Exception as exc:
                logger.warning("[AntiScamAI] Middleware error (non-fatal): %s", exc)

        response = self.get_response(request)

        if hasattr(request, "antiscam") and request.antiscam.decision == "flag":  # type: ignore[attr-defined]
            response["X-AntiScam-Flag"] = "true"
            response["X-AntiScam-Score"] = str(request.antiscam.threat_score)  # type: ignore[attr-defined]

        return response
