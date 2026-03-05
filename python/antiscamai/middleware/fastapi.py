"""
AntiScam AI – FastAPI / Starlette middleware
"""
from __future__ import annotations

import json
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..client import AntiScamClient, AntiScamConfig, InspectRequest, read_body


class AntiScamFastAPIMiddleware(BaseHTTPMiddleware):
    """
    Starlette / FastAPI middleware that inspects every incoming request.

    Usage::

        from fastapi import FastAPI
        from antiscamai.middleware.fastapi import AntiScamFastAPIMiddleware

        app = FastAPI()
        app.add_middleware(
            AntiScamFastAPIMiddleware,
            api_key="YOUR_KEY",
        )
    """

    def __init__(self, app, *, api_key: str, **kwargs):
        super().__init__(app)
        config = AntiScamConfig(api_key=api_key, **kwargs)
        self._client = AntiScamClient(config)
        self._config = config

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        method = request.method.upper()

        # Skip excluded paths / non-inspectable methods
        if any(request.url.path.startswith(p) for p in self._config.exclude_paths):
            return await call_next(request)
        if method not in [m.upper() for m in self._config.inspect_methods]:
            return await call_next(request)

        # Read + buffer body (required because FastAPI reads body once)
        raw_body = await request.body()
        try:
            parsed = json.loads(raw_body)
        except Exception:
            parsed = raw_body

        text, urls = read_body(parsed)

        # Safe headers subset
        safe_headers = {}
        allow_list = ["user-agent", "referer", "x-forwarded-for", "origin"]
        for h in allow_list:
            val = request.headers.get(h)
            if val:
                safe_headers[h] = val

        result = await self._client.inspect(
            InspectRequest(
                body_text=text[:4000],
                extracted_urls=urls[:10],
                headers=safe_headers,
                source_ip=request.client.host if request.client else None,
                endpoint=f"{method} {request.url.path}",
                method=method,
            )
        )

        # Attach to request state
        request.state.antiscam = result

        if self._config.on_threat and result.threats:
            if callable(self._config.on_threat):
                import asyncio
                if asyncio.iscoroutinefunction(self._config.on_threat):
                    await self._config.on_threat(result)
                else:
                    self._config.on_threat(result)

        if result.should_block:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by AntiScam AI",
                    "requestId": result.request_id,
                    "riskLevel": result.risk_level,
                    "reason": result.threats[0].explanation if result.threats else "Suspicious content detected",
                },
            )

        response = await call_next(request)

        if result.decision == "flag":
            response.headers["X-AntiScam-Flag"] = "true"
            response.headers["X-AntiScam-Score"] = str(result.threat_score)

        return response


# ── Convenience dependency ────────────────────────────────────────────────────

def antiscam_fastapi(api_key: str, **kwargs) -> Callable:
    """
    FastAPI dependency that inspects the current request inline (no middleware needed).

    Usage::

        from fastapi import Depends
        from antiscamai.middleware.fastapi import antiscam_fastapi

        checker = antiscam_fastapi("YOUR_KEY")

        @app.post("/submit")
        async def submit(body: MyModel, _: None = Depends(checker)):
            ...
    """
    config = AntiScamConfig(api_key=api_key, **kwargs)
    client = AntiScamClient(config)

    async def _dependency(request: Request):
        from fastapi import HTTPException

        method = request.method.upper()
        if method not in [m.upper() for m in config.inspect_methods]:
            return
        if any(request.url.path.startswith(p) for p in config.exclude_paths):
            return

        raw_body = await request.body()
        try:
            parsed = json.loads(raw_body)
        except Exception:
            parsed = raw_body

        text, urls = read_body(parsed)

        result = await client.inspect(
            InspectRequest(
                body_text=text[:4000],
                extracted_urls=urls[:10],
                source_ip=request.client.host if request.client else None,
                endpoint=f"{method} {request.url.path}",
                method=method,
            )
        )

        request.state.antiscam = result

        if result.should_block:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Request blocked by AntiScam AI",
                    "requestId": result.request_id,
                    "riskLevel": result.risk_level,
                },
            )

    return _dependency
