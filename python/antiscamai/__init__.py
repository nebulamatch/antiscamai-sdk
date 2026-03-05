"""
AntiScam AI Python SDK
AI-powered request inspection middleware for FastAPI, Django, and Flask.
"""

from .client import AntiScamClient, AntiScamConfig, InspectRequest, InspectResponse, ThreatDetail
from .middleware.fastapi import AntiScamFastAPIMiddleware, antiscam_fastapi
from .middleware.django import AntiScamDjangoMiddleware
from .middleware.flask import antiscam_flask

__all__ = [
    "AntiScamClient",
    "AntiScamConfig",
    "InspectRequest",
    "InspectResponse",
    "ThreatDetail",
    "AntiScamFastAPIMiddleware",
    "antiscam_fastapi",
    "AntiScamDjangoMiddleware",
    "antiscam_flask",
]

__version__ = "1.0.0"
