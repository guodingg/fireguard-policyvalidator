"""
API v1路由汇总
"""

from secscan.api.v1.auth import router as auth_router
from secscan.api.v1.users import router as users_router
from secscan.api.v1.scan import router as scan_router
from secscan.api.v1.assets import router as assets_router
from secscan.api.v1.vulns import router as vulns_router
from secscan.api.v1.pocs import router as pocs_router
from secscan.api.v1.reports import router as reports_router
from secscan.api.v1.logs import router as logs_router
from secscan.api.v1.ai import router as ai_router
from secscan.api.v1.dashboard import router as dashboard_router

__all__ = [
    "auth_router",
    "users_router", 
    "scan_router",
    "assets_router",
    "vulns_router",
    "pocs_router",
    "reports_router",
    "logs_router",
    "ai_router",
    "dashboard_router"
]
