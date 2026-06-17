"""
PreviSwit AI-ASPM — Routers Package
Expõe todos os domínios ASPM como routers FastAPI.
"""
from api.routers.auth         import router as auth_router
from api.routers.assets       import router as assets_router
from api.routers.engagements  import router as engagements_router
from api.routers.findings     import router as findings_router
from api.routers.ai_insights  import router as ai_router
from api.routers.risk         import router as risk_router
from api.routers.reports      import router as reports_router
from api.routers.integrations import router as integrations_router
from api.routers.settings     import router as settings_router

__all__ = [
    "auth_router",
    "assets_router",
    "engagements_router",
    "findings_router",
    "ai_router",
    "risk_router",
    "reports_router",
    "integrations_router",
    "settings_router",
]
