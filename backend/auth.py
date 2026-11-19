"""Optional shared-token access for a single trusted workspace."""
import os
import secrets
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Operational probes stay reachable without a token so that a container
# orchestrator can call them; they expose no asset data.
PUBLIC_PATHS = ("/health", "/health/ready")


class AccessControlMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        token = os.getenv('ECDAT_API_TOKEN', '')
        if token and request.url.path not in PUBLIC_PATHS and request.method != 'OPTIONS':
            supplied = request.headers.get('Authorization', '')
            if not secrets.compare_digest(supplied, f'Bearer {token}'):
                return JSONResponse({'detail': 'A valid workspace access token is required.'}, status_code=401)
        return await call_next(request)
