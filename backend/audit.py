"""Forensic audit logging middleware.

Logs every /api/ call to audit_log.jsonl with timestamp, method, path,
status code, and duration.
"""

import json
import os
import time
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware

AUDIT_FILE = os.path.join(os.path.dirname(__file__), "..", "audit_log.jsonl")


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        start = time.time()
        response = await call_next(request)
        duration = round(time.time() - start, 3)

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_s": duration,
        }
        try:
            with open(AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

        return response
