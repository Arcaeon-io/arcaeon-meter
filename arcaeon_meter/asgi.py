"""Pure-ASGI bearer-key middleware for arcaeon_meter.

No framework required: this speaks the ASGI protocol directly, so it wraps
FastAPI, Starlette, Quart, or any raw ASGI callable without importing any
of them. (The README calls this a soft dependency; it's softer than that —
there is nothing to install.)

    app.add_middleware(meter.asgi_middleware())          # FastAPI/Starlette
    app = meter.asgi_middleware()(app)                    # raw ASGI

Denial mapping:
  401  missing_key / unknown_key / revoked / no_cap_configured
  429  over_cap  (plus X-Meter-Cap / X-Meter-Used headers)
Grants stash the `Allowance` at scope["arcaeon_meter"].

Note for the pedantic (correctly so): the key check is a synchronous
single-row SQLite transaction run on the event loop. At micro-tool scale
that's microseconds; if you're serving thousands of requests a second,
front this with a real gateway — which is also where metering stops being
a voluntary path (see the README's honesty section).
"""
from __future__ import annotations

import json


def build_middleware(meter):
    """Return a middleware CLASS bound to `meter` (Starlette's
    `add_middleware` instantiates it with the downstream app)."""

    class MeterMiddleware:
        def __init__(self, app):
            self.app = app
            self.meter = meter

        async def __call__(self, scope, receive, send):
            if scope.get("type") != "http":
                await self.app(scope, receive, send)
                return
            key = None
            for name, value in scope.get("headers") or []:
                if name == b"authorization":
                    text = value.decode("latin-1")
                    if text.lower().startswith("bearer "):
                        key = text[7:].strip()
                    break
            result = self.meter.check(key)
            if result:
                scope["arcaeon_meter"] = result
                await self.app(scope, receive, send)
                return
            status = 429 if result.reason == "over_cap" else 401
            body = json.dumps({
                "error": "metering_denied",
                "reason": result.reason,
                "used": result.used,
                "cap": result.cap,
                "month": result.month,
            }).encode("utf-8")
            headers = [(b"content-type", b"application/json"),
                       (b"content-length", str(len(body)).encode("ascii"))]
            if status == 401:
                headers.append((b"www-authenticate", b"Bearer"))
            if result.cap is not None:
                headers.append((b"x-meter-cap", str(result.cap).encode("ascii")))
            if result.used is not None:
                headers.append((b"x-meter-used", str(result.used).encode("ascii")))
            await send({"type": "http.response.start", "status": status,
                        "headers": headers})
            await send({"type": "http.response.body", "body": body})

    return MeterMiddleware
