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

BILLING POLICY, stated so nobody discovers it on an invoice:
  * `OPTIONS` is not metered (default `skip_methods`). A CORS preflight is
    the browser asking whether it may call, and it does not carry the
    Authorization header — metering it billed a non-call AND answered 401,
    which breaks the very CORS handshake it was inspecting.
  * every other method, `HEAD` included, is billed once at dispatch. Pass
    `skip_methods=("OPTIONS", "HEAD")` if a HEAD is not a call to you.
  * a request whose handler raises or answers 5xx is STILL billed. The cap
    has to be spent before the work runs (that is what makes it a cap and
    what makes it atomic across processes), and a refund would need a
    negative cost — deliberately refused since 0.1.1, because a public
    negative cost is a budget-minting hole. If you need failed calls
    forgiven, credit them in your billing flow, where the money is.

Note for the pedantic (correctly so): the key check is a synchronous
single-row SQLite transaction run on the event loop. At micro-tool scale
that's microseconds; if you're serving thousands of requests a second,
front this with a real gateway — which is also where metering stops being
a voluntary path (see the README's honesty section).
"""
from __future__ import annotations

import json


def build_middleware(meter, *, skip_methods=("OPTIONS",)):
    """Return a middleware CLASS bound to `meter` (Starlette's
    `add_middleware` instantiates it with the downstream app)."""
    skip = frozenset(m.upper() for m in (skip_methods or ()))

    class MeterMiddleware:
        def __init__(self, app):
            self.app = app
            self.meter = meter
            self.skip_methods = skip

        async def __call__(self, scope, receive, send):
            stype = scope.get("type")
            if stype == "lifespan":
                # Startup/shutdown, not a caller. Must pass through.
                await self.app(scope, receive, send)
                return
            if stype != "http":
                # Anything else — websocket above all — used to be waved
                # through unkeyed and uncapped, which is the one thing
                # boundary middleware exists not to do. A streaming endpoint
                # is exactly where unbounded work hides. Refuse it rather
                # than meter it wrong; meter the handshake yourself if you
                # need WS traffic counted.
                await send({"type": "websocket.close", "code": 1008})
                return
            method = str(scope.get("method") or "").upper()
            if method in self.skip_methods:
                # Not a call. Not billed, not authenticated, not denied — a
                # preflight answered 401 is a CORS failure, not a metering
                # decision. Handlers can tell by the None.
                scope["arcaeon_meter"] = None
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
