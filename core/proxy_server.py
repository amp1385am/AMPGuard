"""
core/proxy_server.py
────────────────────
Lightweight intercepting HTTP proxy built on mitmproxy.
Runs on 127.0.0.1:8080 by default.

Usage
-----
    from core.proxy_server import InterceptProxy
    proxy = InterceptProxy(port=8080)
    proxy.request_callback  = lambda flow_data: ...   # called for every request
    proxy.response_callback = lambda flow_data: ...   # called for every response
    proxy.start()   # non-blocking — launches asyncio loop in a daemon thread
    proxy.stop()
"""

import asyncio
import threading
from datetime import datetime
from typing import Callable, Optional

from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster


# ──────────────────────────────────────────────────────
#  Flow data dict schema (passed to callbacks)
# ──────────────────────────────────────────────────────
# {
#   "id":           str,        unique flow id
#   "method":       str,
#   "url":          str,
#   "req_headers":  dict,
#   "req_body":     str,
#   "status":       int | None,
#   "resp_headers": dict,
#   "resp_body":    str,
#   "timestamp":    str,
# }


def _flow_to_dict(flow: http.HTTPFlow) -> dict:
    req = flow.request
    resp = flow.response

    req_body = ""
    try:
        req_body = req.content.decode("utf-8", errors="replace")
    except Exception:
        pass

    resp_body = ""
    status = None
    resp_headers: dict = {}
    if resp:
        try:
            resp_body = resp.content.decode("utf-8", errors="replace")
        except Exception:
            pass
        status = resp.status_code
        resp_headers = dict(resp.headers)

    return {
        "id":           flow.id,
        "method":       req.method,
        "url":          req.pretty_url,
        "req_headers":  dict(req.headers),
        "req_body":     req_body,
        "status":       status,
        "resp_headers": resp_headers,
        "resp_body":    resp_body,
        "timestamp":    datetime.now().strftime("%H:%M:%S"),
    }


# ──────────────────────────────────────────────────────
#  mitmproxy addon
# ──────────────────────────────────────────────────────

class _ProxyAddon:

    def __init__(self, interceptor: "InterceptProxy"):
        self._icp = interceptor

    def request(self, flow: http.HTTPFlow):
        data = _flow_to_dict(flow)
        self._icp._flows[flow.id] = flow          # keep live reference

        if self._icp.request_callback:
            self._icp.request_callback(data)

        # Intercept mode: pause until caller calls resume() or drop()
        if self._icp.intercept_enabled:
            flow.intercept()
            self._icp._pending[flow.id] = flow

    def response(self, flow: http.HTTPFlow):
        data = _flow_to_dict(flow)
        if self._icp.response_callback:
            self._icp.response_callback(data)


# ──────────────────────────────────────────────────────
#  Public API
# ──────────────────────────────────────────────────────

class InterceptProxy:
    """Thread-safe intercepting HTTP proxy."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port

        self.intercept_enabled: bool = False

        self.request_callback:  Optional[Callable[[dict], None]] = None
        self.response_callback: Optional[Callable[[dict], None]] = None

        self._flows:   dict[str, http.HTTPFlow] = {}
        self._pending: dict[str, http.HTTPFlow] = {}

        self._master: Optional[DumpMaster] = None
        self._loop:   Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None

    # ── lifecycle ──────────────────────────────────

    def start(self):
        """Start the proxy in a background daemon thread."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        if self._master:
            self._master.shutdown()
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

    # ── flow control ───────────────────────────────

    def resume_flow(self, flow_id: str):
        """Forward an intercepted request as-is."""
        flow = self._pending.pop(flow_id, None)
        if flow:
            flow.resume()

    def drop_flow(self, flow_id: str):
        """Drop an intercepted request."""
        flow = self._pending.pop(flow_id, None)
        if flow:
            flow.kill()

    def modify_and_resume(self, flow_id: str,
                          method: str = None,
                          url: str = None,
                          headers: dict = None,
                          body: str = None):
        """Edit a pending flow then forward it."""
        flow = self._pending.pop(flow_id, None)
        if not flow:
            return
        req = flow.request
        if method:
            req.method = method
        if url:
            req.url = url
        if headers:
            req.headers.clear()
            req.headers.update(headers)
        if body is not None:
            req.content = body.encode("utf-8", errors="replace")
        flow.resume()

    def replay(self, flow_id: str,
               method: str = None,
               url: str = None,
               headers: dict = None,
               body: str = None):
        """
        Replay a completed flow (optionally with edits).
        Sends the request directly via requests and fires response_callback.
        """
        import requests as req_lib

        orig = self._flows.get(flow_id)
        if not orig:
            return

        _method  = method  or orig.request.method
        _url     = url     or orig.request.pretty_url
        _headers = headers or dict(orig.request.headers)
        _body    = body.encode() if body else orig.request.content

        try:
            resp = req_lib.request(
                _method, _url, headers=_headers, data=_body, timeout=10,
                verify=False, allow_redirects=False
            )
            data = {
                "id":           flow_id + "_replay",
                "method":       _method,
                "url":          _url,
                "req_headers":  _headers,
                "req_body":     _body.decode("utf-8", errors="replace"),
                "status":       resp.status_code,
                "resp_headers": dict(resp.headers),
                "resp_body":    resp.text[:4000],
                "timestamp":    datetime.now().strftime("%H:%M:%S"),
            }
            if self.response_callback:
                self.response_callback(data)
        except Exception as e:
            if self.response_callback:
                self.response_callback({
                    "id": flow_id + "_replay_err",
                    "method": _method, "url": _url,
                    "req_headers": {}, "req_body": "",
                    "status": None, "resp_headers": {},
                    "resp_body": f"Replay error: {e}",
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                })

    # ── internal ───────────────────────────────────

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        opts = options.Options(
            listen_host=self.host,
            listen_port=self.port,
            ssl_insecure=True,
        )

        self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self._master.addons.add(_ProxyAddon(self))

        try:
            self._loop.run_until_complete(self._master.run())
        except Exception:
            pass