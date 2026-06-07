"""
core/proxy_worker.py
────────────────────
QThread wrapper around InterceptProxy.
Emits Qt signals so the GUI can update safely from the proxy thread.
"""

from PySide6.QtCore import QThread, Signal
from core.proxy_server import InterceptProxy


class ProxyWorker(QThread):

    # emitted for every request/response seen by the proxy
    request_signal  = Signal(dict)   # flow_data dict
    response_signal = Signal(dict)   # flow_data dict
    status_signal   = Signal(str)    # human-readable status message

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        super().__init__()
        self.host = host
        self.port = port
        self.proxy = InterceptProxy(host=host, port=port)

    # ── QThread entry point ────────────────────────

    def run(self):
        self.proxy.request_callback  = self.request_signal.emit
        self.proxy.response_callback = self.response_signal.emit
        self.status_signal.emit(f"[PROXY] Listening on {self.host}:{self.port}")
        self.proxy.start()
        # Keep thread alive — proxy runs its own daemon thread
        self.exec()

    def stop_proxy(self):
        self.proxy.stop()
        self.quit()

    # ── Flow control (called from GUI thread) ──────

    def set_intercept(self, enabled: bool):
        self.proxy.intercept_enabled = enabled

    def resume(self, flow_id: str):
        self.proxy.resume_flow(flow_id)

    def drop(self, flow_id: str):
        self.proxy.drop_flow(flow_id)

    def modify_and_resume(self, flow_id: str, method: str,
                          url: str, headers: dict, body: str):
        self.proxy.modify_and_resume(flow_id, method, url, headers, body)

    def replay(self, flow_id: str, method: str,
               url: str, headers: dict, body: str):
        self.proxy.replay(flow_id, method, url, headers, body)