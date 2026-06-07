from PySide6.QtCore import QThread, Signal
import time

from core.scanner import WebScanner
from requests import session


class ScanWorker(QThread):

    log_signal = Signal(str)
    progress_signal = Signal(int)
    vuln_found_signal = Signal(dict)
    finished_signal = Signal(list)

    # ── NEW: real-time stats ──────────────────────────
    stats_signal = Signal(dict)
    # dict keys: urls_scanned, urls_total, speed, eta_sec

    def __init__(self, target, session=None):
        super().__init__()
        self.target = target
        self._start_time = None
        self.custom_session = session

    # ─────────────────────────────────────────────────
    def run(self):
        self._start_time = time.time()

        scanner = WebScanner(self.target, session=self.custom_session)
        scanner.vuln_callback = self.vuln_found_signal.emit

        # Wrap the scanner's URL-by-URL progress so we
        # can emit stats after each URL finishes.
        original_log = None

        def stats_aware_log(msg):
            if original_log:
                original_log(msg)

            elapsed = time.time() - self._start_time
            scanned = len(scanner.visited_urls)
            total   = max(len(scanner.urls_to_scan), scanned, 1)

            speed = scanned / elapsed if elapsed > 0 else 0
            remaining = total - scanned
            eta = int(remaining / speed) if speed > 0 else 0

            self.stats_signal.emit({
                "urls_scanned": scanned,
                "urls_total":   total,
                "speed":        round(speed, 2),
                "eta_sec":      eta,
            })

        original_log = self.log_signal.emit

        self.log_signal.emit("[SYSTEM] Scanner initialized.")
        self.progress_signal.emit(10)

        vulnerabilities = scanner.run_scan(stats_aware_log)

        self.progress_signal.emit(100)

        # Final stats burst
        elapsed = time.time() - self._start_time
        scanned = len(scanner.visited_urls)
        self.stats_signal.emit({
            "urls_scanned": scanned,
            "urls_total":   scanned,
            "speed":        round(scanned / elapsed, 2) if elapsed > 0 else 0,
            "eta_sec":      0,
        })

        self.finished_signal.emit(vulnerabilities)