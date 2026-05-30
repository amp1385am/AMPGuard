from PySide6.QtCore import QThread, Signal

from core.scanner import WebScanner


class ScanWorker(QThread):

    log_signal = Signal(str)

    progress_signal = Signal(int)

    finished_signal = Signal(list)

    def __init__(self, target):

        super().__init__()

        self.target = target

    def run(self):

        scanner = WebScanner(self.target)

        self.log_signal.emit(
            "[SYSTEM] Scanner initialized."
        )

        self.progress_signal.emit(20)

        vulnerabilities = scanner.run_scan(
            self.log_signal.emit
        )

        self.progress_signal.emit(100)

        self.finished_signal.emit(vulnerabilities)