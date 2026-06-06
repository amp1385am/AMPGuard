from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLineEdit, QLabel,
    QProgressBar, QFrame, QListWidget, QStackedWidget,
    QTableWidget, QTableWidgetItem, QComboBox,
    QSizePolicy, QHeaderView
)
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from core.workers import ScanWorker
from core.report_generator import ReportGenerator
from core.database import DatabaseManager
from core.csv_exporter import CSVExporter

from datetime import datetime
import os
import webbrowser


# ══════════════════════════════════════════════════════
#  CHART WIDGET
# ══════════════════════════════════════════════════════

class ChartWidget(FigureCanvas):

    COLORS = {
        "Critical": "#ff2d55",
        "High":     "#ff6b35",
        "Medium":   "#ffd60a",
        "Low":      "#30d158",
    }

    def __init__(self):
        self.figure = Figure(figsize=(5, 5), facecolor="#1a1a1a")
        super().__init__(self.figure)
        self.ax = self.figure.add_subplot(111)
        self.ax.set_facecolor("#1a1a1a")
        self.setMinimumHeight(260)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def update_chart(self, vulnerabilities):
        self.ax.clear()
        self.ax.set_facecolor("#1a1a1a")

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in vulnerabilities:
            s = v.get("severity", "")
            if s in counts:
                counts[s] += 1

        labels = [k for k, v in counts.items() if v > 0]
        values = [counts[k] for k in labels]
        colors = [self.COLORS[k] for k in labels]

        if values:
            wedges, texts, autotexts = self.ax.pie(
                values,
                labels=labels,
                colors=colors,
                autopct="%1.0f%%",
                startangle=140,
                wedgeprops={"linewidth": 2, "edgecolor": "#1a1a1a"},
                textprops={"color": "white", "fontsize": 11},
            )
            for at in autotexts:
                at.set_color("white")
                at.set_fontsize(10)
        else:
            self.ax.text(
                0.5, 0.5, "No data",
                color="#555", ha="center", va="center",
                transform=self.ax.transAxes, fontsize=13
            )

        self.ax.set_title(
            "Vulnerability Breakdown",
            color="#00ff99", fontsize=13, pad=14
        )
        self.figure.tight_layout()
        self.draw()


# ══════════════════════════════════════════════════════
#  STAT CARD
# ══════════════════════════════════════════════════════

class StatCard(QFrame):
    """Compact card: icon label + big counter + sub-label."""

    def __init__(self, title: str, icon: str, accent: str = "#00ff99"):
        super().__init__()
        self.accent = accent
        self.setObjectName("StatCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        # Icon + title row
        top = QHBoxLayout()
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(f"color: {accent}; font-size: 18px;")
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("color: #888; font-size: 12px; font-weight: 600;")
        top.addWidget(icon_lbl)
        top.addWidget(title_lbl)
        top.addStretch()
        layout.addLayout(top)

        # Big number
        self.value_label = QLabel("0")
        self.value_label.setStyleSheet(
            f"color: {accent}; font-size: 32px; font-weight: 700;"
        )
        self.value_label.setAlignment(Qt.AlignLeft)
        layout.addWidget(self.value_label)

        self.setStyleSheet(f"""
            #StatCard {{
                background-color: #1e1e1e;
                border: 1px solid #2a2a2a;
                border-radius: 10px;
            }}
            #StatCard:hover {{
                border: 1px solid {accent};
            }}
        """)

    def set_value(self, v):
        self.value_label.setText(str(v))


# ══════════════════════════════════════════════════════
#  REAL-TIME STATS BAR
# ══════════════════════════════════════════════════════

class StatsBar(QFrame):
    """Horizontal bar showing live scan metrics."""

    def __init__(self):
        super().__init__()
        self.setObjectName("StatsBar")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(24)

        self._lbl_urls  = self._make_metric("URLs scanned", "0 / 0")
        self._lbl_speed = self._make_metric("Speed", "0 URL/s")
        self._lbl_eta   = self._make_metric("ETA", "—")

        for row in [self._lbl_urls, self._lbl_speed, self._lbl_eta]:
            layout.addLayout(row["layout"])
        layout.addStretch()

        self.setStyleSheet("""
            #StatsBar {
                background: #181818;
                border: 1px solid #2a2a2a;
                border-radius: 8px;
            }
        """)
        self.setVisible(False)

    def _make_metric(self, name: str, default: str) -> dict:
        col = QVBoxLayout()
        col.setSpacing(1)
        n = QLabel(name)
        n.setStyleSheet("color: #555; font-size: 10px; font-weight: 600;")
        v = QLabel(default)
        v.setStyleSheet("color: #cccccc; font-size: 13px; font-weight: 600;")
        col.addWidget(n)
        col.addWidget(v)
        return {"layout": col, "value": v}

    def update_stats(self, data: dict):
        self.setVisible(True)
        self._lbl_urls["value"].setText(
            f"{data['urls_scanned']} / {data['urls_total']}"
        )
        self._lbl_speed["value"].setText(f"{data['speed']} URL/s")
        eta = data["eta_sec"]
        self._lbl_eta["value"].setText(
            f"{eta}s" if eta > 0 else ("Done" if data["urls_scanned"] > 0 else "—")
        )

    def reset(self):
        self._lbl_urls["value"].setText("0 / 0")
        self._lbl_speed["value"].setText("0 URL/s")
        self._lbl_eta["value"].setText("—")
        self.setVisible(False)


# ══════════════════════════════════════════════════════
#  RICH TERMINAL
# ══════════════════════════════════════════════════════

class RichTerminal(QTextEdit):
    """Color-coded read-only log terminal."""

    COLORS = {
        "[SYSTEM]":  "#00ff99",
        "[INFO]":    "#5ac8fa",
        "[SCAN]":    "#64d2ff",
        "[CRAWLER]": "#bf5af2",
        "[FOUND]":   "#30d158",
        "[VULN]":    "#ff375f",
        "[FORM]":    "#ffd60a",
        "[DEBUG]":   "#636366",
        "[HEADER]":  "#636366",
        "[REPORT]":  "#5ac8fa",
        "[ERROR]":   "#ff453a",
        "[MULTI]":   "#ffd60a",
        "[HTTP":     "#3a3a3a",
    }
    DEFAULT_COLOR = "#a0a0a0"

    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Courier New", 11))
        self.setStyleSheet("""
            QTextEdit {
                background-color: #0d0d0d;
                color: #a0a0a0;
                border: 1px solid #2a2a2a;
                border-radius: 8px;
                padding: 8px;
            }
        """)
        self.setMinimumHeight(180)

    def append_colored(self, message: str):
        color = self.DEFAULT_COLOR
        for tag, c in self.COLORS.items():
            if tag in message:
                color = c
                break

        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.End)

        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(message + "\n")
        self.setTextCursor(cursor)
        self.ensureCursorVisible()


# ══════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.db = DatabaseManager()
        self.workers = []
        self.current_vulnerabilities = []

        self.setWindowTitle("AMPGuard")
        self.resize(1400, 860)

        # ── Central widget ────────────────────────────
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # ── Sidebar ───────────────────────────────────
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(220)
        for item in ["🛡  Dashboard", "⚡  Scanner", "📄  Reports", "⚙  Settings"]:
            self.sidebar.addItem(item)
        self.sidebar.setStyleSheet("""
            QListWidget {
                background-color: #141414;
                color: #888;
                border: none;
                outline: 0;
                font-size: 14px;
                padding: 8px 0;
            }
            QListWidget::item {
                padding: 13px 18px;
                border-radius: 8px;
                margin: 2px 8px;
            }
            QListWidget::item:selected {
                background-color: #00ff9922;
                color: #00ff99;
                font-weight: bold;
            }
            QListWidget::item:hover:!selected {
                background-color: #1e1e1e;
                color: #cccccc;
            }
        """)

        self.toggle_sidebar_button = QPushButton("☰")
        self.toggle_sidebar_button.setFixedSize(40, 40)
        self.toggle_sidebar_button.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #888;
                font-size: 18px;
                border: none;
            }
            QPushButton:hover { color: #00ff99; }
        """)

        sidebar_wrapper = QVBoxLayout()
        sidebar_wrapper.setContentsMargins(0, 6, 0, 0)
        sidebar_wrapper.setSpacing(0)
        sidebar_wrapper.addWidget(self.toggle_sidebar_button, alignment=Qt.AlignLeft)
        sidebar_wrapper.addWidget(self.sidebar)

        sidebar_frame = QFrame()
        sidebar_frame.setStyleSheet("background-color: #141414; border-right: 1px solid #222;")
        sidebar_frame.setLayout(sidebar_wrapper)

        # ── Pages ─────────────────────────────────────
        self.pages = QStackedWidget()

        # -- Dashboard page ---------------------------
        dash = QWidget()
        dash_layout = QVBoxLayout(dash)
        dash_layout.setSpacing(10)
        dash_layout.setContentsMargins(20, 16, 20, 16)

        # Title
        title = QLabel("AMPGuard  ·  Web Pentest Scanner")
        title.setStyleSheet("font-size: 22px; font-weight: 700; color: #00ff99;")
        title.setAlignment(Qt.AlignLeft)
        dash_layout.addWidget(title)

        # URL row
        url_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://target.example.com")
        self.url_input.setMinimumHeight(38)
        self.start_button = QPushButton("▶  Start Scan")
        self.start_button.setFixedHeight(38)
        self.start_button.setFixedWidth(140)
        url_row.addWidget(self.url_input)
        url_row.addWidget(self.start_button)
        dash_layout.addLayout(url_row)

        # Progress
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setFixedHeight(6)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar { background: #222; border-radius: 3px; border: none; }
            QProgressBar::chunk { background: #00ff99; border-radius: 3px; }
        """)
        dash_layout.addWidget(self.progress)

        # Stats bar
        self.stats_bar = StatsBar()
        dash_layout.addWidget(self.stats_bar)

        # Vuln type cards
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)
        self.sqli_card = StatCard("SQL Injection", "💉", "#ff2d55")
        self.xss_card  = StatCard("XSS",           "⚡", "#ff6b35")
        self.lfi_card  = StatCard("LFI",            "📂", "#ffd60a")
        self.ssrf_card = StatCard("SSRF",           "🌐", "#bf5af2")
        for card in [self.sqli_card, self.xss_card, self.lfi_card, self.ssrf_card]:
            cards_row.addWidget(card)
        dash_layout.addLayout(cards_row)

        # Search / filter row
        filter_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search vulnerabilities…")
        self.search_input.setMaximumWidth(300)
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        filter_row.addWidget(self.search_input)
        filter_row.addWidget(self.severity_filter)
        filter_row.addStretch()
        dash_layout.addLayout(filter_row)

        # Terminal + Chart side by side
        mid_row = QHBoxLayout()
        mid_row.setSpacing(12)

        # Terminal
        self.terminal = RichTerminal()
        self.terminal.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        mid_row.addWidget(self.terminal, stretch=3)

        # Chart
        self.chart = ChartWidget()
        mid_row.addWidget(self.chart, stretch=2)

        dash_layout.addLayout(mid_row)

        # Vuln table
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(3)
        self.vuln_table.setHorizontalHeaderLabels(["Type", "URL", "Severity"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.vuln_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.vuln_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.vuln_table.setAlternatingRowColors(True)
        self.vuln_table.setShowGrid(False)
        self.vuln_table.verticalHeader().setVisible(False)
        self.vuln_table.setMaximumHeight(220)
        self.vuln_table.setStyleSheet("""
            QTableWidget {
                background-color: #111;
                alternate-background-color: #161616;
                color: #ccc;
                border: 1px solid #2a2a2a;
                border-radius: 8px;
                gridline-color: transparent;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #1e1e1e;
                color: #888;
                font-weight: 600;
                font-size: 11px;
                padding: 6px 10px;
                border: none;
                border-bottom: 1px solid #2a2a2a;
                text-transform: uppercase;
            }
            QTableWidget::item { padding: 6px 10px; }
            QTableWidget::item:selected { background-color: #00ff9930; }
        """)
        dash_layout.addWidget(self.vuln_table)

        # -- Scanner page ----------------------------
        scanner_page = QWidget()
        scanner_layout = QVBoxLayout(scanner_page)
        scanner_layout.setContentsMargins(20, 16, 20, 16)

        scanner_title = QLabel("Multi-Target Scanner")
        scanner_title.setStyleSheet("color: #00ff99; font-size: 20px; font-weight: 700;")
        scanner_layout.addWidget(scanner_title)

        self.multi_target_input = QTextEdit()
        self.multi_target_input.setPlaceholderText(
            "Enter multiple targets — one per line:\n"
            "https://site1.example.com\n"
            "https://site2.example.com"
        )
        scanner_layout.addWidget(self.multi_target_input)

        self.multi_scan_button = QPushButton("▶  Start Multi-Target Scan")
        self.multi_scan_button.setFixedHeight(38)
        scanner_layout.addWidget(self.multi_scan_button)
        scanner_layout.addStretch()

        # -- Reports page ----------------------------
        reports_page = QWidget()
        reports_layout = QVBoxLayout(reports_page)
        reports_layout.setContentsMargins(20, 16, 20, 16)

        reports_title = QLabel("Scan History & Reports")
        reports_title.setStyleSheet("color: #00ff99; font-size: 20px; font-weight: 700;")
        reports_layout.addWidget(reports_title)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(3)
        self.history_table.setHorizontalHeaderLabels(["ID", "Target", "Date"])
        self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setShowGrid(False)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setStyleSheet(self.vuln_table.styleSheet())
        reports_layout.addWidget(self.history_table)

        reports_layout.addWidget(QLabel("Generated Reports:"))
        self.report_list = QListWidget()
        self.report_list.setMaximumHeight(160)
        reports_layout.addWidget(self.report_list)

        self.open_report_button = QPushButton("📂  Open Selected Report")
        self.open_report_button.setFixedHeight(36)
        reports_layout.addWidget(self.open_report_button)
        reports_layout.addStretch()

        # -- Settings page ---------------------------
        settings_page = QWidget()
        settings_layout = QVBoxLayout(settings_page)
        settings_layout.setContentsMargins(20, 16, 20, 16)

        settings_title = QLabel("Settings")
        settings_title.setStyleSheet("color: #00ff99; font-size: 20px; font-weight: 700;")
        settings_layout.addWidget(settings_title)

        settings_layout.addWidget(QLabel("UI Theme:"))
        self.theme_selector = QComboBox()
        self.theme_selector.addItems(["Cyber Dark", "Hacker Neon"])
        settings_layout.addWidget(self.theme_selector)

        self.apply_theme_button = QPushButton("Apply Theme")
        self.apply_theme_button.setFixedHeight(36)
        settings_layout.addWidget(self.apply_theme_button)
        settings_layout.addStretch()

        # ── Assemble pages ────────────────────────────
        self.pages.addWidget(dash)
        self.pages.addWidget(scanner_page)
        self.pages.addWidget(reports_page)
        self.pages.addWidget(settings_page)

        main_layout.addWidget(sidebar_frame)
        main_layout.addWidget(self.pages, stretch=1)

        # ── Load theme ────────────────────────────────
        self.load_theme("cyber_dark.qss")

        # ── Signals ───────────────────────────────────
        self.start_button.clicked.connect(self.start_scan)
        self.sidebar.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.open_report_button.clicked.connect(self.open_report)
        self.multi_scan_button.clicked.connect(self.start_multi_scan)
        self.search_input.textChanged.connect(self.filter_vulnerabilities)
        self.severity_filter.currentTextChanged.connect(self.filter_vulnerabilities)
        self.toggle_sidebar_button.clicked.connect(self.toggle_sidebar)
        self.apply_theme_button.clicked.connect(self.change_theme)

        self.sidebar.setCurrentRow(0)
        self.sidebar_expanded = True

        self.load_scan_history()

    # ══════════════════════════════════════════════════
    #  SCAN CONTROL
    # ══════════════════════════════════════════════════

    def start_scan(self):
        target = self.url_input.text().strip()
        if not target:
            self.terminal.append_colored("[ERROR] Please enter a target URL.")
            return

        self.terminal.clear()
        self.vuln_table.setRowCount(0)
        self.progress.setValue(0)
        self.stats_bar.reset()
        self.start_button.setEnabled(False)
        self._reset_cards()

        self.worker = ScanWorker(target)
        self.worker.log_signal.connect(self.terminal.append_colored)
        self.worker.vuln_found_signal.connect(self.add_vuln_live)
        self.worker.progress_signal.connect(self.progress.setValue)
        self.worker.stats_signal.connect(self.stats_bar.update_stats)
        self.worker.finished_signal.connect(self.scan_finished)
        self.worker.start()

    def start_multi_scan(self):
        targets = self.multi_target_input.toPlainText().splitlines()
        for target in targets:
            target = target.strip()
            if not target:
                continue
            self.terminal.append_colored(f"[MULTI] Starting scan: {target}")
            w = ScanWorker(target)
            self.workers.append(w)
            w.log_signal.connect(self.terminal.append_colored)
            w.progress_signal.connect(self.progress.setValue)
            w.stats_signal.connect(self.stats_bar.update_stats)
            w.finished_signal.connect(self.scan_finished)
            w.start()

    # ══════════════════════════════════════════════════
    #  VULN TABLE
    # ══════════════════════════════════════════════════

    SEVERITY_COLORS = {
        "Critical": ("#ff2d55", "#fff"),
        "High":     ("#ff6b35", "#fff"),
        "Medium":   ("#ffd60a", "#000"),
        "Low":      ("#30d158", "#000"),
    }

    def add_vuln_live(self, vuln: dict):
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        self._set_row(row, vuln)

    def fill_vulnerability_table(self, vulns: list):
        self.vuln_table.setRowCount(len(vulns))
        for row, v in enumerate(vulns):
            self._set_row(row, v)

    def _set_row(self, row: int, vuln: dict):
        self.vuln_table.setItem(row, 0, QTableWidgetItem(vuln["type"]))
        self.vuln_table.setItem(row, 1, QTableWidgetItem(vuln["url"]))

        sev   = vuln["severity"]
        item  = QTableWidgetItem(f"  {sev}  ")
        item.setTextAlignment(Qt.AlignCenter)

        bg, fg = self.SEVERITY_COLORS.get(sev, ("#444", "#fff"))
        item.setBackground(QColor(bg))
        item.setForeground(QColor(fg))

        font = item.font()
        font.setBold(True)
        item.setFont(font)

        self.vuln_table.setItem(row, 2, item)

    def filter_vulnerabilities(self):
        if not self.current_vulnerabilities:
            return
        q   = self.search_input.text().lower()
        sev = self.severity_filter.currentText()
        out = [
            v for v in self.current_vulnerabilities
            if (q in v["type"].lower() or q in v["url"].lower())
            and (sev == "All" or v["severity"] == sev)
        ]
        self.fill_vulnerability_table(out)

    # ══════════════════════════════════════════════════
    #  SCAN FINISHED
    # ══════════════════════════════════════════════════

    def scan_finished(self, vulnerabilities: list):
        self.start_button.setEnabled(True)
        self.current_vulnerabilities = vulnerabilities

        self.terminal.append_colored("[SYSTEM] Scan completed successfully.")

        counts = {"sql": 0, "xss": 0, "lfi": 0, "ssrf": 0}
        for v in vulnerabilities:
            t = v["type"].lower()
            for k in counts:
                if k in t:
                    counts[k] += 1

        self.sqli_card.set_value(counts["sql"])
        self.xss_card.set_value(counts["xss"])
        self.lfi_card.set_value(counts["lfi"])
        self.ssrf_card.set_value(counts["ssrf"])

        # DB
        scan_id = self.db.save_scan(self.url_input.text(), str(datetime.now()))
        for v in vulnerabilities:
            self.db.save_vulnerability(scan_id, v["type"], v["url"], v["severity"])

        # Reports
        for gen, tag in [
            (ReportGenerator.generate_json_report, "JSON"),
            (ReportGenerator.generate_html_report, "HTML"),
            (ReportGenerator.generate_pdf_report,  "PDF"),
        ]:
            path = gen(self.url_input.text(), vulnerabilities)
            self.terminal.append_colored(f"[REPORT] {tag} saved: {path}")
            self.report_list.addItem(path)

        csv_path = CSVExporter.export(self.url_input.text(), vulnerabilities)
        self.terminal.append_colored(f"[REPORT] CSV saved: {csv_path}")
        self.report_list.addItem(csv_path)

        self.fill_vulnerability_table(vulnerabilities)
        self.chart.update_chart(vulnerabilities)
        self.load_scan_history()

    # ══════════════════════════════════════════════════
    #  HELPERS
    # ══════════════════════════════════════════════════

    def open_report(self):
        item = self.report_list.currentItem()
        if not item:
            return
        path = item.text()
        if os.path.exists(path):
            webbrowser.open(path)
        else:
            self.terminal.append_colored("[ERROR] Report file not found.")

    def _reset_cards(self):
        for card in [self.sqli_card, self.xss_card, self.lfi_card, self.ssrf_card]:
            card.set_value(0)

    def load_scan_history(self):
        scans = self.db.get_scans()
        self.history_table.setRowCount(len(scans))
        for row, scan in enumerate(scans):
            for col, val in enumerate(scan[:3]):
                self.history_table.setItem(row, col, QTableWidgetItem(str(val)))

    def toggle_sidebar(self):
        self.animation = QPropertyAnimation(self.sidebar, b"maximumWidth")
        self.animation.setDuration(280)
        self.animation.setEasingCurve(QEasingCurve.InOutCubic)
        if self.sidebar_expanded:
            self.animation.setStartValue(220)
            self.animation.setEndValue(0)
            self.sidebar_expanded = False
        else:
            self.animation.setStartValue(0)
            self.animation.setEndValue(220)
            self.sidebar_expanded = True
        self.animation.start()

    def load_theme(self, theme_file: str):
        try:
            base = os.path.dirname(os.path.dirname(__file__))
            path = os.path.join(base, "gui", "styles", theme_file)
            with open(path, "r") as f:
                self.setStyleSheet(f.read())
            print(f"Theme loaded: {theme_file}")
        except Exception as e:
            print(f"Theme error: {e}")

    def change_theme(self):
        name = self.theme_selector.currentText()
        file = "cyber_dark.qss" if name == "Cyber Dark" else "hacker_neon.qss"
        self.load_theme(file)
        self.terminal.append_colored(f"[SYSTEM] Theme changed to {name}")


APP_VERSION = "0.2.1"