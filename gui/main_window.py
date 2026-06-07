from tokenize import tabsize

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLineEdit, QLabel,
    QProgressBar, QFrame, QListWidget, QStackedWidget,
    QTableWidget, QTableWidgetItem, QComboBox,
    QSizePolicy, QHeaderView, QDialog, QDialogButtonBox,
    QScrollArea, QFormLayout, QDoubleSpinBox, QTabWidget        # اضافه شده QDoubleSpinBox
)
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QSettings
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from core.workers import ScanWorker
from core.report_generator import ReportGenerator
from core.database import DatabaseManager
from core.csv_exporter import CSVExporter
from core.md_exporter import MarkdownExporter
from core.xml_exporter import XMLExporter

from datetime import datetime
import os
import webbrowser
import requests


# ══════════════════════════════════════════════════════
#  VULN DETAIL POPUP (بدون تغییر)
# ══════════════════════════════════════════════════════

class VulnDetailDialog(QDialog):
    """Popup showing full details of a single vulnerability."""

    SEVERITY_COLORS = {
        "Critical": "#ff2d55",
        "High":     "#ff6b35",
        "Medium":   "#ffd60a",
        "Low":      "#30d158",
    }

    def __init__(self, vuln: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Vulnerability Detail")
        self.setMinimumWidth(560)
        self.setStyleSheet("""
            QDialog {
                background-color: #111;
                color: #ccc;
            }
            QLabel { color: #ccc; }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(24, 20, 24, 20)

        sev   = vuln.get("severity", "—")
        color = self.SEVERITY_COLORS.get(sev, "#888")

        # ── Header ──────────────────────────────────
        header = QHBoxLayout()
        type_lbl = QLabel(vuln.get("type", "Unknown"))
        type_lbl.setStyleSheet("font-size: 18px; font-weight: 700; color: #fff;")
        sev_lbl = QLabel(f"  {sev}  ")
        sev_lbl.setStyleSheet(
            f"background:{color}; color:{'#000' if sev in ('Medium','Low') else '#fff'};"
            f"border-radius:4px; font-weight:700; font-size:12px; padding:2px 8px;"
        )
        sev_lbl.setFixedHeight(24)
        header.addWidget(type_lbl)
        header.addStretch()
        header.addWidget(sev_lbl)
        layout.addLayout(header)

        # ── Divider ──────────────────────────────────
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #2a2a2a;")
        layout.addWidget(line)

        # ── Fields ───────────────────────────────────
        def field(label: str, value: str, mono=False):
            row = QVBoxLayout()
            row.setSpacing(2)
            lbl = QLabel(label.upper())
            lbl.setStyleSheet("color:#555; font-size:10px; font-weight:700;")
            val = QLabel(value or "—")
            val.setWordWrap(True)
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            style = "color:#e0e0e0; font-size:13px;"
            if mono:
                style += " font-family: 'Courier New', monospace;"
            val.setStyleSheet(style)
            row.addWidget(lbl)
            row.addWidget(val)
            return row

        layout.addLayout(field("URL", vuln.get("url", "—"), mono=True))
        layout.addLayout(field("Detail", vuln.get("detail", "No additional detail")))
        layout.addLayout(field("Severity", sev))
        layout.addLayout(field("Detected at", vuln.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))))

        # ── Remediation hint ─────────────────────────
        hints = {
            "SQL Injection":          "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
            "Reflected XSS":          "Encode all user-supplied output. Implement a strict Content-Security-Policy.",
            "Form XSS":               "Validate and encode form inputs server-side before rendering.",
            "LFI / Path Traversal":   "Whitelist allowed file paths. Never pass user input directly to file-system calls.",
            "SSRF":                   "Whitelist allowed outbound URLs. Block requests to internal/cloud metadata IPs.",
            "Missing CSRF Token":     "Add a cryptographically random CSRF token to every state-changing POST form.",
            "Missing Security Header":"Add the missing HTTP security header to all responses.",
            "Interesting Endpoint":   "Review whether this endpoint should be publicly accessible.",
        }
        hint = hints.get(vuln.get("type", ""), "Consult OWASP guidelines for remediation advice.")
        layout.addLayout(field("Remediation", hint))

        # ── Close button ─────────────────────────────
        btn = QDialogButtonBox(QDialogButtonBox.Close)
        btn.rejected.connect(self.reject)
        btn.setStyleSheet("""
            QPushButton {
                background:#00ff99; color:#000;
                border:none; border-radius:6px;
                padding:6px 20px; font-weight:700;
            }
            QPushButton:hover { background:#00e588; }
        """)
        layout.addWidget(btn)


# ══════════════════════════════════════════════════════
#  DUAL CHART WIDGET  (Bar + Pie side-by-side)
# ══════════════════════════════════════════════════════

class ChartWidget(FigureCanvas):

    SEVERITY_ORDER  = ["Critical", "High", "Medium", "Low"]
    COLORS = {
        "Critical": "#ff2d55",
        "High":     "#ff6b35",
        "Medium":   "#ffd60a",
        "Low":      "#30d158",
    }

    TYPE_COLORS = {
        "SQL Injection":            "#ff2d55",
        "Reflected XSS":            "#ff6b35",
        "Form XSS":                 "#ff9f4a",
        "LFI / Path Traversal":     "#ffd60a",
        "SSRF":                     "#bf5af2",
        "Missing CSRF Token":       "#5ac8fa",
        "Missing Security Header":  "#30d158",
        "Interesting Endpoint":     "#888888",
        "Other":                    "#aaaaaa",
    }

    def __init__(self):
        self.figure = Figure(figsize=(9, 3.6), facecolor="#1a1a1a")
        super().__init__(self.figure)
        self.setMinimumHeight(240)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._draw_empty()

    def _draw_empty(self):
        self.figure.clear()
        for i, title in enumerate(["Vuln Types", "Severity Split"]):
            ax = self.figure.add_subplot(1, 2, i + 1)
            ax.set_facecolor("#1a1a1a")
            ax.text(0.5, 0.5, "No data", color="#444",
                    ha="center", va="center", transform=ax.transAxes, fontsize=12)
            ax.set_title(title, color="#00ff99", fontsize=11, pad=10)
            ax.tick_params(colors="#555")
            for spine in ax.spines.values():
                spine.set_edgecolor("#2a2a2a")
        self.figure.tight_layout(pad=2)
        self.draw()

    def update_chart(self, vulnerabilities):
        self.figure.clear()

        # ── Count by type ────────────────────────────
        type_counts: dict = {}
        sev_counts  = {s: 0 for s in self.SEVERITY_ORDER}

        for v in vulnerabilities:
            t = v.get("type", "Other")
            s = v.get("severity", "")
            type_counts[t] = type_counts.get(t, 0) + 1
            if s in sev_counts:
                sev_counts[s] += 1

        # ── Bar chart (left) ─────────────────────────
        ax_bar = self.figure.add_subplot(1, 2, 1)
        ax_bar.set_facecolor("#1a1a1a")

        if type_counts:
            labels = list(type_counts.keys())
            values = list(type_counts.values())
            bar_colors = [self.TYPE_COLORS.get(l, "#00ff99") for l in labels]
            bars = ax_bar.barh(labels, values, color=bar_colors, height=0.55)
            ax_bar.set_xlabel("Count", color="#666", fontsize=9)
            ax_bar.tick_params(axis="y", labelsize=8, colors="#aaa")
            ax_bar.tick_params(axis="x", labelsize=8, colors="#555")
            for spine in ax_bar.spines.values():
                spine.set_edgecolor("#2a2a2a")
            for bar, val in zip(bars, values):
                ax_bar.text(
                    bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                    str(val), va="center", color="#ccc", fontsize=8
                )
        else:
            ax_bar.text(0.5, 0.5, "No data", color="#444",
                        ha="center", va="center", transform=ax_bar.transAxes)

        ax_bar.set_title("Vuln Types", color="#00ff99", fontsize=11, pad=10)

        # ── Pie chart (right) ────────────────────────
        ax_pie = self.figure.add_subplot(1, 2, 2)
        ax_pie.set_facecolor("#1a1a1a")

        pie_labels = [s for s in self.SEVERITY_ORDER if sev_counts[s] > 0]
        pie_values = [sev_counts[s] for s in pie_labels]
        pie_colors = [self.COLORS[s] for s in pie_labels]

        if pie_values:
            wedges, texts, autotexts = ax_pie.pie(
                pie_values,
                labels=pie_labels,
                colors=pie_colors,
                autopct="%1.0f%%",
                startangle=140,
                wedgeprops={"linewidth": 2, "edgecolor": "#1a1a1a"},
                textprops={"color": "white", "fontsize": 9},
            )
            for at in autotexts:
                at.set_color("white")
                at.set_fontsize(8)
        else:
            ax_pie.text(0.5, 0.5, "No data", color="#444",
                        ha="center", va="center", transform=ax_pie.transAxes)

        ax_pie.set_title("Severity Split", color="#00ff99", fontsize=11, pad=10)

        self.figure.tight_layout(pad=2)
        self.draw()


# ══════════════════════════════════════════════════════
#  STAT CARD
# ══════════════════════════════════════════════════════

class StatCard(QFrame):

    def __init__(self, title: str, icon: str, accent: str = "#00ff99"):
        super().__init__()
        self.accent = accent
        self.setObjectName("StatCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        top = QHBoxLayout()
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(f"color: {accent}; font-size: 18px;")
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("color: #888; font-size: 12px; font-weight: 600;")
        top.addWidget(icon_lbl)
        top.addWidget(title_lbl)
        top.addStretch()
        layout.addLayout(top)

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
            #StatCard:hover {{ border: 1px solid {accent}; }}
        """)

    def set_value(self, v):
        self.value_label.setText(str(v))


# ══════════════════════════════════════════════════════
#  STATS BAR
# ══════════════════════════════════════════════════════

class StatsBar(QFrame):

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
        self._lbl_urls["value"].setText(f"{data['urls_scanned']} / {data['urls_total']}")
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
#  MAIN WINDOW (با احراز هویت + Rate Limiting)
# ══════════════════════════════════════════════════════

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.db = DatabaseManager()
        self.workers = []
        self.current_vulnerabilities = []
        self.auth_config = {"type": "None"}

        self.setWindowTitle("AMPGuard")
        self.resize(1400, 900)

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
            QPushButton { background: transparent; color: #888; font-size: 18px; border: none; }
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

        # ── Dashboard ─────────────────────────────────
        dash = QWidget()
        dash_layout = QVBoxLayout(dash)
        dash_layout.setSpacing(10)
        dash_layout.setContentsMargins(20, 16, 20, 16)

        title = QLabel("AMPGuard  ·  Web Pentest Scanner")
        title.setStyleSheet("font-size: 22px; font-weight: 700; color: #00ff99;")
        dash_layout.addWidget(title)

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

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setFixedHeight(6)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar { background: #222; border-radius: 3px; border: none; }
            QProgressBar::chunk { background: #00ff99; border-radius: 3px; }
        """)
        dash_layout.addWidget(self.progress)

        self.stats_bar = StatsBar()
        dash_layout.addWidget(self.stats_bar)

        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)
        self.sqli_card = StatCard("SQL Injection", "💉", "#ff2d55")
        self.xss_card  = StatCard("XSS",           "⚡", "#ff6b35")
        self.lfi_card  = StatCard("LFI",            "📂", "#ffd60a")
        self.ssrf_card = StatCard("SSRF",           "🌐", "#bf5af2")
        self.csrf_card = StatCard("CSRF",           "🔓", "#5ac8fa")
        for card in [self.sqli_card, self.xss_card, self.lfi_card,
                     self.ssrf_card, self.csrf_card]:
            cards_row.addWidget(card)
        dash_layout.addLayout(cards_row)

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

        mid_row = QHBoxLayout()
        mid_row.setSpacing(12)

        self.terminal = RichTerminal()
        self.terminal.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        mid_row.addWidget(self.terminal, stretch=3)

        self.chart = ChartWidget()
        mid_row.addWidget(self.chart, stretch=3)

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
        self.vuln_table.setToolTip("Double-click a row to see full details")
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
        self.vuln_table.doubleClicked.connect(self._show_vuln_detail)
        dash_layout.addWidget(self.vuln_table)

        # ── Scanner page ──────────────────────────────
        scanner_page = QWidget()
        scanner_layout = QVBoxLayout(scanner_page)
        scanner_layout.setContentsMargins(20, 16, 20, 16)

        tabs = QTabWidget()
        #تب 1: Multi-Target (همان widgets قبلی)
        multi_widget = QWidget()
        multi_layout = QVBoxLayout(multi_widget)
        self.multi_target_input = QTextEdit()
        # ... بقیه اجزای multi-target
        multi_layout.addWidget(self.multi_target_input)
        self.multi_scan_button = QPushButton("▶  Start Multi-Target Scan")
        multi_layout.addWidget(self.multi_scan_button)
        multi_layout.addStretch()
        tabs.addTab(multi_widget, "🌐 Multi-Target")

        # تب 2: REST API Scanner
        api_widget = QWidget()
        api_layout = QVBoxLayout(api_widget)
        api_layout.addWidget(QLabel("Base URL:"))
        self.api_base_url = QLineEdit()
        self.api_base_url.setPlaceholderText("https://api.target.com/v1")
        api_layout.addWidget(self.api_base_url)

        api_layout.addWidget(QLabel("Endpoints (one per line, format: GET /users or POST /users)"))
        self.api_endpoints = QTextEdit()
        self.api_endpoints.setPlaceholderText("GET /users\nPOST /users\nGET /users/{id}\nPUT /users/{id}")
        api_layout.addWidget(self.api_endpoints)

        self.api_scan_button = QPushButton("🚀 Start API Scan")
        api_layout.addWidget(self.api_scan_button)
        api_layout.addStretch()
        tabs.addTab(api_widget, "🔌 REST API")
        scanner_layout.addWidget(tabs)



        # ── Reports page ──────────────────────────────
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

        # ── Settings page ─────────────────────────────
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

        # Authentication section
        auth_label = QLabel("Authentication")
        auth_label.setStyleSheet("color: #00ff99; font-size: 16px; margin-top: 20px;")
        settings_layout.addWidget(auth_label)
        self.auth_button = QPushButton("🔐 Configure Authentication")
        self.auth_button.setFixedHeight(36)
        settings_layout.addWidget(self.auth_button)
        self.auth_button.clicked.connect(self.open_auth_dialog)

        # ── NEW: Rate Limiting section ─────────────────
        rate_label = QLabel("Rate Limiting")
        rate_label.setStyleSheet("color: #00ff99; font-size: 16px; margin-top: 20px;")
        settings_layout.addWidget(rate_label)

        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("Delay between requests (seconds):"))
        self.delay_spinbox = QDoubleSpinBox()
        self.delay_spinbox.setRange(0.0, 5.0)
        self.delay_spinbox.setSingleStep(0.1)
        self.delay_spinbox.setValue(0.2)
        self.delay_spinbox.setSuffix(" s")
        delay_layout.addWidget(self.delay_spinbox)
        delay_layout.addStretch()
        settings_layout.addLayout(delay_layout)

        info_label = QLabel("💡 Lower delay = faster scan, higher risk of being blocked. Recommended: 0.2–0.5 s")
        info_label.setStyleSheet("color: #888; font-size: 11px; margin-left: 20px;")
        settings_layout.addWidget(info_label)

        settings_layout.addStretch()

        # ── Assemble ──────────────────────────────────
        self.pages.addWidget(dash)
        self.pages.addWidget(scanner_page)
        self.pages.addWidget(reports_page)
        self.pages.addWidget(settings_page)

        main_layout.addWidget(sidebar_frame)
        main_layout.addWidget(self.pages, stretch=1)

        # Load settings
        self.load_theme("cyber_dark.qss")
        self.load_auth_settings()
        self.load_rate_limiting_settings()

        # Connect signals
        self.start_button.clicked.connect(self.start_scan)
        self.sidebar.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.open_report_button.clicked.connect(self.open_report)
        self.multi_scan_button.clicked.connect(self.start_multi_scan)
        self.search_input.textChanged.connect(self.filter_vulnerabilities)
        self.severity_filter.currentTextChanged.connect(self.filter_vulnerabilities)
        self.toggle_sidebar_button.clicked.connect(self.toggle_sidebar)
        self.apply_theme_button.clicked.connect(self.change_theme)
        self.delay_spinbox.valueChanged.connect(self.on_delay_changed)

        self.sidebar.setCurrentRow(0)
        self.sidebar_expanded = True
        self.load_scan_history()

    # ══════════════════════════════════════════════════
    #  VULN DETAIL POPUP
    # ══════════════════════════════════════════════════

    def _show_vuln_detail(self, index):
        row = index.row()
        if row < 0 or row >= len(self.current_vulnerabilities):
            return
        vuln = self.current_vulnerabilities[row]
        dlg = VulnDetailDialog(vuln, parent=self)
        dlg.exec()

    # ══════════════════════════════════════════════════
    #  AUTHENTICATION (بدون تغییر)
    # ══════════════════════════════════════════════════

    def open_auth_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Authentication Configuration")
        dialog.setMinimumWidth(450)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("Authentication Type:"))
        auth_type = QComboBox()
        auth_type.addItems(["None", "Basic Auth", "Cookie (from string)", "Bearer Token"])
        layout.addWidget(auth_type)

        stack = QStackedWidget()
        stack.addWidget(QWidget())
        basic_widget = QWidget()
        basic_layout = QFormLayout(basic_widget)
        basic_user = QLineEdit()
        basic_pass = QLineEdit()
        basic_pass.setEchoMode(QLineEdit.Password)
        basic_layout.addRow("Username:", basic_user)
        basic_layout.addRow("Password:", basic_pass)
        stack.addWidget(basic_widget)
        cookie_widget = QWidget()
        cookie_layout = QVBoxLayout(cookie_widget)
        cookie_edit = QTextEdit()
        cookie_edit.setPlaceholderText("sessionid=abc123; csrftoken=xyz...")
        cookie_layout.addWidget(QLabel("Cookie header value (e.g., key1=value1; key2=value2):"))
        cookie_layout.addWidget(cookie_edit)
        stack.addWidget(cookie_widget)
        token_widget = QWidget()
        token_layout = QVBoxLayout(token_widget)
        token_edit = QLineEdit()
        token_edit.setPlaceholderText("eyJhbGciOiJIUzI1NiIs...")
        token_layout.addWidget(QLabel("Token:"))
        token_layout.addWidget(token_edit)
        stack.addWidget(token_widget)

        layout.addWidget(stack)
        auth_type.currentIndexChanged.connect(stack.setCurrentIndex)

        test_btn = QPushButton("Test Connection (with target URL)")
        layout.addWidget(test_btn)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.auth_type = auth_type
        dialog.basic_user = basic_user
        dialog.basic_pass = basic_pass
        dialog.cookie_edit = cookie_edit
        dialog.token_edit = token_edit
        dialog.test_btn = test_btn

        def test_auth():
            target = self.url_input.text().strip()
            if not target:
                self.terminal.append_colored("[ERROR] Please enter a target URL in Dashboard first.")
                return
            session = self._create_session_from_config(
                auth_type.currentText(),
                basic_user.text(),
                basic_pass.text(),
                cookie_edit.toPlainText().strip(),
                token_edit.text().strip()
            )
            try:
                resp = session.get(target, timeout=10)
                self.terminal.append_colored(f"[TEST] Auth test to {target} -> HTTP {resp.status_code}")
                if resp.status_code == 200:
                    self.terminal.append_colored("[TEST] Success! Authentication seems valid.")
                else:
                    self.terminal.append_colored(f"[TEST] Unexpected status code: {resp.status_code}")
            except Exception as e:
                self.terminal.append_colored(f"[TEST] Error: {e}")

        test_btn.clicked.connect(test_auth)

        if dialog.exec() == QDialog.Accepted:
            atype = auth_type.currentText()
            self.auth_config = {
                "type": atype,
                "basic": {"username": basic_user.text(), "password": basic_pass.text()},
                "cookie": cookie_edit.toPlainText().strip(),
                "bearer": token_edit.text().strip(),
            }
            self.save_auth_settings()
            self.terminal.append_colored(f"[SYSTEM] Authentication configured: {atype}")

    def _create_session_from_config(self, atype, basic_user, basic_pass, cookie_str, bearer_token):
        session = requests.Session()
        if atype == "Basic Auth":
            session.auth = (basic_user, basic_pass)
        elif atype == "Cookie (from string)":
            for pair in cookie_str.split(';'):
                if '=' in pair:
                    k, v = pair.strip().split('=', 1)
                    session.cookies.set(k, v)
        elif atype == "Bearer Token":
            session.headers.update({"Authorization": f"Bearer {bearer_token}"})
        return session

    def create_authenticated_session(self):
        cfg = self.auth_config
        return self._create_session_from_config(
            cfg["type"],
            cfg["basic"]["username"],
            cfg["basic"]["password"],
            cfg["cookie"],
            cfg["bearer"]
        )

    def save_auth_settings(self):
        settings = QSettings("AMPGuard", "Auth")
        settings.setValue("type", self.auth_config["type"])
        settings.setValue("basic_user", self.auth_config["basic"]["username"])
        settings.setValue("basic_pass", self.auth_config["basic"]["password"])
        settings.setValue("cookie", self.auth_config["cookie"])
        settings.setValue("bearer", self.auth_config["bearer"])

    def load_auth_settings(self):
        settings = QSettings("AMPGuard", "Auth")
        self.auth_config = {
            "type": settings.value("type", "None"),
            "basic": {
                "username": settings.value("basic_user", ""),
                "password": settings.value("basic_pass", "")
            },
            "cookie": settings.value("cookie", ""),
            "bearer": settings.value("bearer", ""),
        }

    # ══════════════════════════════════════════════════
    #  RATE LIMITING (جدید)
    # ══════════════════════════════════════════════════

    def load_rate_limiting_settings(self):
        settings = QSettings("AMPGuard", "App")
        delay = float(settings.value("request_delay", 0.2))
        self.request_delay = delay
        self.delay_spinbox.setValue(delay)

    def on_delay_changed(self, value):
        self.request_delay = value
        settings = QSettings("AMPGuard", "App")
        settings.setValue("request_delay", value)

    # ══════════════════════════════════════════════════
    #  SCAN CONTROL (با ارسال delay)
    # ══════════════════════════════════════════════════

    def start_scan(self):
        target = self.url_input.text().strip()
        if not target:
            self.terminal.append_colored("[ERROR] Please enter a target URL.")
            return

        session = None
        if self.auth_config["type"] != "None":
            session = self.create_authenticated_session()
            self.terminal.append_colored(f"[SYSTEM] Using authentication: {self.auth_config['type']}")

        self.terminal.append_colored(f"[SYSTEM] Rate limiting: {self.request_delay} s delay between requests")

        self.terminal.clear()
        self.vuln_table.setRowCount(0)
        self.progress.setValue(0)
        self.stats_bar.reset()
        self.start_button.setEnabled(False)
        self._reset_cards()

        self.worker = ScanWorker(target, session=session, delay=self.request_delay)
        self.worker.log_signal.connect(self.terminal.append_colored)
        self.worker.vuln_found_signal.connect(self.add_vuln_live)
        self.worker.progress_signal.connect(self.progress.setValue)
        self.worker.stats_signal.connect(self.stats_bar.update_stats)
        self.worker.finished_signal.connect(self.scan_finished)
        self.worker.start()

    def start_multi_scan(self):
        targets = self.multi_target_input.toPlainText().splitlines()
        session = None
        if self.auth_config["type"] != "None":
            session = self.create_authenticated_session()
            self.terminal.append_colored(f"[SYSTEM] Using authentication for multi-scan: {self.auth_config['type']}")

        self.terminal.append_colored(f"[SYSTEM] Rate limiting for multi-scan: {self.request_delay} s delay")

        for target in targets:
            target = target.strip()
            if not target:
                continue
            self.terminal.append_colored(f"[MULTI] Starting scan: {target}")
            w = ScanWorker(target, session=session, delay=self.request_delay)
            self.workers.append(w)
            w.log_signal.connect(self.terminal.append_colored)
            w.progress_signal.connect(self.progress.setValue)
            w.stats_signal.connect(self.stats_bar.update_stats)
            w.finished_signal.connect(self.scan_finished)
            w.start()

    # ══════════════════════════════════════════════════
    #  VULN TABLE و بقیه توابع (بدون تغییر)
    # ══════════════════════════════════════════════════

    SEVERITY_COLORS = {
        "Critical": ("#ff2d55", "#fff"),
        "High":     ("#ff6b35", "#fff"),
        "Medium":   ("#ffd60a", "#000"),
        "Low":      ("#30d158", "#000"),
    }

    def add_vuln_live(self, vuln: dict):
        self.current_vulnerabilities.append(vuln)
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        self._set_row(row, vuln)
        self.chart.update_chart(self.current_vulnerabilities)
        self._update_cards_from_vulns()

    def fill_vulnerability_table(self, vulns: list):
        self.vuln_table.setRowCount(len(vulns))
        for row, v in enumerate(vulns):
            self._set_row(row, v)

    def _set_row(self, row: int, vuln: dict):
        self.vuln_table.setItem(row, 0, QTableWidgetItem(vuln["type"]))
        self.vuln_table.setItem(row, 1, QTableWidgetItem(vuln["url"]))
        sev = vuln["severity"]
        item = QTableWidgetItem(f"  {sev}  ")
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
        q = self.search_input.text().lower()
        sev = self.severity_filter.currentText()
        out = [
            v for v in self.current_vulnerabilities
            if (q in v["type"].lower() or q in v["url"].lower())
            and (sev == "All" or v["severity"] == sev)
        ]
        self.fill_vulnerability_table(out)

    def _update_cards_from_vulns(self):
        counts = {"sql": 0, "xss": 0, "lfi": 0, "ssrf": 0, "csrf": 0}
        for v in self.current_vulnerabilities:
            t = v["type"].lower()
            if "sql" in t:
                counts["sql"] += 1
            elif "xss" in t:
                counts["xss"] += 1
            elif "lfi" in t or "path traversal" in t:
                counts["lfi"] += 1
            elif "ssrf" in t:
                counts["ssrf"] += 1
            elif "csrf" in t:
                counts["csrf"] += 1
        self.sqli_card.set_value(counts["sql"])
        self.xss_card.set_value(counts["xss"])
        self.lfi_card.set_value(counts["lfi"])
        self.ssrf_card.set_value(counts["ssrf"])
        self.csrf_card.set_value(counts["csrf"])

    def scan_finished(self, vulnerabilities: list):
        self.start_button.setEnabled(True)
        self.current_vulnerabilities = vulnerabilities
        self.terminal.append_colored("[SYSTEM] Scan completed successfully.")
        self._update_cards_from_vulns()
        scan_id = self.db.save_scan(self.url_input.text(), str(datetime.now()))
        for v in vulnerabilities:
            self.db.save_vulnerability(scan_id, v["type"], v["url"], v["severity"])
        target = self.url_input.text()
        for gen, tag in [
            (ReportGenerator.generate_json_report, "JSON"),
            (ReportGenerator.generate_html_report, "HTML"),
            (ReportGenerator.generate_pdf_report,  "PDF"),
        ]:
            path = gen(target, vulnerabilities)
            self.terminal.append_colored(f"[REPORT] {tag} saved: {path}")
            self.report_list.addItem(path)
        for exporter, tag in [
            (lambda t, v: CSVExporter.export(t, v),              "CSV"),
            (lambda t, v: MarkdownExporter.export(t, v),         "Markdown"),
            (lambda t, v: XMLExporter.export(t, v),              "XML"),
        ]:
            path = exporter(target, vulnerabilities)
            self.terminal.append_colored(f"[REPORT] {tag} saved: {path}")
            self.report_list.addItem(path)
        self.fill_vulnerability_table(vulnerabilities)
        self.chart.update_chart(vulnerabilities)
        self.load_scan_history()

    # ══════════════════════════════════════════════════
    #  HELPERS (بدون تغییر)
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
        self.current_vulnerabilities = []
        for card in [self.sqli_card, self.xss_card, self.lfi_card,
                     self.ssrf_card, self.csrf_card]:
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
            with open(path, "r", encoding="utf-8") as f:
                self.setStyleSheet(f.read())
        except Exception as e:
            print(f"Theme error: {e}")

    def change_theme(self):
        name = self.theme_selector.currentText()
        file = "cyber_dark.qss" if name == "Cyber Dark" else "hacker_neon.qss"
        self.load_theme(file)
        self.terminal.append_colored(f"[SYSTEM] Theme changed to {name}")


APP_VERSION = "0.4.5"