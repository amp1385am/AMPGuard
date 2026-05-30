from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTextEdit,
    QLineEdit,
    QLabel,
    QProgressBar,
    QFrame,
    QListWidget,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QComboBox
)

from PySide6.QtCore import Qt
from PySide6.QtCore import QPropertyAnimation,  QEasingCurve

from PySide6.QtGui import QColor

from matplotlib.backends.backend_qt5agg import (
    FigureCanvasQTAgg as FigureCanvas
)

from matplotlib.figure import Figure

from core.workers import ScanWorker
from core.report_generator import ReportGenerator
from core.database import DatabaseManager

from datetime import datetime

from core.csv_exporter import CSVExporter

import os
import webbrowser


# =====================================================
# CHART WIDGET
# =====================================================

class ChartWidget(FigureCanvas):

    def __init__(self):

        self.figure = Figure(figsize=(4, 4))

        super().__init__(self.figure)

        self.ax = self.figure.add_subplot(111)

        self.setStyleSheet("""
            background-color: #121212;
        """)

    # =====================================================
    # UPDATE CHART
    # =====================================================

    def update_chart(self, vulnerabilities):

        self.ax.clear()

        severity_counts = {

            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0

        }

        for vuln in vulnerabilities:

            severity = vuln["severity"]

            if severity in severity_counts:

                severity_counts[severity] += 1

        labels = []
        values = []

        for key, value in severity_counts.items():

            if value > 0:

                labels.append(key)
                values.append(value)

        if values:

            self.ax.pie(
                values,
                labels=labels,
                autopct='%1.1f%%'
            )

        self.ax.set_title(
            "Vulnerability Severity"
        )

        self.draw()


# =====================================================
# MAIN WINDOW
# =====================================================

class MainWindow(QMainWindow):

    def __init__(self):

        super().__init__()

        self.db = DatabaseManager()

        self.setWindowTitle("AMPGuard")

        self.resize(1400, 800)

        # =====================================================
        # CENTRAL WIDGET
        # =====================================================

        central_widget = QWidget()

        self.setCentralWidget(central_widget)

        # =====================================================
        # MAIN LAYOUT
        # =====================================================

        main_layout = QHBoxLayout()

        # =====================================================
        # SIDEBAR
        # =====================================================

        self.sidebar = QListWidget()
        # =========================
        # Sidebar Toggle Button
        # =========================

        self.toggle_sidebar_button = QPushButton("☰")

        self.toggle_sidebar_button.setFixedHeight(40)

        self.toggle_sidebar_button.setFixedWidth(40)

        self.sidebar.setMinimumWidth(0)
        self.sidebar.setMaximumWidth(220)

        self.sidebar.addItem("🛡 Dashboard")
        self.sidebar.addItem("⚡ Scanner")
        self.sidebar.addItem("📄 Reports")
        self.sidebar.addItem("⚙ Settings")

        self.sidebar.setStyleSheet("""

            QListWidget {

                background-color: #1a1a1a;

                color: white;

                border: none;
                
                outline: 0;

                font-size: 16px;

                padding: 10px;  
            }

            QListWidget::item {

                padding: 15px;

                border-radius: 8px;
            }

            QListWidget::item:selected {
        
                background-color: #00ff99;
            
                color: black;
            
                border-radius: 8px;
            
                font-weight: bold;
            
                padding-left: 12px;
            }

            QListWidget::item:hover {

                background-color: #222;

                color: #00ff99;
                
                border-radius: 8px;
            }

        """)

        # =====================================================
        # PAGES
        # =====================================================

        self.pages = QStackedWidget()

        # =====================================================
        # DASHBOARD PAGE
        # =====================================================

        dashboard_page = QWidget()

        dashboard_layout = QVBoxLayout()

        title = QLabel(
            "AMPGuard Web Pentest Scanner"
        )

        title.setAlignment(Qt.AlignCenter)

        title.setStyleSheet("""

            font-size: 28px;

            font-weight: bold;

            color: #00ff99;

            margin: 15px;

        """)

        # URL INPUT

        self.url_input = QLineEdit()

        self.url_input.setPlaceholderText(
            "Enter target URL..."
        )

        # BUTTON

        self.start_button = QPushButton(
            "Start Scan"
        )

        # PROGRESS

        self.progress = QProgressBar()

        self.progress.setValue(0)

        # FILTERS

        filter_layout = QHBoxLayout()

        self.search_input = QLineEdit()

        self.search_input.setPlaceholderText(
            "Search vulnerabilities..."
        )

        self.severity_filter = QComboBox()

        self.severity_filter.addItems([
            "All",
            "Critical",
            "High",
            "Medium",
            "Low"
        ])

        filter_layout.addWidget(
            self.search_input
        )

        filter_layout.addWidget(
            self.severity_filter
        )

        # CARDS

        cards_layout = QHBoxLayout()

        self.sqli_card = self.create_card(
            "SQLi",
            "0"
        )

        self.xss_card = self.create_card(
            "XSS",
            "0"
        )

        self.lfi_card = self.create_card(
            "LFI",
            "0"
        )

        self.ssrf_card = self.create_card(
            "SSRF",
            "0"
        )

        cards_layout.addWidget(
            self.sqli_card
        )

        cards_layout.addWidget(
            self.xss_card
        )

        cards_layout.addWidget(
            self.lfi_card
        )

        cards_layout.addWidget(
            self.ssrf_card
        )

        # TERMINAL

        self.terminal = QTextEdit()

        self.terminal.setReadOnly(True)

        # VULN TABLE

        self.vuln_table = QTableWidget()

        self.vuln_table.setColumnCount(3)

        self.vuln_table.setHorizontalHeaderLabels([

            "Type",
            "URL",
            "Severity"

        ])

        # CHART

        self.chart = ChartWidget()

        # ADD TO DASHBOARD

        dashboard_layout.addWidget(title)

        dashboard_layout.addWidget(self.url_input)

        dashboard_layout.addWidget(self.start_button)

        dashboard_layout.addWidget(self.progress)

        dashboard_layout.addLayout(filter_layout)

        dashboard_layout.addLayout(cards_layout)

        dashboard_layout.addWidget(self.terminal)

        dashboard_layout.addWidget(self.vuln_table)

        dashboard_layout.addWidget(self.chart)

        dashboard_page.setLayout(
            dashboard_layout
        )

        # =====================================================
        # SCANNER PAGE
        # =====================================================

        scanner_page = QWidget()

        scanner_layout = QVBoxLayout()

        scanner_title = QLabel(
            "Advanced Scanner"
        )

        scanner_title.setStyleSheet("""

            color: #00ff99;

            font-size: 24px;

            font-weight: bold;

        """)

        scanner_layout.addWidget(
            scanner_title
        )

        self.multi_target_input = QTextEdit()

        self.multi_target_input.setPlaceholderText(
            "Enter multiple targets...\n"
            "One target per line"
        )

        scanner_layout.addWidget(
            self.multi_target_input
        )

        self.multi_scan_button = QPushButton(
            "Start Multi Target Scan"
        )

        scanner_layout.addWidget(
            self.multi_scan_button
        )

        scanner_page.setLayout(
            scanner_layout
        )

        # =====================================================
        # REPORTS PAGE
        # =====================================================

        reports_page = QWidget()

        reports_layout = QVBoxLayout()

        self.history_table = QTableWidget()

        self.history_table.setColumnCount(3)

        self.history_table.setHorizontalHeaderLabels([
            "ID",
            "Target",
            "Date"
        ])

        reports_layout.addWidget(
            self.history_table
        )

        self.report_list = QListWidget()

        reports_layout.addWidget(
            self.report_list
        )

        self.open_report_button = QPushButton(
            "Open Selected Report"
        )

        reports_layout.addWidget(
            self.open_report_button
        )

        reports_page.setLayout(
            reports_layout
        )

        # =====================================================
        # SETTINGS PAGE
        # =====================================================

        settings_page = QWidget()

        settings_layout = QVBoxLayout()

        settings_label = QLabel("Settings")

        settings_label.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)

        # Theme Selector
        theme_label = QLabel("Select Theme:")

        self.theme_selector = QComboBox()

        self.theme_selector.addItem("Cyber Dark")
        self.theme_selector.addItem("Hacker Neon")

        settings_layout.addWidget(settings_label)
        settings_layout.addWidget(theme_label)
        settings_layout.addWidget(self.theme_selector)

        settings_layout.addStretch()

        settings_page.setLayout(settings_layout)

        # =====================================================
        # ADD PAGES
        # =====================================================

        self.pages.addWidget(
            dashboard_page
        )

        self.pages.addWidget(
            scanner_page
        )

        self.pages.addWidget(
            reports_page
        )

        self.pages.addWidget(
            settings_page
        )

        sidebar_layout = QVBoxLayout()

        sidebar_layout.addWidget(
            self.toggle_sidebar_button
        )

        sidebar_layout.addWidget(
            self.sidebar
        )

        main_layout.addLayout(sidebar_layout)

        # =====================================================
        # ADD TO MAIN LAYOUT
        # =====================================================



        main_layout.addWidget(
            self.pages
        )

        central_widget.setLayout(
            main_layout
        )

        # Load Default Theme
        self.load_theme("cyber_dark.qss")

        # =====================================================
        # SIGNALS
        # =====================================================

        self.start_button.clicked.connect(
            self.start_scan
        )

        self.sidebar.currentRowChanged.connect(
            self.pages.setCurrentIndex
        )

        self.open_report_button.clicked.connect(
            self.open_report
        )

        self.multi_scan_button.clicked.connect(
            self.start_multi_scan
        )

        self.search_input.textChanged.connect(
            self.filter_vulnerabilities
        )

        self.severity_filter.currentTextChanged.connect(
            self.filter_vulnerabilities
        )
        self.toggle_sidebar_button.clicked.connect(
            self.toggle_sidebar
        )

        self.sidebar.setCurrentRow(0)

        self.sidebar_expanded = True

        self.theme_selector.addItem("Hacker Neon")

        self.apply_theme_button = QPushButton(
            "Apply Theme"
        )

        settings_layout.addWidget(
            self.apply_theme_button
        )

        self.apply_theme_button.clicked.connect(
            self.change_theme
        )

        self.load_scan_history()

    # =====================================================
    # START SCAN
    # =====================================================

    def start_scan(self):

        target = self.url_input.text()

        if not target:

            self.terminal.append(
                "[ERROR] Please enter target URL."
            )

            return

        self.terminal.clear()

        self.progress.setValue(0)

        self.start_button.setEnabled(False)

        self.worker = ScanWorker(target)

        self.worker.log_signal.connect(
            self.update_terminal
        )

        self.worker.progress_signal.connect(
            self.update_progress
        )

        self.worker.finished_signal.connect(
            self.scan_finished
        )

        self.worker.start()

    # =====================================================
    # MULTI TARGET SCAN
    # =====================================================

    def start_multi_scan(self):

        targets = (
            self.multi_target_input
            .toPlainText()
            .splitlines()
        )

        for target in targets:

            target = target.strip()

            if not target:
                continue

            self.terminal.append(
                f"[MULTI] Starting scan: {target}"
            )

            worker = ScanWorker(target)

            worker.log_signal.connect(
                self.update_terminal
            )

            worker.progress_signal.connect(
                self.update_progress
            )

            worker.finished_signal.connect(
                self.scan_finished
            )

            worker.start()

    # =====================================================
    # TERMINAL UPDATE
    # =====================================================

    def update_terminal(self, message):

        self.terminal.append(message)

    # =====================================================
    # PROGRESS UPDATE
    # =====================================================

    def update_progress(self, value):

        self.progress.setValue(value)

    # =====================================================
    # FILTER VULNERABILITIES
    # =====================================================

    def filter_vulnerabilities(self):

        if not hasattr(
            self,
            "current_vulnerabilities"
        ):
            return

        search_text = (
            self.search_input.text().lower()
        )

        severity_filter = (
            self.severity_filter.currentText()
        )

        filtered = []

        for vuln in self.current_vulnerabilities:

            vuln_type = vuln["type"].lower()

            vuln_url = vuln["url"].lower()

            vuln_severity = vuln["severity"]

            search_match = (

                search_text in vuln_type

                or

                search_text in vuln_url

            )

            severity_match = (

                severity_filter == "All"

                or

                vuln_severity == severity_filter

            )

            if search_match and severity_match:

                filtered.append(vuln)

        self.fill_vulnerability_table(
            filtered
        )

    # =====================================================
    # FILL TABLE
    # =====================================================

    def fill_vulnerability_table(
        self,
        vulnerabilities
    ):

        self.vuln_table.setRowCount(
            len(vulnerabilities)
        )

        for row, vuln in enumerate(vulnerabilities):

            self.vuln_table.setItem(
                row,
                0,
                QTableWidgetItem(vuln["type"])
            )

            self.vuln_table.setItem(
                row,
                1,
                QTableWidgetItem(vuln["url"])
            )

            severity_item = QTableWidgetItem(
                vuln["severity"]
            )

            severity = vuln["severity"]

            if severity == "Critical":

                severity_item.setBackground(
                    QColor("#ff0000")
                )

            elif severity == "High":

                severity_item.setBackground(
                    QColor("#ff6600")
                )

            elif severity == "Medium":

                severity_item.setBackground(
                    QColor("#ffcc00")
                )

            elif severity == "Low":

                severity_item.setBackground(
                    QColor("#0099ff")
                )

            self.vuln_table.setItem(
                row,
                2,
                severity_item
            )

    # =====================================================
    # SCAN FINISHED
    # =====================================================

    def scan_finished(self, vulnerabilities):

        self.start_button.setEnabled(True)

        self.current_vulnerabilities = vulnerabilities

        self.terminal.append(
            "[SYSTEM] Scan completed successfully."
        )

        # STATS

        sqli_count = 0
        xss_count = 0
        lfi_count = 0
        ssrf_count = 0

        for vuln in vulnerabilities:

            vuln_type = vuln["type"].lower()

            if "sql" in vuln_type:
                sqli_count += 1

            if "xss" in vuln_type:
                xss_count += 1

            if "lfi" in vuln_type:
                lfi_count += 1

            if "ssrf" in vuln_type:
                ssrf_count += 1

        self.sqli_card.value_label.setText(
            str(sqli_count)
        )

        self.xss_card.value_label.setText(
            str(xss_count)
        )

        self.lfi_card.value_label.setText(
            str(lfi_count)
        )

        self.ssrf_card.value_label.setText(
            str(ssrf_count)
        )

        # DATABASE

        scan_id = self.db.save_scan(
            self.url_input.text(),
            str(datetime.now())
        )

        for vuln in vulnerabilities:

            self.db.save_vulnerability(
                scan_id,
                vuln["type"],
                vuln["url"],
                vuln["severity"]
            )

        # REPORTS

        json_report = ReportGenerator.generate_json_report(
            self.url_input.text(),
            vulnerabilities
        )

        html_report = ReportGenerator.generate_html_report(
            self.url_input.text(),
            vulnerabilities
        )

        pdf_report = ReportGenerator.generate_pdf_report(
            self.url_input.text(),
            vulnerabilities
        )

        self.terminal.append(
            f"[REPORT] JSON saved: {json_report}"
        )

        self.terminal.append(
            f"[REPORT] HTML saved: {html_report}"
        )

        self.terminal.append(
            f"[REPORT] PDF saved: {pdf_report}"
        )
        csv_report = CSVExporter.export(

            self.url_input.text(),

            vulnerabilities

        )

        self.fill_vulnerability_table(
            vulnerabilities
        )

        self.report_list.addItem(
            json_report
        )

        self.report_list.addItem(
            html_report
        )

        self.report_list.addItem(
            pdf_report
        )

        self.chart.update_chart(
            vulnerabilities
        )
        self.terminal.append(
            f"[REPORT] CSV saved: {csv_report}"
        )
        self.report_list.addItem(
            csv_report
        )

        self.load_scan_history()

    # =====================================================
    # OPEN REPORT
    # =====================================================

    def open_report(self):

        item = self.report_list.currentItem()

        if not item:
            return

        path = item.text()

        if os.path.exists(path):

            webbrowser.open(path)

        else:

            self.terminal.append(
                "[ERROR] Report file not found."
            )

    # =====================================================
    # CREATE CARD
    # =====================================================

    def create_card(self, title, value):

        card = QFrame()



        layout = QVBoxLayout()

        title_label = QLabel(title)


        value_label = QLabel(value)

        value_label.setStyleSheet("""

            color: white;

            font-size: 28px;

            font-weight: bold;

        """)

        value_label.setAlignment(
            Qt.AlignCenter
        )

        layout.addWidget(title_label)

        layout.addWidget(value_label)

        card.setLayout(layout)

        card.value_label = value_label

        return card

    # =====================================================
    # LOAD HISTORY
    # =====================================================

    def load_scan_history(self):

        scans = self.db.get_scans()

        self.history_table.setRowCount(
            len(scans)
        )

        for row, scan in enumerate(scans):

            scan_id = str(scan[0])

            target = scan[1]

            date = scan[2]

            self.history_table.setItem(
                row,
                0,
                QTableWidgetItem(scan_id)
            )

            self.history_table.setItem(
                row,
                1,
                QTableWidgetItem(target)
            )

            self.history_table.setItem(
                row,
                2,
                QTableWidgetItem(date)
            )

    # =====================================================
    # TOGGLE SIDEBAR
    # =====================================================

    def toggle_sidebar(self):
        self.animation = QPropertyAnimation(self.sidebar, b"maximumWidth")
        self.animation.setDuration(300)
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

    # =====================================================
    # LOAD THEME
    # =====================================================

    def load_theme(self, theme_file):

        try:

            base_path = os.path.dirname(
                os.path.dirname(__file__)
            )

            full_path = os.path.join(
                base_path,
                "gui",
                "styles",
                theme_file
            )

            with open(full_path, "r") as file:

                style = file.read()

                # Clear old style
                self.setStyleSheet("")

                # Apply new style
                self.setStyleSheet(style)

                print(f"Theme loaded: {theme_file}")

        except Exception as e:

            print(f"Theme Error: {e}")

    # =====================================================
    # CHANGE THEME
    # =====================================================

    def change_theme(self):

        theme_name = self.theme_selector.currentText()

        if theme_name == "Cyber Dark":

            self.load_theme(
                "cyber_dark.qss"
            )

        elif theme_name == "Hacker Neon":

            self.load_theme(
                "hacker_neon.qss"
            )

        self.terminal.append(
            f"[SYSTEM] Theme changed to {theme_name}"
        )

APP_VERSION = "1.0.0"
