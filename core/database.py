import sqlite3


class DatabaseManager:

    def __init__(self):

        self.connection = sqlite3.connect(
            "vulnguard.db"
        )

        self.cursor = self.connection.cursor()

        self.create_tables()

    # =====================================================
    # CREATE TABLES
    # =====================================================

    def create_tables(self):

        self.cursor.execute("""

        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            target TEXT,

            scan_date TEXT

        )

        """)

        self.cursor.execute("""

        CREATE TABLE IF NOT EXISTS vulnerabilities (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            scan_id INTEGER,

            vuln_type TEXT,

            url TEXT,

            severity TEXT

        )

        """)

        self.connection.commit()

    # =====================================================
    # SAVE SCAN
    # =====================================================

    def save_scan(
        self,
        target,
        scan_date
    ):

        self.cursor.execute("""

        INSERT INTO scans (
            target,
            scan_date
        )

        VALUES (?, ?)

        """, (target, scan_date))

        self.connection.commit()

        return self.cursor.lastrowid

    # =====================================================
    # SAVE VULNERABILITY
    # =====================================================

    def save_vulnerability(
        self,
        scan_id,
        vuln_type,
        url,
        severity
    ):

        self.cursor.execute("""

        INSERT INTO vulnerabilities (

            scan_id,
            vuln_type,
            url,
            severity

        )

        VALUES (?, ?, ?, ?)

        """, (

            scan_id,
            vuln_type,
            url,
            severity

        ))

        self.connection.commit()

    # =====================================================
    # GET ALL SCANS
    # =====================================================

    def get_scans(self):

        self.cursor.execute("""

        SELECT * FROM scans
        ORDER BY id DESC

        """)

        return self.cursor.fetchall()