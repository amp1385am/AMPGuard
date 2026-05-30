import os
import json
from datetime import datetime
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter

class ReportGenerator:

    @staticmethod
    def generate_json_report(target, vulnerabilities):

        os.makedirs("reports/json", exist_ok=True)

        filename = datetime.now().strftime(
            "reports/json/report_%Y%m%d_%H%M%S.json"
        )

        data = {
            "target": target,
            "scan_date": str(datetime.now()),
            "vulnerabilities": vulnerabilities
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

        return filename

    @staticmethod
    def generate_html_report(target, vulnerabilities):

        os.makedirs("reports/html", exist_ok=True)

        filename = datetime.now().strftime(
            "reports/html/report_%Y%m%d_%H%M%S.html"
        )

        rows = ""

        for vuln in vulnerabilities:

            severity = vuln.get("severity", "Unknown")

            color = {
                "Critical": "#ff0000",
                "High": "#ff6600",
                "Medium": "#ffcc00",
                "Low": "#00ccff"
            }.get(severity, "white")

            rows += f'''
            <tr>
                <td>{vuln.get("type")}</td>
                <td>{vuln.get("url")}</td>
                <td style="color:{color};font-weight:bold;">
                    {severity}
                </td>
            </tr>
            '''

        html = f'''
        <html>
        <head>
            <title>AMPGuard Report</title>

            <style>

                body {{
                    background: #121212;
                    color: white;
                    font-family: Arial;
                    padding: 20px;
                }}

                h1 {{
                    color: #00ff99;
                }}

                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}

                th, td {{
                    border: 1px solid #333;
                    padding: 10px;
                }}

                th {{
                    background: #1e1e1e;
                    color: #00ff99;
                }}

            </style>

        </head>

        <body>

            <h1>AMPGuard Scan Report</h1>

            <p><b>Target:</b> {target}</p>

            <p><b>Date:</b> {datetime.now()}</p>

            <table>

                <tr>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Severity</th>
                </tr>

                {rows}

            </table>

        </body>

        </html>
        '''

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)

        return filename

    @staticmethod
    def generate_pdf_report(target, vulnerabilities):

        os.makedirs("reports/pdf", exist_ok=True)

        filename = datetime.now().strftime(
            "reports/pdf/report_%Y%m%d_%H%M%S.pdf"
        )

        doc = SimpleDocTemplate(
            filename,
            pagesize=letter
        )

        styles = getSampleStyleSheet()

        elements = []

        # =========================
        # Title
        # =========================

        title = Paragraph(
            "VulnGuard Security Report",
            styles['Title']
        )

        elements.append(title)

        elements.append(Spacer(1, 20))

        # =========================
        # Target Info
        # =========================

        target_text = Paragraph(
            f"<b>Target:</b> {target}",
            styles['BodyText']
        )

        date_text = Paragraph(
            f"<b>Date:</b> {datetime.now()}",
            styles['BodyText']
        )

        elements.append(target_text)
        elements.append(date_text)

        elements.append(Spacer(1, 20))

        # =========================
        # Table Data
        # =========================

        data = [
            ["Type", "URL", "Severity"]
        ]

        for vuln in vulnerabilities:
            data.append([
                vuln.get("type"),
                vuln.get("url"),
                vuln.get("severity")
            ])

        # =========================
        # Table
        # =========================

        table = Table(data)

        table.setStyle(TableStyle([

            ('BACKGROUND', (0, 0), (-1, 0), colors.black),

            ('TEXTCOLOR', (0, 0), (-1, 0), colors.green),

            ('GRID', (0, 0), (-1, -1), 1, colors.grey),

            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),

            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),

            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),

        ]))

        elements.append(table)

        # =========================
        # Build PDF
        # =========================

        doc.build(elements)

        return filename