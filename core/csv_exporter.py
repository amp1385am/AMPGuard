import csv
import os
from datetime import datetime


class CSVExporter:

    @staticmethod
    def export(target, vulnerabilities):

        # =========================
        # Reports Folder
        # =========================

        if not os.path.exists("reports"):

            os.makedirs("reports")

        # =========================
        # Filename
        # =========================

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        safe_target = (
            target
            .replace("https://", "")
            .replace("http://", "")
            .replace("/", "_")
        )

        filename = (
            f"reports/{safe_target}_{timestamp}.csv"
        )

        # =========================
        # Write CSV
        # =========================

        with open(

            filename,

            "w",

            newline="",

            encoding="utf-8"

        ) as file:

            writer = csv.writer(file)

            # Header

            writer.writerow([
                "Type",
                "URL",
                "Severity"
            ])

            # Data

            for vuln in vulnerabilities:

                writer.writerow([

                    vuln["type"],

                    vuln["url"],

                    vuln["severity"]

                ])

        return filename