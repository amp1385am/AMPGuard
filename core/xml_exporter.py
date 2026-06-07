import os
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime


class XMLExporter:

    @staticmethod
    def export(target: str, vulnerabilities: list) -> str:

        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"reports/report_{timestamp}.xml"

        root = ET.Element("ampguard_report")
        root.set("generated", datetime.now().isoformat())

        meta = ET.SubElement(root, "meta")
        ET.SubElement(meta, "target").text = target
        ET.SubElement(meta, "total_findings").text = str(len(vulnerabilities))

        summary = ET.SubElement(root, "summary")
        for sev in ["Critical", "High", "Medium", "Low"]:
            count = sum(1 for v in vulnerabilities if v.get("severity") == sev)
            s = ET.SubElement(summary, "severity")
            s.set("level", sev)
            s.text = str(count)

        findings = ET.SubElement(root, "findings")
        for v in vulnerabilities:
            item = ET.SubElement(findings, "vulnerability")
            ET.SubElement(item, "type").text     = v.get("type", "")
            ET.SubElement(item, "url").text      = v.get("url", "")
            ET.SubElement(item, "severity").text = v.get("severity", "")
            ET.SubElement(item, "detail").text   = v.get("detail", "")

        # Pretty-print
        raw = ET.tostring(root, encoding="unicode")
        pretty = minidom.parseString(raw).toprettyxml(indent="  ")

        with open(path, "w", encoding="utf-8") as f:
            f.write(pretty)

        return path