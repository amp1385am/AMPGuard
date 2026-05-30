import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os

class WebScanner:

    def __init__(self, target):

        self.target = target

        self.vulnerabilities = []

        self.visited_urls = set()

        self.urls_to_scan = set()

        self.urls_to_scan.add(target)

        self.max_depth = 2


    # =====================================================
    # MAIN SCAN
    # =====================================================

    def run_scan(self, log_callback=None):

        if log_callback:
            log_callback("[INFO] Starting crawler...")

        # =========================
        # Crawl Target
        # =========================

        self.crawl(self.target, log_callback)

        # =========================
        # Scan All URLs
        # =========================

        all_urls = list(self.urls_to_scan)

        for url in all_urls:

            if log_callback:
                log_callback(f"[SCAN] Scanning: {url}")

            self.target = url

            self.check_headers(log_callback)

            self.check_xss(log_callback)

            self.check_sqli(log_callback)

            # =========================
            # Directory Bruteforce
            # =========================

            self.directory_bruteforce(
                log_callback
            )

        return self.vulnerabilities

    # =====================================================
    # HEADER CHECK
    # =====================================================

    def check_headers(self, log_callback):

        try:

            response = requests.get(
                self.target,
                timeout=10
            )

            headers = response.headers

            security_headers = [

                "Content-Security-Policy",
                "X-Frame-Options",
                "Strict-Transport-Security"

            ]

            for header in security_headers:

                if header not in headers:

                    vuln = {
                        "type": "Missing Security Header",
                        "url": self.target,
                        "severity": "Medium"
                    }

                    self.vulnerabilities.append(vuln)

                    if log_callback:
                        log_callback(
                            f"[WARNING] Missing header: {header}"
                        )

        except Exception as e:

            if log_callback:
                log_callback(f"[ERROR] Header scan failed: {e}")

    # =====================================================
    # XSS CHECK
    # =====================================================

    def check_xss(self, log_callback):

        payload = "<script>alert(1)</script>"

        test_url = f"{self.target}?q={payload}"

        try:

            response = requests.get(
                test_url,
                timeout=10
            )

            if payload in response.text:

                vuln = {
                    "type": "Reflected XSS",
                    "url": test_url,
                    "severity": "High"
                }

                self.vulnerabilities.append(vuln)

                if log_callback:
                    log_callback(
                        "[CRITICAL] XSS vulnerability detected!"
                    )

        except Exception as e:

            if log_callback:
                log_callback(f"[ERROR] XSS scan failed: {e}")

    # =====================================================
    # SQLi CHECK
    # =====================================================

    def check_sqli(self, log_callback):

        payload = "'"

        test_url = f"{self.target}?id={payload}"

        sql_errors = [

            "mysql",
            "syntax error",
            "sql",
            "database error",
            "mysqli"

        ]

        try:

            response = requests.get(
                test_url,
                timeout=10
            )

            response_text = response.text.lower()

            for error in sql_errors:

                if error in response_text:

                    vuln = {
                        "type": "SQL Injection",
                        "url": test_url,
                        "severity": "Critical"
                    }

                    self.vulnerabilities.append(vuln)

                    if log_callback:
                        log_callback(
                            "[CRITICAL] SQL Injection detected!"
                        )

                    break

        except Exception as e:

            if log_callback:
                log_callback(f"[ERROR] SQLi scan failed: {e}")

    # =====================================================
    # RECURSIVE CRAWLER
    # =====================================================

    def crawl(self, url, log_callback, depth=0):

        if depth > self.max_depth:
            return

        try:

            if url in self.visited_urls:
                return

            self.visited_urls.add(url)

            if log_callback:
                log_callback(
                    f"[CRAWLER] Depth {depth} -> {url}"
                )

            response = requests.get(
                url,
                timeout=10
            )

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            # =========================
            # FIND LINKS
            # =========================

            links = soup.find_all("a")

            for link in links:

                href = link.get("href")

                if not href:
                    continue

                absolute_url = urljoin(url, href)

                parsed_target = urlparse(self.target)
                parsed_link = urlparse(absolute_url)

                # Same Domain Only

                if parsed_target.netloc != parsed_link.netloc:
                    continue

                if absolute_url not in self.visited_urls:

                    self.urls_to_scan.add(
                        absolute_url
                    )

                    if log_callback:
                        log_callback(
                            f"[FOUND] {absolute_url}"
                        )

                    # Recursive Crawl

                    self.crawl(
                        absolute_url,
                        log_callback,
                        depth + 1
                    )

            # =========================
            # FIND FORMS
            # =========================

            self.extract_forms(
                url,
                soup,
                log_callback
            )

        except Exception as e:

            if log_callback:
                log_callback(
                    f"[ERROR] Crawl failed: {e}"
                )

    # =====================================================
    # FORM EXTRACTION
    # =====================================================

    def extract_forms(self, url, soup, log_callback):

        forms = soup.find_all("form")

        for form in forms:

            action = form.get("action")

            method = form.get(
                "method",
                "get"
            ).lower()

            inputs = form.find_all("input")

            input_names = []

            for input_tag in inputs:

                name = input_tag.get("name")

                if name:
                    input_names.append(name)

            form_info = {
                "url": url,
                "action": action,
                "method": method,
                "inputs": input_names
            }

            if log_callback:
                log_callback(
                    f"[FORM] {method.upper()} -> "
                    f"{action} | Inputs: {input_names}"
                )
        self.test_forms_xss(
            form_info,
            log_callback
        )

    # =====================================================
    # FORM XSS TEST
    # =====================================================

    def test_forms_xss(self, form_info, log_callback):

        payload = "<script>alert(1)</script>"

        target_url = urljoin(
            form_info["url"],
            form_info["action"]
        )

        data = {}

        for input_name in form_info["inputs"]:
            data[input_name] = payload

        try:

            if form_info["method"] == "post":

                response = requests.post(
                    target_url,
                    data=data,
                    timeout=10
                )

            else:

                response = requests.get(
                    target_url,
                    params=data,
                    timeout=10
                )

            if payload in response.text:

                vuln = {
                    "type": "Form XSS",
                    "url": target_url,
                    "severity": "High"
                }

                self.vulnerabilities.append(vuln)

                if log_callback:
                    log_callback(
                        f"[CRITICAL] Form XSS detected: "
                        f"{target_url}"
                    )

        except Exception as e:

            if log_callback:
                log_callback(
                    f"[ERROR] Form XSS failed: {e}"
                )

    # =====================================================
    # DIRECTORY BRUTEFORCE
    # =====================================================

    def directory_bruteforce(self, log_callback):

        wordlist_path = "wordlists/common.txt"

        if not os.path.exists(wordlist_path):

            if log_callback:
                log_callback(
                    "[ERROR] Wordlist not found."
                )

            return

        try:

            with open(wordlist_path, "r") as f:

                paths = f.read().splitlines()

            for path in paths:

                url = urljoin(
                    self.target + "/",
                    path
                )

                try:

                    response = requests.get(
                        url,
                        timeout=5
                    )

                    if response.status_code in [200, 301, 302, 403]:

                        vuln = {
                            "type": "Interesting Endpoint",
                            "url": url,
                            "severity": "Low"
                        }

                        self.vulnerabilities.append(vuln)

                        if log_callback:
                            log_callback(
                                f"[FOUND] {url} "
                                f"({response.status_code})"
                            )

                except:
                    pass

        except Exception as e:

            if log_callback:
                log_callback(
                    f"[ERROR] Directory scan failed: {e}"
                )