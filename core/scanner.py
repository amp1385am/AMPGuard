import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os

class WebScanner:

    def __init__(self, target):

        self.base_target = target
        self.target = target

        self.session = requests.Session()

        self.vulnerabilities = []
        self.vuln_set = set()

        self.visited_urls = set()
        self.urls_to_scan = set()

        self.urls_to_scan.add(target)

        self.max_depth = 2
        self.max_urls = 50

    # =====================================================
    # SAFE REQUEST
    # =====================================================

    def safe_get(self, url):

        try:
            return self.session.get(url, timeout=5)
        except:
            return None

    # =====================================================
    # ADD VULNERABILITY
    # =====================================================

    def add_vuln(self, vuln_type, url, severity, log_callback):

        key = f"{vuln_type}:{url}"

        if key in self.vuln_set:
            return

        self.vuln_set.add(key)

        vuln = {
            "type": vuln_type,
            "url": url,
            "severity": severity
        }

        self.vulnerabilities.append(vuln)

        if log_callback:
            log_callback(f"[VULN] {vuln_type} -> {url}")

    # =====================================================
    # MAIN SCAN
    # =====================================================

    def run_scan(self, log_callback=None):

        if log_callback:
            log_callback("[INFO] Starting crawler...")

        self.crawl(self.base_target, log_callback)

        all_urls = list(self.urls_to_scan)

        if log_callback:
            log_callback(f"[INFO] URLs collected: {len(all_urls)}")

        for url in all_urls:

            self.target = url

            if log_callback:
                log_callback(f"[SCAN] {url}")

            self.check_headers(log_callback)
            self.check_xss(log_callback)
            self.check_sqli(log_callback)

        # directory brute force only once
        self.target = self.base_target
        self.directory_bruteforce(log_callback)

        return self.vulnerabilities

    # =====================================================
    # HEADERS
    # =====================================================

    def check_headers(self, log_callback):

        response = self.safe_get(self.target)

        if not response:
            return

        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security"
        ]

        for header in security_headers:

            if header not in response.headers:

                self.add_vuln(
                    "Missing Security Header",
                    self.target,
                    "Medium",
                    log_callback
                )

    # =====================================================
    # XSS
    # =====================================================

    def check_xss(self, log_callback):

        payload = "<script>alert(1)</script>"

        test_url = f"{self.target}?q=test"

        response = self.safe_get(test_url)

        if not response:
            return

        if payload in response.text:

            self.add_vuln(
                "Reflected XSS",
                test_url,
                "High",
                log_callback
            )

    # =====================================================
    # SQLI
    # =====================================================

    def check_sqli(self, log_callback):

        test_url = f"{self.target}?id=1'"

        sql_errors = [
            "mysql",
            "syntax error",
            "sql",
            "database error"
        ]

        response = self.safe_get(test_url)

        if not response:
            return

        text = response.text.lower()

        for err in sql_errors:

            if err in text:

                self.add_vuln(
                    "SQL Injection",
                    test_url,
                    "Critical",
                    log_callback
                )

                break

    # =====================================================
    # CRAWLER
    # =====================================================

    def crawl(self, url, log_callback, depth=0):

        if depth > self.max_depth:
            return

        if len(self.urls_to_scan) >= self.max_urls:
            return

        if url in self.visited_urls:
            return

        self.visited_urls.add(url)

        if log_callback:
            log_callback(f"[CRAWLER] {url}")

        response = self.safe_get(url)

        if not response:
            return

        soup = BeautifulSoup(response.text, "html.parser")

        links = soup.find_all("a")

        for link in links:

            href = link.get("href")

            if not href:
                continue

            absolute = urljoin(url, href)

            parsed_root = urlparse(self.base_target)
            parsed_link = urlparse(absolute)

            if parsed_root.netloc != parsed_link.netloc:
                continue

            clean_url = parsed_link.scheme + "://" + parsed_link.netloc + parsed_link.path

            if clean_url not in self.visited_urls:

                self.urls_to_scan.add(clean_url)

                if log_callback:
                    log_callback(f"[FOUND] {clean_url}")

                self.crawl(clean_url, log_callback, depth + 1)

        self.extract_forms(url, soup, log_callback)

    # =====================================================
    # FORMS
    # =====================================================

    def extract_forms(self, url, soup, log_callback):

        forms = soup.find_all("form")

        for form in forms:

            action = form.get("action")
            method = form.get("method", "get").lower()

            inputs = []

            for inp in form.find_all("input"):

                name = inp.get("name")

                if name:
                    inputs.append(name)

            form_info = {
                "url": url,
                "action": action,
                "method": method,
                "inputs": inputs
            }

            if log_callback:
                log_callback(f"[FORM] {action}")

            self.test_forms_xss(form_info, log_callback)

    # =====================================================
    # FORM XSS
    # =====================================================

    def test_forms_xss(self, form_info, log_callback):

        payload = "<script>alert(1)</script>"

        target_url = urljoin(
            form_info["url"],
            form_info["action"] or ""
        )

        data = {}

        for name in form_info["inputs"]:
            data[name] = payload

        try:

            if form_info["method"] == "post":

                response = self.session.post(
                    target_url,
                    data=data,
                    timeout=5
                )

            else:

                response = self.session.get(
                    target_url,
                    params=data,
                    timeout=5
                )

            if payload in response.text:

                self.add_vuln(
                    "Form XSS",
                    target_url,
                    "High",
                    log_callback
                )

        except:
            pass

    # =====================================================
    # DIRECTORY BRUTEFORCE
    # =====================================================

    def directory_bruteforce(self, log_callback):

        wordlist_path = "wordlists/common.txt"

        if not os.path.exists(wordlist_path):
            return

        if log_callback:
            log_callback("[INFO] Directory scan started")

        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            paths = f.read().splitlines()[:100]

        for path in paths:

            url = urljoin(self.base_target + "/", path)

            response = self.safe_get(url)

            if not response:
                continue

            if response.status_code in [200, 301, 302, 403]:

                self.add_vuln(
                    "Interesting Endpoint",
                    url,
                    "Low",
                    log_callback
                )
