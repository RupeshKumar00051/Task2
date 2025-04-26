import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
import re

class WebVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebVulnerabilityScanner/1.0"
        }
        self.visited_urls = set()
        self.vulnerabilities = []

    def is_valid_url(self, url):
        """Check if a URL is valid and belongs to the target domain"""
        parsed = urlparse(url)
        return parsed.netloc == urlparse(self.target_url).netloc

    def get_all_forms(self, url):
        """Extract all forms from a webpage"""
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except requests.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return []

    def scan_page(self, url):
        """Scan a single page for vulnerabilities"""
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        
        print(f"Scanning: {url}")
        forms = self.get_all_forms(url)
        
        for form in forms:
            self.test_xss_in_form(form, url)
            self.test_sql_injection_in_form(form, url)

    def test_xss_in_form(self, form, url):
        """Test a form for XSS vulnerability"""
        form_details = self.get_form_details(form)
        payload = "<script>alert('XSS')</script>"
        
        for input_field in form_details["inputs"]:
            if input_field["type"] == "hidden":
                continue
            
            data = {}
            for input_field_data in form_details["inputs"]:
                if input_field_data["type"] == "hidden":
                    data[input_field_data["name"]] = input_field_data["value"]
                elif input_field_data["name"] == input_field["name"]:
                    data[input_field_data["name"]] = payload
                else:
                    data[input_field_data["name"]] = "test"
            
            try:
                response = self.submit_form(form_details, url, data)
                if payload in response.text:
                    self.vulnerabilities.append({
                        "type": "XSS",
                        "url": url,
                        "form": form_details["action"],
                        "field": input_field["name"],
                        "payload": payload
                    })
                    print(f"[!] XSS vulnerability found in {url}")
                    print(f"    Form action: {form_details['action']}")
                    print(f"    Vulnerable field: {input_field['name']}")
            except requests.RequestException:
                continue

    def test_sql_injection_in_form(self, form, url):
        """Test a form for SQL injection vulnerability"""
        form_details = self.get_form_details(form)
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "1 AND 1=1",
            "1 AND 1=2",
            "1' ORDER BY 1--",
            "1' UNION SELECT null, version()--"
        ]
        
        for payload in sql_payloads:
            data = {}
            for input_field in form_details["inputs"]:
                if input_field["type"] == "hidden":
                    data[input_field["name"]] = input_field["value"]
                else:
                    data[input_field["name"]] = payload
            
            try:
                response = self.submit_form(form_details, url, data)
                errors = [
                    "SQL syntax",
                    "MySQL server",
                    "ORA-",
                    "syntax error",
                    "unclosed quotation mark",
                    "SQL command not properly ended"
                ]
                
                for error in errors:
                    if error.lower() in response.text.lower():
                        self.vulnerabilities.append({
                            "type": "SQL Injection",
                            "url": url,
                            "form": form_details["action"],
                            "payload": payload,
                            "error": error
                        })
                        print(f"[!] Possible SQL Injection found in {url}")
                        print(f"    Form action: {form_details['action']}")
                        print(f"    Payload: {payload}")
                        print(f"    Error detected: {error}")
                        break
            except requests.RequestException:
                continue

    def get_form_details(self, form):
        """Extract details from a form"""
        details = {
            "action": form.attrs.get("action", "").lower(),
            "method": form.attrs.get("method", "get").lower(),
            "inputs": []
        }
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            if input_name:
                details["inputs"].append({
                    "type": input_type,
                    "name": input_name,
                    "value": input_value
                })
        
        return details

    def submit_form(self, form_details, url, data):
        """Submit a form with given data"""
        target_url = urljoin(url, form_details["action"])
        
        if form_details["method"] == "post":
            return self.session.post(target_url, data=data)
        else:
            return self.session.get(target_url, params=data)

    def crawl(self, url=None):
        """Crawl the website starting from the target URL"""
        if url is None:
            url = self.target_url
        
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Scan current page
            self.scan_page(url)
            
            # Find and follow all links
            for link in soup.find_all("a", href=True):
                href = link["href"]
                full_url = urljoin(url, href)
                
                if full_url.startswith(self.target_url) and full_url not in self.visited_urls:
                    self.crawl(full_url)
        except requests.RequestException as e:
            print(f"Error crawling {url}: {e}")

    def report_vulnerabilities(self):
        """Generate a report of found vulnerabilities"""
        if not self.vulnerabilities:
            print("\nNo vulnerabilities found!")
            return
        
        print("\n=== Vulnerability Report ===")
        print(f"Target URL: {self.target_url}")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"{i}. {vuln['type']} Vulnerability")
            print(f"   URL: {vuln['url']}")
            print(f"   Form action: {vuln.get('form', 'N/A')}")
            
            if vuln["type"] == "XSS":
                print(f"   Vulnerable field: {vuln['field']}")
                print(f"   Payload: {vuln['payload']}")
            elif vuln["type"] == "SQL Injection":
                print(f"   Payload: {vuln['payload']}")
                print(f"   Error detected: {vuln['error']}")
            
            print()

def main():
    parser = argparse.ArgumentParser(
        description="Web Application Vulnerability Scanner - Identify common vulnerabilities like XSS and SQL Injection"
    )
    parser.add_argument(
        "target_url",
        help="URL of the web application to scan"
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=1,
        help="Crawl depth (1 for single page, higher for more pages)"
    )
    
    args = parser.parse_args()
    
    scanner = WebVulnerabilityScanner(args.target_url)
    print(f"Starting scan of {args.target_url}")
    
    if args.depth == 1:
        scanner.scan_page(args.target_url)
    else:
        scanner.crawl(args.target_url)
    
    scanner.report_vulnerabilities()

if __name__ == "__main__":
    main()