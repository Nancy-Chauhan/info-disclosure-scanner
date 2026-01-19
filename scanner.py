#!/usr/bin/env python3
"""
AI-Powered Information Disclosure Scanner
Detects sensitive information leakage in web applications
"""

import os
import requests
import json
import re
import argparse
import subprocess
import tempfile
import shutil
import sys
from urllib.parse import urljoin, urlparse
from datetime import datetime
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

# Rich library for beautiful console output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize console
console = Console() if RICH_AVAILABLE else None

BANNER = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ██╗███╗   ██╗███████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗  ║
║   ██║████╗  ██║██╔════╝██╔═══██╗    ██╔════╝██╔════╝██╔══██╗████╗ ║
║   ██║██╔██╗ ██║█████╗  ██║   ██║    ███████╗██║     ███████║██╔██╗║
║   ██║██║╚██╗██║██╔══╝  ██║   ██║    ╚════██║██║     ██╔══██║██║╚██║
║   ██║██║ ╚████║██║     ╚██████╔╝    ███████║╚██████╗██║  ██║██║ ╚█║
║   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ║
║                                                                   ║
║          AI-Powered Information Disclosure Scanner                ║
║                        v1.0.0                                     ║
╚═══════════════════════════════════════════════════════════════════╝
"""

SEVERITY_COLORS = {
    'HIGH': 'red',
    'MEDIUM': 'yellow',
    'LOW': 'blue',
    'INFO': 'cyan'
}

SEVERITY_ICONS = {
    'HIGH': '🔴',
    'MEDIUM': '🟠',
    'LOW': '🟡',
    'INFO': '🔵'
}


def print_banner():
    """Print the ASCII banner"""
    if RICH_AVAILABLE:
        console.print(BANNER, style="bold cyan")
    else:
        print(BANNER)


def print_finding(severity, title):
    """Print a finding with color"""
    icon = SEVERITY_ICONS.get(severity, '⚪')
    if RICH_AVAILABLE:
        color = SEVERITY_COLORS.get(severity, 'white')
        console.print(f"  {icon} [{color}][{severity}][/{color}] {title}")
    else:
        print(f"  {icon} [{severity}] {title}")


class InfoDisclosureScanner:
    def __init__(self, target_url, api_key=None, verbose=False, wordlist=None, no_ffuf=False,
                 custom_headers=None, delay=0, quiet=False):
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.quiet = quiet
        self.delay = delay
        self.findings = []
        self.wordlist = wordlist
        self.no_ffuf = no_ffuf
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # Add custom headers
        if custom_headers:
            self.session.headers.update(custom_headers)

        self.session.verify = False

        # Initialize Anthropic client if API key provided
        self.client = None
        if api_key:
            self.client = Anthropic(api_key=api_key)

    def log(self, message):
        if self.verbose:
            if RICH_AVAILABLE:
                console.print(f"  [dim][*] {message}[/dim]")
            else:
                print(f"[*] {message}")

    def add_finding(self, category, title, description, severity, evidence=None):
        finding = {
            'category': category,
            'title': title,
            'description': description,
            'severity': severity,
            'evidence': evidence[:500] if evidence else None,
            'timestamp': datetime.now().isoformat()
        }
        self.findings.append(finding)
        print_finding(severity, title)

    # ==================== CHECK MODULES ====================

    def check_common_paths(self):
        """Check for sensitive files and directories"""
        paths = [
            # Version control
            ('/.git/config', 'Git repository exposed'),
            ('/.git/HEAD', 'Git HEAD file exposed'),
            ('/.svn/entries', 'SVN repository exposed'),
            ('/.hg/hgrc', 'Mercurial repository exposed'),

            # Config & backup files
            ('/.env', 'Environment file exposed'),
            ('/config.php', 'PHP config file'),
            ('/config.php.bak', 'PHP config backup'),
            ('/config.yml', 'YAML config file'),
            ('/config.json', 'JSON config file'),
            ('/settings.py', 'Django settings exposed'),
            ('/web.config', 'IIS config exposed'),
            ('/.htaccess', 'Apache htaccess exposed'),
            ('/nginx.conf', 'Nginx config exposed'),

            # Info files
            ('/robots.txt', 'Robots.txt file'),
            ('/sitemap.xml', 'Sitemap file'),
            ('/crossdomain.xml', 'Flash crossdomain policy'),
            ('/clientaccesspolicy.xml', 'Silverlight policy'),
            ('/security.txt', 'Security.txt file'),
            ('/.well-known/security.txt', 'Security.txt (well-known)'),

            # Debug & admin
            ('/phpinfo.php', 'PHP info page'),
            ('/info.php', 'PHP info page'),
            ('/debug', 'Debug endpoint'),
            ('/debug/', 'Debug directory'),
            ('/admin', 'Admin panel'),
            ('/administrator', 'Administrator panel'),
            ('/console', 'Console access'),
            ('/actuator', 'Spring actuator'),
            ('/actuator/health', 'Spring health endpoint'),
            ('/actuator/env', 'Spring environment'),
            ('/api/swagger', 'Swagger API docs'),
            ('/swagger.json', 'Swagger JSON'),
            ('/api-docs', 'API documentation'),

            # Backup files
            ('/backup', 'Backup directory'),
            ('/backup/', 'Backup directory'),
            ('/db.sql', 'Database dump'),
            ('/database.sql', 'Database dump'),
            ('/dump.sql', 'Database dump'),
            ('/.DS_Store', 'macOS metadata'),
            ('/Thumbs.db', 'Windows thumbnails'),

            # Logs
            ('/logs', 'Logs directory'),
            ('/log', 'Log directory'),
            ('/error.log', 'Error log'),
            ('/access.log', 'Access log'),
            ('/debug.log', 'Debug log'),

            # Package managers
            ('/package.json', 'NPM package file'),
            ('/package-lock.json', 'NPM lock file'),
            ('/composer.json', 'Composer file'),
            ('/Gemfile', 'Ruby Gemfile'),
            ('/requirements.txt', 'Python requirements'),

            # Juice Shop specific
            ('/ftp', 'FTP directory (Juice Shop)'),
            ('/encryptionkeys', 'Encryption keys (Juice Shop)'),
            ('/api', 'API endpoint'),
            ('/api/Users', 'Users API'),
            ('/api/Products', 'Products API'),
            ('/api/Feedbacks', 'Feedbacks API'),
            ('/rest/admin', 'Admin REST API'),
        ]

        for path, description in paths:
            try:
                url = urljoin(self.target_url, path)
                resp = self.session.get(url, timeout=10, allow_redirects=False)

                if resp.status_code == 200:
                    content_type = resp.headers.get('Content-Type', '')
                    content = resp.text[:1000]

                    # Determine severity based on content
                    severity = 'INFO'
                    if any(x in path for x in ['.git', '.env', 'config', 'backup', '.sql', 'password']):
                        severity = 'HIGH'
                    elif any(x in path for x in ['admin', 'debug', 'actuator', 'api']):
                        severity = 'MEDIUM'
                    elif any(x in path for x in ['robots', 'sitemap', 'package.json']):
                        severity = 'LOW'

                    self.add_finding(
                        category='Sensitive Path',
                        title=f'{description} - {path}',
                        description=f'Found accessible path: {url}',
                        severity=severity,
                        evidence=content
                    )

            except requests.RequestException as e:
                self.log(f"Error checking {path}: {e}")

    def check_error_disclosure(self):
        """Trigger errors to find verbose error messages"""
        test_cases = [
            # SQL injection triggers
            ("/?id='", "SQL error trigger (quote)"),
            ("/?id=1'--", "SQL error trigger (comment)"),
            ("/?id=1 OR 1=1", "SQL error trigger (OR)"),

            # Path traversal
            ("/?file=../../../etc/passwd", "Path traversal test"),
            ("/?page=....//....//etc/passwd", "Path traversal bypass"),

            # Type confusion
            ("/?id[]=1", "Array parameter"),
            ("/?id=null", "Null value"),
            ("/?id=undefined", "Undefined value"),
            ("/?id=-1", "Negative ID"),
            ("/?id=99999999", "Large ID"),
            ("/?id=0", "Zero ID"),

            # Special characters
            ("/?q=<script>", "XSS probe"),
            ("/?q={{7*7}}", "SSTI probe"),
            ("/?q=${7*7}", "Expression injection"),

            # Non-existent resources
            ("/nonexistent12345", "404 error page"),
            ("/api/nonexistent12345", "API 404 error"),
        ]

        error_patterns = [
            (r'(Exception|Error|Traceback|Stack trace)', 'Stack trace exposed'),
            (r'(mysql|postgresql|sqlite|oracle|mssql)', 'Database type exposed'),
            (r'at\s+[\w\.]+\([\w\.]+:\d+\)', 'Code location exposed'),
            (r'(\/usr\/|\/var\/|\/home\/|C:\\)', 'File path exposed'),
            (r'(password|passwd|pwd|secret|key|token)\s*[=:]\s*\S+', 'Credential exposed'),
            (r'(version|ver)\s*[=:\"\']\s*[\d\.]+', 'Version info exposed'),
            (r'<b>Warning</b>:|<b>Fatal error</b>:', 'PHP error exposed'),
            (r'Line \d+ in file', 'Debug info exposed'),
        ]

        for path, description in test_cases:
            try:
                url = urljoin(self.target_url, path)
                resp = self.session.get(url, timeout=10)
                content = resp.text

                for pattern, finding_type in error_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        self.add_finding(
                            category='Error Disclosure',
                            title=f'{finding_type} via {description}',
                            description=f'Verbose error found at: {url}',
                            severity='MEDIUM',
                            evidence=str(matches[:3])
                        )
                        break

            except requests.RequestException as e:
                self.log(f"Error testing {path}: {e}")

        # Test invalid HTTP methods
        try:
            resp = self.session.request('INVALID', self.target_url, timeout=10)
            if 'error' in resp.text.lower() or resp.status_code >= 400:
                if len(resp.text) > 100:  # Verbose response
                    self.add_finding(
                        category='Error Disclosure',
                        title='Verbose response to invalid HTTP method',
                        description='Server returns detailed error for invalid methods',
                        severity='LOW',
                        evidence=resp.text[:300]
                    )
        except:
            pass

    def check_headers(self):
        """Check response headers for information disclosure"""
        try:
            resp = self.session.get(self.target_url, timeout=10)
            headers = resp.headers

            # Server header
            if 'Server' in headers:
                self.add_finding(
                    category='Header Disclosure',
                    title='Server header exposes technology',
                    description=f'Server: {headers["Server"]}',
                    severity='LOW',
                    evidence=headers['Server']
                )

            # X-Powered-By
            if 'X-Powered-By' in headers:
                self.add_finding(
                    category='Header Disclosure',
                    title='X-Powered-By header exposes technology',
                    description=f'X-Powered-By: {headers["X-Powered-By"]}',
                    severity='LOW',
                    evidence=headers['X-Powered-By']
                )

            # Missing security headers
            security_headers = [
                ('X-Content-Type-Options', 'nosniff'),
                ('X-Frame-Options', None),
                ('X-XSS-Protection', None),
                ('Strict-Transport-Security', None),
                ('Content-Security-Policy', None),
            ]

            for header, expected in security_headers:
                if header not in headers:
                    self.add_finding(
                        category='Missing Security Header',
                        title=f'Missing {header} header',
                        description=f'The {header} header is not set',
                        severity='INFO',
                        evidence=None
                    )

        except requests.RequestException as e:
            self.log(f"Error checking headers: {e}")

    def check_html_comments(self):
        """Check for sensitive information in HTML comments"""
        try:
            resp = self.session.get(self.target_url, timeout=10)
            content = resp.text

            # Find HTML comments
            comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)

            sensitive_patterns = [
                (r'(TODO|FIXME|HACK|XXX|BUG)', 'Developer notes'),
                (r'(password|passwd|pwd|secret|key|token)', 'Potential credential'),
                (r'(api|endpoint|url)\s*[=:]\s*\S+', 'API reference'),
                (r'(version|ver)\s*[=:]\s*[\d\.]+', 'Version info'),
                (r'(debug|test|dev)', 'Debug reference'),
                (r'(@\w+\.\w+)', 'Email address'),
            ]

            for comment in comments:
                for pattern, finding_type in sensitive_patterns:
                    if re.search(pattern, comment, re.IGNORECASE):
                        self.add_finding(
                            category='HTML Comment',
                            title=f'{finding_type} in HTML comment',
                            description='Sensitive information found in HTML comment',
                            severity='LOW',
                            evidence=comment[:200]
                        )
                        break

        except requests.RequestException as e:
            self.log(f"Error checking HTML: {e}")

    def check_js_files(self):
        """Check JavaScript files for sensitive information"""
        try:
            resp = self.session.get(self.target_url, timeout=10)
            content = resp.text

            # Find JS file references
            js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', content)
            js_files = list(set(js_files))[:10]  # Limit to 10 files

            sensitive_patterns = [
                (r'(api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']+)["\']', 'API Key'),
                (r'(secret|token)\s*[=:]\s*["\']([^"\']+)["\']', 'Secret/Token'),
                (r'(password|passwd)\s*[=:]\s*["\']([^"\']+)["\']', 'Password'),
                (r'(aws_|amazon_)\w+\s*[=:]\s*["\']([^"\']+)["\']', 'AWS Credential'),
                (r'(firebase|google_api)\w*\s*[=:]\s*["\']([^"\']+)["\']', 'Firebase/Google Key'),
                (r'//.*?(TODO|FIXME|HACK|XXX)', 'Developer comment'),
                (r'console\.(log|debug|info)\s*\(', 'Debug logging'),
            ]

            for js_file in js_files:
                try:
                    js_url = urljoin(self.target_url, js_file)
                    js_resp = self.session.get(js_url, timeout=10)
                    js_content = js_resp.text

                    for pattern, finding_type in sensitive_patterns:
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        if matches:
                            self.add_finding(
                                category='JavaScript Disclosure',
                                title=f'{finding_type} found in {js_file}',
                                description=f'Sensitive data in JavaScript file: {js_url}',
                                severity='HIGH' if 'Key' in finding_type or 'Password' in finding_type else 'MEDIUM',
                                evidence=str(matches[:2])
                            )

                except requests.RequestException:
                    continue

        except requests.RequestException as e:
            self.log(f"Error checking JS files: {e}")

    def check_ffuf_discovery(self, wordlist=None):
        """Use ffuf for comprehensive directory/file discovery"""
        if not shutil.which('ffuf'):
            self.log("ffuf not found, skipping fuzzing")
            return

        # Default wordlist locations
        default_wordlists = [
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/local/share/seclists/Discovery/Web-Content/common.txt',
        ]

        if not wordlist:
            for wl in default_wordlists:
                if os.path.exists(wl):
                    wordlist = wl
                    break

        if not wordlist:
            self.log("No wordlist found for ffuf. Use -w to specify a wordlist.")
            return

        self.log(f"Running ffuf with wordlist: {wordlist}")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            output_file = tmp.name

        try:
            # Build ffuf command
            cmd = [
                'ffuf',
                '-u', f'{self.target_url}/FUZZ',
                '-w', wordlist,
                '-o', output_file,
                '-of', 'json',
                '-mc', '200,201,202,203,204,301,302,307,401,403,405,500',
                '-t', '50',  # threads
                '-timeout', '10',
                '-s',  # silent mode
            ]

            # Run ffuf
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            # Parse results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    try:
                        ffuf_results = json.load(f)
                    except json.JSONDecodeError:
                        self.log("Failed to parse ffuf output")
                        return

                results = ffuf_results.get('results', [])
                self.log(f"ffuf found {len(results)} endpoints")

                # Sensitive path patterns
                sensitive_patterns = {
                    'HIGH': [
                        r'\.git', r'\.env', r'\.htpasswd', r'\.ssh', r'backup',
                        r'config', r'credential', r'password', r'secret', r'\.sql',
                        r'dump', r'admin', r'phpmyadmin', r'\.bak'
                    ],
                    'MEDIUM': [
                        r'api', r'debug', r'console', r'test', r'dev', r'staging',
                        r'actuator', r'swagger', r'graphql', r'internal', r'private',
                        r'manager', r'portal'
                    ],
                    'LOW': [
                        r'robots\.txt', r'sitemap', r'\.json$', r'\.xml$', r'info',
                        r'status', r'health', r'version'
                    ]
                }

                for entry in results:
                    path = entry.get('input', {}).get('FUZZ', '')
                    status = entry.get('status', 0)
                    length = entry.get('length', 0)
                    url = entry.get('url', f"{self.target_url}/{path}")

                    # Determine severity
                    severity = 'INFO'
                    for sev, patterns in sensitive_patterns.items():
                        if any(re.search(p, path, re.IGNORECASE) for p in patterns):
                            severity = sev
                            break

                    # Upgrade severity for interesting status codes
                    if status in [401, 403] and severity == 'INFO':
                        severity = 'LOW'  # Protected resource found
                    elif status == 500 and severity == 'INFO':
                        severity = 'MEDIUM'  # Server error

                    self.add_finding(
                        category='FFUF Discovery',
                        title=f'Discovered: /{path} (HTTP {status})',
                        description=f'ffuf found endpoint: {url} - Status: {status}, Length: {length}',
                        severity=severity,
                        evidence=f'Status: {status}, Content-Length: {length}'
                    )

        except subprocess.TimeoutExpired:
            self.log("ffuf timed out after 5 minutes")
        except subprocess.SubprocessError as e:
            self.log(f"ffuf error: {e}")
        finally:
            # Cleanup temp file
            if os.path.exists(output_file):
                os.unlink(output_file)

    # ==================== AI ANALYSIS ====================

    def ai_analyze_response(self, url, response_text):
        """Use Claude to analyze a response for sensitive information"""
        if not self.client:
            return None

        prompt = f"""Analyze this HTTP response for information disclosure vulnerabilities.

URL: {url}

Response content (truncated):
{response_text[:3000]}

Look for:
1. Exposed credentials (API keys, passwords, tokens)
2. Internal paths or file locations
3. Database information
4. Technology stack details
5. Debug or error information
6. Personal data (PII)
7. Internal IP addresses or hostnames
8. Developer comments with sensitive info

Respond in JSON format:
{{
    "findings": [
        {{
            "type": "finding type",
            "description": "what was found",
            "severity": "HIGH/MEDIUM/LOW",
            "evidence": "the specific text found"
        }}
    ],
    "summary": "brief overall assessment"
}}

If nothing sensitive is found, return empty findings array."""

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )

            result_text = response.content[0].text
            # Extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', result_text)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            self.log(f"AI analysis error: {e}")

        return None

    def ai_deep_scan(self):
        """Perform AI-powered deep analysis on key pages"""
        if not self.client:
            self.log("Skipping AI analysis (no API key)")
            return

        # Pages to analyze
        pages_to_check = [
            self.target_url,
            urljoin(self.target_url, '/robots.txt'),
            urljoin(self.target_url, '/api'),
        ]

        for url in pages_to_check:
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200:
                    analysis = self.ai_analyze_response(url, resp.text)
                    if analysis and analysis.get('findings'):
                        for finding in analysis['findings']:
                            self.add_finding(
                                category='AI Analysis',
                                title=f"[AI] {finding.get('type', 'Finding')}",
                                description=finding.get('description', ''),
                                severity=finding.get('severity', 'MEDIUM'),
                                evidence=finding.get('evidence', '')
                            )
            except requests.RequestException:
                continue

    # ==================== REPORTING ====================

    def generate_report(self):
        """Generate a markdown report of findings"""
        report = f"""# Information Disclosure Scan Report

**Target:** {self.target_url}
**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Findings:** {len(self.findings)}

## Summary

| Severity | Count |
|----------|-------|
| 🔴 HIGH | {len([f for f in self.findings if f['severity'] == 'HIGH'])} |
| 🟠 MEDIUM | {len([f for f in self.findings if f['severity'] == 'MEDIUM'])} |
| 🟡 LOW | {len([f for f in self.findings if f['severity'] == 'LOW'])} |
| 🔵 INFO | {len([f for f in self.findings if f['severity'] == 'INFO'])} |

## Findings

"""
        # Group by severity
        for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity_findings = [f for f in self.findings if f['severity'] == severity]
            if severity_findings:
                icons = {'HIGH': '🔴', 'MEDIUM': '🟠', 'LOW': '🟡', 'INFO': '🔵'}
                report += f"### {icons[severity]} {severity} Severity\n\n"

                for f in severity_findings:
                    report += f"#### {f['title']}\n\n"
                    report += f"**Category:** {f['category']}  \n"
                    report += f"**Description:** {f['description']}  \n"
                    if f['evidence']:
                        report += f"\n```\n{f['evidence']}\n```\n"
                    report += "\n---\n\n"

        return report

    def generate_html_report(self):
        """Generate a professional HTML report"""
        import html as html_module

        high_count = len([f for f in self.findings if f['severity'] == 'HIGH'])
        medium_count = len([f for f in self.findings if f['severity'] == 'MEDIUM'])
        low_count = len([f for f in self.findings if f['severity'] == 'LOW'])
        info_count = len([f for f in self.findings if f['severity'] == 'INFO'])
        total_count = len(self.findings)

        # Calculate risk score (0-100)
        risk_score = min(100, (high_count * 25) + (medium_count * 10) + (low_count * 3) + (info_count * 1))
        risk_level = "Critical" if risk_score >= 75 else "High" if risk_score >= 50 else "Medium" if risk_score >= 25 else "Low"
        risk_color = "#dc3545" if risk_score >= 75 else "#fd7e14" if risk_score >= 50 else "#ffc107" if risk_score >= 25 else "#28a745"

        # Group findings by category
        categories = {}
        for f in self.findings:
            cat = f['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(f)

        findings_html = ""
        for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity_findings = [f for f in self.findings if f['severity'] == severity]
            for f in severity_findings:
                evidence_escaped = html_module.escape(f['evidence']) if f['evidence'] else ''
                evidence_html = f'<pre class="evidence">{evidence_escaped}</pre>' if evidence_escaped else ''
                title_escaped = html_module.escape(f['title'])
                desc_escaped = html_module.escape(f['description'])
                cat_escaped = html_module.escape(f['category'])

                findings_html += f'''
                <div class="finding {severity.lower()}" data-severity="{severity.lower()}">
                    <div class="finding-header" onclick="this.parentElement.classList.toggle('collapsed')">
                        <span class="severity-badge {severity.lower()}">{severity}</span>
                        <span class="finding-title">{title_escaped}</span>
                        <span class="finding-category">{cat_escaped}</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                    <div class="finding-body">
                        <p><strong>Description:</strong> {desc_escaped}</p>
                        {evidence_html}
                    </div>
                </div>
                '''

        scan_date = datetime.now().strftime('%B %d, %Y at %H:%M:%S')

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {html_module.escape(self.target_url)}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --border-color: #334155;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --severity-high: #ef4444;
            --severity-medium: #f59e0b;
            --severity-low: #3b82f6;
            --severity-info: #06b6d4;
            --success: #10b981;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}

        /* Header */
        .report-header {{
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-primary) 100%);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 2.5rem;
            margin-bottom: 2rem;
            position: relative;
            overflow: hidden;
        }}

        .report-header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple));
        }}

        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1.5rem;
        }}

        .brand {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}

        .brand-icon {{
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
        }}

        .brand-text h1 {{
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
        }}

        .brand-text span {{
            font-size: 0.875rem;
            color: var(--text-secondary);
        }}

        .report-meta {{
            text-align: right;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}

        .report-meta .date {{
            color: var(--text-muted);
        }}

        .target-info {{
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}

        .target-info .label {{
            color: var(--text-muted);
            font-size: 0.875rem;
        }}

        .target-info .url {{
            color: var(--accent-blue);
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9rem;
        }}

        /* Stats Grid */
        .stats-section {{
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}

        .risk-score-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 2rem;
            text-align: center;
        }}

        .risk-score-card h3 {{
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 1rem;
        }}

        .risk-gauge {{
            position: relative;
            width: 160px;
            height: 160px;
            margin: 0 auto 1rem;
        }}

        .risk-gauge svg {{
            transform: rotate(-90deg);
        }}

        .risk-gauge-bg {{
            fill: none;
            stroke: var(--bg-tertiary);
            stroke-width: 12;
        }}

        .risk-gauge-fill {{
            fill: none;
            stroke: {risk_color};
            stroke-width: 12;
            stroke-linecap: round;
            stroke-dasharray: 377;
            stroke-dashoffset: {377 - (377 * risk_score / 100)};
            transition: stroke-dashoffset 1s ease;
        }}

        .risk-score-value {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }}

        .risk-score-value .number {{
            font-size: 2.5rem;
            font-weight: 700;
            color: {risk_color};
        }}

        .risk-score-value .label {{
            font-size: 0.875rem;
            color: var(--text-muted);
        }}

        .risk-level {{
            display: inline-block;
            padding: 0.5rem 1rem;
            background: {risk_color}20;
            color: {risk_color};
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.875rem;
        }}

        .severity-cards {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
        }}

        .severity-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
            cursor: pointer;
        }}

        .severity-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        }}

        .severity-card.active {{
            border-color: var(--accent-blue);
        }}

        .severity-card .count {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }}

        .severity-card.high .count {{ color: var(--severity-high); }}
        .severity-card.medium .count {{ color: var(--severity-medium); }}
        .severity-card.low .count {{ color: var(--severity-low); }}
        .severity-card.info .count {{ color: var(--severity-info); }}

        .severity-card .label {{
            color: var(--text-muted);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .severity-card .bar {{
            height: 4px;
            background: var(--bg-tertiary);
            border-radius: 2px;
            margin-top: 1rem;
            overflow: hidden;
        }}

        .severity-card .bar-fill {{
            height: 100%;
            border-radius: 2px;
            transition: width 0.5s ease;
        }}

        .severity-card.high .bar-fill {{ background: var(--severity-high); }}
        .severity-card.medium .bar-fill {{ background: var(--severity-medium); }}
        .severity-card.low .bar-fill {{ background: var(--severity-low); }}
        .severity-card.info .bar-fill {{ background: var(--severity-info); }}

        /* Findings Section */
        .findings-section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            overflow: hidden;
        }}

        .findings-header {{
            padding: 1.5rem 2rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .findings-header h2 {{
            font-size: 1.25rem;
            font-weight: 600;
        }}

        .filter-buttons {{
            display: flex;
            gap: 0.5rem;
        }}

        .filter-btn {{
            padding: 0.5rem 1rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-secondary);
            font-size: 0.875rem;
            cursor: pointer;
            transition: all 0.2s;
        }}

        .filter-btn:hover, .filter-btn.active {{
            background: var(--accent-blue);
            border-color: var(--accent-blue);
            color: white;
        }}

        .findings-list {{
            padding: 1rem;
        }}

        .finding {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 0.75rem;
            overflow: hidden;
            transition: all 0.2s;
        }}

        .finding:hover {{
            border-color: var(--text-muted);
        }}

        .finding.high {{ border-left: 3px solid var(--severity-high); }}
        .finding.medium {{ border-left: 3px solid var(--severity-medium); }}
        .finding.low {{ border-left: 3px solid var(--severity-low); }}
        .finding.info {{ border-left: 3px solid var(--severity-info); }}

        .finding-header {{
            padding: 1rem 1.25rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            cursor: pointer;
            user-select: none;
        }}

        .finding-header:hover {{
            background: var(--bg-secondary);
        }}

        .severity-badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .severity-badge.high {{ background: var(--severity-high)20; color: var(--severity-high); }}
        .severity-badge.medium {{ background: var(--severity-medium)20; color: var(--severity-medium); }}
        .severity-badge.low {{ background: var(--severity-low)20; color: var(--severity-low); }}
        .severity-badge.info {{ background: var(--severity-info)20; color: var(--severity-info); }}

        .finding-title {{
            flex: 1;
            font-weight: 500;
            color: var(--text-primary);
        }}

        .finding-category {{
            font-size: 0.75rem;
            color: var(--text-muted);
            background: var(--bg-tertiary);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
        }}

        .toggle-icon {{
            color: var(--text-muted);
            transition: transform 0.2s;
        }}

        .finding.collapsed .toggle-icon {{
            transform: rotate(-90deg);
        }}

        .finding.collapsed .finding-body {{
            display: none;
        }}

        .finding-body {{
            padding: 1rem 1.25rem;
            border-top: 1px solid var(--border-color);
            background: var(--bg-secondary);
        }}

        .finding-body p {{
            color: var(--text-secondary);
            margin-bottom: 0.75rem;
        }}

        .finding-body strong {{
            color: var(--text-primary);
        }}

        .evidence {{
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 1rem;
            overflow-x: auto;
            font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
            font-size: 0.8rem;
            color: #e6edf3;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        /* Footer */
        .report-footer {{
            margin-top: 2rem;
            padding: 1.5rem;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.875rem;
        }}

        .report-footer a {{
            color: var(--accent-blue);
            text-decoration: none;
        }}

        .report-footer a:hover {{
            text-decoration: underline;
        }}

        /* Print styles */
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            .container {{
                max-width: 100%;
            }}
            .finding {{
                break-inside: avoid;
            }}
            .filter-buttons {{
                display: none;
            }}
        }}

        /* Responsive */
        @media (max-width: 1024px) {{
            .stats-section {{
                grid-template-columns: 1fr;
            }}
            .severity-cards {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}

        @media (max-width: 640px) {{
            .header-top {{
                flex-direction: column;
                gap: 1rem;
            }}
            .report-meta {{
                text-align: left;
            }}
            .severity-cards {{
                grid-template-columns: repeat(2, 1fr);
            }}
            .filter-buttons {{
                flex-wrap: wrap;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <div class="header-top">
                <div class="brand">
                    <div class="brand-icon">🛡️</div>
                    <div class="brand-text">
                        <h1>Security Scan Report</h1>
                        <span>Information Disclosure Assessment</span>
                    </div>
                </div>
                <div class="report-meta">
                    <div>Report Generated</div>
                    <div class="date">{scan_date}</div>
                </div>
            </div>
            <div class="target-info">
                <span class="label">Target:</span>
                <span class="url">{html_module.escape(self.target_url)}</span>
            </div>
        </div>

        <div class="stats-section">
            <div class="risk-score-card">
                <h3>Risk Score</h3>
                <div class="risk-gauge">
                    <svg width="160" height="160" viewBox="0 0 160 160">
                        <circle class="risk-gauge-bg" cx="80" cy="80" r="60"/>
                        <circle class="risk-gauge-fill" cx="80" cy="80" r="60"/>
                    </svg>
                    <div class="risk-score-value">
                        <div class="number">{risk_score}</div>
                        <div class="label">/ 100</div>
                    </div>
                </div>
                <span class="risk-level">{risk_level} Risk</span>
            </div>

            <div class="severity-cards">
                <div class="severity-card high" onclick="filterFindings('high')">
                    <div class="count">{high_count}</div>
                    <div class="label">High</div>
                    <div class="bar"><div class="bar-fill" style="width: {(high_count/max(total_count,1))*100}%"></div></div>
                </div>
                <div class="severity-card medium" onclick="filterFindings('medium')">
                    <div class="count">{medium_count}</div>
                    <div class="label">Medium</div>
                    <div class="bar"><div class="bar-fill" style="width: {(medium_count/max(total_count,1))*100}%"></div></div>
                </div>
                <div class="severity-card low" onclick="filterFindings('low')">
                    <div class="count">{low_count}</div>
                    <div class="label">Low</div>
                    <div class="bar"><div class="bar-fill" style="width: {(low_count/max(total_count,1))*100}%"></div></div>
                </div>
                <div class="severity-card info" onclick="filterFindings('info')">
                    <div class="count">{info_count}</div>
                    <div class="label">Info</div>
                    <div class="bar"><div class="bar-fill" style="width: {(info_count/max(total_count,1))*100}%"></div></div>
                </div>
            </div>
        </div>

        <div class="findings-section">
            <div class="findings-header">
                <h2>Findings ({total_count})</h2>
                <div class="filter-buttons">
                    <button class="filter-btn active" onclick="filterFindings('all')">All</button>
                    <button class="filter-btn" onclick="filterFindings('high')">High</button>
                    <button class="filter-btn" onclick="filterFindings('medium')">Medium</button>
                    <button class="filter-btn" onclick="filterFindings('low')">Low</button>
                    <button class="filter-btn" onclick="filterFindings('info')">Info</button>
                </div>
            </div>
            <div class="findings-list">
                {findings_html}
            </div>
        </div>

        <div class="report-footer">
            Generated by <strong>Info Disclosure Scanner</strong> &middot; AI-Powered Security Analysis
        </div>
    </div>

    <script>
        function filterFindings(severity) {{
            const findings = document.querySelectorAll('.finding');
            const buttons = document.querySelectorAll('.filter-btn');

            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            findings.forEach(finding => {{
                if (severity === 'all' || finding.dataset.severity === severity) {{
                    finding.style.display = 'block';
                }} else {{
                    finding.style.display = 'none';
                }}
            }});
        }}

        // Collapse all findings by default except HIGH
        document.querySelectorAll('.finding').forEach(f => {{
            if (!f.classList.contains('high')) {{
                f.classList.add('collapsed');
            }}
        }});
    </script>
</body>
</html>'''
        return html

    # ==================== MAIN SCAN ====================

    def run_scan(self):
        """Run all checks with progress indication"""
        if not self.quiet:
            print_banner()

            if RICH_AVAILABLE:
                console.print(Panel(
                    f"[bold white]Target:[/bold white] [cyan]{self.target_url}[/cyan]\n"
                    f"[bold white]AI Analysis:[/bold white] [{'green' if self.client else 'red'}]{'Enabled' if self.client else 'Disabled'}[/{'green' if self.client else 'red'}]",
                    title="[bold]Scan Configuration[/bold]",
                    border_style="cyan"
                ))
                console.print()
            else:
                print(f"\n  Target: {self.target_url}")
                print(f"  AI Analysis: {'Enabled' if self.client else 'Disabled'}\n")

        scan_tasks = [
            ("Headers", "Checking response headers", self.check_headers),
            ("Paths", "Checking sensitive paths", self.check_common_paths),
            ("Errors", "Checking error disclosure", self.check_error_disclosure),
            ("HTML", "Analyzing HTML comments", self.check_html_comments),
            ("JavaScript", "Scanning JavaScript files", self.check_js_files),
        ]

        if not self.no_ffuf:
            scan_tasks.append(("Fuzzing", "Running directory fuzzing", lambda: self.check_ffuf_discovery(self.wordlist)))

        if self.client:
            scan_tasks.append(("AI Analysis", "Running AI deep analysis", self.ai_deep_scan))

        total_tasks = len(scan_tasks)

        for idx, (short_name, description, func) in enumerate(scan_tasks, 1):
            if not self.quiet:
                if RICH_AVAILABLE:
                    # Show section header with progress
                    console.print(f"\n[bold cyan]▶ [{idx}/{total_tasks}] {description}...[/bold cyan]")
                else:
                    print(f"\n[{idx}/{total_tasks}] {description}...")

            func()

            # Add delay between scan phases if specified
            if self.delay > 0 and idx < total_tasks:
                import time
                time.sleep(self.delay)

        # Print summary
        if not self.quiet:
            self._print_summary()

        return self.findings

    def _print_summary(self):
        """Print scan summary"""
        high_count = len([f for f in self.findings if f['severity'] == 'HIGH'])
        medium_count = len([f for f in self.findings if f['severity'] == 'MEDIUM'])
        low_count = len([f for f in self.findings if f['severity'] == 'LOW'])
        info_count = len([f for f in self.findings if f['severity'] == 'INFO'])

        if RICH_AVAILABLE:
            console.print()

            # Create summary table
            table = Table(
                title="[bold]Scan Complete[/bold]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            table.add_column("Severity", style="bold", justify="center")
            table.add_column("Count", justify="center")

            table.add_row("🔴 HIGH", f"[red bold]{high_count}[/red bold]")
            table.add_row("🟠 MEDIUM", f"[yellow bold]{medium_count}[/yellow bold]")
            table.add_row("🟡 LOW", f"[blue bold]{low_count}[/blue bold]")
            table.add_row("🔵 INFO", f"[cyan bold]{info_count}[/cyan bold]")
            table.add_row("", "")
            table.add_row("[bold]TOTAL[/bold]", f"[bold white]{len(self.findings)}[/bold white]")

            console.print(table)
            console.print()
        else:
            print(f"\n{'='*60}")
            print(f"  Scan Complete - {len(self.findings)} findings")
            print(f"{'='*60}")
            print(f"\n  🔴 HIGH:   {high_count}")
            print(f"  🟠 MEDIUM: {medium_count}")
            print(f"  🟡 LOW:    {low_count}")
            print(f"  🔵 INFO:   {info_count}")
            print()


def main():
    parser = argparse.ArgumentParser(
        description='AI-Powered Information Disclosure Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s https://target.com                    Basic scan
  %(prog)s https://target.com -v                 Verbose output
  %(prog)s -L targets.txt                        Scan multiple targets
  %(prog)s https://target.com -c "session=abc"   With cookies
  %(prog)s https://target.com -H "Auth: Bearer x" With custom header
  %(prog)s https://target.com --html report.html Save HTML report
  %(prog)s --demo                                Scan demo target
        '''
    )
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('-L', '--list', help='File containing list of target URLs (one per line)')
    parser.add_argument('-k', '--api-key', help='Anthropic API key for AI analysis')
    parser.add_argument('-o', '--output', help='Output report file (markdown)')
    parser.add_argument('--html', help='Output HTML report file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - only show findings and summary')
    parser.add_argument('--json', action='store_true', help='Output findings as JSON')
    parser.add_argument('-w', '--wordlist', help='Wordlist for ffuf directory fuzzing')
    parser.add_argument('--no-ffuf', action='store_true', help='Skip ffuf directory discovery')
    parser.add_argument('--demo', action='store_true', help='Run scan against demo target (httpbin.org)')

    # Authentication options
    parser.add_argument('-c', '--cookie', help='Cookie string (e.g., "session=abc123; token=xyz")')
    parser.add_argument('-H', '--header', action='append', dest='headers', help='Custom header (can be used multiple times)')
    parser.add_argument('--auth', help='Basic auth credentials (user:password)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds')

    args = parser.parse_args()

    # Handle demo mode
    if args.demo:
        args.target = 'https://httpbin.org'
        args.no_ffuf = True

    # Get list of targets
    targets = []
    if args.list:
        if os.path.exists(args.list):
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        else:
            print(f"Error: Target list file not found: {args.list}")
            sys.exit(1)
    elif args.target:
        targets = [args.target]
    else:
        parser.print_help()
        sys.exit(1)

    # Validate URLs
    targets = [t if t.startswith(('http://', 'https://')) else 'http://' + t for t in targets]

    # Build custom headers dict
    custom_headers = {}
    if args.headers:
        for h in args.headers:
            if ':' in h:
                key, value = h.split(':', 1)
                custom_headers[key.strip()] = value.strip()

    if args.cookie:
        custom_headers['Cookie'] = args.cookie

    if args.auth:
        import base64
        auth_encoded = base64.b64encode(args.auth.encode()).decode()
        custom_headers['Authorization'] = f'Basic {auth_encoded}'

    # Run scanner for each target
    api_key = args.api_key or os.environ.get('ANTHROPIC_API_KEY')
    all_findings = []

    for idx, target_url in enumerate(targets, 1):
        if len(targets) > 1 and RICH_AVAILABLE and not args.quiet:
            console.print(f"\n[bold magenta]━━━ Target {idx}/{len(targets)} ━━━[/bold magenta]")

        scanner = InfoDisclosureScanner(
            target_url=target_url,
            api_key=api_key,
            verbose=args.verbose,
            wordlist=args.wordlist,
            no_ffuf=args.no_ffuf,
            custom_headers=custom_headers,
            delay=args.delay,
            quiet=args.quiet
        )

        findings = scanner.run_scan()
        all_findings.extend(findings)

    # Output results
    if args.json:
        print(json.dumps(all_findings, indent=2))
    elif args.html:
        # For HTML, use last scanner's method but with all findings
        scanner.findings = all_findings
        report = scanner.generate_html_report()
        with open(args.html, 'w') as f:
            f.write(report)
        if RICH_AVAILABLE:
            console.print(f"[green]✓[/green] HTML report saved to: [cyan]{args.html}[/cyan]")
        else:
            print(f"HTML report saved to: {args.html}")
    elif args.output:
        scanner.findings = all_findings
        report = scanner.generate_report()
        with open(args.output, 'w') as f:
            f.write(report)
        if RICH_AVAILABLE:
            console.print(f"[green]✓[/green] Report saved to: [cyan]{args.output}[/cyan]")
        else:
            print(f"Report saved to: {args.output}")
    else:
        # Just show a hint about saving reports
        if not args.quiet:
            if RICH_AVAILABLE:
                console.print(f"[dim]Tip: Use --html report.html or -o report.md to save the full report[/dim]")
            else:
                print("Tip: Use --html report.html or -o report.md to save the full report")


if __name__ == '__main__':
    main()
