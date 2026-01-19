# Info Disclosure Scanner

An AI-powered security scanner that detects sensitive information leakage in web applications using Claude AI for intelligent analysis.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![AI Powered](https://img.shields.io/badge/AI-Claude%20Powered-blueviolet.svg)

![Screenshot](screenshot.png)

## Features

- **AI-Powered Analysis** - Uses Claude AI to intelligently identify information disclosure vulnerabilities
- **Beautiful CLI Output** - Rich terminal interface with progress bars, colored output, and ASCII banner
- **Comprehensive Scanning** - Checks 50+ common sensitive paths and files
- **Header Analysis** - Detects technology disclosure and missing security headers
- **Error Disclosure Detection** - Triggers various error conditions to find verbose error messages
- **JavaScript Analysis** - Scans JS files for hardcoded secrets, tokens, and sensitive data
- **HTML Comment Scanning** - Extracts potentially sensitive comments from HTML source
- **Directory Fuzzing** - Optional ffuf integration for discovering hidden paths
- **Multiple Output Formats** - Beautiful HTML reports, Markdown reports, JSON output, or console display

## Quick Demo with OWASP Juice Shop

Test the scanner against [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), a deliberately vulnerable web application:

```bash
# 1. Start Juice Shop in Docker
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# 2. Wait for it to start (about 30 seconds), then run the scanner
python scanner.py http://localhost:3000 --html report.html

# 3. Open the report in your browser
open report.html  # macOS
# or: xdg-open report.html  # Linux
# or: start report.html  # Windows
```

The scanner will find **80+ vulnerabilities** including exposed git repositories, config files, stack traces, hardcoded passwords in JavaScript, and missing security headers.

See [examples/sample-report.html](examples/sample-report.html) for a sample report.

## Installation

```bash
# Clone the repository
git clone https://github.com/Nancy-Chauhan/info-disclosure-scanner.git
cd info-disclosure-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up your API key
cp .env.example .env
# Edit .env and add your Anthropic API key
```

## Configuration

Create a `.env` file in the project root:

```env
ANTHROPIC_API_KEY=your-api-key-here
```

Get your API key from [console.anthropic.com](https://console.anthropic.com)

## Usage

### Basic Scan

```bash
python scanner.py https://target.com
```

### Verbose Output

```bash
python scanner.py https://target.com -v
```

### Save Report to File

```bash
python scanner.py https://target.com -o report.md
```

### Generate HTML Report

```bash
python scanner.py https://target.com --html report.html
```

### JSON Output

```bash
python scanner.py https://target.com --json > results.json
```

### With Directory Fuzzing (requires ffuf)

```bash
python scanner.py https://target.com -w /path/to/wordlist.txt
```

### Skip Directory Fuzzing

```bash
python scanner.py https://target.com --no-ffuf
```

### Quick Online Demo (no Docker required)

```bash
python scanner.py --demo
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `target` | Target URL to scan |
| `-k, --api-key` | Anthropic API key (or use .env file) |
| `-o, --output` | Save report to file (Markdown format) |
| `--html` | Save beautiful HTML report |
| `-v, --verbose` | Enable verbose output |
| `--json` | Output findings as JSON |
| `-w, --wordlist` | Wordlist for ffuf directory fuzzing |
| `--no-ffuf` | Skip ffuf directory discovery |
| `--demo` | Run scan against demo target (httpbin.org) |

## What It Detects

### High Severity
- Exposed `.git` repositories
- Environment files (`.env`)
- Configuration files with credentials
- Database dumps
- Hardcoded passwords in JavaScript

### Medium Severity
- Admin panels and debug endpoints
- API documentation (Swagger/OpenAPI)
- Stack traces and verbose errors
- Secrets/tokens in JavaScript files
- Spring Actuator endpoints

### Low Severity
- Server version disclosure
- Technology stack fingerprinting
- Robots.txt information
- Verbose error messages

### Informational
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)

## Sample Output

```
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

╭───────────────────────────── Scan Configuration ─────────────────────────────╮
│ Target: http://localhost:3000                                                │
│ AI Analysis: Enabled                                                         │
╰──────────────────────────────────────────────────────────────────────────────╯

▶ [1/7] Checking response headers...
  🔵 [INFO] Missing Content-Security-Policy header

▶ [2/7] Checking sensitive paths...
  🔴 [HIGH] Git repository exposed - /.git/config
  🔴 [HIGH] Environment file exposed - /.env
  🟠 [MEDIUM] Admin panel - /admin

▶ [3/7] Checking error disclosure...
  🟠 [MEDIUM] Stack trace exposed via SQL error trigger

▶ [5/7] Scanning JavaScript files...
  🔴 [HIGH] Password found in main.js
  🟠 [MEDIUM] Secret/Token found in main.js

▶ [7/7] Running AI deep analysis...
  🟠 [MEDIUM] [AI] Technology Stack Disclosure

    Scan Complete
╭───────────┬───────╮
│ Severity  │ Count │
├───────────┼───────┤
│  🔴 HIGH  │  14   │
│ 🟠 MEDIUM │  33   │
│  🟡 LOW   │   7   │
│  🔵 INFO  │  28   │
│           │       │
│   TOTAL   │  82   │
╰───────────┴───────╯

✓ HTML report saved to: report.html
```

## Requirements

- Python 3.8+
- Anthropic API key (for AI analysis)
- Docker (for Juice Shop demo)
- ffuf (optional, for directory fuzzing)

## Legal Disclaimer

This tool is intended for authorized security testing and educational purposes only. Always obtain proper authorization before scanning any web application. The authors are not responsible for any misuse or damage caused by this tool.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Anthropic](https://anthropic.com) for Claude AI
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) for the demo vulnerable application
- [ffuf](https://github.com/ffuf/ffuf) for directory fuzzing capabilities
