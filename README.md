# FineSec Detect - Professional Pentest Suite

A professional, modular, and cloud-ready penetration testing toolkit. Optimized for security researchers and automated scanning environments (including Apify).

## 🚀 Features

*   **Modular Architecture**: Easily extendable scanners for Critical, High, and Medium/Low vulnerabilities.
*   **AI-Powered Explanations**: Integrated DeepSeek analysis for discovered vulnerabilities.
*   **External Payloads**: Standardized JSON-based payload management.
*   **Cloud Ready**: Built-in support for structured logging and Apify Actor integration.
*   **Comprehensive Coverage**: RCE, SQLi, SSRF, XSS, IDOR, Credential Leaks, and more.

## 📂 Project Structure

*   `main.py`: The primary entry point for the suite.
*   `modules/`: Severity-based scanning logic.
*   `src/core/`: Base classes and core orchestration logic.
*   `ai/`: DeepSeek model integration and training scripts.
*   `data/`: Payloads and datasets.
*   `docs/`: Detailed guides and legacy documentation.

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yangxiaoxuan123/FineSec_detect.git
cd FineSec_detect

# Install dependencies
pip install -r requirements.txt
```

## 📖 Usage

### Standard CLI
```bash
python main.py --target https://example.com --output reports/my_scan.json
```

### Apify Actor
This project is ready to be uploaded as an Apify Actor. It automatically reads from `INPUT.json` if present and outputs structured results to `stdout`.

## 🛡️ Testing Modules

| Module | Focus |
| --- | --- |
| `critical.py` | RCE, Advanced SQLi, SSRF, PII Disclosure |
| `high.py` | Stored XSS, Credential Leaks, IDOR, CSRF |
| `medium_low.py` | Reflected XSS, Directory Listings, Info Disclosure |

## ⚖️ Legal Disclaimer

**IMPORTANT**: This tool is for authorized security testing only. Obtaining written authorization before testing is mandatory. Unauthorized testing is illegal.

---

**Status**: ✅ Production Ready (Apify Optimized)  
**Version**: 3.0 (Modular)
