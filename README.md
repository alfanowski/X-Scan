# X-Scan

<div align="center">

![X-Scan Banner](https://img.shields.io/badge/X--Scan-Security%20Assessment%20Tool-red?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/license-Proprietary-darkred?style=flat-square)
![Version](https://img.shields.io/badge/version-1.0-orange?style=flat-square)

**A Professional Network Vulnerability Scanner with Real-Time CVE Analysis**

*Developed by [alfanowski](https://github.com/alfanoandrea)*

---

</div>

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [System Requirements](#-system-requirements)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [Architecture](#-architecture)
- [Configuration](#-configuration)
- [Report Generation](#-report-generation)
- [Troubleshooting](#-troubleshooting)
- [Disclaimer](#-disclaimer)
- [Contributing](#-contributing)
- [Author](#-author)

---

## 🎯 Overview

**X-Scan** is a sophisticated network vulnerability assessment tool designed for security professionals and system administrators. It combines aggressive network reconnaissance with real-time CVE (Common Vulnerabilities and Exposures) analysis from the National Vulnerability Database (NVD).

The tool performs three critical phases:
1. **Network Scanning** - Aggressive port scanning with service enumeration
2. **Data Acquisition** - Real-time vulnerability lookup via NVD API
3. **Intelligent Prioritization** - Advanced semantic filtering to identify truly relevant threats

### Why X-Scan?

- 🚀 **Fast & Accurate** - Combines Nmap's power with NVD's comprehensive vulnerability database
- 🧠 **Smart Filtering** - Semantic analysis eliminates false positives by matching versions and CVSS scores
- 📊 **Professional Reports** - Generates detailed, actionable security assessments
- 🔄 **Resilient** - Exponential backoff retry logic handles rate limiting and timeouts gracefully
- 🎨 **User-Friendly** - Colorized terminal interface with interactive menus

---

## ⚡ Features

### Phase 1: Aggressive Network Scanning
- **SYN Scan** (-sS) for stealthy port enumeration with TCP Connect fallback (-sT) on non-privileged systems
- **Service Version Detection** (-sV) to identify running services and applications
- **OS Detection** (-O) for comprehensive target profiling
- **Flexible Targeting** - Single IP addresses or entire CIDR networks
- **Default Port Range** - Scans ports 1-1000 (configurable)

### Phase 2: Real-Time Vulnerability Lookup
- **NVD API Integration** - Direct connection to NIST Vulnerability Database
- **Comprehensive CVE Data** - CVE IDs, descriptions, CVSS scores, and severity ratings
- **CVSS Dual Support** - Prioritizes CVSS v3.1, falls back to v2.0 for older vulnerabilities
- **Exponential Backoff** - Intelligent retry mechanism with configurable retry limits
- **Rate Limiting Handling** - Graceful management of 429/403 HTTP responses
- **Connection Resilience** - Timeout detection and automatic reconnection logic

### Phase 3: Intelligent Vulnerability Prioritization
- **Version Matching** - Semantic analysis to match detected versions with vulnerable versions in CVE descriptions
- **CVSS Filtering** - Configurable severity thresholds (default: ≥ 7.0 for High/Critical)
- **False Positive Reduction** - Advanced regex pattern matching for accurate version extraction
- **Fallback Logic** - Graceful degradation when version parsing fails
- **Top 5 Results** - Returns the most relevant vulnerabilities for each service

### Phase 4: Professional Reporting
- **Detailed Text Reports** - Structured, timestamp-named output files
- **Executive Summary** - Quick overview of risk assessment
- **Per-Host Breakdown** - Service-by-service vulnerability analysis
- **Actionable Recommendations** - Specific guidance for remediation
- **Methodology Documentation** - Complete transparency about assessment approach

---

## 💻 System Requirements

### Minimum Requirements
- **Python** - 3.8 or higher
- **RAM** - 512 MB (1 GB recommended)
- **Disk Space** - 100 MB for dependencies and reports
- **Network** - Active internet connection for NVD API queries

### Operating Systems
- ✅ **Linux** (Recommended for root-required SYN scans)
- ✅ **macOS**
- ✅ **Windows** (with Nmap installed)
- ✅ **BSD Variants**

### Permissions
- **Linux/macOS**: Root/sudo privileges required for SYN scans (-sS)
  - Without root, automatically falls back to TCP Connect scan (-sT)
- **Windows**: Standard user permissions sufficient (uses TCP Connect by default)

---

## 📦 Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/alfanoandrea/X-Scan.git
cd X-Scan
```

### Step 2: Install System Dependencies

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install nmap python3-pip
```

#### Linux (Fedora/RHEL)
```bash
sudo yum install nmap python3-pip
```

#### macOS
```bash
brew install nmap python3
```

#### Windows
- Download and install Nmap from [nmap.org](https://nmap.org)
- Add Nmap to your system PATH
- Install Python 3 from [python.org](https://www.python.org)

### Step 3: Install Python Dependencies
```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install python-nmap requests packaging
```

### Step 4: Verify Installation
```bash
python xscan.py
```

You should see the X-Scan banner and main menu.

---

## 🚀 Quick Start

### Basic Single IP Scan
```bash
python xscan.py
# Select option 1 (Scan Single IP)
# Enter target IP: 192.168.1.1
# Wait for scan and analysis to complete
# Review report in ./scans/ directory
```

### Scan Entire Network
```bash
python xscan.py
# Select option 2 (Scan CIDR Network)
# Enter CIDR network: 192.168.1.0/24
# Tool scans all 256 hosts in the range
```

### On Linux with Root Privileges (Recommended)
```bash
sudo python xscan.py
# Enables full SYN scan capability for maximum stealth
```

---

## 📖 Usage Guide

### Interactive Menu System

```
   __ __     _____ _____ _____ _____ 
  |  |  |___|   __|     |  _  |   | |
  |-   -|___|__   |   --|     | | | |
  |__|__|   |_____|_____|__|__|_|___| 
    by alfanowski       version: x.x

  (1) Scan Single IP
  (2) Scan CIDR Network
  (X) Exit

   >> 
```

### Single IP Scan Workflow
1. Choose option **1**
2. Enter target IP in format: `xxx.xxx.xxx.xxx`
3. Press Enter
4. Wait for scan completion (typically 30-120 seconds depending on network)
5. Tool automatically analyzes results and generates report
6. View summary in console and detailed report in `scans/` directory

### CIDR Network Scan Workflow
1. Choose option **2**
2. Enter CIDR network in format: `xxx.xxx.xxx.xxx/yy`
3. Press Enter
4. Tool scans all hosts in range
5. Consolidated report generated for all hosts

### Example Scan Session

**Input:**
```
Option: 1
Target IP: 192.168.1.100
```

**Output:**
```
  [-] Starting scan on 192.168.1.100...
  [+] Scan complete. Found 3 open services on 1 analyzed host(s).

  [***] Starting Dynamic Analysis and Prioritization [***]

  [>] Analysis: Host 192.168.1.100 | apache version 2.4.29 (Port 80)
  [+] Found 2 Prioritized CVEs.

  [>] Analysis: Host 192.168.1.100 | OpenSSH version 7.4 (Port 22)
  [+] Found 1 Prioritized CVE.

  [+] Report successfully generated: scans/xscan-report_20240315_143022.txt
```

---

## 🏗️ Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────┐
│              X-Scan Architecture                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  [CLI Interface]                                        │
│       ↓                                                 │
│  [Input Validation]  ← User enters IP/CIDR              │
│       ↓                                                 │
│  [PHASE 1: SCANNER]   ← Nmap aggressive scan            │
│       ├─ SYN Scan (-sS)                                 │
│       ├─ Service Detection (-sV)                        │
│       └─ OS Detection (-O)                              │
│       ↓                                                 │
│  [PHASE 2: DATA ACQUISITION]  ← Query NVD API           │
│       ├─ Product lookup                                 │
│       ├─ Retry logic with exponential backoff           │
│       └─ Timeout handling                               │
│       ↓                                                 │
│  [PHASE 3: PRIORITIZATION]  ← Semantic analysis         │
│       ├─ Version matching                               │
│       ├─ CVSS filtering                                 │
│       └─ False positive reduction                       │ 
│       ↓                                                 │
│  [PHASE 4: REPORTING]                                   │
│       ├─ Executive summary generation                   │
│       ├─ Detailed vulnerability breakdown               │
│       ├─ File output (./scans/)                         │
│       └─ Console summary display                        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Class Structure

#### `Style`
Terminal color and formatting codes for enhanced readability.

#### `Graphic`
Terminal UI management:
- `clear()` - Cross-platform screen clearing
- `intro()` - Animated banner display with optional timing

#### Key Functions

| Function | Purpose | Input | Output |
|----------|---------|-------|--------|
| `run_aggressive_scan()` | Execute Nmap scan | Target IP/CIDR | Dict with ports_data |
| `fetch_vulnerabilities()` | Query NVD API | Product name | List of CVEs |
| `prioritize_vulnerabilities()` | Filter relevant CVEs | Raw CVE list + version | Top 5 relevant CVEs |
| `analyze_scan_data()` | Full analysis pipeline | Scan results | Complete assessment |
| `generate_txt_report()` | Create report file | Assessment data | File path |
| `print_report_summary()` | Display console output | Assessment data | Console output |
| `userInput()` | CLI menu handler | User input | Target address |

---

## ⚙️ Configuration

### Modifiable Global Constants (In `xscan.py`)

```python
# API Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # NVD endpoint
USER_AGENT = f'X-Scanner/{version}'  # API request header
DEFAULT_PORTS = '1-1000'  # Port range for scanning

# Resilience Configuration
MAX_RETRIES = 5  # Maximum retry attempts for API calls
API_TIMEOUT = 15  # Seconds before request timeout

# Output
OUTPUT_DIR = 'scans'  # Directory for report storage
```

### Adjusting Scan Parameters

**To scan a different port range**, edit line ~34:
```python
DEFAULT_PORTS = '1-65535'  # Scan all ports (slow!)
```

**To modify API retry behavior**, edit line ~40:
```python
MAX_RETRIES = 10  # More retries for unreliable networks
API_TIMEOUT = 30  # Longer timeout
```

**To change output directory**, edit line ~41:
```python
OUTPUT_DIR = '/var/log/xscan_reports'
```

---

## 📊 Report Generation

### Report Structure

Each scan generates a timestamped text report in the `scans/` directory with the format:
```
xscan-report_YYYYMMDD_HHMMSS.txt
```

### Example Report Content

```
================================================================================
X-SCAN REPORT | TARGET: 192.168.1.100 | DATE: 2024-03-15 14:30:22
TOOL DEVELOPED BY ALFANOWSKI
================================================================================

--- EXECUTIVE SUMMARY ---
STATUS: High/Critical Risk identified on 1 host(s). IMMEDIATE ACTION REQUIRED.
-----------------------------------

#####################
### HOST ANALYZED ### --> 192.168.1.100
#####################
################################################################################
VULNERABLE SERVICE: apache 2.4.29 (Port TCP/80)
################################################################################
  [CRITICAL FINDING] CVE ID: CVE-2021-41773 | SEVERITY: HIGH (CVSS: 7.5)
      Description: Apache HTTP Server 2.4.41 through 2.4.49 contains an out-of-bounds 
                   write in the mod_auth_digest module which may allow an attacker...
      --- RECOMMENDED ACTION: Immediate patching by updating the service to a fixed 
                   version (consult NVD for exact fix version).

================================================================================
METHODOLOGY: Aggressive Nmap Scan (sV) + Dynamic NVD API Analysis with Exponential 
Backoff + Version & CVSS Match Prioritization.
DISCLAIMER: This tool provides a risk assessment based on public data. It does 
not guarantee the complete absence of vulnerabilities.
================================================================================
```

---

## 🐛 Troubleshooting

### Issue: "Missing modules! Run 'pip install -r requirements.txt'"

**Solution:**
```bash
pip install -r requirements.txt
# or manually:
pip install python-nmap requests packaging
```

### Issue: "WARNING: SYN scan requires root privileges"

**Cause:** Running on Linux without sudo
**Solution:**
```bash
sudo python xscan.py  # Automatic fallback to TCP Connect if you don't have root
```

### Issue: "Invalid IP format" error

**Cause:** Incorrect IP address format
**Solution:** Use standard IPv4 notation: `192.168.1.1`
For networks: Use CIDR notation: `192.168.1.0/24`

### Issue: "Nmap Error. Check permissions or target syntax"

**Possible Causes:**
- Nmap not installed or not in PATH
- Invalid target address
- Firewall blocking port scanning

**Solutions:**
```bash
# Verify Nmap installation
nmap --version

# Test basic scan
nmap 192.168.1.1

# Add Nmap to PATH on Windows (if needed)
# System Properties → Environment Variables → PATH → Add Nmap installation directory
```

### Issue: "NVD Rate Limit (403/429)" repeated errors

**Cause:** API rate limiting from NVD
**Solution:** 
- Tool automatically handles this with exponential backoff
- Consider running scans during off-peak hours
- Check NVD API status at [services.nvd.nist.gov](https://services.nvd.nist.gov)

### Issue: "Connection Timeout" errors

**Cause:** Network connectivity issues or slow internet
**Solution:**
```bash
# Increase API timeout (edit xscan.py line 40)
API_TIMEOUT = 30  # Increased from 15
MAX_RETRIES = 10  # Increased from 5
```

### Issue: No reports generated

**Cause:** Output directory permission issue
**Solution:**
```bash
# Verify scans directory is writable
ls -la | grep scans

# If needed, create manually
mkdir -p scans
chmod 755 scans
```

### Issue: "Unknown Product and Version" skipped

**Cause:** Service not recognized by Nmap or version detection failed
**Solution:**
- This is expected behavior for unusual services
- Manual inspection of the scan may reveal more information
- Try running with more aggressive Nmap options (edit DEFAULT_PORTS)

---

## ⚠️ Disclaimer

**IMPORTANT LEGAL NOTICE:**

1. **Authorization Required**
   - Only scan networks and systems you own or have explicit written permission to test
   - Unauthorized network scanning may violate laws in your jurisdiction

2. **Liability**
   - X-Scan is provided "as-is" without warranty
   - Authors are not responsible for misuse or damages caused by this tool
   - Users assume full responsibility for their actions

3. **Data Accuracy**
   - This tool provides risk assessments based on public vulnerability data
   - It does not guarantee the complete absence of vulnerabilities
   - Results should be interpreted by qualified security professionals
   - False positives and false negatives are possible

4. **Compliance**
   - Ensure compliance with:
     - GDPR (if EU citizens' data involved)
     - HIPAA (healthcare systems)
     - PCI-DSS (payment systems)
     - CFAA (Computer Fraud and Abuse Act - US)
     - Similar regulations in your jurisdiction

5. **Responsible Disclosure**
   - If you discover vulnerabilities via this tool, follow responsible disclosure practices
   - Report findings to affected organizations through proper channels

---

## 🤝 Contributing

**Contributions are welcome and encouraged!** X-Scan uses a **Community License** that allows anyone to contribute improvements, bug fixes, and enhancements.

### How to Contribute

1. **Fork** the repository on GitHub
2. **Create** a feature branch (`git checkout -b feature/your-feature`)
3. **Make** your changes and improvements
4. **Test** thoroughly before submitting
5. **Commit** with clear messages (`git commit -m 'Add your feature'`)
6. **Push** to your fork (`git push origin feature/your-feature`)
7. **Submit** a Pull Request to the main repository

### Contribution Guidelines

- Follow **PEP 8** Python style guide
- Add **docstrings** to new functions and classes
- Include **type hints** where possible
- Test your code and ensure no regressions
- Update **README** if adding new features
- Provide clear commit messages and PR descriptions
- Respect the Community License terms

### What We Accept

✅ Bug fixes and patches
✅ Performance improvements
✅ New features and enhancements
✅ Documentation improvements
✅ Code refactoring and cleanup
✅ Security hardening
✅ Test coverage expansion
✅ Integration with other tools

### Attribution

All contributors will be recognized in the project. By contributing, you agree to:
- License your contributions under this **Community License**
- Accept that your code may be used commercially with proper attribution
- Allow the Creator (alfanowski) to integrate your changes into the main project

### Questions?

- Check existing [GitHub Issues](https://github.com/alfanoandrea/X-Scan/issues)
- Start a discussion in [GitHub Discussions](https://github.com/alfanoandrea/X-Scan/discussions)
- Contact the Creator directly if needed

---

## 📄 License

**Community License v1.0** - Owned by alfanowski

X-Scan is distributed under a **Community License** that balances open-source collaboration with creator ownership.

### License Summary

| Capability | Allowed |
|-----------|---------|
| **Use the Software** | ✅ Yes |
| **Modify & Create Derivatives** | ✅ Yes |
| **Distribute & Sublicense** | ✅ Yes |
| **Commercial Use** | ✅ Yes |
| **Fork on GitHub** | ✅ Yes |
| **Contribute Improvements** | ✅ Yes |
| **Reverse Engineer** | ✅ Yes |
| **Security Research** | ✅ Yes |
| **SaaS/Cloud Hosting** | ✅ Yes |

### Key Requirements

When using, modifying, or distributing X-Scan, you must:

1. **Maintain Attribution** - Include copyright notice: `© 2024-2025 alfanowski`
2. **Include License** - Distribute this Community License with all copies
3. **Document Changes** - Include a changelog noting your modifications
4. **Keep it Open** - If distributing derivatives, license under this same Community License
5. **Link Original** - Include a link to the original repository

### Creator Ownership

- **alfanowski** retains ownership of the original X-Scan source code
- The Creator has final say on what gets merged into the main project
- All contributors retain ownership of their contributions
- Contributors grant the Creator a royalty-free license to use their work

### No Licensing Fees

- **Free to use** - No fees, royalties, or compensation required
- **Free to modify** - Create and distribute derivatives at no cost
- **Free to commercialize** - Build commercial products using X-Scan

### Open Collaboration

The Community License encourages:
- 🍴 Forking and maintaining alternative versions
- 🔧 Creating and sharing improvements
- 🤝 Contributing bug fixes and features
- 📚 Publishing research and findings
- 💼 Building commercial products
- 🔬 Security research and analysis

**See the [LICENSE](LICENSE) file for complete legal terms.**

---

## 👤 Author

**alfanowski**

- GitHub: [@alfanoandrea](https://github.com/alfanoandrea)

### Special Thanks
- NIST National Vulnerability Database (NVD) for vulnerability data
- Nmap project for outstanding network security tools
- Python community for excellent libraries

---

## 📞 Support & Feedback

Have questions or found a bug? 

- 🐛 **Report Bugs** - [GitHub Issues](https://github.com/alfanoandrea/X-Scan/issues)
- 💡 **Feature Requests** - [GitHub Discussions](https://github.com/alfanoandrea/X-Scan/discussions)
- 📧 **Security Issues** - Contact directly via GitHub (do not use public issues)

---

## 📚 Additional Resources

### Learning Resources
- [NMAP Documentation](https://nmap.org/book/man.html)
- [CVSS Scoring Guide](https://www.first.org/cvss/v3.1/specification-document)
- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

### Related Tools
- [Metasploit Framework](https://www.metasploit.com/) - Penetration testing
- [OpenVAS](https://www.openvas.org/) - Vulnerability scanner
- [Qualys VMDR](https://www.qualys.com/forms/vmdr-trial/) - Enterprise scanning
- [Shodan](https://www.shodan.io/) - Internet search engine for devices

---

<div align="center">

**Made with ❤️ by alfanowski**

*Last Updated: December 2025*

[⬆ back to top](#-overview)

</div>