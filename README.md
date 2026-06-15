# 🛡️ DOMAIN OSINT v10.0 - Defensive Security Edition

**Advanced Domain Intelligence Tool | Cross-Platform (Windows + Linux)**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![C](https://img.shields.io/badge/Language-C-00599C.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D7.svg)]()

> ⚠️ **Disclaimer**: This tool is for AUTHORIZED security assessments only. Unauthorized use against systems you don't own or have explicit written permission to test is illegal and unethical.

---

## 📋 About

**DOMAIN OSINT** is a comprehensive domain intelligence gathering tool written in C. It performs security assessments and reconnaissance for defensive purposes.

### Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **DNS Records** | A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, DMARC |
| 🌐 **IP Intelligence** | Geolocation, Organization, rDNS, CDN detection |
| 📝 **Whois Lookup** | Registration info, creation date, abuse contacts |
| 🔌 **Port Scanning** | 50+ common ports with risk assessment |
| 🧪 **Tech Fingerprinting** | CMS, web servers, frameworks detection |
| 📧 **Email Security** | SPF, DKIM, DMARC, MTA-STS validation |
| 🕸️ **Subdomain Enumeration** | 100+ common subdomains + CT logs |
| 🔐 **Security Headers** | CSP, HSTS, X-Frame-Options analysis |
| ⚠️ **Vulnerability Detection** | Zone Transfer, exposed files, misconfigurations |

---

## 🚀 Installation & Usage

### Prerequisites

- **Windows**: MinGW or TDM-GCC
- **Linux**: GCC + libresolv + pthread

### Build

```bash
# Windows (MinGW)
gcc -O2 -o domain_osint.exe domain_osint.c -lws2_32 -ldnsapi

# Linux
gcc -O2 -o domain_osint domain_osint.c -lresolv -lpthread
Usage
bash
# Interactive mode
./domain_osint

# Single domain scan
./domain_osint -d example.com

# Skip port scan
./domain_osint -d example.com --no-ports

# Batch scan from file
./domain_osint --batch domains.txt
📊 Output Example
text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ◈ IP ADDRESS & NETWORK INFO
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [+] IPv4 Address   : 172.##.##.###
  [+] Organization   : Verizon Media
  [+] Location       : IRAQ | Mosual
  
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ◈ EMAIL SECURITY (SPF / DMARC / DKIM)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [+] SPF Record     : ####
  [+] SPF Policy     : ####
  [+] DMARC Record   : ####
  [+] DMARC Policy   :####
📁 Project Structure
text
domain-osint/
├── domain_osint.c      # Main source code
├── README.md           # This file
├── LICENSE             # MIT License
└── osint_reports/      # JSON reports output directory
🛡️ License
MIT License - See LICENSE file for details.

Copyright (c) 2025 RussianHarvey

⭐ Star History
If you find this tool useful, please consider giving it a star on GitHub!

🙏 Acknowledgments
Built for defensive security research

Inspired by OSINT best practices

C implementation for maximum performance


Made with ❤️ by RussianHarvey
