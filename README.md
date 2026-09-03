# 🔐 JWT/OAuth Token Analyzer

> A lightweight, zero-dependency JWT token analyzer that decodes, parses, and analyzes JSON Web Tokens with security checks.

[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Size](https://img.shields.io/badge/Size-%3C150%20lines-lightgrey.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen.svg)]()

---

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Examples](#-output-examples)
- [Security Checks](#-security-checks)
- [Supported Claims](#-supported-claims)
- [Commands Reference](#-commands-reference)
- [Use Cases](#-use-cases)
- [License](#-license)

---

## ✨ Features

- **JWT decoding** - Parse and decode JWT tokens instantly
- **Security analysis** - Detect expired tokens, weak algorithms, missing claims
- **Claim extraction** - Display user, email, roles, scopes, and more
- **Multiple formats** - Read tokens from arguments, files, or stdin
- **Verbose mode** - View complete header, payload, and signature
- **Zero dependencies** - Pure Python standard library
- **Single file** - Entire tool in one Python file (< 150 lines)

---

## 🚀 Quick Start

```bash
# Clone or download
git clone https://github.com/Believe-sec-io/OAuth-Token-analyzer.git
cd jwt-analyzer

# Analyze a JWT token
python jwt_analyzer.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Done! No installation needed.
