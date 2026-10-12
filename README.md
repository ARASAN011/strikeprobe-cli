# ⚡ StrikeProbe Developer CLI (`strikeprobe-cli`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![OWASP MASVS](https://img.shields.io/badge/OWASP%20MASVS-v2.0-4285F4.svg)](https://mas.owasp.org/MASVS/)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg)](https://www.python.org/)
[![Zero Retention](https://img.shields.io/badge/Privacy-Zero%20Database%20Storage-22C55E.svg)](#zero-retention-architecture)

**StrikeProbe Developer CLI** is a lightweight, **100% local and zero-retention** Static Application Security Testing (SAST) command-line tool for Android developers and DevSecOps engineers.

It audits compiled Android binaries (`.apk`), source archives (`.zip`), or Android project directories against **OWASP MASVS v2.0 / MASTG** directly in your terminal or CI/CD pipeline—without uploading proprietary code to external servers or storing anything in a database.

---

## ✨ Features

- **100% Local & Ephemeral (Zero-Retention)**: Unpacks `.apk` binaries in an isolated temporary directory, runs all checks in volatile RAM, and immediately erases temporary files inside a `finally` block.
- **Binary `AndroidManifest.xml` Auditing**:
  - Detects `android:debuggable="true"`, `android:allowBackup="true"`, `android:usesCleartextTraffic="true"`, and missing `networkSecurityConfig`.
  - Identifies unprotected exported `activity`, `service`, `receiver`, and `provider` components (`CWE-926`).
  - Flags high-risk permissions & banking overlay trojan heuristics (`BIND_ACCESSIBILITY_SERVICE` + `SYSTEM_ALERT_WINDOW` + `INTERNET`).
- **DEX Bytecode & Source Code SAST**:
  - Scans `.dex` bytecode strings and `.java`, `.kt`, `.smali`, `.xml`, `.json`, `.js` files against OWASP MASVS v2.0 YAML rules.
  - Detects hardcoded AWS/GCP/Firebase keys, Bearer/JWT tokens, `AES/ECB` weak ciphers, `MD5`/`SHA-1` hashes, static IVs, insecure `WebView` bridges, SQL injection vectors, and `DexClassLoader` dynamic payload droppers.
- **Multi-Format Developer Reports**:
  - Rich ANSI Terminal Scorecard (`--format terminal`)
  - GitHub Code Scanning **SARIF v2.1.0** (`--format sarif`)
  - Machine-readable **JSON** (`--format json`)
  - Standalone dark-mode **HTML** (`--format html`) & **Markdown** (`--format markdown`)
- **CI/CD Security Gate (`--fail-on`)**:
  - Automatically fails your GitHub Actions / GitLab CI build with exit code `1` if vulnerabilities meet or exceed your severity threshold (`critical`, `high`, `medium`, `low`).

---

## 📦 Installation

```bash
git clone https://github.com/ARASAN011/strikeprobe-cli.git
cd strikeprobe-cli
pip install .
```

Verify installation:
```bash
strikeprobe version
strikeprobe rules
```

---

## 🚀 Usage Examples

### 1. Audit an Android APK in the Terminal
```bash
strikeprobe scan app-release.apk
```

### 2. Scan an Android Studio Source Directory & Export HTML Report
```bash
strikeprobe scan ./my-android-project --output audit-report.html
```

### 3. Export SARIF v2.1.0 for GitHub Code Scanning & Fail CI on High/Critical Issues
```bash
strikeprobe scan app-release.apk --format sarif --output results.sarif --fail-on high
```

### 4. Filter Terminal Output to Critical & High Findings Only
```bash
strikeprobe scan app-release.apk --severity high
```

---

## 🤖 GitHub Actions CI/CD Integration

Add StrikeProbe CLI to `.github/workflows/android-security.yml` to block pull requests that introduce `High` or `Critical` OWASP MASVS vulnerabilities:

```yaml
name: Android OWASP MASVS Audit

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  strikeprobe-sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install StrikeProbe Developer CLI
        run: pip install git+https://github.com/ARASAN011/strikeprobe-cli.git

      - name: Run OWASP MASVS v2.0 Audit
        run: strikeprobe scan . --format sarif --output strikeprobe.sarif --fail-on high
```

---

## 🛡️ OWASP MASVS v2.0 Coverage

| MASVS Category | Checks Performed |
| :--- | :--- |
| **`MASVS-STORAGE`** | Hardcoded secrets/passwords, `MODE_WORLD_READABLE`, `android:allowBackup="true"` |
| **`MASVS-CRYPTO`** | Hardcoded cloud API keys (`AKIA...`, `AIza...`), `ECB` cipher mode, `MD5`/`SHA-1`, static IVs |
| **`MASVS-AUTH`** | Hardcoded Bearer / JWT tokens in code or DEX strings |
| **`MASVS-NETWORK`** | `usesCleartextTraffic="true"`, missing `networkSecurityConfig`, `TrustAll` X509TrustManager, `http://` URLs |
| **`MASVS-PLATFORM`** | Unprotected exported Activities/Services/Receivers/Providers, `WebView` JS bridge & file access, outdated `targetSdkVersion` |
| **`MASVS-CODE`** | Raw SQLite query concatenation (`rawQuery`), `Runtime.exec()` / `ProcessBuilder` command execution |
| **`MASVS-RESILIENCE`** | `android:debuggable="true"`, `DexClassLoader` dynamic code loading, Accessibility + Overlay trojan heuristics |
| **`MASVS-PRIVACY`** | High-risk hardware & PII permissions (`READ_SMS`, `RECEIVE_SMS`, `RECORD_AUDIO`, `CAMERA`, `ACCESS_FINE_LOCATION`) |

---

## 📄 License

Released under the [MIT License](./LICENSE).
