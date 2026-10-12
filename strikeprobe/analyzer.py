import hashlib
import os
import re
import shutil
import tempfile
import time
import zipfile
from typing import List, Dict, Any, Set
import yaml
from pyaxmlparser import APK

from strikeprobe.models import Finding, ScanReport

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

MASVS_CATEGORIES = [
    "MASVS-STORAGE",
    "MASVS-CRYPTO",
    "MASVS-AUTH",
    "MASVS-NETWORK",
    "MASVS-PLATFORM",
    "MASVS-CODE",
    "MASVS-RESILIENCE",
    "MASVS-PRIVACY",
]

DANGEROUS_PERMISSIONS = {
    "READ_SMS": ("High", "MASVS-PRIVACY", "CWE-359", "Application requests access to read user SMS messages."),
    "RECEIVE_SMS": ("High", "MASVS-PRIVACY", "CWE-359", "Application can intercept incoming SMS messages (potential OTP theft vector)."),
    "SEND_SMS": ("High", "MASVS-PRIVACY", "CWE-359", "Application can send SMS messages without user interaction."),
    "RECORD_AUDIO": ("Medium", "MASVS-PRIVACY", "CWE-359", "Application requests microphone recording privileges."),
    "CAMERA": ("Medium", "MASVS-PRIVACY", "CWE-359", "Application requests hardware camera access."),
    "ACCESS_FINE_LOCATION": ("Medium", "MASVS-PRIVACY", "CWE-359", "Application tracks precise GPS location coordinates."),
    "READ_CONTACTS": ("Medium", "MASVS-PRIVACY", "CWE-359", "Application can read the user's address book contacts."),
    "SYSTEM_ALERT_WINDOW": ("High", "MASVS-RESILIENCE", "CWE-1021", "Application can draw overlays on top of other apps (Cloak & Dagger / tapjacking risk)."),
    "BIND_ACCESSIBILITY_SERVICE": ("Critical", "MASVS-RESILIENCE", "CWE-250", "Application binds to Android Accessibility Service, allowing full screen reading and UI automation."),
    "BIND_DEVICE_ADMIN": ("Critical", "MASVS-RESILIENCE", "CWE-250", "Application requests Device Administrator privileges."),
    "REQUEST_INSTALL_PACKAGES": ("High", "MASVS-CODE", "CWE-494", "Application can initiate installation of arbitrary external APK packages."),
}


def load_rules() -> List[Dict[str, Any]]:
    rules_path = os.path.join(os.path.dirname(__file__), "rules", "masvs_rules.yaml")
    if not os.path.exists(rules_path):
        return []
    with open(rules_path, "r", encoding="utf-8") as f:
        parsed = yaml.safe_load(f) or {}
        return parsed.get("rules", [])


def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    if os.path.isdir(path):
        for root, _, files in sorted(os.walk(path)):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as f:
                        while chunk := f.read(65536):
                            h.update(chunk)
                except Exception:
                    pass
        return h.hexdigest()

    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class StrikeProbeAnalyzer:
    """Zero-Retention Ephemeral Static Analyzer for Android APKs & Source Code."""

    def __init__(self):
        self.rules = load_rules()

    def scan_target(self, target_path: str) -> ScanReport:
        start_time = time.time()
        abs_path = os.path.abspath(target_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Target not found: {abs_path}")

        is_dir = os.path.isdir(abs_path)
        lower_name = os.path.basename(abs_path).lower()
        if is_dir:
            target_type = "directory"
            file_size = sum(
                os.path.getsize(os.path.join(r, f))
                for r, _, files in os.walk(abs_path)
                for f in files
            )
        elif lower_name.endswith(".apk"):
            target_type = "apk"
            file_size = os.path.getsize(abs_path)
            self._verify_zip_magic(abs_path)
        elif lower_name.endswith(".zip"):
            target_type = "source_zip"
            file_size = os.path.getsize(abs_path)
            self._verify_zip_magic(abs_path)
        else:
            raise ValueError("Unsupported target. Provide an .apk file, .zip archive, or source directory.")

        report = ScanReport(
            target_name=os.path.basename(abs_path),
            target_type=target_type,
            sha256=compute_sha256(abs_path),
            file_size_bytes=file_size,
        )

        # Ephemeral workspace: automatically wiped upon leaving context
        temp_extract_dir = tempfile.mkdtemp(prefix="strikeprobe_ephemeral_")
        try:
            if target_type == "apk":
                self._analyze_apk_manifest(abs_path, report)
                with zipfile.ZipFile(abs_path, "r") as zf:
                    zf.extractall(temp_extract_dir)
                self._scan_extracted_tree(temp_extract_dir, report)
            elif target_type == "source_zip":
                with zipfile.ZipFile(abs_path, "r") as zf:
                    zf.extractall(temp_extract_dir)
                self._scan_extracted_tree(temp_extract_dir, report)
            else:
                self._scan_extracted_tree(abs_path, report)
        finally:
            shutil.rmtree(temp_extract_dir, ignore_errors=True)

        report.findings = self._deduplicate_findings(report.findings)
        self._compute_masvs_scorecard(report)
        report.scan_duration_sec = round(time.time() - start_time, 2)
        return report

    @staticmethod
    def _verify_zip_magic(file_path: str):
        with open(file_path, "rb") as f:
            magic = f.read(4)
        if magic != b"PK\x03\x04":
            raise ValueError("Invalid archive header: expected PK\\x03\\x04 ZIP/APK magic bytes.")

    def _analyze_apk_manifest(self, apk_path: str, report: ScanReport):
        try:
            apk = APK(apk_path)
        except Exception as exc:
            report.findings.append(
                Finding(
                    rule_id="SP-MANIFEST-PARSE",
                    title="Corrupted or Obfuscated AndroidManifest.xml",
                    severity="Low",
                    confidence="Medium",
                    masvs_category="MASVS-RESILIENCE",
                    description=f"Binary XML parser encountered an anomaly: {exc}",
                    evidence=str(exc),
                    affected_file="AndroidManifest.xml",
                )
            )
            return

        report.package_name = getattr(apk, "package", None) or "Unknown"
        report.version_name = str(getattr(apk, "version_name", None) or "N/A")
        report.version_code = str(getattr(apk, "version_code", None) or "N/A")
        report.min_sdk = str(getattr(apk, "min_sdk_version", None) or "N/A")
        report.target_sdk = str(getattr(apk, "target_sdk_version", None) or "N/A")
        report.permissions = sorted(list(set(apk.permissions or [])))

        # 1. Target SDK Check
        try:
            if report.target_sdk.isdigit() and int(report.target_sdk) < 31:
                report.findings.append(
                    Finding(
                        rule_id="SP-MANIFEST-001",
                        title=f"Outdated Target SDK Level (API {report.target_sdk})",
                        severity="Medium" if int(report.target_sdk) < 29 else "Low",
                        confidence="High",
                        masvs_category="MASVS-PLATFORM",
                        description=f"Application targets Android API level {report.target_sdk}, missing modern Android runtime sandbox enforcements.",
                        evidence=f"android:targetSdkVersion=\"{report.target_sdk}\"",
                        affected_file="AndroidManifest.xml",
                        remediation="Upgrade targetSdkVersion to API 34+ in build.gradle.",
                        cwe="CWE-1188",
                    )
                )
        except Exception:
            pass

        # 2. Dangerous Permissions & Malware Correlation
        short_perms = set()
        for perm in report.permissions:
            short = perm.split(".")[-1].upper()
            short_perms.add(short)
            if short in DANGEROUS_PERMISSIONS:
                sev, cat, cwe, desc = DANGEROUS_PERMISSIONS[short]
                report.findings.append(
                    Finding(
                        rule_id=f"SP-PERM-{short[:12]}",
                        title=f"Sensitive Android Permission: {short}",
                        severity=sev,
                        confidence="High",
                        masvs_category=cat,
                        description=desc,
                        evidence=f"<uses-permission android:name=\"{perm}\" />",
                        affected_file="AndroidManifest.xml",
                        remediation=f"Verify that {short} is strictly required for core functionality and follows least-privilege principles.",
                        cwe=cwe,
                    )
                )

        if {"BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "INTERNET"}.issubset(short_perms):
            report.findings.append(
                Finding(
                    rule_id="SP-HEURISTIC-OVERLAY",
                    title="Critical Malware Heuristic: Accessibility + Overlay + Internet",
                    severity="Critical",
                    confidence="High",
                    masvs_category="MASVS-RESILIENCE",
                    description="Combines Accessibility Service, System Alert Window overlays, and Internet access—characteristic of Android banking overlay trojans.",
                    evidence="BIND_ACCESSIBILITY_SERVICE + SYSTEM_ALERT_WINDOW + INTERNET",
                    affected_file="AndroidManifest.xml",
                    remediation="Remove AccessibilityService or System Alert Window permissions unless explicitly justified.",
                    cwe="CWE-1021",
                )
            )

        # 3. Application Flags & Exported Components
        try:
            manifest_xml = apk.xml.get("AndroidManifest.xml")
            if manifest_xml is None:
                return

            for elem in manifest_xml.iter():
                if elem.tag == "application":
                    debuggable = elem.get(f"{ANDROID_NS}debuggable")
                    allow_backup = elem.get(f"{ANDROID_NS}allowBackup")
                    cleartext = elem.get(f"{ANDROID_NS}usesCleartextTraffic")
                    net_config = elem.get(f"{ANDROID_NS}networkSecurityConfig")

                    if debuggable and debuggable.lower() == "true":
                        report.findings.append(
                            Finding(
                                rule_id="SP-MANIFEST-DEBUG",
                                title="Application Debuggable Flag Enabled in Build",
                                severity="Critical",
                                confidence="High",
                                masvs_category="MASVS-RESILIENCE",
                                description="android:debuggable=\"true\" allows attackers to attach JDWP debuggers, dump memory, and execute arbitrary code in the app context.",
                                evidence="android:debuggable=\"true\"",
                                affected_file="AndroidManifest.xml",
                                remediation="Set android:debuggable=\"false\" in release builds.",
                                cwe="CWE-489",
                            )
                        )

                    if allow_backup is None or allow_backup.lower() == "true":
                        report.findings.append(
                            Finding(
                                rule_id="SP-MANIFEST-BACKUP",
                                title="ADB Backup Enabled (android:allowBackup=\"true\")",
                                severity="Medium",
                                confidence="High",
                                masvs_category="MASVS-STORAGE",
                                description="Allows anyone with USB debugging enabled to extract application sandbox data via `adb backup`.",
                                evidence=f"android:allowBackup=\"{allow_backup or 'true (default)'}\"",
                                affected_file="AndroidManifest.xml",
                                remediation="Explicitly set android:allowBackup=\"false\" or configure fullBackupContent exclusions.",
                                cwe="CWE-530",
                            )
                        )

                    if cleartext and cleartext.lower() == "true":
                        report.findings.append(
                            Finding(
                                rule_id="SP-MANIFEST-CLEARTEXT",
                                title="Cleartext HTTP Network Traffic Permitted",
                                severity="High",
                                confidence="High",
                                masvs_category="MASVS-NETWORK",
                                description="Application explicitly permits unencrypted HTTP connections, exposing API payloads to Man-in-the-Middle (MitM) interception.",
                                evidence="android:usesCleartextTraffic=\"true\"",
                                affected_file="AndroidManifest.xml",
                                remediation="Set android:usesCleartextTraffic=\"false\" and enforce HTTPS in Network Security Config.",
                                cwe="CWE-319",
                            )
                        )

                    if not net_config:
                        report.findings.append(
                            Finding(
                                rule_id="SP-MANIFEST-NETCFG",
                                title="Missing Explicit Network Security Configuration",
                                severity="Low",
                                confidence="High",
                                masvs_category="MASVS-NETWORK",
                                description="No android:networkSecurityConfig attribute declared on <application>. Pinning and trust anchors are not declaratively enforced.",
                                evidence="<application> missing android:networkSecurityConfig",
                                affected_file="AndroidManifest.xml",
                                remediation="Add res/xml/network_security_config.xml with cleartextTrafficPermitted=\"false\" and certificate pins.",
                                cwe="CWE-295",
                            )
                        )

                elif elem.tag in {"activity", "service", "receiver", "provider"}:
                    comp_name = elem.get(f"{ANDROID_NS}name") or "UnnamedComponent"
                    exported = elem.get(f"{ANDROID_NS}exported")
                    perm = elem.get(f"{ANDROID_NS}permission")
                    has_intent_filter = any(child.tag == "intent-filter" for child in elem)

                    is_exported = (exported and exported.lower() == "true") or (
                        exported is None and has_intent_filter
                    )
                    if is_exported:
                        report.exported_components.append(f"{elem.tag}:{comp_name}")
                        is_main_launcher = "MAIN" in (
                            child.get(f"{ANDROID_NS}name", "")
                            for f in elem.findall("intent-filter")
                            for child in f
                        )
                        if not perm and not is_main_launcher:
                            sev = "High" if elem.tag in {"provider", "service"} else "Medium"
                            report.findings.append(
                                Finding(
                                    rule_id=f"SP-EXPORTED-{elem.tag.upper()}",
                                    title=f"Unprotected Exported {elem.tag.capitalize()}: {comp_name.split('.')[-1]}",
                                    severity=sev,
                                    confidence="Medium",
                                    masvs_category="MASVS-PLATFORM",
                                    description=f"The {elem.tag} `{comp_name}` is exported to other apps on the device without an explicit permission guard.",
                                    evidence=f"<{elem.tag} android:name=\"{comp_name}\" android:exported=\"true\" />",
                                    affected_file="AndroidManifest.xml",
                                    remediation=f"Set android:exported=\"false\" on {comp_name} or protect it with a signature-level custom permission.",
                                    cwe="CWE-926",
                                )
                            )
        except Exception:
            pass

    def _scan_extracted_tree(self, root_dir: str, report: ScanReport):
        url_regex = re.compile(r"https?://[a-zA-Z0-9\.\-_]+(?:/[a-zA-Z0-9\.\-_/%\?=&#]*)?")
        ignored_hosts = {
            "schemas.android.com",
            "www.w3.org",
            "apache.org",
            "xmlpull.org",
            "example.com",
            "localhost",
            "127.0.0.1",
        }
        endpoints: Set[str] = set()

        for root, _, files in os.walk(root_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, root_dir).replace("\\", "/")
                ext = os.path.splitext(fname)[1].lower()

                # Extract printable strings from DEX bytecode files
                if ext == ".dex":
                    self._scan_dex_binary(fpath, rel_path, report, url_regex, ignored_hosts, endpoints)
                    continue

                if ext not in {".java", ".kt", ".smali", ".xml", ".json", ".js", ".ts", ".properties"}:
                    continue

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                self._scan_text_content(content, rel_path, ext, report, url_regex, ignored_hosts, endpoints)

        report.discovered_endpoints = sorted(list(endpoints))[:100]

    def _scan_dex_binary(
        self,
        dex_path: str,
        rel_path: str,
        report: ScanReport,
        url_regex: re.Pattern,
        ignored_hosts: Set[str],
        endpoints: Set[str],
    ):
        try:
            with open(dex_path, "rb") as f:
                raw = f.read()
            ascii_strings = re.findall(rb"[\x20-\x7e]{8,}", raw)
            decoded = "\n".join(s.decode("ascii", errors="ignore") for s in ascii_strings)
            self._scan_text_content(decoded, rel_path, ".smali", report, url_regex, ignored_hosts, endpoints)
        except Exception:
            pass

    def _scan_text_content(
        self,
        content: str,
        rel_path: str,
        ext: str,
        report: ScanReport,
        url_regex: re.Pattern,
        ignored_hosts: Set[str],
        endpoints: Set[str],
    ):
        lines = content.splitlines()

        for m in url_regex.finditer(content):
            url = m.group(0).rstrip(".,;'\")")
            if not any(h in url for h in ignored_hosts):
                endpoints.add(url)
                if url.startswith("http://"):
                    report.findings.append(
                        Finding(
                            rule_id="SP-NET-HTTP-URL",
                            title="Hardcoded Cleartext HTTP Endpoint",
                            severity="Medium",
                            confidence="High",
                            masvs_category="MASVS-NETWORK",
                            description="Hardcoded unencrypted `http://` URL discovered in application binary or source.",
                            evidence=url[:120],
                            affected_file=rel_path,
                            remediation="Migrate endpoint to `https://` with TLS 1.2/1.3.",
                            cwe="CWE-319",
                        )
                    )

        for rule in self.rules:
            allowed_exts = rule.get("extensions", [])
            if allowed_exts and ext not in allowed_exts:
                continue

            pattern = rule.get("match")
            if not pattern:
                continue

            exclude = rule.get("exclude")
            rx = re.compile(pattern)
            ex_rx = re.compile(exclude, re.IGNORECASE) if exclude else None

            for idx, line in enumerate(lines, 1):
                for match in rx.finditer(line):
                    snippet = match.group(0).strip()
                    if ex_rx and ex_rx.search(snippet):
                        continue
                    report.findings.append(
                        Finding(
                            rule_id=rule.get("id", "SP-RULE"),
                            title=rule.get("title", "Code Security Finding"),
                            severity=rule.get("severity", "Medium"),
                            confidence="High",
                            masvs_category=rule.get("category", "MASVS-CODE"),
                            description=rule.get("description", ""),
                            evidence=snippet[:140],
                            affected_file=rel_path,
                            affected_line=idx if ext != ".smali" else None,
                            remediation=rule.get("remediation", ""),
                            cwe=rule.get("cwe", ""),
                        )
                    )

    @staticmethod
    def _deduplicate_findings(findings: List[Finding]) -> List[Finding]:
        seen = {}
        severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        for f in findings:
            key = (f.rule_id, f.title, f.affected_file, f.evidence[:80])
            if key not in seen:
                seen[key] = f
        return sorted(seen.values(), key=lambda x: (severity_rank.get(x.severity, 4), x.rule_id))

    @staticmethod
    def _compute_masvs_scorecard(report: ScanReport):
        weights = {"Critical": 18, "High": 10, "Medium": 4, "Low": 1}
        penalty = sum(weights.get(f.severity, 1) for f in report.findings)
        report.security_score = max(5, 100 - min(95, penalty))

        if report.security_score >= 90:
            report.grade = "A"
        elif report.security_score >= 75:
            report.grade = "B"
        elif report.security_score >= 60:
            report.grade = "C"
        elif report.security_score >= 40:
            report.grade = "D"
        else:
            report.grade = "F"

        summary = {}
        for cat in MASVS_CATEGORIES:
            cat_findings = [f for f in report.findings if f.masvs_category == cat]
            crit_high = sum(1 for f in cat_findings if f.severity in {"Critical", "High"})
            status = "FAIL" if crit_high > 0 else ("WARN" if cat_findings else "PASS")
            summary[cat] = {
                "status": status,
                "findings_count": len(cat_findings),
                "critical_or_high": crit_high,
            }
        report.masvs_summary = summary
