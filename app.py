import atexit
import base64
import hashlib
import html
import ipaddress
import json
import os
import posixpath
import re
import socket
import sqlite3
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from flask import (
    Flask,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)
app.secret_key = "vulnerable-lms-coraza-waf-key"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "security_lab.db")
CORAZA_EXE = os.path.join(BASE_DIR, "coraza-waf.exe")
CADDYFILE_PATH = os.path.join(BASE_DIR, "Caddyfile")
CORAZA_RULES_PATH = os.path.join(BASE_DIR, "coraza_rules.conf")
CORAZA_AUDIT_LOG = os.path.join(BASE_DIR, "coraza_audit.log")

CRS_DIR = os.path.join(BASE_DIR, "owasp-crs")
CRS_RULES_DIR = os.path.join(CRS_DIR, "rules")
CRS_SETUP_CONF = os.path.join(CRS_DIR, "crs-setup.conf")

PUBLIC_WAF_PORT = 5001
INTERNAL_FLASK_PORT = 5002

GUEST_TOKEN_B64 = base64.b64encode(b"user=guest").decode()  # dXNlcj1ndWVzdA==
ADMIN_TOKEN_B64 = base64.b64encode(b"user=admin").decode()  # dXNlcj1hZG1pbg==
GUEST_UNSALTED_SHA256 = hashlib.sha256(b"user=guest").hexdigest()
ADMIN_UNSALTED_SHA256 = hashlib.sha256(b"user=admin").hexdigest()

coraza_process = None


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            student_name TEXT NOT NULL,
            course TEXT NOT NULL,
            grade TEXT NOT NULL,
            role TEXT NOT NULL,
            secret_note TEXT NOT NULL
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS waf_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secrule_id INTEGER NOT NULL,
            rule_id TEXT NOT NULL,
            category TEXT NOT NULL,
            paranoia_level INTEGER NOT NULL DEFAULT 1,
            secrule_target TEXT NOT NULL,
            pattern TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        )
        """
    )

    default_settings = {
        "difficulty": "low",
        "waf_mode": "off",
        "waf_paranoia": "1",
    }
    for k, v in default_settings.items():
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

    c.execute("SELECT COUNT(*) FROM grades")
    if c.fetchone()[0] == 0:
        seed_grades = [
            (
                "admin",
                "Prof. R. Vance (Dean's Key)",
                "CS-404 Web Security Final Exam",
                "100% (A+)",
                "admin",
                "FLAG{SQLI_ALL_DIFFICULTIES_MASTERED} | Final Exam Master Answer Key",
            ),
            (
                "alice",
                "Alice Mercer",
                "CS-404 Web Security",
                "94% (A)",
                "student",
                "Lab 1 & Lab 2 submitted on time.",
            ),
            (
                "bob",
                "Bobkowsky",
                "CS-404 Web Security",
                "78% (B-)",
                "student",
                "Needs improvement on SQL parameterization.",
            ),
            (
                "charlie",
                "Charlie Kim",
                "CS-404 Web Security",
                "86% (B+)",
                "student",
                "Good report on OWASP Top 10.",
            ),
        ]
        c.executemany(
            "INSERT INTO grades (username, student_name, course, grade, role, secret_note) VALUES (?, ?, ?, ?, ?, ?)",
            seed_grades,
        )

    c.execute("SELECT COUNT(*) FROM comments")
    if c.fetchone()[0] == 0:
        c.execute(
            "INSERT INTO comments (author, content, created_at) VALUES (?, ?, ?)",
            (
                "Prof. Vance (Instructor)",
                "Welcome to CS-404! Post your questions about the midterm project or lab assignments below.",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

    # Table for Module 7: IDOR (Student Academic Dossiers)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            gpa TEXT NOT NULL,
            disciplinary TEXT NOT NULL,
            scholarship TEXT NOT NULL,
            medical TEXT NOT NULL
        )
        """
    )
    c.execute("SELECT COUNT(*) FROM students")
    if c.fetchone()[0] == 0:
        seed_students = [
            (
                "1",
                "Dean Vance (Provost & Department Chair)",
                "vance@campus.unimoodle.edu",
                "4.00 (Summa Cum Laude)",
                "CLASSIFIED DOSSIER | FLAG{IDOR_DIRECT_OBJECT_REF_MASTERED}",
                "Full Presidential Fellowship ($50,000 / year)",
                "Restricted - Executive Faculty Medical Record",
            ),
            (
                "2",
                "Alice Mercer",
                "alice.mercer@campus.unimoodle.edu",
                "3.92 (Honors)",
                "Clean record - Peer Tutor for CS-404 Web Security",
                "Dean's Merit Scholarship ($12,000 / year)",
                "No health restrictions on file",
            ),
            (
                "3",
                "Bob Kowalski",
                "bob.kowalski@campus.unimoodle.edu",
                "2.85",
                "Academic Warning (Fall 2025: Unsanitized Queries)",
                "Partial Need-based Aid ($4,000 / year)",
                "Annual routine physical cleared",
            ),
            (
                "4",
                "Charlie Kim",
                "charlie.kim@campus.unimoodle.edu",
                "3.60",
                "Good conduct standing",
                "Athletic Excellence Grant ($8,000 / year)",
                "Varsity sports medical clearance active",
            ),
        ]
        c.executemany(
            "INSERT INTO students (student_id, full_name, email, gpa, disciplinary, scholarship, medical) VALUES (?, ?, ?, ?, ?, ?, ?)",
            seed_students,
        )

    # Table for Module 8: CSRF (Student Account Profiles)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS user_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            role TEXT NOT NULL
        )
        """
    )
    c.execute("SELECT COUNT(*) FROM user_profiles")
    if c.fetchone()[0] == 0:
        c.execute(
            "INSERT INTO user_profiles (username, email, role) VALUES (?, ?, ?)",
            ("guest_student", "student_guest@campus.unimoodle.edu", "Student"),
        )

    # Check if waf_rules has secrule_id column; recreate table if upgrading schema
    cols = [r[1] for r in c.execute("PRAGMA table_info(waf_rules)").fetchall()]
    if "secrule_id" not in cols:
        c.execute("DROP TABLE IF EXISTS waf_rules")
        c.execute(
            """
            CREATE TABLE waf_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                secrule_id INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                category TEXT NOT NULL,
                paranoia_level INTEGER NOT NULL DEFAULT 1,
                secrule_target TEXT NOT NULL,
                pattern TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
            )
            """
        )

    c.execute("DELETE FROM waf_rules")
    default_rules = [
        # --- UNIVERSITY VIRTUAL PATCHES (APPLICATION-SPECIFIC BUSINESS LOGIC) ---
        (
            1003,
            "WAF-VAULT-BASIC",
            "Access Control",
            1,
            "ARGS:is_admin|REQUEST_COOKIES:user_role|REQUEST_COOKIES:auth_token|REQUEST_COOKIES:vault_sig|REQUEST_HEADERS:X-Forwarded-For|REQUEST_HEADERS:X-Original-URL|ARGS:sim_exploit",
            r"(^(true|TRUE|admin|ADMIN|low|medium|high)$|dXNlcj1hZG1pbg==|127\.0\.0\.1|/admin/vault|52c876f2a69205692536a1f2857b4e4c70312142b068e23f4d87d506680183c5)",
            "Protects Dean's Vault (/vault) against client-side parameter tampering (is_admin=true, role=admin, Base64 auth token).",
            "CRITICAL",
            1,
        ),
        (
            2003,
            "WAF-VAULT-BYPASS",
            "Access Control",
            2,
            "REQUEST_COOKIES:auth_token|REQUEST_COOKIES:vault_sig|REQUEST_HEADERS:X-Forwarded-For|REQUEST_HEADERS:X-Original-URL|ARGS:sim_exploit",
            r"(?i)(dXNlcj1hZG1pbg==|dXNlcj1BRE1JTg==|localhost|127\.0\.0\.1|/admin|52c876f2a69205692536a1f2857b4e4c70312142b068e23f4d87d506680183c5|^bypass$)",
            "Protects Dean's Vault (L2) against uppercase Base64 token (user=ADMIN) and X-Forwarded-For: localhost spoofing.",
            "CRITICAL",
            1,
        ),
        (
            1030,
            "WAF-FORCED-BROWSING-ADMIN",
            "Forced Browsing",
            1,
            "REQUEST_URI",
            r"(?i)(/admin-console|/secret-backup|/admin_panel|/faculty-console)",
            "Protects unlisted administrative consoles and backups from direct URL manipulation in browser address bar.",
            "CRITICAL",
            1,
        ),
        (
            1043,
            "WAF-IDOR-DEAN-DOSSIER",
            "IDOR",
            1,
            "ARGS:student_id|REQUEST_URI",
            r"(?i)(\bstudent_id=1\b|^1$)",
            "Protects Provost & Department Chair confidential academic dossier (#1) from unauthorized direct reference.",
            "CRITICAL",
            1,
        ),
        (
            1049,
            "WAF-CSRF-ANOMALOUS-ORIGIN",
            "CSRF",
            2,
            "REQUEST_HEADERS:Referer|ARGS:email",
            r"(?i)(attacker\.com|evil\.com)",
            "Detects cross-origin requests originating from known attacker domains targeting student email updates.",
            "HIGH",
            1,
        ),
    ]
    c.executemany(
        """
        INSERT INTO waf_rules (secrule_id, rule_id, category, paranoia_level, secrule_target, pattern, description, severity, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        default_rules,
    )

    conn.commit()
    conn.close()
    sync_coraza_waf(reload_live=False)


# ==============================================================================
# OWASP CORAZA WAF (REAL REVERSE-PROXY WAF ENGINE MANAGEMENT)
# ==============================================================================
def ensure_owasp_crs():
    """Verifies that the official OWASP Core Rule Set (CRS v4.10.0) is present and ready."""
    crs_rules = os.path.join(BASE_DIR, "owasp-crs", "rules")
    crs_setup = os.path.join(BASE_DIR, "owasp-crs", "crs-setup.conf")
    crs_example = os.path.join(BASE_DIR, "owasp-crs", "crs-setup.conf.example")

    if not os.path.exists(crs_rules) or not os.path.exists(crs_setup):
        if os.path.exists(crs_example) and not os.path.exists(crs_setup):
            import shutil
            shutil.copyfile(crs_example, crs_setup)
        else:
            print("[*] Fetching official OWASP Core Rule Set (CRS v4.10.0)...")
            try:
                subprocess.run(
                    [
                        "git",
                        "clone",
                        "--depth",
                        "1",
                        "--branch",
                        "v4.10.0",
                        "https://github.com/coreruleset/coreruleset.git",
                        os.path.join(BASE_DIR, "owasp-crs"),
                    ],
                    check=True,
                )
                if os.path.exists(crs_example) and not os.path.exists(crs_setup):
                    import shutil
                    shutil.copyfile(crs_example, crs_setup)
                print("[+] OWASP Core Rule Set (CRS v4.10.0) downloaded successfully.")
            except Exception as e:
                print(f"[!] Warning: could not download OWASP CRS: {e}")


def write_coraza_config_files():
    """Generates real ModSecurity/Coraza SecRule directives in coraza_rules.conf and Caddyfile."""
    ensure_owasp_crs()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    settings = {r["key"]: r["value"] for r in rows}
    waf_mode = settings.get("waf_mode", "off")
    paranoia = int(settings.get("waf_paranoia", "1"))

    rules = conn.execute(
        "SELECT * FROM waf_rules WHERE enabled = 1 AND paranoia_level <= ? ORDER BY paranoia_level ASC, secrule_id ASC",
        (paranoia,),
    ).fetchall()
    conn.close()

    if waf_mode == "off":
        engine_state = "Off"
    elif waf_mode == "detect":
        engine_state = "DetectionOnly"
    else:
        engine_state = "On"

    secrules_lines = [
        "# ======================================================================",
        "# OWASP CORAZA WAF — OFFICIAL CORE RULE SET (CRS v4.10.0) CONFIGURATION",
        f"# Active Mode: SecRuleEngine {engine_state} | Active Paranoia Level: L{paranoia}",
        "# ======================================================================",
        f"SecRuleEngine {engine_state}",
        "SecRequestBodyAccess On",
        "SecResponseBodyAccess On",
        "SecAuditEngine RelevantOnly",
        "SecAuditLogParts ABIJDEFHZ",
        "SecAuditLogType Serial",
        "SecAuditLogFormat JSON",
        "SecAuditLog ./coraza_audit.log",
        "",
        "# 1. Whitelist WAF Admin Dashboard, Hints, Settings & Blocked endpoints",
        'SecRule REQUEST_URI "@rx ^/(waf-dashboard|waf/|settings/|hints|coraza-blocked|static/)" "id:999,phase:1,pass,nolog,ctl:ruleEngine=Off"',
        "",
        "# 2. Local Lab Compatibility: Allow connecting via IP address 127.0.0.1 (disables rule 920350)",
        "SecRuleRemoveById 920350",
        "",
        "# 3. Configure Dynamic Paranoia Level for OWASP CRS",
        f'SecAction "id:900000,phase:1,pass,t:none,nolog,tag:\'OWASP_CRS\',ver:\'OWASP_CRS/4.10.0\',setvar:tx.blocking_paranoia_level={paranoia}"',
        "",
        "# 4. Include Official OWASP ModSecurity Core Rule Set (CRS v4.10.0)",
        "Include ./owasp-crs/crs-setup.conf",
        "Include ./owasp-crs/rules/*.conf",
        "",
        "# 5. University Virtual Patching Rules (Business Logic Protection)",
        "# Only evaluate Access Control cookie/header rules on POST requests so GET page loads are never locked out by stale cookies",
        'SecRule REQUEST_METHOD "@streq GET" "id:998,phase:1,pass,nolog,ctl:ruleRemoveById=1003,ctl:ruleRemoveById=2003"',
        "",
    ]

    for r in rules:
        # Sanitize double quotes in regex for ModSecurity SecRule syntax
        safe_pattern = r["pattern"].replace('"', r"\x22")
        transforms = (
            "t:urlDecodeUni,"
            if "ARGS" in r["secrule_target"] or r["paranoia_level"] >= 2
            else ""
        )
        action_verb = "deny,status:403" if waf_mode == "block" else "pass"
        secrules_lines.append(f"# {r['rule_id']} ({r['category']} - L{r['paranoia_level']})")
        secrules_lines.append(
            f'SecRule {r["secrule_target"]} "@rx {safe_pattern}" '
            f'"id:{r["secrule_id"]},phase:2,{transforms}{action_verb},log,auditlog,ctl:auditEngine=On,'
            f"msg:'{r['rule_id']}',tag:'{r['category']}',severity:'CRITICAL'\""
        )
        secrules_lines.append("")

    with open(CORAZA_RULES_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(secrules_lines))

    rev_stamp = f"{time.time():.6f}"
    caddyfile_content = f"""{{
    admin 127.0.0.1:2019
    grace_period 1ms
    order coraza_waf first
}}

:{PUBLIC_WAF_PORT} {{
    coraza_waf {{
        directives `
            # Revision: {rev_stamp}
            Include ./coraza_rules.conf
        `
    }}
    reverse_proxy 127.0.0.1:{INTERNAL_FLASK_PORT}
    handle_errors {{
        rewrite * /coraza-blocked
        reverse_proxy 127.0.0.1:{INTERNAL_FLASK_PORT} {{
            method GET
            header_up -Content-Length
            header_up -Content-Type
        }}
    }}
}}
"""
    with open(CADDYFILE_PATH, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(caddyfile_content)


def sync_coraza_waf(reload_live=True):
    write_coraza_config_files()
    if reload_live:
        try:
            with open(CADDYFILE_PATH, "rb") as f:
                caddy_bytes = f.read()
            req = urllib.request.Request(
                "http://127.0.0.1:2019/load",
                data=caddy_bytes,
                headers={
                    "Content-Type": "text/caddyfile",
                    "Cache-Control": "must-revalidate",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2):
                pass
        except Exception:
            if os.path.exists(CORAZA_EXE):
                subprocess.Popen(
                    [
                        CORAZA_EXE,
                        "run",
                        "--config",
                        CADDYFILE_PATH,
                        "--adapter",
                        "caddyfile",
                    ],
                    cwd=BASE_DIR,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )


def start_coraza_reverse_proxy():
    """Starts the standalone OWASP Coraza WAF + Caddy reverse proxy on port 5001."""
    global coraza_process
    ensure_owasp_crs()
    if not os.path.exists(CORAZA_EXE):
        print(f"[*] {CORAZA_EXE} not found. Downloading official OWASP Coraza WAF binary...")
        try:
            url = "https://caddyserver.com/api/download?os=windows&arch=amd64&p=github.com%2Fcorazawaf%2Fcoraza-caddy%2Fv2"
            urllib.request.urlretrieve(url, CORAZA_EXE)
            print("[+] OWASP Coraza WAF binary downloaded successfully.")
        except Exception as e:
            print(f"[WARNING] Could not auto-download coraza-waf.exe: {e}")
            return

    sync_coraza_waf(reload_live=False)

    # Stop any existing coraza-waf.exe instance to free port 5001 / 2019
    try:
        subprocess.run(
            ["taskkill", "/F", "/IM", "coraza-waf.exe"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.4)
    except Exception:
        pass

    coraza_process = subprocess.Popen(
        [CORAZA_EXE, "run", "--config", CADDYFILE_PATH, "--adapter", "caddyfile"],
        cwd=BASE_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    atexit.register(stop_coraza_reverse_proxy)
    time.sleep(0.8)


def stop_coraza_reverse_proxy():
    global coraza_process
    if coraza_process and coraza_process.poll() is None:
        coraza_process.terminate()


def parse_coraza_audit_logs(limit=100):
    """Reads and parses the JSON audit log produced by OWASP Coraza WAF."""
    if not os.path.exists(CORAZA_AUDIT_LOG):
        return []

    parsed_logs = []
    try:
        with open(CORAZA_AUDIT_LOG, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                tx = entry.get("transaction", {})
                req = tx.get("request", {})
                msgs = entry.get("messages", [])
                if not msgs:
                    continue

                attack_msg = None
                for m in msgs:
                    err = m.get("error_message", "")
                    if "949110" not in err and "920350" not in err and '[id "' in err:
                        attack_msg = m
                        break
                if not attack_msg:
                    attack_msg = msgs[-1]

                err_str = attack_msg.get("error_message", "")
                rule_id_match = re.search(r'\[msg "(.*?)"\]', err_str)
                sec_id_match = re.search(r'\[id "(.*?)"\]', err_str)
                tag_match = re.search(r'\[tag "(.*?)"\]', err_str)
                file_match = re.search(r'\[file "(.*?)"\]', err_str)

                rule_name = rule_id_match.group(1) if rule_id_match else "OWASP-CRS-RULE"
                sec_id = sec_id_match.group(1) if sec_id_match else "1000"
                file_name = os.path.basename(file_match.group(1)) if file_match else ""

                category = "WAF"
                err_lower = err_str.lower()
                if "sqli" in err_lower or "sql injection" in err_lower:
                    category = "SQLi"
                elif "xss" in err_lower:
                    category = "XSS"
                elif "rce" in err_lower or "command execution" in err_lower:
                    category = "RCE"
                elif "lfi" in err_lower or "path traversal" in err_lower:
                    category = "LFI / Traversal"
                elif "ssrf" in err_lower:
                    category = "SSRF"
                elif "access control" in err_lower or "bac" in err_lower:
                    category = "Access Control"
                elif "scanner" in err_lower:
                    category = "Scanner Detection"
                elif "protocol" in err_lower:
                    category = "Protocol Enforcement"
                elif tag_match:
                    category = tag_match.group(1)

                is_blocked = tx.get("is_interrupted", False) or "Access denied" in err_str
                action_taken = (
                    "BLOCKED (403)" if is_blocked else "DETECTED (DetectionOnly)"
                )

                uri = req.get("uri", "/")
                body = req.get("body", "")
                headers = req.get("headers", {})
                cookie_hdr = ""
                for hk, hv in headers.items():
                    if hk.lower() in ("cookie", "x-forwarded-for", "x-original-url"):
                        cookie_hdr += f" {hk}: {','.join(hv)}"

                matched_payload = f"{uri} {body} {cookie_hdr}".strip()

                display_rule = f"{rule_name} (id:{sec_id})"
                if file_name:
                    display_rule += f" [{file_name}]"

                parsed_logs.append(
                    {
                        "tx_id": tx.get("id", "N/A"),
                        "timestamp": tx.get("timestamp", ""),
                        "ip_address": tx.get("client_ip", "127.0.0.1"),
                        "http_method": req.get("method", "GET"),
                        "endpoint": uri.split("?")[0],
                        "rule_id": display_rule,
                        "category": category,
                        "severity": "CRITICAL",
                        "matched_payload": matched_payload[:280],
                        "raw_coraza_msg": err_str,
                        "action_taken": action_taken,
                    }
                )
                if len(parsed_logs) >= limit:
                    break
            except Exception:
                continue
    except Exception:
        pass

    return parsed_logs


def get_owasp_crs_modules():
    """Returns a list of all official OWASP CRS rule files, their titles, rule counts and sizes."""
    if not os.path.exists(CRS_RULES_DIR):
        return []
    modules = []
    category_titles = {
        "901": "Initialization & Environment Setup",
        "905": "Common Application Exceptions",
        "911": "HTTP Method Enforcement",
        "913": "Scanner & Automated Bot Detection",
        "920": "HTTP Protocol Enforcement",
        "921": "HTTP Protocol Attack & Splitting",
        "922": "Multipart Attack Detection",
        "930": "Local File Inclusion (LFI) & Path Traversal",
        "931": "Remote File Inclusion (RFI)",
        "932": "Remote Code Execution (RCE)",
        "933": "PHP Code Injection Protection",
        "934": "NodeJS / Generic Code Injection",
        "941": "Cross-Site Scripting (XSS) Protection",
        "942": "SQL Injection (SQLi) Protection",
        "943": "Session Fixation & Broken Access Control",
        "944": "Java & Log4j / JNDI Deserialization",
        "949": "Inbound Anomaly Scoring & Blocking Evaluation",
        "950": "Outbound Sensitive Data Leakage",
        "951": "SQL Error & Source Code Leakage",
        "952": "Java Error & Stack Trace Leakage",
        "953": "PHP Information Leakage",
        "954": "IIS Server Error Leakage",
        "955": "Web Shell & Backdoor Detection",
        "959": "Outbound Anomaly Scoring Evaluation",
        "980": "Correlation & Threat Scoring",
    }
    for fname in sorted(os.listdir(CRS_RULES_DIR)):
        if fname.endswith(".conf"):
            full_path = os.path.join(CRS_RULES_DIR, fname)
            size_kb = round(os.path.getsize(full_path) / 1024, 1)
            rule_count = 0
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.strip().startswith("SecRule "):
                            rule_count += 1
            except Exception:
                pass
            match = re.search(r"-(\d{3})-", fname)
            code = match.group(1) if match else ""
            title = category_titles.get(code, "OWASP Core Rule Set Module")
            modules.append({
                "filename": fname,
                "title": title,
                "code": code,
                "rules_count": rule_count,
                "size_kb": size_kb,
            })
    return modules


def get_settings():
    db = get_db()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
    s = {row["key"]: row["value"] for row in rows}
    if "waf_paranoia" not in s:
        s["waf_paranoia"] = "1"
    return s


@app.before_request
def coraza_detect_banner_notifier():
    """Displays a top flash alert banner when OWASP Coraza WAF is in DetectionOnly (DETECT) mode."""
    if request.path.startswith("/static") or request.path in (
        "/waf-dashboard",
        "/waf/rules/toggle",
        "/waf/rules/add",
        "/waf/logs/clear",
        "/settings/update",
        "/hints",
        "/coraza-blocked",
    ):
        return None

    settings = get_settings()
    if settings.get("waf_mode") != "detect":
        return None

    paranoia = int(settings.get("waf_paranoia", "1"))
    db = get_db()
    rules = db.execute(
        "SELECT * FROM waf_rules WHERE enabled = 1 AND paranoia_level <= ? ORDER BY paranoia_level ASC, secrule_id ASC",
        (paranoia,),
    ).fetchall()

    # Collect request inputs matching the SecRule targets
    args_str = " ".join(
        list(request.args.values()) + list(request.form.values())
    )
    if paranoia >= 2:
        args_str = urllib.parse.unquote_plus(html.unescape(args_str))

    for rule in rules:
        target = rule["secrule_target"]
        pat = rule["pattern"].replace(r"\x22", '"')
        if "REQUEST_COOKIES" in target or "REQUEST_HEADERS" in target:
            if request.method == "GET":
                continue
            candidates = [
                request.form.get("is_admin", ""),
                request.form.get("sim_exploit", ""),
                request.cookies.get("user_role", ""),
                request.cookies.get("auth_token", ""),
                request.cookies.get("vault_sig", ""),
                request.headers.get("X-Forwarded-For", ""),
                request.headers.get("X-Original-URL", ""),
            ]
        else:
            candidates = [args_str]
            if "REQUEST_URI" in target:
                candidates.extend([request.full_path, request.path, request.environ.get("REQUEST_URI", "")])

        try:
            if any(c and re.search(pat, c) for c in candidates):
                flash(
                    f"🛡️ OWASP Coraza WAF IDS Alert (DetectionOnly): SecRule id:{rule['secrule_id']} ({rule['rule_id']} — {rule['category']}) triggered and recorded in coraza_audit.log!",
                    "warning",
                )
                break
        except re.error:
            continue

    return None


@app.after_request
def cleanup_tampered_vault_cookies(response):
    """After a POST to /vault or a 403 block page, reset vault cookies to guest so the browser never stays stuck."""
    if (request.path == "/vault" and request.method == "POST") or request.path == "/coraza-blocked":
        response.set_cookie("user_role", "guest", httponly=False)
        response.set_cookie("auth_token", GUEST_TOKEN_B64, httponly=False)
        response.set_cookie("vault_sig", GUEST_UNSALTED_SHA256, httponly=False)
    return response


@app.context_processor
def inject_globals():
    settings = get_settings()
    logs = parse_coraza_audit_logs(limit=200)
    blocked_logs = sum(1 for l in logs if "BLOCKED" in l["action_taken"])
    return {
        "settings": settings,
        "waf_stats": {"total": len(logs), "blocked": blocked_logs},
        "guest_token_b64": GUEST_TOKEN_B64,
        "admin_token_b64": ADMIN_TOKEN_B64,
        "admin_unsalted_sha256": ADMIN_UNSALTED_SHA256,
    }


@app.route("/coraza-blocked", methods=["GET", "POST"])
def coraza_blocked():
    """Rendered when Caddy/OWASP Coraza WAF interrupts a request with HTTP 403."""
    settings = get_settings()
    logs = parse_coraza_audit_logs(limit=1)
    if logs:
        latest = logs[0]
        incident = {
            "tx_id": latest["tx_id"],
            "rule_id": latest["rule_id"],
            "category": latest["category"],
            "severity": latest["severity"],
            "description": latest["raw_coraza_msg"],
            "matched_input": latest["matched_payload"],
            "pattern": "Evaluated by OWASP Coraza WAF SecRule Engine (Reverse Proxy :5001)",
        }
    else:
        incident = {
            "tx_id": "CORAZA-403",
            "rule_id": "OWASP Coraza SecRule",
            "category": "WAF IPS",
            "severity": "CRITICAL",
            "description": "Blocked at Reverse Proxy layer by OWASP Coraza WAF.",
            "matched_input": request.url,
            "pattern": "SecRuleEngine On",
        }
    return render_template("waf_blocked.html", incident=incident, settings=settings), 403


@app.route("/")
def index():
    return redirect(url_for("sqli_lab"))


@app.route("/settings/update", methods=["POST"])
def update_settings():
    db = get_db()
    difficulty = request.form.get("difficulty")
    waf_mode = request.form.get("waf_mode")
    waf_paranoia = request.form.get("waf_paranoia")

    if difficulty in ("low", "medium", "high", "impossible"):
        db.execute(
            "UPDATE settings SET value = ? WHERE key = 'difficulty'", (difficulty,)
        )
        db.execute(
            "UPDATE user_profiles SET email = 'student_guest@campus.unimoodle.edu' WHERE username = 'guest_student'"
        )
        session.pop("csrf_error", None)
    if waf_mode in ("off", "detect", "block"):
        db.execute("UPDATE settings SET value = ? WHERE key = 'waf_mode'", (waf_mode,))
    if waf_paranoia in ("1", "2"):
        db.execute(
            "UPDATE settings SET value = ? WHERE key = 'waf_paranoia'", (waf_paranoia,)
        )
    db.commit()

    # Hot-reload OWASP Coraza WAF with updated SecRuleEngine / Paranoia configuration
    sync_coraza_waf(reload_live=True)

    ref_path = (
        urllib.parse.urlparse(request.referrer).path
        if request.referrer
        else url_for("sqli_lab")
    )
    return redirect(ref_path or url_for("sqli_lab"))


# ==============================================================================
# MODULE 1: STUDENT GRADEBOOK SEARCH (SQL INJECTION)
# ==============================================================================
@app.route("/sqli", methods=["GET"])
def sqli_lab():
    settings = get_settings()
    difficulty = settings["difficulty"]
    raw_query = request.args.get("query", "")
    results = []
    executed_sql = ""
    error = None
    filtered_query = raw_query

    db = get_db()
    if raw_query != "":
        try:
            if difficulty == "low":
                executed_sql = f"SELECT id, username, student_name, course, grade, role, secret_note FROM grades WHERE username = '{raw_query}'"
                cursor = db.execute(executed_sql)
                results = cursor.fetchall()

            elif difficulty == "medium":
                filtered_query = re.sub(
                    r"(?i)(\bunion\b|\bselect\b|\bdrop\b|\s+)", "", raw_query
                )
                executed_sql = f"SELECT id, username, student_name, course, grade, role, secret_note FROM grades WHERE username = '{filtered_query}'"
                cursor = db.execute(executed_sql)
                results = cursor.fetchall()

            elif difficulty == "high":
                filtered_query = re.sub(
                    r"(?i)(\s+|/\*.*?\*/|--|;|\bor\b|\bunion\b|\bselect\b)",
                    "",
                    raw_query,
                )
                executed_sql = f"SELECT id, username, student_name, course, grade, role, secret_note FROM grades WHERE username = '{filtered_query}'"
                cursor = db.execute(executed_sql)
                results = cursor.fetchall()

            else:
                executed_sql = "SELECT id, username, student_name, course, grade, role, secret_note FROM grades WHERE username = ?  -- [Parameterized Bound: (?)]"
                cursor = db.execute(
                    "SELECT id, username, student_name, course, grade, role, secret_note FROM grades WHERE username = ?",
                    (raw_query,),
                )
                results = cursor.fetchall()
        except Exception as e:
            error = f"Database Error: {str(e)}"

    return render_template(
        "sqli.html",
        search_query=raw_query,
        filtered_query=filtered_query,
        results=results,
        executed_sql=executed_sql,
        error=error,
    )


# ==============================================================================
# MODULE 2: COURSE FORUM & Q&A (REFLECTED & STORED XSS)
# ==============================================================================
def sanitize_xss(text: str, difficulty: str) -> str:
    if not text:
        return ""
    if difficulty == "low":
        return text
    elif difficulty == "medium":
        return re.sub(r"(?i)<\s*/?\s*script\b[^>]*>", "", text)
    elif difficulty == "high":
        cleaned = re.sub(r"(?i)<\s*/?\s*(script|iframe|img|svg|body)\b[^>]*>", "", text)
        cleaned = re.sub(
            r"(?i)\b(onerror|onload|onclick|onmouseover)\s*=", "data-blocked=", cleaned
        )
        return cleaned
    else:
        return html.escape(text)


@app.route("/xss", methods=["GET", "POST"])
def xss_lab():
    settings = get_settings()
    difficulty = settings["difficulty"]
    db = get_db()

    if request.method == "POST":
        author = request.form.get("author", "Student").strip() or "Student"
        content = request.form.get("content", "")
        sanitized_content = sanitize_xss(content, difficulty)
        db.execute("DELETE FROM comments WHERE id > 1")
        db.execute(
            "INSERT INTO comments (author, content, created_at) VALUES (?, ?, ?)",
            (author, sanitized_content, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
        db.commit()
        flash("Forum post published!", "success")
        return redirect(url_for("xss_lab"))

    reflected_raw = request.args.get("reflect", "")
    reflected_output = sanitize_xss(reflected_raw, difficulty)

    comments = db.execute("SELECT * FROM comments ORDER BY id DESC").fetchall()
    # Auto-clean user-submitted payloads after fetching for this render so page reloads don't re-trigger alerts
    db.execute("DELETE FROM comments WHERE id > 1")
    db.commit()

    return render_template(
        "xss.html",
        reflected_raw=reflected_raw,
        reflected_output=reflected_output,
        comments=comments,
    )


@app.route("/xss/clear", methods=["POST"])
def clear_comments():
    db = get_db()
    db.execute("DELETE FROM comments")
    db.execute(
        "INSERT INTO comments (author, content, created_at) VALUES (?, ?, ?)",
        (
            "Prof. Vance (Instructor)",
            "Forum history reset. Post your course questions below.",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    db.commit()
    return redirect(url_for("xss_lab"))


# ==============================================================================
# MODULE 3: DEAN'S GRADE OVERRIDE (BURP SUITE TAMPERING)
# ==============================================================================
@app.route("/vault", methods=["GET", "POST"])
def vault_lab():
    settings = get_settings()
    difficulty = settings["difficulty"]

    vault_unlocked = False
    vault_message = None
    vault_flag = None

    form_is_admin = request.form.get("is_admin", "false")
    cookie_role = request.cookies.get("user_role", "guest")
    cookie_token = request.cookies.get("auth_token", GUEST_TOKEN_B64)
    cookie_sig = request.cookies.get("vault_sig", GUEST_UNSALTED_SHA256)
    hdr_xff = request.headers.get("X-Forwarded-For", "")
    hdr_orig_url = request.headers.get("X-Original-URL", "")

    sim_exploit = request.form.get("sim_exploit", "")
    if sim_exploit == "low":
        form_is_admin = "true"
        cookie_role = "admin"
    elif sim_exploit == "medium":
        cookie_token = ADMIN_TOKEN_B64
        hdr_xff = "127.0.0.1"
    elif sim_exploit == "high":
        cookie_token = ADMIN_TOKEN_B64
        cookie_sig = ADMIN_UNSALTED_SHA256
        hdr_xff = "127.0.0.1"
        hdr_orig_url = "/admin/vault"
    elif sim_exploit == "bypass":
        cookie_token = "dXNlcj1BRE1JTg=="
        hdr_xff = "localhost"

    decoded_token = ""
    try:
        decoded_token = base64.b64decode(cookie_token).decode("utf-8", errors="ignore")
    except Exception:
        decoded_token = "invalid_base64"

    request_details = {
        "POST form field is_admin": form_is_admin,
        "Cookie user_role": cookie_role,
        "Cookie auth_token (Base64)": f"{cookie_token}  ->  '{decoded_token}'",
        "Cookie vault_sig (SHA-256)": cookie_sig[:24] + "...",
        "Header X-Forwarded-For": hdr_xff or "(Not Set)",
        "Header X-Original-URL": hdr_orig_url or "(Not Set)",
    }

    if request.method == "POST":
        is_waf_bypass_payload = (
            decoded_token.strip() == "user=ADMIN"
            and hdr_xff.strip().lower() == "localhost"
        )
        if difficulty != "impossible" and is_waf_bypass_payload:
            vault_unlocked = True
            vault_message = "WAF L1 BYPASS EXPLOITED: Backend accepted uppercase Base64 'auth_token=dXNlcj1BRE1JTg==' ('user=ADMIN') + 'X-Forwarded-For: localhost'!"
            vault_flag = "FLAG{BURP_WAF_L1_BYPASS_MASTERED}"
        elif difficulty == "low":
            if form_is_admin.lower() == "true" or cookie_role.lower() == "admin":
                vault_unlocked = True
                vault_message = "LOW LEVEL EXPLOITED: Backend trusted client-controlled 'is_admin=true' or 'Cookie: user_role=admin'."
                vault_flag = "FLAG{BURP_LOW_PARAMETER_TAMPERING}"
            else:
                vault_message = "Access Denied (Low): Neither POST 'is_admin=true' nor 'Cookie: user_role=admin' was found."

        elif difficulty == "medium":
            if decoded_token.strip().lower() == "user=admin" and hdr_xff.strip().lower() in ("127.0.0.1", "localhost"):
                vault_unlocked = True
                vault_message = "MEDIUM LEVEL EXPLOITED: Backend trusted Base64 'auth_token=dXNlcj1hZG1pbg==' + spoofed 'X-Forwarded-For: 127.0.0.1'!"
                vault_flag = "FLAG{BURP_MEDIUM_BASE64_AND_XFF_BYPASS}"
            else:
                missing = []
                if decoded_token.strip() != "user=admin":
                    missing.append(
                        f"Cookie auth_token must Base64-encode 'user=admin' ({ADMIN_TOKEN_B64})"
                    )
                if hdr_xff.strip() != "127.0.0.1":
                    missing.append("Header 'X-Forwarded-For: 127.0.0.1' required")
                vault_message = "Access Denied (Medium): " + " AND ".join(missing)

        elif difficulty == "high":
            expected_unsalted_sig = hashlib.sha256(
                decoded_token.strip().encode()
            ).hexdigest()
            sig_ok = (
                cookie_sig.strip().lower() == expected_unsalted_sig.lower()
                and decoded_token.strip() == "user=admin"
            )
            url_ok = hdr_orig_url.strip() == "/admin/vault"
            ip_ok = hdr_xff.strip() == "127.0.0.1"

            if sig_ok and url_ok and ip_ok:
                vault_unlocked = True
                vault_message = "HIGH LEVEL EXPLOITED: Forged unsalted SHA-256 signature sha256('user=admin') + 'X-Original-URL: /admin/vault' + 'X-Forwarded-For: 127.0.0.1'!"
                vault_flag = "FLAG{BURP_HIGH_SHA256_FORGERY_AND_PROXY_BYPASS}"
            else:
                missing = []
                if decoded_token.strip() != "user=admin":
                    missing.append(f"auth_token must be '{ADMIN_TOKEN_B64}'")
                if cookie_sig.strip().lower() != ADMIN_UNSALTED_SHA256.lower():
                    missing.append(
                        f"vault_sig must match unsalted sha256('user=admin') = {ADMIN_UNSALTED_SHA256}"
                    )
                if not ip_ok:
                    missing.append("Header 'X-Forwarded-For: 127.0.0.1' required")
                if not url_ok:
                    missing.append("Header 'X-Original-URL: /admin/vault' required")
                vault_message = "Access Denied (High): " + " | ".join(missing)

        else:
            vault_unlocked = False
            vault_message = "IMPOSSIBLE (PATCHED): Server enforces server-side HMAC session validation and ignores all client-side role fields, Base64 cookies, and proxy headers."

    if vault_unlocked and settings.get("waf_mode") == "block":
        if str(settings.get("waf_paranoia", "1")) == "1":
            flash(
                "⚠️ WAF BYPASS: атака прошла через OWASP Coraza WAF (BLOCK), потому что CRS Paranoia = L1. "
                "L1 ловит только 'is_admin=true' / 'user_role=admin' (SecRule 1003). Base64-токен, X-Forwarded-For, "
                "SHA-256 подпись и X-Original-URL ловит только L2 (SecRule 2003) — переключите Paranoia на L2.",
                "warning",
            )

    resp = make_response(
        render_template(
            "vault.html",
            vault_unlocked=vault_unlocked,
            vault_message=vault_message,
            vault_flag=vault_flag,
            request_details=request_details,
        )
    )
    if "user_role" not in request.cookies:
        resp.set_cookie("user_role", "guest", httponly=False)
    if "auth_token" not in request.cookies:
        resp.set_cookie("auth_token", GUEST_TOKEN_B64, httponly=False)
    if "vault_sig" not in request.cookies:
        resp.set_cookie("vault_sig", GUEST_UNSALTED_SHA256, httponly=False)
    return resp


# ==============================================================================
# MODULE 4: CAMPUS SERVER DIAGNOSTIC (COMMAND INJECTION / RCE)
# ==============================================================================
@app.route("/rce", methods=["GET", "POST"])
def rce_lab():
    settings = get_settings()
    difficulty = settings["difficulty"]
    target_input = "127.0.0.1"
    command_executed = False
    executed_cmd = ""
    command_output = ""
    rce_flag = None

    if request.method == "POST":
        sim_payload = request.form.get("sim_payload", "")
        if sim_payload == "low":
            target_input = "127.0.0.1 && whoami"
        elif sim_payload == "medium":
            target_input = "127.0.0.1 | whoami"
        elif sim_payload == "high":
            target_input = "127.0.0.1&whoami"
        elif sim_payload == "bypass":
            target_input = "127.0.0.1&w'h'o'a'm'i"
        else:
            target_input = request.form.get("target", "127.0.0.1").strip()

        sanitized_target = target_input
        can_execute = True

        if difficulty == "low":
            executed_cmd = f"ping -n 1 {sanitized_target}"
        elif difficulty == "medium":
            # Blacklist && and ;
            sanitized_target = sanitized_target.replace("&&", "").replace(";", "")
            executed_cmd = f"ping -n 1 {sanitized_target}"
        elif difficulty == "high":
            # Blacklist &&, ;, |, and spaces, but allow single & without space
            sanitized_target = sanitized_target.replace("&&", "").replace(";", "").replace("|", "")
            sanitized_target = re.sub(r"\s+", "", sanitized_target)
            executed_cmd = f"ping -n 1 {sanitized_target}"
        else:
            # Impossible: Validate strictly as IP address
            try:
                ipaddress.ip_address(sanitized_target)
                executed_cmd = f"ping -n 1 {sanitized_target}"
            except ValueError:
                can_execute = False
                command_executed = True
                executed_cmd = f"ping -n 1 {sanitized_target} [BLOCKED BY IP WHITELIST]"
                command_output = "SECURITY ERROR: Parameter failed strict RFC 791 IPv4 / RFC 8200 IPv6 address validation. Subprocess invocation cancelled."

        if can_execute:
            command_executed = True
            # Compatibility translation for cmd.exe if quotes evasion was used
            shell_cmd = executed_cmd
            if "w'h'o'a'm'i" in shell_cmd:
                shell_cmd = shell_cmd.replace("w'h'o'a'm'i", "whoami")
            try:
                proc = subprocess.run(
                    shell_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                command_output = proc.stdout + proc.stderr
            except subprocess.TimeoutExpired:
                command_output = "Command timed out after 5 seconds."
            except Exception as e:
                command_output = f"Execution error: {str(e)}"

        if command_output and any(
            k in command_output.lower()
            for k in [
                os.environ.get("USERNAME", "").lower(),
                os.environ.get("USER", "").lower(),
                "desktop",
                "nt authority",
                "user",
                "whoami",
                "windows\\system32",
                "\\",
            ]
            if k
        ):
            if any(sep in executed_cmd for sep in ["&", "|", ";"]):
                rce_flag = "FLAG{RCE_COMMAND_INJECTION_PWNED}"

    return render_template(
        "rce.html",
        target_input=target_input,
        command_executed=command_executed,
        executed_cmd=executed_cmd,
        command_output=command_output,
        rce_flag=rce_flag,
    )


# ==============================================================================
# MODULE 5: COURSE DOCUMENTS READER (PATH TRAVERSAL / LFI)
# ==============================================================================
@app.route("/lfi", methods=["GET"])
def lfi_lab():
    settings = get_settings()
    difficulty = settings["difficulty"]
    doc_param = request.args.get("doc", "syllabus_cs404.txt")
    file_content = None
    error_msg = None
    lfi_flag = None

    course_files_dir = os.path.join(BASE_DIR, "course_files")

    if doc_param:
        target_path = ""
        is_safe = True

        if difficulty == "low":
            target_path = os.path.join(course_files_dir, doc_param)
        elif difficulty == "medium":
            # Non-recursive strip of ../ and ..\
            cleaned_doc = doc_param.replace("../", "").replace("..\\", "")
            target_path = os.path.join(course_files_dir, cleaned_doc)
        elif difficulty == "high":
            # Requires filename to start with syllabus_
            if not doc_param.startswith("syllabus_"):
                is_safe = False
                error_msg = "Access Denied: High security policy requires document names to start with 'syllabus_'."
            else:
                target_path = os.path.join(course_files_dir, doc_param)
        else:
            # Impossible: Whitelist check
            allowed_docs = {"syllabus_cs404.txt", "lecture1_intro.txt"}
            if doc_param not in allowed_docs:
                is_safe = False
                error_msg = "Access Denied (Patched): Only verified white-listed course documents may be opened."
            else:
                target_path = os.path.join(course_files_dir, doc_param)

        if is_safe and target_path:
            try:
                target_path = os.path.normpath(target_path)
                if not (os.path.exists(target_path) and os.path.isfile(target_path)):
                    base_name = os.path.basename(target_path)
                    candidates = [
                        os.path.join(course_files_dir, base_name),
                        os.path.join(BASE_DIR, base_name),
                        os.path.join(BASE_DIR, "course_files", base_name),
                        os.path.join(os.path.dirname(BASE_DIR), "course_files", base_name),
                    ]
                    for cand in candidates:
                        if os.path.exists(cand) and os.path.isfile(cand):
                            target_path = cand
                            break
                if os.path.exists(target_path) and os.path.isfile(target_path):
                    with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                        file_content = f.read()
                    if "FLAG{LFI_PATH_TRAVERSAL_MASTERED}" in file_content or "secret_exam_key.txt" in target_path.lower():
                        lfi_flag = "FLAG{LFI_PATH_TRAVERSAL_MASTERED}"
                else:
                    error_msg = f"File not found: {target_path}"
            except Exception as e:
                error_msg = f"File reading error: {str(e)}"

    return render_template(
        "lfi.html",
        doc_param=doc_param,
        file_content=file_content,
        error_msg=error_msg,
        lfi_flag=lfi_flag,
    )


# ==============================================================================
# MODULE 6: LEARNING RESOURCE IMPORTER (SSRF)
# ==============================================================================
@app.route("/admin/secret-keys", methods=["GET"])
def admin_secret_keys():
    """Confidential internal university microservice, intended for loopback access only."""
    return {
        "status": "CONFIDENTIAL_ADMIN_KEYS",
        "service": "University Intranet Exam Key Server",
        "flag": "FLAG{SSRF_INTRANET_PIVOT_MASTERED}",
        "internal_api_token": "uni-prod-jwt-secret-9941a8-faculty",
        "aws_metadata_mock": "arn:aws:iam::123456789012:role/VulnerableLMSRegistrarRole",
    }


@app.route("/ssrf", methods=["GET", "POST"])
def ssrf_lab():
    settings = get_settings()
    difficulty = settings["difficulty"]
    target_url = ""
    http_status = None
    fetched_body = None
    error_msg = None
    ssrf_flag = None

    if request.method in ("POST", "GET") and (request.form.get("url") or request.args.get("url")):
        target_url = (request.form.get("url") or request.args.get("url", "")).strip()

        is_allowed = True
        lowered_url = target_url.lower()

        if difficulty == "low":
            pass
        elif difficulty == "medium":
            # Blacklist literal 127.0.0.1 and localhost
            if "127.0.0.1" in lowered_url or "localhost" in lowered_url:
                is_allowed = False
                error_msg = "Blocked by Medium Firewall: Direct '127.0.0.1' and 'localhost' references are prohibited."
        elif difficulty == "high":
            # Blacklist 127., localhost, 0.0.0.0, and decimal 2130706433
            if any(k in lowered_url for k in ["127.", "localhost", "0.0.0.0", "2130706433"]):
                is_allowed = False
                error_msg = "Blocked by High Firewall: Loopback IPs and decimal encodings (2130706433) are prohibited."
        else:
            # Impossible: DNS resolution + check private/loopback RFC ranges
            try:
                parsed = urllib.parse.urlparse(target_url)
                if parsed.scheme not in ("http", "https"):
                    is_allowed = False
                    error_msg = "Security Error: Only http/https protocols permitted."
                else:
                    host = parsed.hostname
                    resolved_ip = socket.gethostbyname(host)
                    ip_obj = ipaddress.ip_address(resolved_ip)
                    if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_link_local:
                        is_allowed = False
                        error_msg = f"Security Error: Destination IP {resolved_ip} is an internal/loopback network address."
            except Exception as e:
                is_allowed = False
                error_msg = f"DNS Validation Error: {str(e)}"

        if is_allowed:
            try:
                fetch_url = target_url
                parsed = urllib.parse.urlparse(fetch_url)
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                if host:
                    norm_ip = None
                    if host.isdigit():
                        try:
                            norm_ip = str(ipaddress.IPv4Address(int(host)))
                        except Exception:
                            pass
                    elif host.lower().startswith("0x"):
                        try:
                            norm_ip = str(ipaddress.IPv4Address(int(host, 16)))
                        except Exception:
                            pass
                    elif host in ("::1", "[::1]"):
                        norm_ip = "127.0.0.1"
                    elif host.startswith("0") and "." in host:
                        try:
                            parts = host.split(".")
                            norm_ip = ".".join(str(int(p, 8)) for p in parts)
                        except Exception:
                            pass
                    if norm_ip:
                        netloc = f"{norm_ip}:{port}" if parsed.port else norm_ip
                        fetch_url = urllib.parse.urlunparse(parsed._replace(netloc=netloc))

                req = urllib.request.Request(
                    fetch_url,
                    headers={"User-Agent": "VulnerableLMS-Resource-Fetcher/2.0"},
                )
                with urllib.request.urlopen(req, timeout=4) as resp:
                    http_status = resp.status
                    fetched_body = resp.read().decode("utf-8", errors="ignore")
                    if "FLAG{SSRF_INTRANET_PIVOT_MASTERED}" in fetched_body:
                        ssrf_flag = "FLAG{SSRF_INTRANET_PIVOT_MASTERED}"
            except urllib.error.HTTPError as e:
                http_status = e.code
                fetched_body = e.read().decode("utf-8", errors="ignore")
            except Exception as e:
                error_msg = f"Network connection error: {str(e)}"

    return render_template(
        "ssrf.html",
        target_url=target_url,
        http_status=http_status,
        fetched_body=fetched_body,
        error_msg=error_msg,
        ssrf_flag=ssrf_flag,
    )


# ==============================================================================
# MODULE 7: CAMPUS GOVERNANCE & PRIVILEGED CONSOLES (FORCED BROWSING / URL ACCESS)
# ==============================================================================
@app.route("/forced-browsing")
def forced_browsing_redirect():
    return redirect(url_for("forced_browsing_lab", subpath="student-dashboard"))


@app.route("/portal", defaults={"subpath": "student-dashboard"}, methods=["GET"])
@app.route("/portal/<path:subpath>", methods=["GET"])
def forced_browsing_lab(subpath="student-dashboard"):
    settings = get_settings()
    difficulty = settings["difficulty"]

    # Gather all variations of the requested path
    raw_uri = request.environ.get("REQUEST_URI", request.path)
    if "/portal/" in raw_uri:
        uri_sub = raw_uri.split("/portal/", 1)[1].split("?")[0]
    else:
        uri_sub = subpath

    unquoted_sub = urllib.parse.unquote(uri_sub)
    norm_sub = posixpath.normpath(unquoted_sub).lstrip("/")

    # Check if target resolves to the Dean's admin console or backup
    resolves_to_admin = (
        norm_sub in ("admin-console", "admin_panel", "faculty-console") or
        norm_sub.endswith("/admin-console") or
        "admin-console" in unquoted_sub.lower() or
        "admin-console" in uri_sub.lower()
    )
    resolves_to_backup = (
        norm_sub in ("secret-backup", "backup") or
        "secret-backup" in unquoted_sub.lower()
    )

    is_accessible = False
    is_admin_console = False
    is_backup = False
    error_msg = None
    fb_flag = None

    if resolves_to_admin or resolves_to_backup:
        if difficulty == "low":
            # Low: Completely vulnerable to direct URL manipulation in browser address bar
            is_accessible = True
            if resolves_to_admin:
                is_admin_console = True
                fb_flag = "FLAG{FORCED_BROWSING_URL_MASTERED}"
            else:
                is_backup = True
                fb_flag = "FLAG{FORCED_BROWSING_URL_MASTERED}"
        elif difficulty == "medium":
            # Medium: Blacklists literal 'admin-console' in URL path (case-sensitive)
            is_direct = uri_sub.rstrip("/") == "admin-console"
            if is_direct:
                is_accessible = False
                error_msg = "Blocked by Medium Filter: Direct access to '/admin-console' is blacklisted. Bypass by manipulating the URL with URL-encoding (/portal/%61dmin-console), case manipulation (/portal/ADMIN-CONSOLE) or encoded traversal (/portal/public/%2e%2e/admin-console)!"
            else:
                is_accessible = True
                is_admin_console = True
                fb_flag = "FLAG{FORCED_BROWSING_URL_MASTERED}"
        elif difficulty == "high":
            # High: Enforces that URL path must reside inside the '/portal/faculty/' directory prefix
            if not (uri_sub.startswith("faculty/") or unquoted_sub.startswith("faculty/")):
                is_accessible = False
                error_msg = "Blocked by High Filter: Portal security policy restricts access strictly to the '/portal/faculty/' namespace. Bypass by editing the URL to traverse out of faculty directory: /portal/faculty/%2e%2e/admin-console (or navigate to /portal/faculty/admin-console)!"
            else:
                is_accessible = True
                is_admin_console = True
                fb_flag = "FLAG{FORCED_BROWSING_URL_MASTERED}"
        else:
            # Impossible: Cryptographic Role-Based Access Control (RBAC)
            is_accessible = False
            error_msg = "Access Denied (Patched): Strict cryptographic Role-Based Access Control (RBAC) enforced. Only verified Dean / Provost session tokens may access administrative consoles regardless of URL."
    else:
        # Standard public student dashboard or course catalog
        is_accessible = True

    return render_template(
        "forced_browsing.html",
        current_subpath=uri_sub or "student-dashboard",
        full_url_path=request.path,
        is_accessible=is_accessible,
        is_admin_console=is_admin_console,
        is_backup=is_backup,
        error_msg=error_msg,
        fb_flag=fb_flag,
    )


# ==============================================================================
# MODULE 7 (LEGACY / COMPAT): STUDENT DOSSIER & TRANSCRIPT RECORDS (IDOR)
# ==============================================================================
@app.route("/idor", methods=["GET"])
def idor_lab():
    settings = get_settings()
    difficulty = settings["difficulty"]
    param_value = request.args.get("student_id", "2").strip()
    student = None
    error_msg = None
    idor_flag = None

    db = get_db()
    target_id = None

    if difficulty == "low":
        target_id = param_value
    elif difficulty == "medium":
        # Base64 encoded reference
        try:
            decoded = base64.b64decode(param_value).decode("utf-8")
            if decoded.isdigit():
                target_id = decoded
            else:
                target_id = param_value
        except Exception:
            target_id = param_value
    elif difficulty == "high":
        # MD5 hash reference
        md5_map = {
            "c4ca4238a0b923820dcc509a6f75849b": "1",
            "c81e728d9d4c2f636f067f89cc14862c": "2",
            "eccbc87e4b5ce2fe28308fd9f2a7baf3": "3",
            "a87ff679a2f3e71d9181a67b7542122c": "4",
        }
        if param_value in md5_map:
            target_id = md5_map[param_value]
        elif param_value.isdigit():
            target_id = str(int(param_value))
        else:
            error_msg = "Invalid Identifier: High security requires MD5 dossier token or padded index."
    else:
        # Impossible: Strict session identity binding (Alice Mercer = 2)
        target_id = "2"

    if target_id and not error_msg:
        try:
            row = db.execute(
                "SELECT * FROM students WHERE student_id = ? OR id = ?",
                (target_id, target_id),
            ).fetchone()
            if row:
                student = row
                if str(student["student_id"]) == "1" or student["id"] == 1:
                    idor_flag = "FLAG{IDOR_DIRECT_OBJECT_REF_MASTERED}"
            else:
                error_msg = f"Student Record #{target_id} not found in Registrar database."
        except Exception as e:
            error_msg = f"Database query error: {str(e)}"

    return render_template(
        "idor.html",
        param_value=param_value,
        student=student,
        error_msg=error_msg,
        idor_flag=idor_flag,
    )


# ==============================================================================
# MODULE 8: NOTIFICATION EMAIL & PROFILE SETTINGS (CSRF)
# ==============================================================================
@app.route("/csrf", methods=["GET"])
def csrf_lab():
    settings = get_settings()
    difficulty = settings["difficulty"]
    db = get_db()
    user_row = db.execute("SELECT * FROM user_profiles WHERE username = 'guest_student'").fetchone()
    current_email = user_row["email"] if user_row else "student_guest@campus.unimoodle.edu"

    csrf_token_val = hashlib.sha256(b"uni-session-token-cs404-guest").hexdigest()[:32]
    csrf_error = session.pop("csrf_error", None)
    csrf_flag = None
    if not csrf_error and current_email != "student_guest@campus.unimoodle.edu":
        csrf_flag = "FLAG{CSRF_EMAIL_HIJACK_MASTERED}"

    return render_template(
        "csrf.html",
        current_email=current_email,
        target_email="attacker@evil.com",
        csrf_token_val=csrf_token_val if difficulty == "impossible" else None,
        csrf_flag=csrf_flag,
        csrf_error=csrf_error,
    )


@app.route("/csrf/change-email", methods=["GET", "POST"])
def csrf_change_email():
    settings = get_settings()
    difficulty = settings["difficulty"]
    db = get_db()

    new_email = ""
    sim_csrf = request.form.get("sim_csrf", "")

    if sim_csrf == "low":
        new_email = "attacker@evil.com"
    elif sim_csrf == "medium":
        new_email = "attacker_referer_bypass@evil.com"
    elif sim_csrf == "high":
        new_email = "attacker_header_bypass@evil.com"
    elif sim_csrf == "bypass":
        new_email = "attacker_get_bypass@evil.com"
    else:
        new_email = request.form.get("email") or request.args.get("email", "")

    new_email = new_email.strip()
    is_valid = True
    error_msg = None

    if difficulty == "low":
        pass
    elif difficulty == "medium":
        referer = request.headers.get("Referer", "")
        # Reject normal direct browser submission from the /csrf page so the student is forced to forge the request in Burp Suite
        is_direct_form = not referer or referer.endswith("/csrf") or referer.rstrip("/").endswith(":5001/csrf") or referer.rstrip("/").endswith(":5002/csrf")
        if is_direct_form and sim_csrf != "medium":
            is_valid = False
            error_msg = "CSRF Failed (Medium): Direct browser form submission rejected. Use Burp Suite to forge an external cross-origin Referer containing 127.0.0.1 (e.g. Referer: http://attacker.com/?ref=127.0.0.1)!"
        elif "127.0.0.1" not in referer and "localhost" not in referer:
            is_valid = False
            error_msg = "CSRF Failed (Medium): Referer header did not originate from 127.0.0.1 / localhost. Bypass by appending ?ref=127.0.0.1 in Burp Suite!"
    elif difficulty == "high":
        # Requires POST with custom header OR GET parameter bypass
        if request.method == "POST":
            hdr = request.headers.get("X-Requested-With", "")
            if hdr.lower() != "xmlhttprequest":
                if sim_csrf != "high":
                    is_valid = False
                    error_msg = "CSRF Failed (High): Missing anti-CSRF custom header 'X-Requested-With: XMLHttpRequest'."
    else:
        # Impossible: Strict POST method + valid CSRF token
        if request.method != "POST":
            is_valid = False
            error_msg = "CSRF Failed (Patched): State-changing operations prohibited over HTTP GET."
        else:
            token = request.form.get("csrf_token", "")
            expected_token = hashlib.sha256(b"uni-session-token-cs404-guest").hexdigest()[:32]
            if token != expected_token:
                is_valid = False
                error_msg = "CSRF Failed (Patched): Invalid or missing cryptographic CSRF token."

    if is_valid and new_email:
        db.execute("UPDATE user_profiles SET email = ? WHERE username = 'guest_student'", (new_email,))
        db.commit()
        session.pop("csrf_error", None)
        flash(f"Profile notification email updated to '{new_email}'!", "success")
    elif error_msg:
        session["csrf_error"] = error_msg

    return redirect(url_for("csrf_lab"))


@app.route("/csrf/reset", methods=["POST"])
def csrf_reset():
    db = get_db()
    db.execute(
        "UPDATE user_profiles SET email = 'student_guest@campus.unimoodle.edu' WHERE username = 'guest_student'"
    )
    db.commit()
    session.pop("csrf_error", None)
    flash("Email reset back to student_guest@campus.unimoodle.edu.", "info")
    return redirect(url_for("csrf_lab"))


# ==============================================================================
# DEDICATED HINTS & EXPLANATIONS PAGE (/hints)
# ==============================================================================
@app.route("/hints", methods=["GET"])
def hints_page():
    return render_template("hints.html")


# ==============================================================================
# AUTOMATED 9-VECTOR VULNERABILITY & OWASP CORAZA WAF SCANNER
# ==============================================================================
@app.route("/scanner", methods=["GET", "POST"])
def auto_scanner():
    settings = get_settings()
    scan_results = []
    scan_summary = None

    if request.method == "POST":
        test_cases = [
            {
                "id": "SCAN-01",
                "name": "SQLi Level 1 (Low): Classic OR Tautology",
                "category": "SQLi (Low)",
                "method": "GET",
                "path": "/sqli",
                "query_string": {"query": "' OR '1'='1"},
                "payload_display": "GET /sqli?query=' OR '1'='1",
                "success_marker": "FLAG{SQLI_ALL_DIFFICULTIES_MASTERED}",
            },
            {
                "id": "SCAN-02",
                "name": "SQLi Level 2 (Medium Bypass): Comment Obfuscation /**/",
                "category": "SQLi (Medium)",
                "method": "GET",
                "path": "/sqli",
                "query_string": {"query": "admin'/**/oR/**/1=1--"},
                "payload_display": "GET /sqli?query=admin'/**/oR/**/1=1--",
                "success_marker": "FLAG{SQLI_ALL_DIFFICULTIES_MASTERED}",
            },
            {
                "id": "SCAN-03",
                "name": "SQLi Level 3 (High Bypass): Spaceless Quote Logic",
                "category": "SQLi (High)",
                "method": "GET",
                "path": "/sqli",
                "query_string": {"query": "admin'AND'1'='1"},
                "payload_display": "GET /sqli?query=admin'AND'1'='1",
                "success_marker": "FLAG{SQLI_ALL_DIFFICULTIES_MASTERED}",
            },
            {
                "id": "SCAN-04",
                "name": "XSS Level 1 (Low): Basic <script> Injection",
                "category": "XSS (Low)",
                "method": "GET",
                "path": "/xss",
                "query_string": {"reflect": "<script>alert('XSS-Low')</script>"},
                "payload_display": "GET /xss?reflect=<script>alert('XSS-Low')</script>",
                "success_marker": "<script>alert('XSS-Low')</script>",
            },
            {
                "id": "SCAN-05",
                "name": "XSS Level 2 (Medium Bypass): <img onerror=> Handler",
                "category": "XSS (Medium)",
                "method": "GET",
                "path": "/xss",
                "query_string": {"reflect": "<img src=x onerror=alert('XSS-Med')>"},
                "payload_display": "GET /xss?reflect=<img src=x onerror=alert('XSS-Med')>",
                "success_marker": "<img src=x onerror=alert('XSS-Med')>",
            },
            {
                "id": "SCAN-06",
                "name": "XSS Level 3 (High Bypass): <details open ontoggle=>",
                "category": "XSS (High)",
                "method": "GET",
                "path": "/xss",
                "query_string": {
                    "reflect": "<details open ontoggle=alert('XSS-High')>X</details>"
                },
                "payload_display": "GET /xss?reflect=<details open ontoggle=alert('XSS-High')>",
                "success_marker": "<details open ontoggle=alert('XSS-High')>",
            },
            {
                "id": "SCAN-07",
                "name": "Burp Tampering Level 1 (Low): POST Form is_admin=true",
                "category": "Access Control (Low)",
                "method": "POST",
                "path": "/vault",
                "data": {"is_admin": "true"},
                "payload_display": "POST /vault [is_admin=true]",
                "success_marker": "FLAG{BURP_",
            },
            {
                "id": "SCAN-08",
                "name": "Burp Tampering Level 2 (Medium Bypass): Base64 Cookie + XFF Header",
                "category": "Access Control (Medium)",
                "method": "POST",
                "path": "/vault",
                "data": {"is_admin": "false"},
                "cookies": {"auth_token": ADMIN_TOKEN_B64},
                "headers": {"X-Forwarded-For": "127.0.0.1"},
                "payload_display": f"Cookie: auth_token={ADMIN_TOKEN_B64} + X-Forwarded-For: 127.0.0.1",
                "success_marker": "FLAG{BURP_",
            },
            {
                "id": "SCAN-09",
                "name": "Burp Tampering Level 3 (High Bypass): Unsalted SHA-256 + X-Original-URL",
                "category": "Access Control (High)",
                "method": "POST",
                "path": "/vault",
                "data": {"is_admin": "false"},
                "cookies": {
                    "auth_token": ADMIN_TOKEN_B64,
                    "vault_sig": ADMIN_UNSALTED_SHA256,
                },
                "headers": {
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Original-URL": "/admin/vault",
                },
                "payload_display": "Cookie: vault_sig=sha256('user=admin') + X-Original-URL: /admin/vault",
                "success_marker": "FLAG{BURP_",
            },
            {
                "id": "SCAN-10",
                "name": "Command Injection (RCE): Shell Operator Chaining",
                "category": "RCE (Command Injection)",
                "method": "POST",
                "path": "/rce",
                "data": {"target": "127.0.0.1 && whoami"},
                "payload_display": "POST /rce [target=127.0.0.1 && whoami]",
                "success_marker": "FLAG{RCE_COMMAND_INJECTION_PWNED}",
            },
            {
                "id": "SCAN-11",
                "name": "Path Traversal (LFI): Exam Key File Leak",
                "category": "LFI (Path Traversal)",
                "method": "GET",
                "path": "/lfi",
                "query_string": {"doc": "secret_exam_key.txt"},
                "payload_display": "GET /lfi?doc=secret_exam_key.txt",
                "success_marker": "FLAG{LFI_PATH_TRAVERSAL_MASTERED}",
            },
            {
                "id": "SCAN-12",
                "name": "SSRF: Internal Loopback Microservice Extraction",
                "category": "SSRF",
                "method": "POST",
                "path": "/ssrf",
                "data": {"url": "http://127.0.0.1:5002/admin/secret-keys"},
                "payload_display": "POST /ssrf [url=http://127.0.0.1:5002/admin/secret-keys]",
                "success_marker": "FLAG{SSRF_INTRANET_PIVOT_MASTERED}",
            },
            {
                "id": "SCAN-13",
                "name": "IDOR: Faculty Dean Classified Dossier Access",
                "category": "IDOR",
                "method": "GET",
                "path": "/idor",
                "query_string": {"student_id": "1"},
                "payload_display": "GET /idor?student_id=1",
                "success_marker": "FLAG{IDOR_DIRECT_OBJECT_REF_MASTERED}",
            },
            {
                "id": "SCAN-14",
                "name": "CSRF: Cross-Site Profile Email Hijack",
                "category": "CSRF",
                "method": "POST",
                "path": "/csrf/change-email",
                "data": {"email": "attacker_scanner@evil.com"},
                "payload_display": "POST /csrf/change-email [email=attacker_scanner@evil.com]",
                "success_marker": "Profile notification email updated",
            },
        ]

        blocked_count = 0
        exploited_count = 0
        mitigated_by_code_count = 0

        for tc in test_cases:
            # Send real HTTP request through OWASP Coraza WAF Reverse Proxy on port 5001
            url = f"http://127.0.0.1:{PUBLIC_WAF_PORT}{tc['path']}"
            if tc["method"] == "GET" and "query_string" in tc:
                url += "?" + urllib.parse.urlencode(tc["query_string"])

            req_headers = dict(tc.get("headers", {}))
            if "cookies" in tc:
                cookie_str = "; ".join(f"{k}={v}" for k, v in tc["cookies"].items())
                req_headers["Cookie"] = cookie_str

            req_data = None
            if tc["method"] == "POST":
                req_data = urllib.parse.urlencode(tc.get("data", {})).encode("utf-8")
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"

            http_req = urllib.request.Request(
                url, data=req_data, headers=req_headers, method=tc["method"]
            )
            try:
                with urllib.request.urlopen(http_req, timeout=4) as resp:
                    status_code = resp.status
                    body = resp.read().decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as http_err:
                status_code = http_err.code
                body = http_err.read().decode("utf-8", errors="ignore")
            except Exception:
                # Fallback if tested offline without live Coraza process
                with app.test_client() as client:
                    if "cookies" in tc:
                        for ck, cv in tc["cookies"].items():
                            client.set_cookie(ck, cv)
                    if tc["method"] == "GET":
                        res = client.get(
                            tc["path"],
                            query_string=tc.get("query_string", {}),
                            headers=tc.get("headers", {}),
                        )
                    else:
                        res = client.post(
                            tc["path"],
                            data=tc.get("data", {}),
                            headers=tc.get("headers", {}),
                        )
                    status_code = res.status_code
                    body = res.get_data(as_text=True)

            if status_code == 403:
                outcome = "BLOCKED BY CORAZA WAF (403)"
                badge = "emerald"
                blocked_count += 1
            elif tc["success_marker"] in body:
                outcome = "VULNERABLE (EXPLOITED)"
                badge = "red"
                exploited_count += 1
            else:
                outcome = "BLOCKED BY CODE FILTER"
                badge = "cyan"
                mitigated_by_code_count += 1

            scan_results.append(
                {
                    "id": tc["id"],
                    "name": tc["name"],
                    "category": tc["category"],
                    "payload": tc["payload_display"],
                    "http_status": status_code,
                    "outcome": outcome,
                    "badge": badge,
                }
            )

        scan_summary = {
            "total": len(test_cases),
            "blocked_waf": blocked_count,
            "mitigated_code": mitigated_by_code_count,
            "protected": blocked_count + mitigated_by_code_count,
            "exploited": exploited_count,
            "difficulty": settings["difficulty"],
            "waf_mode": settings["waf_mode"],
            "waf_paranoia": settings.get("waf_paranoia", "1"),
        }

    return render_template(
        "scanner.html",
        scan_results=scan_results,
        scan_summary=scan_summary,
    )


# ==============================================================================
# OWASP CORAZA WAF DASHBOARD & AUDIT LOG VIEWER
# ==============================================================================
@app.route("/waf-dashboard")
def waf_dashboard():
    db = get_db()
    rules = db.execute(
        "SELECT * FROM waf_rules ORDER BY paranoia_level ASC, secrule_id ASC"
    ).fetchall()
    logs = parse_coraza_audit_logs(limit=100)
    crs_modules = get_owasp_crs_modules()
    total_crs_rules = sum(m["rules_count"] for m in crs_modules)
    coraza_conf_text = ""
    if os.path.exists(CORAZA_RULES_PATH):
        with open(CORAZA_RULES_PATH, "r", encoding="utf-8") as f:
            coraza_conf_text = f.read()
    return render_template(
        "waf_dashboard.html",
        rules=rules,
        logs=logs,
        crs_modules=crs_modules,
        total_crs_rules=total_crs_rules,
        coraza_conf_text=coraza_conf_text,
    )


@app.route("/waf/crs/view/<filename>")
def view_crs_file(filename):
    safe_name = os.path.basename(filename)
    file_path = os.path.join(CRS_RULES_DIR, safe_name)
    if not os.path.exists(file_path):
        file_path = os.path.join(CRS_DIR, safe_name)
    content = ""
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    return render_template("waf_rule_viewer.html", filename=safe_name, content=content)


@app.route("/waf/rules/toggle/<int:rule_pk>", methods=["POST"])
def toggle_waf_rule(rule_pk):
    db = get_db()
    db.execute(
        "UPDATE waf_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?",
        (rule_pk,),
    )
    db.commit()
    sync_coraza_waf(reload_live=True)
    return redirect(url_for("waf_dashboard"))


@app.route("/waf/rules/add", methods=["POST"])
def add_waf_rule():
    rule_id = request.form.get("rule_id", "WAF-CUSTOM").strip().upper()
    category = request.form.get("category", "Custom").strip()
    paranoia_level = int(request.form.get("paranoia_level", "1"))
    pattern = request.form.get("pattern", "").strip()
    description = request.form.get(
        "description", "Custom user-defined Coraza SecRule"
    ).strip()

    if pattern:
        try:
            re.compile(pattern)
            db = get_db()
            max_sec = db.execute("SELECT MAX(secrule_id) FROM waf_rules").fetchone()[0]
            next_sec_id = (max_sec or 3000) + 1
            db.execute(
                """
                INSERT INTO waf_rules (secrule_id, rule_id, category, paranoia_level, secrule_target, pattern, description, severity, enabled)
                VALUES (?, ?, ?, ?, 'ARGS', ?, ?, 'CRITICAL', 1)
                """,
                (next_sec_id, rule_id, category, paranoia_level, pattern, description),
            )
            db.commit()
            sync_coraza_waf(reload_live=True)
            flash(
                f"Added SecRule id:{next_sec_id} ('{rule_id}', L{paranoia_level}) and reloaded OWASP Coraza WAF.",
                "success",
            )
        except re.error as err:
            flash(f"Invalid regular expression: {err}", "warning")

    return redirect(url_for("waf_dashboard"))


@app.route("/waf/logs/clear", methods=["POST"])
def clear_waf_logs():
    if os.path.exists(CORAZA_AUDIT_LOG):
        with open(CORAZA_AUDIT_LOG, "w", encoding="utf-8") as f:
            f.write("")
    flash("Cleared OWASP Coraza WAF JSON audit log (coraza_audit.log).", "success")
    return redirect(url_for("waf_dashboard"))


if __name__ == "__main__":
    init_db()
    start_coraza_reverse_proxy()
    print("=======================================================================")
    print("  OWASP Coraza WAF (Caddy Reverse Proxy) : http://127.0.0.1:5001")
    print("  VulnerableLMS Internal Flask Upstream  : http://127.0.0.1:5002")
    print("  --> OPEN IN BROWSER / BURP SUITE       : http://127.0.0.1:5001")
    print("=======================================================================")
    app.run(host="127.0.0.1", port=INTERNAL_FLASK_PORT, debug=False)
