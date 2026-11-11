import atexit
import base64
import hashlib
import html
import json
import os
import re
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
    url_for,
)

app = Flask(__name__)
app.secret_key = "moodle-uni-portal-coraza-waf-key"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "security_lab.db")
CORAZA_EXE = os.path.join(BASE_DIR, "coraza-waf.exe")
CADDYFILE_PATH = os.path.join(BASE_DIR, "Caddyfile")
CORAZA_RULES_PATH = os.path.join(BASE_DIR, "coraza_rules.conf")
CORAZA_AUDIT_LOG = os.path.join(BASE_DIR, "coraza_audit.log")

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
        # --- SECTION 942: SQL INJECTION (SQLi) ---
        (
            1001,
            "WAF-SQLI-BASIC",
            "SQLi",
            1,
            "ARGS",
            r"(?i)(union\s+select|or\s+['\x22]?\d+['\x22]?\s*=\s*['\x22]?\d+|/\*\*/\s*or\s*/\*\*/|'and'1'='1|drop\s+table|--)",
            "OWASP CRS 942: Blocks standard Low/Medium/High SQLi (' OR 1=1 --, /**/OR/**/, 'AND'1'='1).",
            "CRITICAL",
            1,
        ),
        (
            1011,
            "WAF-SQLI-STACKED-QUERIES",
            "SQLi",
            1,
            "ARGS",
            r"(?i);\s*(insert|update|delete|drop|alter|create|truncate)\s+",
            "OWASP CRS 942: Detects stacked SQL queries attempting database modification or dropping tables.",
            "CRITICAL",
            1,
        ),
        (
            1012,
            "WAF-SQLI-METADATA-PROBING",
            "SQLi",
            1,
            "ARGS",
            r"(?i)\b(information_schema|sqlite_master|sqlite_temp_master|pg_tables|sys\.databases)\b",
            "OWASP CRS 942: Detects database schema enumeration and metadata probing.",
            "HIGH",
            1,
        ),
        (
            2001,
            "WAF-SQLI-BYPASS",
            "SQLi",
            2,
            "ARGS",
            r"(?i)(/\*.*\*/|'\s*(or|and)\s*'[a-z0-9]+'\s*=\s*'|['\x22]\s*(or|and)\s*\d+\s*=\s*\d+|--|;\s*(drop|select|insert|update))",
            "OWASP CRS 942 (L2): Catches alpha quote-delimited SQLi bypasses (admin'AND'a'='a) and comment fragmentation.",
            "CRITICAL",
            1,
        ),
        (
            2011,
            "WAF-SQLI-BLIND-FUNCTIONS",
            "SQLi",
            2,
            "ARGS",
            r"(?i)\b(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\()",
            "OWASP CRS 942 (L2): Blocks time-based blind SQL injection functions.",
            "HIGH",
            1,
        ),
        (
            2012,
            "WAF-SQLI-OUTFILE-INJECTION",
            "SQLi",
            2,
            "ARGS",
            r"(?i)\b(extractvalue|updatexml|load_file|into\s+outfile|into\s+dumpfile)\b",
            "OWASP CRS 942 (L2): Detects error-based extraction and arbitrary file read/write SQL clauses.",
            "CRITICAL",
            1,
        ),

        # --- SECTION 941: CROSS-SITE SCRIPTING (XSS) ---
        (
            1002,
            "WAF-XSS-BASIC",
            "XSS",
            1,
            "ARGS",
            r"(?i)(<\s*script\b|javascript\s*:|<\s*iframe\b|<\s*object\b|<\s*embed\b|<\s*img\b|\bonerror\s*=|<\s*details\b|\bontoggle\s*=)",
            "OWASP CRS 941: Blocks standard Low/Medium/High XSS (<script>, <img onerror>, <details ontoggle>).",
            "CRITICAL",
            1,
        ),
        (
            1021,
            "WAF-XSS-DATA-SCHEME",
            "XSS",
            1,
            "ARGS",
            r"(?i)data:text/(html|javascript)",
            "OWASP CRS 941: Blocks malicious payload delivery via data: URI scheme.",
            "HIGH",
            1,
        ),
        (
            1022,
            "WAF-XSS-STYLE-EXPRESSION",
            "XSS",
            1,
            "ARGS",
            r"(?i)(style\s*=.*expression\s*\(|vbscript\s*:)",
            "OWASP CRS 941: Blocks CSS expression execution and active scripting protocols.",
            "HIGH",
            1,
        ),
        (
            2002,
            "WAF-XSS-BYPASS",
            "XSS",
            2,
            "ARGS",
            r"(?i)(\bon[a-z]+\s*=|<\s*(svg|img|body|details|input|video|audio|marquee|object|embed)\b)",
            "OWASP CRS 941 (L2): Catches all DOM event handlers (onfocus=, onerror=, ontoggle=) and HTML5 tags.",
            "CRITICAL",
            1,
        ),
        (
            2021,
            "WAF-XSS-AUTOFOCUS-FOCUS",
            "XSS",
            2,
            "ARGS",
            r"(?i)(autofocus|onfocus|onload|onmouseover|onpointerenter)\s*=",
            "OWASP CRS 941 (L2): Blocks modern zero-click DOM autofocus/onfocus evasion vectors.",
            "HIGH",
            1,
        ),

        # --- SECTION 943: BROKEN ACCESS CONTROL & PRIVILEGE ESCALATION ---
        (
            1003,
            "WAF-BAC-BASIC",
            "Access Control",
            1,
            "ARGS:is_admin|REQUEST_COOKIES:user_role|REQUEST_COOKIES:auth_token|REQUEST_COOKIES:vault_sig|REQUEST_HEADERS:X-Forwarded-For|REQUEST_HEADERS:X-Original-URL|ARGS:sim_exploit",
            r"(^(true|TRUE|admin|ADMIN|low|medium|high)$|dXNlcj1hZG1pbg==|127\.0\.0\.1|/admin/vault|52c876f2a69205692536a1f2857b4e4c70312142b068e23f4d87d506680183c5)",
            "OWASP CRS 943: Blocks standard Burp tampering (is_admin=true, user_role=admin, dXNlcj1hZG1pbg==, 127.0.0.1).",
            "CRITICAL",
            1,
        ),
        (
            1031,
            "WAF-BAC-PRIVILEGE-ESCALATION",
            "Access Control",
            1,
            "ARGS|REQUEST_COOKIES",
            r"(?i)\b(role=(root|superuser|administrator)|admin=1|is_staff=true|is_dean=true)\b",
            "OWASP CRS 943: Blocks direct parameter tampering attempting administrative privilege escalation.",
            "HIGH",
            1,
        ),
        (
            2003,
            "WAF-BAC-BYPASS",
            "Access Control",
            2,
            "REQUEST_COOKIES:auth_token|REQUEST_COOKIES:vault_sig|REQUEST_HEADERS:X-Forwarded-For|REQUEST_HEADERS:X-Original-URL|ARGS:sim_exploit",
            r"(?i)(dXNlcj1hZG1pbg==|dXNlcj1BRE1JTg==|localhost|127\.0\.0\.1|/admin|52c876f2a69205692536a1f2857b4e4c70312142b068e23f4d87d506680183c5|^bypass$)",
            "OWASP CRS 943 (L2): Catches uppercase Base64 token (dXNlcj1BRE1JTg==) and X-Forwarded-For: localhost WAF bypass.",
            "CRITICAL",
            1,
        ),
        (
            2031,
            "WAF-BAC-PROXY-SPOOF",
            "Access Control",
            2,
            "REQUEST_HEADERS:X-Real-IP|REQUEST_HEADERS:X-Originating-IP|REQUEST_HEADERS:Client-IP",
            r"(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|::1)",
            "OWASP CRS 943 (L2): Detects spoofing of internal loopback origin in secondary proxy headers.",
            "HIGH",
            1,
        ),

        # --- SECTION 913: SCANNER & AUTOMATED ATTACK TOOL DETECTION ---
        (
            913100,
            "WAF-SCANNER-USERAGENT",
            "Scanner Detection",
            1,
            "REQUEST_HEADERS:User-Agent",
            r"(?i)(sqlmap|nikto|acunetix|dirbuster|gobuster|wpscan|havij|nessus|masscan|zgrab|openvas|arachni)",
            "OWASP CRS 913: Detects automated vulnerability scanners and web application security testing bots.",
            "HIGH",
            1,
        ),
        (
            913110,
            "WAF-SCANNER-VULN-PROBES",
            "Scanner Detection",
            1,
            "ARGS|REQUEST_URI",
            r"(?i)(acunetix_wvs|nessus_token|appscan_probe|openvas_scan)",
            "OWASP CRS 913: Blocks probe signatures and canary tokens generated by commercial DAST scanners.",
            "MEDIUM",
            1,
        ),

        # --- SECTION 920 & 921: PROTOCOL ATTACKS & REQUEST TAMPERING ---
        (
            920100,
            "WAF-PROTOCOL-INVALID-METHOD",
            "Protocol Enforcement",
            1,
            "REQUEST_METHOD",
            r"(?i)^(PUT|DELETE|CONNECT|TRACE|TRACK)$",
            "OWASP CRS 920: Blocks dangerous HTTP methods disallowed by portal security policy.",
            "MEDIUM",
            1,
        ),
        (
            921110,
            "WAF-PROTOCOL-HTTP-SPLITTING",
            "Protocol Enforcement",
            1,
            "ARGS|REQUEST_HEADERS",
            r"(?i)(%0d%0a|\r\n)(set-cookie|location|content-type):",
            "OWASP CRS 921: Blocks HTTP Response Splitting and header CRLF injection attacks.",
            "HIGH",
            1,
        ),

        # --- SECTION 930 & 931: PATH TRAVERSAL / LFI & RFI ---
        (
            930100,
            "WAF-LFI-PATH-TRAVERSAL",
            "LFI / Path Traversal",
            1,
            "ARGS|REQUEST_URI",
            r"(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|c:\\windows|c:/windows|boot\.ini|win\.ini)",
            "OWASP CRS 930: Blocks directory traversal attempts accessing system configuration or SAM files.",
            "CRITICAL",
            1,
        ),
        (
            930110,
            "WAF-LFI-NULL-BYTE",
            "LFI / Path Traversal",
            1,
            "ARGS|REQUEST_URI",
            r"(?i)(%00|\\x00|%2500)",
            "OWASP CRS 930: Blocks null byte poison injection used to bypass file extension filters.",
            "HIGH",
            1,
        ),
        (
            931100,
            "WAF-RFI-REMOTE-INCLUDE",
            "RFI",
            1,
            "ARGS",
            r"(?i)(https?|ftp|file)://",
            "OWASP CRS 931: Blocks remote file inclusion loading payloads from external hosts.",
            "CRITICAL",
            1,
        ),
        (
            931110,
            "WAF-PHP-STREAM-WRAPPERS",
            "RFI",
            1,
            "ARGS",
            r"(?i)php://(input|filter|memory|temp)",
            "OWASP CRS 931: Blocks dangerous PHP I/O stream wrappers used in pseudo-protocol exploits.",
            "HIGH",
            1,
        ),

        # --- SECTION 932: REMOTE COMMAND EXECUTION (RCE) ---
        (
            932100,
            "WAF-RCE-SHELL-BINARIES",
            "RCE",
            1,
            "ARGS",
            r"(?i)(/bin/(bash|sh|zsh|dash)|/usr/bin/id|/usr/bin/whoami|cmd\.exe|powershell(\.exe)?|nc\s+-e)",
            "OWASP CRS 932: Blocks invocation of core OS shell interpreters and interactive netcat listeners.",
            "CRITICAL",
            1,
        ),
        (
            932110,
            "WAF-RCE-WINDOWS-LOLBINS",
            "RCE",
            1,
            "ARGS",
            r"(?i)\b(certutil|bitsadmin|vssadmin|wmic|curl\s+.*\|\s*sh|wget\s+.*\|\s*sh)\b",
            "OWASP CRS 932: Detects Living-off-the-Land (LOLBins) binaries and pipe-to-shell downloaders.",
            "HIGH",
            1,
        ),
        (
            932150,
            "WAF-RCE-COMMAND-CHAINING",
            "RCE",
            2,
            "ARGS",
            r"(?i)(;\s*(cat|ls|dir|whoami|id|echo|curl|wget)\b|\|\s*(cat|grep|whoami|bash)\b)",
            "OWASP CRS 932 (L2): Detects shell command chaining operators (; | && ||) executing system utilities.",
            "CRITICAL",
            1,
        ),

        # --- SECTION 933: CODE INJECTION & SERVER-SIDE TEMPLATES (SSTI) ---
        (
            933100,
            "WAF-PHP-CODE-EXECUTION",
            "Code Injection",
            1,
            "ARGS",
            r"(?i)(<\?php|\b(eval|assert|passthru|shell_exec|proc_open)\s*\()",
            "OWASP CRS 933: Detects arbitrary PHP code tags and dangerous dynamic execution primitives.",
            "CRITICAL",
            1,
        ),
        (
            933150,
            "WAF-SSTI-TEMPLATE-INJECTION",
            "Code Injection",
            1,
            "ARGS",
            r"(?i)(\{\{.*(config|self|import|builtins|request|class).*\}\}|\$\{.*(Runtime|ProcessBuilder).*\})",
            "OWASP CRS 933: Blocks Server-Side Template Injection (Jinja2, Twig, Spring EL expression breakouts).",
            "CRITICAL",
            1,
        ),

        # --- SECTION 944: JAVA DESERIALIZATION & LOG4SHELL ---
        (
            944100,
            "WAF-LOG4J-JNDI-INJECTION",
            "Deserialization / RCE",
            1,
            "ARGS|REQUEST_HEADERS",
            r"(?i)jndi:(ldap|rmi|dns|corba|iiop|nis)",
            "OWASP CRS 944: Blocks Log4Shell (CVE-2021-44228) and JNDI LDAP/RMI lookup strings.",
            "CRITICAL",
            1,
        ),
        (
            944110,
            "WAF-JAVA-DESERIALIZATION",
            "Deserialization / RCE",
            1,
            "ARGS|REQUEST_COOKIES",
            r"(?i)(rO0ABX|aced0005)",
            "OWASP CRS 944: Blocks Java serialized object magic headers (ysoserial gadget payloads).",
            "HIGH",
            1,
        ),

        # --- SECTION 950: SENSITIVE DATA LEAKAGE & DEBUG PARAMS ---
        (
            950100,
            "WAF-LEAK-DEBUG-ENDPOINTS",
            "Information Leak",
            1,
            "ARGS|REQUEST_URI",
            r"(?i)\b(phpinfo|xdebug|actuator/(health|env)|dump_env|trace\.axd|elmah\.axd)\b",
            "OWASP CRS 950: Blocks access to framework debug probes, metrics actuators, and stack traces.",
            "MEDIUM",
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
def write_coraza_config_files():
    """Generates real ModSecurity/Coraza SecRule directives in coraza_rules.conf and Caddyfile."""
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

    audit_path_posix = CORAZA_AUDIT_LOG.replace("\\", "/")
    rules_path_posix = CORAZA_RULES_PATH.replace("\\", "/")

    secrules_lines = [
        "# ======================================================================",
        "# OWASP CORAZA WAF — MODSECURITY SECLANG CONFIGURATION (AUTO-GENERATED)",
        f"# Active Mode: SecRuleEngine {engine_state} | Active Paranoia Level: L{paranoia}",
        "# ======================================================================",
        f"SecRuleEngine {engine_state}",
        "SecRequestBodyAccess On",
        "SecAuditEngine Off",
        "SecAuditLogParts ABIJDEFHZ",
        "SecAuditLogType Serial",
        "SecAuditLogFormat JSON",
        f"SecAuditLog {audit_path_posix}",
        "",
        "# Whitelist WAF Admin Dashboard, Hints & Settings endpoints",
        'SecRule REQUEST_URI "@rx ^/(waf-dashboard|waf/|settings/|hints|coraza-blocked)" "id:999,phase:1,pass,nolog,ctl:ruleEngine=Off"',
        "# Only evaluate Access Control cookie/header rules on POST requests so GET page loads are never locked out by stale cookies",
        'SecRule REQUEST_METHOD "@streq GET" "id:998,phase:1,pass,nolog,ctl:ruleRemoveById=1003,ctl:ruleRemoveById=1031,ctl:ruleRemoveById=2003,ctl:ruleRemoveById=2031"',
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
            Include {rules_path_posix}
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
    with open(CADDYFILE_PATH, "w", encoding="utf-8") as f:
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

                first_msg = msgs[-1]
                err_str = first_msg.get("error_message", "")

                rule_id_match = re.search(r'\[msg "(.*?)"\]', err_str)
                sec_id_match = re.search(r'\[id "(.*?)"\]', err_str)
                tag_match = re.search(r'\[tag "(.*?)"\]', err_str)

                rule_name = rule_id_match.group(1) if rule_id_match else "CORAZA-RULE"
                sec_id = sec_id_match.group(1) if sec_id_match else "1000"
                category = tag_match.group(1) if tag_match else "WAF"

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

                parsed_logs.append(
                    {
                        "tx_id": tx.get("id", "N/A"),
                        "timestamp": tx.get("timestamp", ""),
                        "ip_address": tx.get("client_ip", "127.0.0.1"),
                        "http_method": req.get("method", "GET"),
                        "endpoint": uri.split("?")[0],
                        "rule_id": f"{rule_name} (id:{sec_id})",
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
    coraza_conf_text = ""
    if os.path.exists(CORAZA_RULES_PATH):
        with open(CORAZA_RULES_PATH, "r", encoding="utf-8") as f:
            coraza_conf_text = f.read()
    return render_template(
        "waf_dashboard.html",
        rules=rules,
        logs=logs,
        coraza_conf_text=coraza_conf_text,
    )


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
    print("  UniMoodle Internal Flask Upstream      : http://127.0.0.1:5002")
    print("  --> OPEN IN BROWSER / BURP SUITE       : http://127.0.0.1:5001")
    print("=======================================================================")
    app.run(host="127.0.0.1", port=INTERNAL_FLASK_PORT, debug=False)
