# ADD PARTIAL RECON FOR A NEW PIPELINE SECTION

Extend the partial recon system to support a new tool/section from the recon pipeline. Partial recon lets users run a single pipeline phase on demand from the workflow graph, without running the full pipeline. Results are merged into the existing Neo4j graph (always deduplicated via MERGE).

> **Reference implementation**: SubdomainDiscovery is fully implemented as the first partial recon tool. Study it as the pattern to follow for every new tool.

---

## Critical Rules

- **NEVER duplicate recon code.** Import and call the exact same functions from the existing pipeline modules (`domain_recon.py`, `port_scan.py`, `http_probe.py`, etc.). The partial recon entry point is a thin orchestration layer.
- **All graph writes use MERGE.** Neo4j uniqueness constraints prevent duplicates. Never use CREATE for nodes that might already exist.
- **Container-based execution.** Partial recon runs inside the same `redamon-recon` Docker image as the full pipeline, with a different command (`python /app/recon/partial_recon.py`). The orchestrator manages the container lifecycle.
- **Settings come from `get_settings()`.** The recon container fetches project settings via the webapp API (camelCase to UPPER_SNAKE_CASE conversion). Never pass raw camelCase settings.
- **Input node types come from `nodeMapping.ts`.** This is the single source of truth for what each tool consumes and produces. The modal reads from this mapping.
- **User inputs require validation.** If the tool accepts user-provided values (e.g., custom IPs for port scanning), validate format on both frontend and backend. Create a `UserInput` node in Neo4j to track provenance.
- **Mutual exclusion.** Only one partial recon OR full recon can run at a time per project. The orchestrator enforces this (409 Conflict).
- **Rebuild the recon image** after changing `recon/partial_recon.py`: `docker compose --profile tools build recon`

---

## Architecture Overview

```
User clicks Play on tool node (ProjectForm) 
  -> PartialReconModal opens (config-only: shows input/output node types, optional user inputs)
  -> User clicks "Run"
  -> Frontend POST /api/recon/{projectId}/partial
  -> Proxied to orchestrator POST /recon/{project_id}/partial  
  -> Orchestrator writes config JSON to /tmp/redamon/, spawns recon container
  -> Container runs: python /app/recon/partial_recon.py
  -> partial_recon.py reads config, calls get_settings(), imports & runs the tool function
  -> Updates Neo4j graph via mixin methods
  -> Orchestrator streams logs via SSE
  -> Graph page shows drawer with real-time logs (same as full pipeline)
```

---

## What to Implement for Each New Tool

### 1. Backend: `recon/partial_recon.py`

Add a new `run_<tool_name>(config)` function following this pattern:

```python
def run_<tool_name>(config: dict) -> None:
    from recon.<module> import <tool_function>
    from recon.project_settings import get_settings

    # Read config
    user_inputs = config.get("user_inputs", [])
    dedup_enabled = config.get("dedup_enabled", True)
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")
    settings = get_settings()

    # If tool accepts user inputs, create UserInput node
    user_input_id = None
    if user_inputs:
        # Validate inputs, create UserInput node (see SubdomainDiscovery pattern)
        ...

    # Build the input data structure the tool function expects
    # CRITICAL: Query Neo4j graph to get the input nodes this tool needs
    # (e.g., port scanning needs IPs from the graph, HTTP probing needs subdomains + ports)
    recon_data = _build_input_from_graph(tool_id, user_id, project_id, settings, user_inputs)

    # Call the exact same function the full pipeline uses
    result = <tool_function>(recon_data=recon_data, settings=settings)

    # Update the graph
    graph_client.update_graph_from_<stage>(result, user_id, project_id)
```

**Register in `main()`:**
```python
def main():
    config = load_config()
    tool_id = config.get("tool_id", "")
    if tool_id == "SubdomainDiscovery":
        run_subdomain_discovery(config)
    elif tool_id == "<NewToolId>":
        run_<tool_name>(config)
    else:
        print(f"[!][Partial] Unknown tool_id: {tool_id}")
        sys.exit(1)
```

**Key difference from SubdomainDiscovery:** Most tools (port scan, HTTP probe, resource enum, vuln scan) need INPUT DATA from the existing graph. SubdomainDiscovery only needs the domain name. Other tools need to query Neo4j first to build a `recon_data` dict that the tool function expects. For example:
- **Port scanning (Naabu)**: needs list of IPs and subdomains from graph
- **HTTP probing (Httpx)**: needs subdomains + open ports from graph
- **Resource enumeration (Katana)**: needs live BaseURLs from graph
- **Vulnerability scanning (Nuclei)**: needs BaseURLs + endpoints from graph

You must query Neo4j to assemble this input, then call the tool function with the same dict structure `main.py` would pass.

### 2. Backend: Graph Mixin (if needed)

File: `graph_db/mixins/recon_mixin.py`

Most tools already have an `update_graph_from_<stage>()` method that handles MERGE + dedup. You can reuse them directly. Only add a new `update_graph_from_partial_<tool>()` method if:
- You need to track `user_input_id` via PRODUCED relationships
- You need different stats tracking (new vs existing counts)

**Existing graph update methods you can reuse as-is:**
- `update_graph_from_domain_discovery()` -- Domain, Subdomain, IP, DNSRecord
- `update_graph_from_port_scan()` -- Port, Service
- `update_graph_from_nmap()` -- Port, Service, Technology
- `update_graph_from_http_probe()` -- BaseURL, Certificate, Technology, Header
- `update_graph_from_resource_enum()` -- Endpoint, Parameter
- `update_graph_from_vuln_scan()` -- Vulnerability, CVE, Exploit, MitreData, Capec
- `update_graph_from_js_recon()` -- JsReconFinding, Secret, Endpoint

### 3. Backend: Graph Input Query

File: `graph_db/mixins/recon_mixin.py` -- method `get_graph_inputs_for_tool()`

Add a new case for the tool_id that queries the right nodes. Example for Naabu:
```python
if tool_id == "Naabu":
    result = session.run("""
        MATCH (s:Subdomain {user_id: $uid, project_id: $pid})-[:RESOLVES_TO]->(i:IP)
        RETURN collect(DISTINCT i.address) AS ips, collect(DISTINCT s.name) AS subdomains
    """, uid=user_id, pid=project_id)
    record = result.single()
    return {
        "ips": record["ips"],
        "subdomains": record["subdomains"],
        "source": "graph",
    }
```

Also update the webapp graph-inputs API route (`webapp/src/app/api/recon/[projectId]/graph-inputs/[toolId]/route.ts`) if the new tool needs a different Neo4j query or different fallback behavior.

### 4. Frontend: Enable the Play Button

File: `webapp/src/lib/recon-types.ts`

Add the tool_id to the supported set:
```typescript
export const PARTIAL_RECON_SUPPORTED_TOOLS = new Set(['SubdomainDiscovery', '<NewToolId>'])
```

That's it -- the play button on `ToolNode.tsx` already checks this set. The `PartialReconModal` already reads input/output node types from `nodeMapping.ts`.

### 5. Frontend: PartialReconModal Input Handling (if tool accepts user inputs)

File: `webapp/src/components/projects/ProjectForm/WorkflowView/PartialReconModal.tsx`

Currently the modal is generic: shows input/output node types from `nodeMapping.ts`, domain from graph, and a Run button. If the new tool needs user-provided values (e.g., custom IPs for port scanning, custom URLs for HTTP probing):

1. Detect the `toolId` and conditionally render an input section
2. Validate input format on the frontend (regex for IPs, URLs, etc.)
3. Pass values via `user_inputs` array in `PartialReconParams`
4. The backend creates a `UserInput` node with `input_type` set appropriately ("ips", "urls", etc.)

**Validation examples by input type:**
- IPs: `/^(\d{1,3}\.){3}\d{1,3}$/` or CIDR
- URLs: must start with `http://` or `https://`
- Domains: `/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/`

### 6. Frontend: Update Drawer Title

File: `webapp/src/app/graph/page.tsx`

The `ReconLogsDrawer` title currently says "Partial Recon: Subdomain Discovery". When adding new tools, make the title dynamic based on the running tool_id. The `partialReconState.tool_id` field contains the tool name.

### 7. Frontend: Update Toolbar Badge

File: `webapp/src/app/graph/components/GraphToolbar/GraphToolbar.tsx`

The toolbar badge currently says "Partial: Subdomain Discovery". Make it dynamic using the tool_id from the partial recon state.

---

## File Reference

### Files you MUST modify:

| File | What to change |
|------|----------------|
| `recon/partial_recon.py` | Add `run_<tool>(config)` function + register in `main()` |
| `webapp/src/lib/recon-types.ts` | Add tool_id to `PARTIAL_RECON_SUPPORTED_TOOLS` |

### Files you MAY need to modify:

| File | When |
|------|------|
| `graph_db/mixins/recon_mixin.py` | If you need a custom `update_graph_from_partial_<tool>()` or new graph input query |
| `webapp/src/app/api/recon/[projectId]/graph-inputs/[toolId]/route.ts` | If the tool needs a different Neo4j query for graph inputs |
| `webapp/src/components/.../PartialReconModal.tsx` | If the tool accepts user-provided input values |
| `webapp/src/app/graph/page.tsx` | To make drawer title dynamic (one-time change for all tools) |
| `webapp/src/app/graph/components/GraphToolbar/GraphToolbar.tsx` | To make badge text dynamic (one-time change for all tools) |

### Files you should NOT modify:

| File | Why |
|------|-----|
| `recon/domain_recon.py`, `port_scan.py`, `http_probe.py`, etc. | These are the source pipeline modules. Import, don't modify. |
| `recon/main.py` | The full pipeline. Partial recon is independent. |
| `recon_orchestrator/api.py` | Endpoints are generic (tool_id-agnostic). Already handles any tool. |
| `recon_orchestrator/container_manager.py` | Container management is generic. Already handles any tool. |
| `webapp/src/hooks/usePartialReconStatus.ts` | Generic hook, works for any tool_id. |
| `webapp/src/hooks/usePartialReconSSE.ts` | Generic hook, works for any tool_id. |
| `webapp/src/components/.../ToolNode.tsx` | Play button is already generic (checks `PARTIAL_RECON_SUPPORTED_TOOLS`). |
| `webapp/src/components/.../WorkflowView.tsx` | Already passes `onRunPartial` callback. |
| `webapp/src/components/.../ProjectForm.tsx` | Already handles partial recon confirm flow. |

### Key reference files (read-only, for understanding):

| File | Contains |
|------|----------|
| `webapp/src/components/projects/ProjectForm/nodeMapping.ts` | `SECTION_INPUT_MAP` and `SECTION_NODE_MAP` -- single source of truth for tool I/O node types |
| `webapp/src/components/projects/ProjectForm/WorkflowView/workflowDefinition.ts` | `WORKFLOW_TOOLS` array -- all tool IDs, labels, groups, enabled fields |
| `graph_db/schema.py` | Neo4j constraints and indexes -- shows uniqueness rules for each node type |
| `recon/project_settings.py` | `get_settings()` + `DEFAULT_SETTINGS` -- how settings are loaded |
| `recon/main.py` | Full pipeline flow -- shows how each tool function is called and what `recon_data` structure it expects |

---

## Tool-Specific Implementation Notes

### Port Scanning (Naabu, Masscan)
- **Input from graph**: IPs and Subdomains (query RESOLVES_TO relationships)
- **Tool function**: `run_port_scan(recon_data, settings=settings)` from `port_scan.py`
- **Graph update**: `update_graph_from_port_scan()` -- creates Port, Service nodes
- **User inputs**: Could accept custom IPs (validate format: IPv4, IPv6, CIDR)
- **Note**: Uses Docker-in-Docker (spawns naabu/masscan containers)

### HTTP Probing (Httpx)
- **Input from graph**: Subdomains + Ports (query HAS_PORT relationships)
- **Tool function**: `run_http_probe(recon_data, settings=settings)` from `http_probe.py`
- **Graph update**: `update_graph_from_http_probe()` -- creates BaseURL, Technology, Header, Certificate nodes
- **User inputs**: Could accept custom URLs
- **Note**: Uses Docker-in-Docker (spawns httpx container)

### Resource Enumeration (Katana, Hakrawler, GAU, etc.)
- **Input from graph**: BaseURLs (query HAS_BASE_URL relationships)
- **Tool function**: `run_resource_enum(recon_data, settings=settings)` from `resource_enum.py`
- **Graph update**: `update_graph_from_resource_enum()` -- creates Endpoint, Parameter nodes
- **User inputs**: Could accept custom base URLs
- **Note**: Runs multiple sub-tools in parallel

### Vulnerability Scanning (Nuclei)
- **Input from graph**: BaseURLs + Endpoints
- **Tool function**: `run_vuln_scan(recon_data, settings=settings)` from `vuln_scan.py`
- **Graph update**: `update_graph_from_vuln_scan()` -- creates Vulnerability, CVE, MitreData, Capec nodes
- **User inputs**: Could accept custom target URLs
- **Note**: Heavy tool, can take a long time

### JS Recon
- **Input from graph**: BaseURLs + Endpoints (JS files)
- **Tool function**: `run_js_recon(combined_result, settings)` from `js_recon.py`
- **Graph update**: `update_graph_from_js_recon()` -- creates JsReconFinding, Secret, Endpoint nodes

---

## UserInput Node (for tools that accept user values)

When the user provides custom input values (IPs, URLs, subdomains), create a `UserInput` node:

```python
graph_client.create_user_input_node(
    domain=domain,
    user_input_data={
        "id": str(uuid.uuid4()),
        "input_type": "ips",  # or "urls", "subdomains", "domains"
        "values": user_inputs,
        "tool_id": "<ToolId>",
        "dedup_enabled": True,
    },
    user_id=user_id,
    project_id=project_id,
)
```

The `UserInput` node is connected to the Domain via `HAS_USER_INPUT` and to produced output nodes via `PRODUCED` relationships. This provides audit trail for user-provided data.

**Schema** (already defined in `graph_db/schema.py`):
- Constraint: `(ui.id) IS UNIQUE`
- Index: `(ui.user_id, ui.project_id)`

---

## Build & Verification

After implementing:

1. `docker compose --profile tools build recon` (new code baked into image)
2. `docker compose restart recon-orchestrator` (picks up volume-mounted changes)
3. Dev webapp hot-reloads automatically
4. Test: click play button on the new tool in workflow graph
5. Verify: modal shows correct input/output node types from nodeMapping.ts
6. Verify: click Run, redirects to /graph, drawer opens with logs
7. Verify: query Neo4j to confirm new nodes were created/merged
8. Verify: running partial recon disables "Start Recon Pipeline" button
9. Verify: full pipeline still works unchanged

---

## Existing Tests

- **Python**: `recon/tests/test_partial_recon.py` -- unit tests for config loading + subdomain discovery orchestration
- **TypeScript**: `webapp/src/lib/partial-recon-types.test.ts` -- type shape validation tests

Add tests for the new tool following the same patterns.
