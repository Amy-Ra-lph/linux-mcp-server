# SELinux Security Tools — Quickstart

Try the SELinux diagnosis, remediation, and offline analysis tools contributed
from [enforcement-mcp](https://github.com/Amy-Ra-lph/enforcement-mcp).

## Prerequisites

- Python 3.10+ with [uv](https://docs.astral.sh/uv/getting-started/installation/)
- A RHEL 9 or 10 target host with SSH key access
- `setools-console` on the target: `dnf install -y setools-console`

## Clone and build

```bash
git clone https://github.com/Amy-Ra-lph/linux-mcp-server.git
cd linux-mcp-server
git checkout feat/selinux-tools
uv sync
```

## Run the tests

```bash
make test        # 1085 tests, all pass
make ci          # full CI: lint + format + types + test
```

## Start the server

```bash
export LINUX_MCP_HOST=your-rhel-host.example.com
uv run linux-mcp-server
```

Or configure Claude Code (`.mcp.json`):

```json
{
  "linux-mcp-server": {
    "command": "uv",
    "args": ["run", "--directory", "/path/to/linux-mcp-server", "linux-mcp-server"],
    "env": {
      "LINUX_MCP_HOST": "your-rhel-host.example.com"
    }
  }
}
```

## SELinux tools included

### Base branch: `feat/selinux-tools`

| Tool | Description |
|------|-------------|
| `get_selinux_status` | SELinux mode, policy type, MLS status |
| `get_selinux_booleans` | Boolean list with current state |
| `get_selinux_file_context` | Expected vs actual file context |
| `get_selinux_denials` | Recent AVC denials, parsed and structured |
| `get_selinux_ports` | SELinux port label mappings |

### Feature branches (stack incrementally)

Each branch adds tools on top of `feat/selinux-tools`. Check out any
branch, run `uv sync`, and `make test`:

| Branch | What it adds | New tools |
|--------|-------------|-----------|
| `feat/selinux-policy-query` | sesearch policy rule query | `get_selinux_policy_rules` |
| `feat/selinux-denial-explain` | Denial explain + troubleshoot (stacks on policy-query) | `explain_selinux_denial`, `troubleshoot_selinux` |
| `feat/selinux-remediation` | Ansible playbook generation (stacks on policy-query) | `generate_selinux_playbook` |
| `feat/fapolicyd-aide-tools` | fapolicyd + AIDE diagnosis | `get_fapolicyd_status`, `check_fapolicyd_trust`, `get_aide_status`, `check_aide` |
| `feat/cve-exposure-offline` | CVE exposure + offline AVC parsing | `get_cve_exposure`, `parse_offline_denials` |
| `feat/hardened-parsers` | Hardened parser backend (optional dep) | Same tools, hardened input handling |
| `feat/spiffe-auth` | SPIFFE/WID identity auth provider | No new tools — adds `SPIFFETokenVerifier` |

### Dependency chain

```
feat/selinux-tools (base)
├── feat/selinux-policy-query
│   ├── feat/selinux-denial-explain
│   └── feat/selinux-remediation
├── feat/fapolicyd-aide-tools
├── feat/cve-exposure-offline
├── feat/hardened-parsers
└── feat/spiffe-auth
```

Independent branches can be tested standalone against the base.
`denial-explain` and `remediation` require `policy-query` to be present.

## Try it: diagnose a denial

With your MCP client connected:

> "Why can't httpd serve files from /home on my-rhel-host?"

The agent will call `get_selinux_denials` → `explain_selinux_denial` → suggest
a fix (boolean toggle or file context relabel).

On the `feat/selinux-remediation` branch, it can also generate a ready-to-run
Ansible playbook using `fedora.linux_system_roles.selinux`.

## Try it: offline analysis

On the `feat/cve-exposure-offline` branch, feed raw `audit.log` text
without any SSH connection:

```json
{
  "tool": "parse_offline_denials",
  "arguments": {
    "raw_text": "type=AVC msg=audit(1697051234.567:890): avc:  denied  { read } for  pid=1234 comm=\"httpd\" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file"
  }
}
```

Returns structured JSON — source types, target types, permissions, summary
stats — without touching any live system.

## Architecture: what ships where

```
┌─────────────────────────────────────────────────┐
│  linux-mcp-server                               │
│  ┌───────────────────────────────────────────┐   │
│  │  Tier 1: Diagnosis (read-only)            │   │
│  │  SELinux, fapolicyd, AIDE, CVE exposure   │   │
│  ├───────────────────────────────────────────┤   │
│  │  Tier 2: Remediation (read-only output)   │   │
│  │  Ansible playbooks — never executes       │   │
│  └───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  enforcement-mcp (standalone)                    │
│  ┌───────────────────────────────────────────┐   │
│  │  Tier 3: Management (mutating)            │   │
│  │  set_boolean, load_module, cve_contain    │   │
│  │  RBAC, identity verification, audit trail │   │
│  └───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

- **Tiers 1+2** ship as modules within linux-mcp-server. Security team
  maintains the code, linux-mcp hosts it. No separate server for diagnosis.
- **Tier 3** stays in enforcement-mcp. Mutating policy operations require
  identity verification, RBAC, and audit trail that are out of scope for
  linux-mcp's read-only model.

## Security

All branches include:
- Input validation via `sanitize_*` functions (command injection prevention)
- `readOnlyHint=True` on all tool annotations
- Mantis security manifests in `manifests/`
- Tests for injection rejection on every user-facing parameter
