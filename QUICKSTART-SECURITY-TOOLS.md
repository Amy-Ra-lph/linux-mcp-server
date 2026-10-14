# linux-mcp-server — Security Tools Quick Start

Read-only MCP tools for SELinux, fapolicyd, AIDE, and CVE exposure on RHEL systems.
Built as feature branches on top of upstream [rhel-lightspeed/linux-mcp-server](https://github.com/rhel-lightspeed/linux-mcp-server).

## Build & Run (Container)

```bash
git clone https://github.com/Amy-Ra-lph/linux-mcp-server.git
cd linux-mcp-server
git checkout feat/selinux-policy-query   # see branch table below

# Build (podman or docker — auto-detected)
make container-build-fast

# Run against a target host via SSH
podman run --rm -it \
  -v ~/.ssh:/var/lib/mcp/.ssh:ro \
  localhost/linux-mcp-server \
  linux-mcp-server --host <target-host>
```

## Build & Run (pip)

```bash
git clone https://github.com/Amy-Ra-lph/linux-mcp-server.git
cd linux-mcp-server
git checkout feat/selinux-policy-query

pip install -e .
# or: uv sync && uv run linux-mcp-server --host <target-host>

linux-mcp-server --host <target-host>
```

## Use with Claude Code

Add to your MCP config (`.claude/settings.json` or project `mcp_servers`):

```json
{
  "linux-mcp": {
    "command": "linux-mcp-server",
    "args": ["--host", "TARGET_HOST"]
  }
}
```

Or with the container:

```json
{
  "linux-mcp": {
    "command": "podman",
    "args": ["run", "--rm", "-i",
             "-v", "~/.ssh:/var/lib/mcp/.ssh:ro",
             "localhost/linux-mcp-server",
             "linux-mcp-server", "--host", "TARGET_HOST"]
  }
}
```

## Branches

Each branch adds a self-contained feature. All branches include the base SELinux tools.

| Branch | What it adds | New tools |
|--------|-------------|-----------|
| `feat/selinux-policy-query` | Query SELinux policy rules via sesearch | `get_selinux_policy_rules` |
| `feat/selinux-denial-explain` | Explain AVC denials + auto-troubleshoot | `explain_selinux_denial`, `troubleshoot_selinux` |
| `feat/selinux-remediation` | Generate Ansible playbooks from findings | `generate_selinux_playbook` |
| `feat/fapolicyd-aide-tools` | fapolicyd + AIDE diagnostic tools | `get_fapolicyd_status`, `get_fapolicyd_denials`, `get_aide_status`, `run_aide_check` |
| `feat/cve-exposure-offline` | CVE exposure check + offline AVC parser | `check_cve_exposure`, `parse_avc_denials` |
| `feat/hardened-parsers` | Optional hardened parser backend | (internal — hardens existing tool parsers) |
| `feat/spiffe-auth` | SPIFFE/Workload Identity auth provider | (auth layer — no new user-facing tools) |

**Dependency chain:** `denial-explain` and `remediation` depend on `policy-query`. All others are independent.

**Recommended starting branch:** `feat/selinux-policy-query` — base SELinux tools + policy query. Covers `get_selinux_status`, `get_selinux_booleans`, `get_selinux_file_context`, `get_selinux_denials`, `get_selinux_ports`, `get_selinux_policy_rules`.

## All tools are read-only

Every tool has `readOnlyHint=True`. No mutations, no remediation actions. Safe to point at production systems.

## Prerequisites on the target host

- RHEL 9 or 10 (any SELinux-enforcing system works)
- SSH access (key-based)
- For SELinux tools: `semanage`, `sesearch`, `ausearch` available
- For fapolicyd: `fapolicyd` service running
- For AIDE: `aide` package installed
- For CVE: internet access (queries Red Hat Security Data API)

## Run tests

```bash
uv sync
uv run pytest           # full suite
make verify             # lint + format + types + tests
```
