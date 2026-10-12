# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""SELinux security tools."""

from __future__ import annotations

import re
import typing as t

import yaml

from fastmcp.exceptions import ToolError
from mcp.types import TextContent
from mcp.types import ToolAnnotations
from pydantic import Field

from linux_mcp_server.audit import log_tool_call
from linux_mcp_server.commands import get_command
from linux_mcp_server.commands import get_command_group
from linux_mcp_server.models import SELinuxBooleans
from linux_mcp_server.models import SELinuxDenials
from linux_mcp_server.models import SELinuxFileContext
from linux_mcp_server.models import SELinuxPolicyRules
from linux_mcp_server.models import SELinuxPorts
from linux_mcp_server.models import SELinuxStatus
from linux_mcp_server.parsers import parse_selinux_booleans
from linux_mcp_server.parsers import parse_selinux_denials
from linux_mcp_server.parsers import parse_selinux_file_context
from linux_mcp_server.parsers import parse_selinux_ports
from linux_mcp_server.parsers import parse_sesearch_output
from linux_mcp_server.parsers import parse_sestatus
from linux_mcp_server.server import mcp
from linux_mcp_server.utils.types import Host
from linux_mcp_server.utils.validation import is_successful_output
from linux_mcp_server.utils.validation import validate_path


_SELINUX_IDENTIFIER = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_VALID_FINDING_TYPES = {"denial", "file_context", "boolean"}


def _validate_selinux_identifier(value: str, field_name: str) -> str:
    if not _SELINUX_IDENTIFIER.match(value):
        raise ToolError(f"Invalid {field_name}: {value!r}. Must match [a-zA-Z_][a-zA-Z0-9_]*")
    return value


@mcp.tool(
    title="Get SELinux status",
    description="Get SELinux enforcement mode, loaded policy name, MLS status, and other policy details.",
    tags={"fixed", "selinux", "security", "system"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_selinux_status(
    host: Host,
) -> SELinuxStatus:
    """Get SELinux enforcement status and policy information."""
    group = get_command_group("selinux_status")

    getenforce_mode = ""
    sestatus_output = ""

    for name, cmd in group.commands.items():
        try:
            returncode, stdout, _ = await cmd.run(host=host)
            if is_successful_output(returncode, stdout):
                if name == "getenforce":
                    getenforce_mode = stdout.strip()
                elif name == "sestatus":
                    sestatus_output = stdout
        except Exception as e:
            raise ToolError(f"Error gathering SELinux status: {str(e)}") from e

    if sestatus_output:
        status = parse_sestatus(sestatus_output)
        if getenforce_mode and not status.mode:
            status.mode = getenforce_mode
        return status

    return SELinuxStatus(mode=getenforce_mode or "unknown")


@mcp.tool(
    title="Get SELinux booleans",
    description="List all SELinux booleans and their current on/off state.",
    tags={"fixed", "selinux", "security", "system"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_selinux_booleans(
    host: Host,
) -> SELinuxBooleans:
    """Get all SELinux booleans and their states."""
    cmd = get_command("selinux_booleans")

    try:
        returncode, stdout, stderr = await cmd.run(host=host)
    except Exception as e:
        raise ToolError(f"Error gathering SELinux booleans: {str(e)}") from e

    if not is_successful_output(returncode, stdout):
        raise ToolError(f"Unable to retrieve SELinux booleans: {stderr}")

    return parse_selinux_booleans(stdout)


@mcp.tool(
    title="Get SELinux file context",
    description="Get the SELinux security context label for a file or directory.",
    tags={"fixed", "selinux", "security", "filesystem"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_selinux_file_context(
    path: t.Annotated[str, Field(description="Absolute path to the file or directory")],
    host: Host,
) -> SELinuxFileContext:
    """Get the SELinux security context for a specific path."""
    validate_path(path)
    cmd = get_command("selinux_file_contexts")

    try:
        returncode, stdout, stderr = await cmd.run(host=host, path=path)
    except Exception as e:
        raise ToolError(f"Error getting SELinux context for {path}: {str(e)}") from e

    if not is_successful_output(returncode, stdout):
        raise ToolError(f"Unable to get SELinux context for {path}: {stderr}")

    return parse_selinux_file_context(stdout)


@mcp.tool(
    title="Get SELinux AVC denials",
    description="Get recent SELinux AVC denial messages from the audit log via journalctl.",
    tags={"fixed", "selinux", "security", "logs"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_selinux_denials(
    lines: t.Annotated[int, Field(description="Number of log lines to retrieve", ge=1, le=1000)] = 100,
    since: t.Annotated[str | None, Field(description="Show entries since this time (e.g. '1 hour ago')")] = None,
    *,
    host: Host,
) -> SELinuxDenials:
    """Get recent SELinux AVC denials from the audit log."""
    cmd = get_command("selinux_avc_denials")

    try:
        kwargs: dict[str, object] = {"lines": lines}
        if since:
            kwargs["since"] = since
        returncode, stdout, stderr = await cmd.run(host=host, **kwargs)
    except Exception as e:
        raise ToolError(f"Error retrieving SELinux denials: {str(e)}") from e

    if returncode != 0 and "No entries" not in stderr:
        raise ToolError(f"Unable to retrieve SELinux denials: {stderr}")

    if not stdout.strip():
        return SELinuxDenials(denials=[])

    return parse_selinux_denials(stdout)


@mcp.tool(
    title="Get SELinux port types",
    description="List SELinux port type definitions showing which network ports are assigned to which SELinux types.",
    tags={"fixed", "selinux", "security", "network"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_selinux_ports(
    host: Host,
) -> SELinuxPorts:
    """Get SELinux port type definitions."""
    cmd = get_command("selinux_ports")

    try:
        returncode, stdout, stderr = await cmd.run(host=host)
    except Exception as e:
        raise ToolError(f"Error retrieving SELinux port types: {str(e)}") from e

    if not is_successful_output(returncode, stdout):
        raise ToolError(f"Unable to retrieve SELinux port types: {stderr}")

    return parse_selinux_ports(stdout)


@mcp.tool(
    title="Get SELinux policy rules",
    description="Query SELinux policy rules using sesearch. Filter by source type, target type, "
    "object class, permission, or boolean name. Returns matching allow rules from the loaded policy.",
    tags={"fixed", "selinux", "security", "policy"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_selinux_policy_rules(
    host: Host,
    source: t.Annotated[str | None, Field(description="Source SELinux type (e.g. httpd_t)")] = None,
    target: t.Annotated[str | None, Field(description="Target SELinux type (e.g. http_port_t)")] = None,
    tclass: t.Annotated[str | None, Field(description="Object class (e.g. tcp_socket, file)")] = None,
    permission: t.Annotated[str | None, Field(description="Permission to search for (e.g. read, write)")] = None,
    boolean: t.Annotated[str | None, Field(description="Boolean name to find rules gated by")] = None,
) -> SELinuxPolicyRules:
    """Query SELinux policy rules via sesearch."""
    cmd = get_command("selinux_sesearch")

    kwargs: dict[str, object] = {}
    if source:
        kwargs["source"] = source
    if target:
        kwargs["target"] = target
    if tclass:
        kwargs["tclass"] = tclass
    if permission:
        kwargs["permission"] = permission
    if boolean:
        kwargs["boolean"] = boolean

    try:
        returncode, stdout, stderr = await cmd.run(host=host, **kwargs)
    except Exception as e:
        raise ToolError(f"Error querying SELinux policy: {str(e)}") from e

    if not is_successful_output(returncode, stdout):
        raise ToolError(f"Unable to query SELinux policy: {stderr}")

    return parse_sesearch_output(stdout)


def _build_boolean_task(finding: dict[str, str]) -> dict[str, t.Any]:
    name = finding.get("name", "")
    _validate_selinux_identifier(name, "boolean name")
    desired = finding.get("desired_state", "on")
    state = desired.lower() in ("on", "true", "yes")
    return {
        "name": f"Set SELinux boolean {name}",
        "ansible.posix.seboolean": {
            "name": name,
            "state": state,
            "persistent": True,
        },
    }


def _build_file_context_tasks(finding: dict[str, str]) -> list[dict[str, t.Any]]:
    path = finding.get("path", "")
    validate_path(path)
    expected = finding.get("expected_context", "")
    _validate_selinux_identifier(expected, "expected_context")
    return [
        {
            "name": f"Set SELinux file context for {path}",
            "community.general.sefcontext": {
                "target": path + "(/.*)?" if not path.endswith("(/.*)?") else path,
                "setype": expected,
                "state": "present",
            },
        },
        {
            "name": f"Restore SELinux context on {path}",
            "ansible.builtin.command": f"restorecon -R {path}",
        },
    ]


async def _build_denial_tasks(finding: dict[str, str], host: Host) -> list[dict[str, t.Any]]:
    source = finding.get("source_type", "")
    target = finding.get("target_type", "")
    perm = finding.get("permission", "")
    tclass = finding.get("tclass", "")

    _validate_selinux_identifier(source, "source_type")
    _validate_selinux_identifier(target, "target_type")
    _validate_selinux_identifier(perm, "permission")
    _validate_selinux_identifier(tclass, "tclass")

    cmd = get_command("selinux_sesearch")
    try:
        returncode, stdout, _ = await cmd.run(
            host=host, source=source, target=target, tclass=tclass, permission=perm,
        )
    except Exception:
        stdout = ""
        returncode = 1

    if returncode == 0 and stdout:
        rules = parse_sesearch_output(stdout)
        for rule in rules.rules:
            if rule.conditional:
                return [
                    {
                        "name": f"Enable boolean {rule.conditional} for {source} -> {target}:{tclass}",
                        "ansible.posix.seboolean": {
                            "name": rule.conditional,
                            "state": True,
                            "persistent": True,
                        },
                    }
                ]

    module_name = f"local_{source}_{perm}_{tclass}"
    cil_content = f"(allow {source} {target} ({tclass} ({perm})))"
    return [
        {
            "name": f"Create CIL module {module_name}",
            "ansible.builtin.copy": {
                "dest": f"/tmp/{module_name}.cil",
                "content": cil_content,
                "mode": "0644",
            },
        },
        {
            "name": f"Load CIL module {module_name}",
            "ansible.builtin.command": f"semodule -i /tmp/{module_name}.cil",
        },
    ]


@mcp.tool(
    title="Generate SELinux remediation playbook",
    description="Generate an Ansible playbook to remediate SELinux issues. Accepts a list of findings "
    "(denial, file_context, boolean) and produces a YAML playbook using standard Ansible SELinux modules. "
    "Read-only: returns the playbook text without executing it.",
    tags={"fixed", "selinux", "security", "remediation"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def generate_selinux_playbook(
    host: Host,
    findings: t.Annotated[
        list[dict[str, str]],
        Field(
            description="List of findings to remediate. Each finding is a dict with 'type' "
            "(denial|file_context|boolean) and relevant fields: "
            "denial: source_type, target_type, permission, tclass; "
            "file_context: path, expected_context; "
            "boolean: name, desired_state (on/off)"
        ),
    ],
) -> list[TextContent]:
    """Generate an Ansible playbook to remediate SELinux findings."""
    if not findings:
        raise ToolError("No findings provided to generate a playbook")

    tasks: list[dict[str, t.Any]] = []

    for finding in findings:
        finding_type = finding.get("type", "")
        if finding_type not in _VALID_FINDING_TYPES:
            raise ToolError(f"Unknown finding type: {finding_type!r}. Must be one of: {_VALID_FINDING_TYPES}")

        if finding_type == "boolean":
            tasks.append(_build_boolean_task(finding))
        elif finding_type == "file_context":
            tasks.extend(_build_file_context_tasks(finding))
        elif finding_type == "denial":
            tasks.extend(await _build_denial_tasks(finding, host))

    playbook = {
        "name": "SELinux remediation",
        "hosts": "all",
        "become": True,
        "collections": ["ansible.posix", "community.general"],
        "tasks": tasks,
    }

    playbook_yaml = yaml.dump([playbook], default_flow_style=False, sort_keys=False)
    return [TextContent(type="text", text=playbook_yaml)]
