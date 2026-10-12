# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""SELinux security tools."""

from __future__ import annotations

import json
import re
import typing as t

from fastmcp.exceptions import ToolError
from mcp.types import TextContent
from mcp.types import ToolAnnotations
from pydantic import Field

from linux_mcp_server.audit import log_tool_call
from linux_mcp_server.commands import get_command
from linux_mcp_server.commands import get_command_group
from linux_mcp_server.models import SELinuxBooleans
from linux_mcp_server.models import SELinuxDenialExplanation
from linux_mcp_server.models import SELinuxDenials
from linux_mcp_server.models import SELinuxFileContext
from linux_mcp_server.models import SELinuxPolicyRules
from linux_mcp_server.models import SELinuxPorts
from linux_mcp_server.models import SELinuxStatus
from linux_mcp_server.models import SELinuxTroubleshootIssue
from linux_mcp_server.models import SELinuxTroubleshootReport
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


_AVC_PATTERN = re.compile(
    r"avc:\s+denied\s+\{\s*(\S+)\s*\}.*?"
    r"scontext=(\S+).*?"
    r"tcontext=(\S+).*?"
    r"tclass=(\S+)"
)


def _extract_type_from_context(context: str) -> str:
    """Extract the type field from an SELinux context (user:role:type:level)."""
    parts = context.split(":")
    return parts[2] if len(parts) >= 3 else context


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


@mcp.tool(
    title="Explain SELinux denial",
    description="Analyze a raw AVC denial message and explain what happened: the source process, target resource, "
    "denied permission, and possible resolution approaches including boolean toggles and policy rules.",
    tags={"fixed", "selinux", "security", "diagnosis"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def explain_selinux_denial(
    host: Host,
    denial: t.Annotated[str, Field(description="Raw AVC denial line from audit log or journalctl")],
) -> list[TextContent]:
    """Analyze a raw AVC denial and return a structured explanation."""
    match = _AVC_PATTERN.search(denial)
    if not match:
        explanation = SELinuxDenialExplanation(
            denial_summary="Could not parse AVC denial — expected 'avc: denied { perm }' with scontext/tcontext/tclass",
        )
        return [TextContent(type="text", text=json.dumps(explanation.model_dump()))]

    permission = match.group(1)
    scontext = match.group(2)
    tcontext = match.group(3)
    tclass = match.group(4)
    source_type = _extract_type_from_context(scontext)
    target_type = _extract_type_from_context(tcontext)

    existing_rules = 0
    try:
        sesearch_cmd = get_command("selinux_sesearch")
        returncode, stdout, _ = await sesearch_cmd.run(
            host=host, source=source_type, target=target_type, tclass=tclass, permission=permission,
        )
        if returncode == 0 and stdout.strip():
            parsed = parse_sesearch_output(stdout)
            existing_rules = parsed.total
    except Exception:
        pass

    resolution_options: list[str] = []
    if existing_rules > 0:
        resolution_options.append(f"Matching allow rules exist ({existing_rules}) — check if a boolean enables them")
    resolution_options.append(f"Check booleans: sesearch -b -s {source_type} -t {target_type} -c {tclass}")
    resolution_options.append("Verify file label: ls -Z on the target; restorecon if mislabeled")
    resolution_options.append("Custom module: audit2allow -M mypolicy < /var/log/audit/audit.log")

    explanation = SELinuxDenialExplanation(
        denial_summary=f"{source_type} denied {permission} on {target_type}:{tclass}",
        source_context=scontext,
        source_type=source_type,
        target_context=tcontext,
        target_type=target_type,
        denied_permission=permission,
        object_class=tclass,
        existing_rules=existing_rules,
        resolution_options=resolution_options,
    )
    return [TextContent(type="text", text=json.dumps(explanation.model_dump()))]


def _count_denial_patterns(stdout: str) -> dict[tuple[str, str, str, str], int]:
    """Deduplicate AVC denials by (source_type, target_type, permission, tclass)."""
    counts: dict[tuple[str, str, str, str], int] = {}
    for line in stdout.strip().splitlines():
        match = _AVC_PATTERN.search(line)
        if match:
            key = (
                _extract_type_from_context(match.group(2)),
                _extract_type_from_context(match.group(3)),
                match.group(1),
                match.group(4),
            )
            counts[key] = counts.get(key, 0) + 1
    return counts


async def _build_issue(
    host: Host, src: str, tgt: str, perm: str, tcls: str, count: int,
) -> SELinuxTroubleshootIssue:
    """Build a troubleshoot issue with resolution suggestions from sesearch."""
    resolution_options: list[str] = []
    try:
        sesearch_cmd = get_command("selinux_sesearch")
        rc, out, _ = await sesearch_cmd.run(host=host, source=src, target=tgt, tclass=tcls, permission=perm)
        if rc == 0 and out.strip():
            parsed = parse_sesearch_output(out)
            if parsed.total > 0:
                resolution_options.append(f"{parsed.total} matching rules — check boolean toggles")
    except Exception:
        pass
    resolution_options.append(f"Check booleans: sesearch -b -s {src} -t {tgt} -c {tcls}")
    resolution_options.append("Verify file labels with ls -Z; restorecon if mislabeled")
    return SELinuxTroubleshootIssue(
        source_type=src, target_type=tgt, permission=perm, object_class=tcls,
        count=count, resolution_options=resolution_options,
    )


@mcp.tool(
    title="Troubleshoot SELinux issues",
    description="Fetch recent AVC denials and analyze each one, providing a consolidated troubleshooting report "
    "with explanations and suggested resolutions for all current SELinux issues.",
    tags={"fixed", "selinux", "security", "diagnosis"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def troubleshoot_selinux(
    host: Host,
    lines: t.Annotated[int, Field(description="Number of recent log lines to check", ge=1, le=500)] = 50,
    since: t.Annotated[str | None, Field(description="Show entries since this time (e.g. '1 hour ago')")] = None,
) -> list[TextContent]:
    """Fetch recent denials and return a consolidated troubleshooting report."""
    selinux_mode = ""
    try:
        getenforce_cmd = get_command("selinux_status", "getenforce")
        returncode, stdout, _ = await getenforce_cmd.run(host=host)
        if returncode == 0:
            selinux_mode = stdout.strip()
    except Exception:
        pass

    denial_cmd = get_command("selinux_avc_denials")
    try:
        kwargs: dict[str, object] = {"lines": lines}
        if since:
            kwargs["since"] = since
        returncode, stdout, stderr = await denial_cmd.run(host=host, **kwargs)
    except Exception as e:
        raise ToolError(f"Error fetching denials for troubleshooting: {str(e)}") from e

    if returncode != 0 and "No entries" not in stderr:
        raise ToolError(f"Unable to fetch denials: {stderr}")

    issue_counts = _count_denial_patterns(stdout) if stdout.strip() else {}
    total_denials = sum(issue_counts.values())

    issues = [
        await _build_issue(host, src, tgt, perm, tcls, count)
        for (src, tgt, perm, tcls), count in issue_counts.items()
    ]

    report = SELinuxTroubleshootReport(
        selinux_mode=selinux_mode,
        total_denials=total_denials,
        unique_issues=len(issues),
        issues=issues,
    )
    return [TextContent(type="text", text=json.dumps(report.model_dump()))]
