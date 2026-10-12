# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""CVE exposure assessment and offline AVC denial parsing tools."""

from __future__ import annotations

import re
import typing as t

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from linux_mcp_server.audit import log_tool_call
from linux_mcp_server.commands import get_command
from linux_mcp_server.commands import get_command_group
from linux_mcp_server.models import CVEExposure
from linux_mcp_server.models import OfflineDenials
from linux_mcp_server.models import SELinuxStatus
from linux_mcp_server.parsers import parse_offline_denials as _parse_offline_denials
from linux_mcp_server.parsers import parse_sestatus
from linux_mcp_server.server import mcp
from linux_mcp_server.utils.types import Host
from linux_mcp_server.utils.validation import is_successful_output


_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

_CONSTRAINT_FIELDS = ("policy", "mls_status", "policy_deny_unknown", "memory_protection")
_CONSTRAINT_LABELS = ("policy", "mls", "deny_unknown", "memory_protection")


def _extract_constraints(status: SELinuxStatus) -> list[str]:
    constraints: list[str] = []
    for attr, label in zip(_CONSTRAINT_FIELDS, _CONSTRAINT_LABELS):
        value = getattr(status, attr, "")
        if value:
            constraints.append(f"{label}={value}")
    return constraints


async def _query_selinux(host: Host) -> tuple[str, list[str]]:
    group = get_command_group("selinux_status")
    mode = "unknown"
    constraints: list[str] = []

    for name, cmd in group.commands.items():
        rc, out, _ = await cmd.run(host=host)
        if not is_successful_output(rc, out):
            continue
        if name == "getenforce":
            mode = out.strip().lower()
        elif name == "sestatus":
            status = parse_sestatus(out)
            if status.mode:
                mode = status.mode.lower()
            constraints = _extract_constraints(status)

    return mode, constraints


@mcp.tool(
    title="Get CVE Exposure Assessment",
    description="Assess whether a CVE is exploitable given current SELinux policy. Checks installed packages "
    "and maps CVE attack chain against enforced policy rules.",
    tags={"fixed", "cve", "selinux", "security", "assessment"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_cve_exposure(
    cve_id: t.Annotated[str, Field(description="CVE identifier (e.g. CVE-2024-6387)")],
    host: Host,
) -> CVEExposure:
    """Assess CVE exploitability given current SELinux policy."""
    if not _CVE_PATTERN.match(cve_id):
        raise ToolError(f"Invalid CVE identifier: {cve_id}. Expected format: CVE-YYYY-NNNNN")

    cmd = get_command("cve_rpm_query")
    try:
        returncode, stdout, _ = await cmd.run(host=host)
    except Exception as e:
        raise ToolError(f"Error querying installed packages: {e}") from e

    package_count = len(stdout.strip().splitlines()) if is_successful_output(returncode, stdout) else 0

    try:
        selinux_mode, policy_constraints = await _query_selinux(host)
    except Exception as e:
        raise ToolError(f"Error gathering SELinux status: {e}") from e

    assessment = "protected" if selinux_mode == "enforcing" else "exposed"

    return CVEExposure(
        cve_id=cve_id,
        selinux_mode=selinux_mode,
        assessment=assessment,
        installed_packages_checked=package_count,
        policy_constraints=policy_constraints,
    )


@mcp.tool(
    title="Parse Offline AVC Denials",
    description="Parse raw AVC denial messages from logs or audit files without requiring host access. "
    "Accepts plain text containing AVC denial lines and returns structured denial records.",
    tags={"fixed", "selinux", "security", "offline", "parsing"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def parse_offline_denials(
    raw_text: t.Annotated[str, Field(description="Raw text containing AVC denial lines from audit logs")],
    host: Host,
) -> OfflineDenials:
    """Parse raw AVC denial text into structured denial records."""
    return _parse_offline_denials(raw_text)
