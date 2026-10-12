# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""fapolicyd application whitelisting tools."""

import typing as t

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from linux_mcp_server.audit import log_tool_call
from linux_mcp_server.commands import get_command
from linux_mcp_server.models import FapolicydStatus
from linux_mcp_server.models import FapolicydTrustCheck
from linux_mcp_server.parsers import parse_fapolicyd_status
from linux_mcp_server.parsers import parse_fapolicyd_trust_check
from linux_mcp_server.server import mcp
from linux_mcp_server.utils.types import Host
from linux_mcp_server.utils.validation import is_successful_output
from linux_mcp_server.utils.validation import validate_path


@mcp.tool(
    title="Get fapolicyd status",
    description="Get fapolicyd daemon status including enforcement mode, rule count, and trust database size.",
    tags={"fixed", "fapolicyd", "security", "system"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_fapolicyd_status(
    host: Host,
) -> FapolicydStatus:
    """Get fapolicyd daemon status."""
    cmd = get_command("fapolicyd_status")

    try:
        returncode, stdout, stderr = await cmd.run(host=host)
    except Exception as e:
        raise ToolError(f"Error gathering fapolicyd status: {str(e)}") from e

    if not is_successful_output(returncode, stdout):
        raise ToolError(f"Unable to retrieve fapolicyd status: {stderr}")

    return parse_fapolicyd_status(stdout)


@mcp.tool(
    title="Check fapolicyd trust",
    description="Check whether a file path is trusted by fapolicyd.",
    tags={"fixed", "fapolicyd", "security", "filesystem"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_fapolicyd_trust_check(
    path: t.Annotated[str, Field(description="Absolute path to check for trust status")],
    host: Host,
) -> FapolicydTrustCheck:
    """Check if a path is trusted by fapolicyd."""
    validate_path(path)
    cmd = get_command("fapolicyd_check_path")

    try:
        returncode, stdout, stderr = await cmd.run(host=host, path=path)
    except Exception as e:
        raise ToolError(f"Error checking fapolicyd trust for {path}: {str(e)}") from e

    if not is_successful_output(returncode, stdout):
        raise ToolError(f"Unable to check fapolicyd trust for {path}: {stderr}")

    return parse_fapolicyd_trust_check(stdout, path)
