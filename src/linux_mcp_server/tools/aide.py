# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""AIDE integrity checking tools."""

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from linux_mcp_server.audit import log_tool_call
from linux_mcp_server.commands import get_command
from linux_mcp_server.commands import get_command_group
from linux_mcp_server.models import AIDECheckResult
from linux_mcp_server.models import AIDEStatus
from linux_mcp_server.parsers import parse_aide_check
from linux_mcp_server.parsers import parse_aide_version
from linux_mcp_server.server import mcp
from linux_mcp_server.utils.types import Host


@mcp.tool(
    title="Run AIDE integrity check",
    description="Run AIDE integrity check and return a summary of filesystem changes detected.",
    tags={"fixed", "aide", "security", "integrity"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_aide_check(
    host: Host,
) -> AIDECheckResult:
    """Run AIDE integrity check."""
    cmd = get_command("aide_check")

    try:
        returncode, stdout, stderr = await cmd.run(host=host)
    except Exception as e:
        raise ToolError(f"Error running AIDE check: {str(e)}") from e

    # aide --check returns non-zero when differences are found — that's expected
    if not stdout.strip() and returncode != 0:
        raise ToolError(f"Unable to run AIDE check: {stderr}")

    return parse_aide_check(stdout)


@mcp.tool(
    title="Get AIDE status",
    description="Check AIDE installation status, version, and whether the integrity database exists.",
    tags={"fixed", "aide", "security", "system"},
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def get_aide_status(
    host: Host,
) -> AIDEStatus:
    """Get AIDE installation and database status."""
    group = get_command_group("aide_status")

    installed = False
    version = ""
    database_exists = False

    for name, cmd in group.commands.items():
        try:
            returncode, stdout, _ = await cmd.run(host=host)
            if name == "version" and returncode == 0:
                installed = True
                version = parse_aide_version(stdout)
            elif name == "db_check":
                database_exists = returncode == 0
        except Exception as e:
            raise ToolError(f"Error checking AIDE status: {str(e)}") from e

    return AIDEStatus(installed=installed, version=version, database_exists=database_exists)
