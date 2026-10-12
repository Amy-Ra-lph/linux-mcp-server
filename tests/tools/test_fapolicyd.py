# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""Tests for fapolicyd tools."""

import pytest

from fastmcp import exceptions


@pytest.fixture
def mock_execute(mock_execute_with_fallback_for):
    return mock_execute_with_fallback_for("linux_mcp_server.commands")


FAPOLICYD_STATUS_OUTPUT = """\
Permissive: 0
Trust db size: 89234
Rules:   2450"""

FAPOLICYD_STATUS_PERMISSIVE = """\
Permissive: 1
Trust db size: 12000
Rules:   100"""


class TestGetFapolicydStatus:
    async def test_returns_enforcing_status(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, FAPOLICYD_STATUS_OUTPUT, "")

        result = await mcp_client.call_tool("get_fapolicyd_status", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["active"] is True
        assert result.structured_content["mode"] == "enforcing"
        assert result.structured_content["rules_count"] == 2450
        assert result.structured_content["trust_db_size"] == 89234

    async def test_returns_permissive_status(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, FAPOLICYD_STATUS_PERMISSIVE, "")

        result = await mcp_client.call_tool("get_fapolicyd_status", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["mode"] == "permissive"
        assert result.structured_content["rules_count"] == 100

    async def test_raises_on_unsuccessful_output(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "", "")

        with pytest.raises(exceptions.ToolError, match="Unable to retrieve fapolicyd status"):
            await mcp_client.call_tool("get_fapolicyd_status", {"host": "localhost"})

    async def test_raises_on_exception(self, mcp_client, mock_execute):
        mock_execute.side_effect = RuntimeError("Connection refused")

        with pytest.raises(exceptions.ToolError, match="Error gathering fapolicyd status"):
            await mcp_client.call_tool("get_fapolicyd_status", {"host": "localhost"})


class TestGetFapolicydTrustCheck:
    async def test_trusted_path(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "/usr/bin/bash is trusted (rpm)\n", "")

        result = await mcp_client.call_tool(
            "get_fapolicyd_trust_check", {"path": "/usr/bin/bash", "host": "localhost"}
        )

        assert result.structured_content is not None
        assert result.structured_content["path"] == "/usr/bin/bash"
        assert result.structured_content["trusted"] is True
        assert result.structured_content["trust_source"] == "rpm"

    async def test_untrusted_path(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "/tmp/malware is not trusted\n", "")

        result = await mcp_client.call_tool(
            "get_fapolicyd_trust_check", {"path": "/tmp/malware", "host": "localhost"}
        )

        assert result.structured_content is not None
        assert result.structured_content["trusted"] is False

    async def test_rejects_relative_path(self, mcp_client, mock_execute):
        with pytest.raises(exceptions.ToolError, match="Path must be absolute"):
            await mcp_client.call_tool(
                "get_fapolicyd_trust_check", {"path": "relative/path", "host": "localhost"}
            )

    async def test_rejects_path_traversal(self, mcp_client, mock_execute):
        with pytest.raises(exceptions.ToolError, match="Path contains invalid"):
            await mcp_client.call_tool(
                "get_fapolicyd_trust_check", {"path": "/usr/../etc/shadow", "host": "localhost"}
            )

    async def test_raises_on_unsuccessful_output(self, mcp_client, mock_execute):
        mock_execute.return_value = (1, "", "No such file")

        with pytest.raises(exceptions.ToolError, match="Unable to check fapolicyd trust"):
            await mcp_client.call_tool(
                "get_fapolicyd_trust_check", {"path": "/nonexistent", "host": "localhost"}
            )

    async def test_raises_on_exception(self, mcp_client, mock_execute):
        mock_execute.side_effect = RuntimeError("SSH failed")

        with pytest.raises(exceptions.ToolError, match="Error checking fapolicyd trust"):
            await mcp_client.call_tool(
                "get_fapolicyd_trust_check", {"path": "/usr/bin/bash", "host": "localhost"}
            )
