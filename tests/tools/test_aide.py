# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""Tests for AIDE tools."""

import pytest

from fastmcp import exceptions


@pytest.fixture
def mock_execute(mock_execute_with_fallback_for):
    return mock_execute_with_fallback_for("linux_mcp_server.commands")


AIDE_CHECK_OUTPUT = """\
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:\t62150
  Added entries:\t\t2
  Removed entries:\t\t0
  Changed entries:\t\t1

---------------------------------------------------
Added entries:
---------------------------------------------------
f++++++++++++++++: /etc/new-config.conf
f++++++++++++++++: /opt/app/new-binary

---------------------------------------------------
Changed entries:
---------------------------------------------------
f =.... mc.. .. : /etc/hosts"""

AIDE_CHECK_NO_CHANGES = """\
AIDE found NO differences between database and filesystem. Looks okay!!

Summary:
  Total number of entries:\t62150
  Added entries:\t\t0
  Removed entries:\t\t0
  Changed entries:\t\t0"""

AIDE_VERSION_OUTPUT = """\
Aide 0.16.1

Compiled with the following options:

WITH_MHASH
WITH_ZLIB"""


def create_mock_side_effect(command_responses: dict[str, str | tuple[int, str, str]]):
    def side_effect(*args, **_kwargs):
        cmd = args[0][0]
        if response := command_responses.get(cmd):
            if isinstance(response, tuple):
                return response
            return (0, response, "")
        return (0, "", "")

    return side_effect


class TestGetAideCheck:
    async def test_returns_changes(self, mcp_client, mock_execute):
        mock_execute.return_value = (1, AIDE_CHECK_OUTPUT, "")

        result = await mcp_client.call_tool("get_aide_check", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["total_entries"] == 62150
        assert result.structured_content["added"] == 2
        assert result.structured_content["removed"] == 0
        assert result.structured_content["changed"] == 1
        assert len(result.structured_content["changes"]) == 3
        assert result.structured_content["changes"][0]["path"] == "/etc/new-config.conf"
        assert result.structured_content["changes"][0]["change_type"] == "added"
        assert result.structured_content["changes"][2]["path"] == "/etc/hosts"
        assert result.structured_content["changes"][2]["change_type"] == "changed"

    async def test_returns_no_changes(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, AIDE_CHECK_NO_CHANGES, "")

        result = await mcp_client.call_tool("get_aide_check", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["added"] == 0
        assert result.structured_content["changed"] == 0
        assert result.structured_content["changes"] == []

    async def test_raises_on_empty_error(self, mcp_client, mock_execute):
        mock_execute.return_value = (1, "", "aide: command not found")

        with pytest.raises(exceptions.ToolError, match="Unable to run AIDE check"):
            await mcp_client.call_tool("get_aide_check", {"host": "localhost"})

    async def test_raises_on_exception(self, mcp_client, mock_execute):
        mock_execute.side_effect = RuntimeError("SSH failed")

        with pytest.raises(exceptions.ToolError, match="Error running AIDE check"):
            await mcp_client.call_tool("get_aide_check", {"host": "localhost"})


class TestGetAideStatus:
    async def test_installed_with_database(self, mcp_client, mock_execute):
        mock_execute.side_effect = create_mock_side_effect({
            "aide": AIDE_VERSION_OUTPUT,
            "test": (0, "", ""),
        })

        result = await mcp_client.call_tool("get_aide_status", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["installed"] is True
        assert result.structured_content["version"] == "0.16.1"
        assert result.structured_content["database_exists"] is True

    async def test_installed_without_database(self, mcp_client, mock_execute):
        mock_execute.side_effect = create_mock_side_effect({
            "aide": AIDE_VERSION_OUTPUT,
            "test": (1, "", ""),
        })

        result = await mcp_client.call_tool("get_aide_status", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["installed"] is True
        assert result.structured_content["database_exists"] is False

    async def test_not_installed(self, mcp_client, mock_execute):
        mock_execute.side_effect = create_mock_side_effect({
            "aide": (1, "", "command not found"),
            "test": (1, "", ""),
        })

        result = await mcp_client.call_tool("get_aide_status", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["installed"] is False
        assert result.structured_content["version"] == ""

    async def test_raises_on_exception(self, mcp_client, mock_execute):
        mock_execute.side_effect = RuntimeError("Connection refused")

        with pytest.raises(exceptions.ToolError, match="Error checking AIDE status"):
            await mcp_client.call_tool("get_aide_status", {"host": "localhost"})
