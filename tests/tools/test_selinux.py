# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""Tests for SELinux tools."""

import pytest

from fastmcp import exceptions


@pytest.fixture
def mock_execute(mock_execute_with_fallback_for):
    return mock_execute_with_fallback_for("linux_mcp_server.commands")


SESTATUS_OUTPUT = """\
SELinux status:                 enabled
SELinuxfs mount:                /sys/fs/selinux
SELinux root directory:         /etc/selinux
Loaded policy name:             targeted
Current mode:                   enforcing
Mode from config file:          enforcing
Policy MLS status:              enabled
Policy deny_unknown status:     allowed
Memory protection checking:     actual (secure)
Max kernel policy version:      33"""

GETSEBOOL_OUTPUT = """\
abrt_anon_write --> off
httpd_can_network_connect --> on
allow_console_login --> on"""


def create_mock_side_effect(command_responses: dict[str, str | Exception]):
    def side_effect(*args, **_kwargs):
        cmd = args[0][0]
        if response := command_responses.get(cmd):
            if isinstance(response, Exception):
                raise response
            return (0, response, "")
        return (0, "", "")

    return side_effect


class TestGetSelinuxStatus:
    async def test_returns_enforcing_status(self, mcp_client, mock_execute):
        mock_execute.side_effect = create_mock_side_effect({
            "getenforce": "Enforcing\n",
            "sestatus": SESTATUS_OUTPUT,
        })

        result = await mcp_client.call_tool("get_selinux_status", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["mode"] == "enforcing"
        assert result.structured_content["policy"] == "targeted"
        assert result.structured_content["mls_status"] == "enabled"

    async def test_returns_getenforce_only_when_sestatus_fails(self, mcp_client, mock_execute):
        mock_execute.side_effect = create_mock_side_effect({
            "getenforce": "Enforcing\n",
            "sestatus": "",
        })

        result = await mcp_client.call_tool("get_selinux_status", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["mode"] == "Enforcing"

    async def test_raises_on_exception(self, mcp_client, mock_execute):
        mock_execute.side_effect = RuntimeError("Connection refused")

        with pytest.raises(exceptions.ToolError, match="Error gathering SELinux status"):
            await mcp_client.call_tool("get_selinux_status", {"host": "localhost"})

    async def test_returns_unknown_when_both_commands_fail(self, mcp_client, mock_execute):
        mock_execute.return_value = (1, "", "command not found")

        result = await mcp_client.call_tool("get_selinux_status", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["mode"] == "unknown"


class TestGetSelinuxBooleans:
    async def test_returns_booleans(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, GETSEBOOL_OUTPUT, "")

        result = await mcp_client.call_tool("get_selinux_booleans", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["total"] == 3
        assert result.structured_content["booleans"][0]["name"] == "abrt_anon_write"

    async def test_raises_on_unsuccessful_output(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "", "")

        with pytest.raises(exceptions.ToolError, match="Unable to retrieve SELinux booleans"):
            await mcp_client.call_tool("get_selinux_booleans", {"host": "localhost"})

    async def test_raises_on_exception(self, mcp_client, mock_execute):
        mock_execute.side_effect = RuntimeError("SSH failed")

        with pytest.raises(exceptions.ToolError, match="Error gathering SELinux booleans"):
            await mcp_client.call_tool("get_selinux_booleans", {"host": "localhost"})


class TestGetSelinuxFileContext:
    async def test_returns_file_context(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "system_u:object_r:etc_t:s0 /etc/passwd", "")

        result = await mcp_client.call_tool(
            "get_selinux_file_context", {"path": "/etc/passwd", "host": "localhost"}
        )

        assert result.structured_content is not None
        assert result.structured_content["context"] == "system_u:object_r:etc_t:s0"
        assert result.structured_content["path"] == "/etc/passwd"

    async def test_rejects_relative_path(self, mcp_client, mock_execute):
        with pytest.raises(exceptions.ToolError, match="Path must be absolute"):
            await mcp_client.call_tool(
                "get_selinux_file_context", {"path": "relative/path", "host": "localhost"}
            )

    async def test_rejects_path_traversal(self, mcp_client, mock_execute):
        with pytest.raises(exceptions.ToolError, match="Path contains invalid"):
            await mcp_client.call_tool(
                "get_selinux_file_context", {"path": "/etc/../shadow", "host": "localhost"}
            )

    async def test_raises_on_unsuccessful_output(self, mcp_client, mock_execute):
        mock_execute.return_value = (1, "", "No such file or directory")

        with pytest.raises(exceptions.ToolError, match="Unable to get SELinux context"):
            await mcp_client.call_tool(
                "get_selinux_file_context", {"path": "/nonexistent", "host": "localhost"}
            )

    async def test_raises_on_exception(self, mcp_client, mock_execute):
        mock_execute.side_effect = RuntimeError("SSH failed")

        with pytest.raises(exceptions.ToolError, match="Error getting SELinux context"):
            await mcp_client.call_tool(
                "get_selinux_file_context", {"path": "/etc/passwd", "host": "localhost"}
            )


class TestGetSelinuxDenials:
    async def test_returns_denials(self, mcp_client, mock_execute):
        denial_output = (
            "Oct 10 14:23:01 host audit[1234]: AVC avc:  denied  { read } for  pid=5678 "
            "comm=\"httpd\" scontext=system_u:system_r:httpd_t:s0\n"
            "Oct 10 14:23:02 host kernel: non-avc audit message\n"
        )
        mock_execute.return_value = (0, denial_output, "")

        result = await mcp_client.call_tool("get_selinux_denials", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["total"] == 1
        assert "denied" in result.structured_content["denials"][0]["raw"]

    async def test_returns_empty_when_no_denials(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "", "")

        result = await mcp_client.call_tool("get_selinux_denials", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["total"] == 0

    async def test_handles_no_entries_stderr(self, mcp_client, mock_execute):
        mock_execute.return_value = (1, "", "No entries")

        result = await mcp_client.call_tool("get_selinux_denials", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["total"] == 0

    async def test_accepts_since_parameter(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "", "")

        result = await mcp_client.call_tool(
            "get_selinux_denials", {"since": "1 hour ago", "host": "localhost"}
        )

        assert result.structured_content is not None

    async def test_raises_on_exception(self, mcp_client, mock_execute):
        mock_execute.side_effect = RuntimeError("Connection refused")

        with pytest.raises(exceptions.ToolError, match="Error retrieving SELinux denials"):
            await mcp_client.call_tool("get_selinux_denials", {"host": "localhost"})

    async def test_raises_on_real_error(self, mcp_client, mock_execute):
        mock_execute.return_value = (1, "", "Permission denied")

        with pytest.raises(exceptions.ToolError, match="Unable to retrieve SELinux denials"):
            await mcp_client.call_tool("get_selinux_denials", {"host": "localhost"})


class TestGetSelinuxPorts:
    async def test_returns_port_types(self, mcp_client, mock_execute):
        port_output = """\
SELinux Port Type              Proto    Port Number

http_port_t                    tcp      80, 81, 443, 8008, 8009, 8443
ssh_port_t                     tcp      22"""
        mock_execute.return_value = (0, port_output, "")

        result = await mcp_client.call_tool("get_selinux_ports", {"host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["total"] == 2
        assert result.structured_content["ports"][0]["type"] == "http_port_t"

    async def test_raises_on_unsuccessful_output(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "", "")

        with pytest.raises(exceptions.ToolError, match="Unable to retrieve SELinux port types"):
            await mcp_client.call_tool("get_selinux_ports", {"host": "localhost"})

    async def test_raises_on_exception(self, mcp_client, mock_execute):
        mock_execute.side_effect = RuntimeError("Command failed")

        with pytest.raises(exceptions.ToolError, match="Error retrieving SELinux port types"):
            await mcp_client.call_tool("get_selinux_ports", {"host": "localhost"})


SESEARCH_TOOL_OUTPUT = """\
allow httpd_t httpd_config_t:file { getattr ioctl lock open read };
allow httpd_t http_port_t:tcp_socket { name_bind name_connect };"""


class TestGetSelinuxPolicyRules:
    async def test_returns_policy_rules(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, SESEARCH_TOOL_OUTPUT, "")

        result = await mcp_client.call_tool(
            "get_selinux_policy_rules", {"source": "httpd_t", "host": "localhost"}
        )

        assert result.structured_content is not None
        assert result.structured_content["total"] == 2
        assert result.structured_content["rules"][0]["source"] == "httpd_t"

    async def test_passes_all_filters(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, SESEARCH_TOOL_OUTPUT, "")

        result = await mcp_client.call_tool(
            "get_selinux_policy_rules",
            {
                "source": "httpd_t",
                "target": "httpd_config_t",
                "tclass": "file",
                "permission": "read",
                "host": "localhost",
            },
        )

        assert result.structured_content is not None

    async def test_returns_empty_when_no_rules(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "Found 0 semantic av rules.", "")

        result = await mcp_client.call_tool(
            "get_selinux_policy_rules", {"source": "nonexistent_t", "host": "localhost"}
        )

        assert result.structured_content is not None
        assert result.structured_content["total"] == 0

    async def test_raises_on_unsuccessful_output(self, mcp_client, mock_execute):
        mock_execute.return_value = (1, "", "sesearch: command not found")

        with pytest.raises(exceptions.ToolError, match="Unable to query SELinux policy"):
            await mcp_client.call_tool(
                "get_selinux_policy_rules", {"source": "httpd_t", "host": "localhost"}
            )

    async def test_raises_on_exception(self, mcp_client, mock_execute):
        mock_execute.side_effect = RuntimeError("Connection refused")

        with pytest.raises(exceptions.ToolError, match="Error querying SELinux policy"):
            await mcp_client.call_tool(
                "get_selinux_policy_rules", {"source": "httpd_t", "host": "localhost"}
            )

    async def test_boolean_filter(self, mcp_client, mock_execute):
        boolean_output = (
            "allow httpd_t http_cache_port_t:tcp_socket { name_connect };"
            " [ httpd_can_network_connect ]:True"
        )
        mock_execute.return_value = (0, boolean_output, "")

        result = await mcp_client.call_tool(
            "get_selinux_policy_rules",
            {"boolean": "httpd_can_network_connect", "host": "localhost"},
        )

        assert result.structured_content is not None
        assert result.structured_content["total"] == 1
        assert result.structured_content["rules"][0]["conditional"] == "httpd_can_network_connect"


class TestGenerateSelinuxPlaybook:
    async def test_generates_boolean_playbook(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "", "")

        result = await mcp_client.call_tool(
            "generate_selinux_playbook",
            {
                "findings": [
                    {"type": "boolean", "name": "httpd_can_network_connect", "desired_state": "on"}
                ],
                "host": "localhost",
            },
        )

        assert len(result.content) > 0
        text = result.content[0].text
        assert "httpd_can_network_connect" in text
        assert "seboolean" in text

    async def test_generates_file_context_playbook(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "", "")

        result = await mcp_client.call_tool(
            "generate_selinux_playbook",
            {
                "findings": [
                    {"type": "file_context", "path": "/var/www/custom", "expected_context": "httpd_sys_content_t"}
                ],
                "host": "localhost",
            },
        )

        assert len(result.content) > 0
        text = result.content[0].text
        assert "restorecon" in text
        assert "sefcontext" in text

    async def test_generates_denial_with_boolean_fix(self, mcp_client, mock_execute):
        sesearch_output = (
            "allow httpd_t http_cache_port_t:tcp_socket { name_connect };"
            " [ httpd_can_network_connect ]:True"
        )
        mock_execute.return_value = (0, sesearch_output, "")

        result = await mcp_client.call_tool(
            "generate_selinux_playbook",
            {
                "findings": [
                    {
                        "type": "denial",
                        "source_type": "httpd_t",
                        "target_type": "http_cache_port_t",
                        "permission": "name_connect",
                        "tclass": "tcp_socket",
                    }
                ],
                "host": "localhost",
            },
        )

        assert len(result.content) > 0
        text = result.content[0].text
        assert "httpd_can_network_connect" in text

    async def test_generates_denial_with_cil_module(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "Found 0 semantic av rules.", "")

        result = await mcp_client.call_tool(
            "generate_selinux_playbook",
            {
                "findings": [
                    {
                        "type": "denial",
                        "source_type": "httpd_t",
                        "target_type": "user_home_t",
                        "permission": "read",
                        "tclass": "file",
                    }
                ],
                "host": "localhost",
            },
        )

        assert len(result.content) > 0
        text = result.content[0].text
        assert "semodule" in text
        assert "cil" in text.lower()

    async def test_rejects_empty_findings(self, mcp_client, mock_execute):
        with pytest.raises(exceptions.ToolError, match="No findings"):
            await mcp_client.call_tool(
                "generate_selinux_playbook",
                {"findings": [], "host": "localhost"},
            )

    async def test_rejects_invalid_finding_type(self, mcp_client, mock_execute):
        with pytest.raises(exceptions.ToolError, match="Unknown finding type"):
            await mcp_client.call_tool(
                "generate_selinux_playbook",
                {
                    "findings": [{"type": "invalid_type"}],
                    "host": "localhost",
                },
            )

    async def test_rejects_invalid_boolean_name(self, mcp_client, mock_execute):
        with pytest.raises(exceptions.ToolError, match="Invalid"):
            await mcp_client.call_tool(
                "generate_selinux_playbook",
                {
                    "findings": [
                        {"type": "boolean", "name": "$(evil)", "desired_state": "on"}
                    ],
                    "host": "localhost",
                },
            )

    async def test_multiple_findings(self, mcp_client, mock_execute):
        mock_execute.return_value = (0, "", "")

        result = await mcp_client.call_tool(
            "generate_selinux_playbook",
            {
                "findings": [
                    {"type": "boolean", "name": "httpd_can_network_connect", "desired_state": "on"},
                    {"type": "file_context", "path": "/var/www/custom", "expected_context": "httpd_sys_content_t"},
                ],
                "host": "localhost",
            },
        )

        assert len(result.content) > 0
        text = result.content[0].text
        assert "httpd_can_network_connect" in text
        assert "restorecon" in text
