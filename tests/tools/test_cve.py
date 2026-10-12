# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""Tests for CVE exposure and offline denial parsing tools."""

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

RPM_OUTPUT = """\
bash-5.2.26-3.el10.x86_64
openssh-server-9.7p1-5.el10.x86_64
openssl-3.2.2-6.el10.x86_64"""

AVC_DENIAL_1 = (
    'type=AVC msg=audit(1234567890.123:456): avc:  denied  { read } for  pid=1234 comm="httpd" '
    "name=\"index.html\" dev=\"sda1\" ino=12345 "
    "scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:user_home_t:s0 tclass=file permissive=0"
)
AVC_DENIAL_2 = (
    'type=AVC msg=audit(1234567890.124:457): avc:  denied  { connectto } for  pid=5678 comm="nginx" '
    'path="/var/run/php-fpm.sock" '
    "scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:system_r:php_fpm_t:s0 "
    "tclass=unix_stream_socket permissive=0"
)


def create_mock_side_effect(command_responses: dict[str, str | Exception]):
    def side_effect(*args, **_kwargs):
        cmd = args[0][0]
        if response := command_responses.get(cmd):
            if isinstance(response, Exception):
                raise response
            return (0, response, "")
        return (0, "", "")

    return side_effect


class TestGetCveExposure:
    async def test_enforcing_returns_protected(self, mcp_client, mock_execute):
        mock_execute.side_effect = create_mock_side_effect({
            "rpm": RPM_OUTPUT,
            "getenforce": "Enforcing\n",
            "sestatus": SESTATUS_OUTPUT,
        })

        result = await mcp_client.call_tool("get_cve_exposure", {"cve_id": "CVE-2024-6387", "host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["cve_id"] == "CVE-2024-6387"
        assert result.structured_content["assessment"] == "protected"
        assert result.structured_content["selinux_mode"] == "enforcing"
        assert result.structured_content["installed_packages_checked"] == 3
        assert len(result.structured_content["policy_constraints"]) > 0

    async def test_permissive_returns_exposed(self, mcp_client, mock_execute):
        mock_execute.side_effect = create_mock_side_effect({
            "rpm": RPM_OUTPUT,
            "getenforce": "Permissive\n",
            "sestatus": "",
        })

        result = await mcp_client.call_tool("get_cve_exposure", {"cve_id": "CVE-2024-6387", "host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["assessment"] == "exposed"
        assert result.structured_content["selinux_mode"] == "permissive"

    async def test_invalid_cve_raises_error(self, mcp_client, mock_execute):
        with pytest.raises(exceptions.ToolError, match="Invalid CVE identifier"):
            await mcp_client.call_tool("get_cve_exposure", {"cve_id": "not-a-cve", "host": "localhost"})

    async def test_raises_on_exception(self, mcp_client, mock_execute):
        mock_execute.side_effect = RuntimeError("Connection refused")

        with pytest.raises(exceptions.ToolError, match="Error querying installed packages"):
            await mcp_client.call_tool("get_cve_exposure", {"cve_id": "CVE-2024-6387", "host": "localhost"})


class TestParseOfflineDenials:
    async def test_valid_denials_parsed(self, mcp_client, mock_execute):
        raw_text = f"{AVC_DENIAL_1}\n{AVC_DENIAL_2}"

        result = await mcp_client.call_tool("parse_offline_denials", {"raw_text": raw_text, "host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["total"] == 2
        assert result.structured_content["denials"][0]["permission"] == "read"
        assert result.structured_content["denials"][0]["source_context"] == "system_u:system_r:httpd_t:s0"
        assert result.structured_content["denials"][0]["target_context"] == "system_u:object_r:user_home_t:s0"
        assert result.structured_content["denials"][0]["target_class"] == "file"
        assert result.structured_content["denials"][1]["permission"] == "connectto"
        assert result.structured_content["denials"][1]["target_class"] == "unix_stream_socket"

    async def test_empty_text_returns_zero(self, mcp_client, mock_execute):
        result = await mcp_client.call_tool("parse_offline_denials", {"raw_text": "", "host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["total"] == 0
        assert result.structured_content["denials"] == []

    async def test_mixed_lines_only_parses_avc(self, mcp_client, mock_execute):
        raw_text = f"some random log line\n{AVC_DENIAL_1}\nanother non-avc line\n"

        result = await mcp_client.call_tool("parse_offline_denials", {"raw_text": raw_text, "host": "localhost"})

        assert result.structured_content is not None
        assert result.structured_content["total"] == 1
        assert result.structured_content["denials"][0]["permission"] == "read"
