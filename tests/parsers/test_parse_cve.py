# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""Tests for CVE/offline denial parsers."""

from linux_mcp_server.parsers import parse_avc_denial_line
from linux_mcp_server.parsers import parse_offline_denials


AVC_LINE = (
    'type=AVC msg=audit(1234567890.123:456): avc:  denied  { read } for  pid=1234 comm="httpd" '
    "name=\"index.html\" dev=\"sda1\" ino=12345 "
    "scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:user_home_t:s0 tclass=file permissive=0"
)


class TestParseAvcDenialLine:
    def test_valid_line_parsed(self):
        result = parse_avc_denial_line(AVC_LINE)

        assert result is not None
        assert result.permission == "read"
        assert result.source_context == "system_u:system_r:httpd_t:s0"
        assert result.target_context == "system_u:object_r:user_home_t:s0"
        assert result.target_class == "file"
        assert "denied" in result.raw_line

    def test_non_avc_line_returns_none(self):
        result = parse_avc_denial_line("Oct 10 14:23:02 host kernel: normal audit message")

        assert result is None

    def test_empty_line_returns_none(self):
        result = parse_avc_denial_line("")

        assert result is None


class TestParseOfflineDenials:
    def test_multiple_lines(self):
        connectto_line = (
            'type=AVC msg=audit(1234567890.124:457): avc:  denied  { connectto } for  pid=5678 comm="nginx" '
            'path="/var/run/php-fpm.sock" '
            "scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:system_r:php_fpm_t:s0 "
            "tclass=unix_stream_socket permissive=0"
        )
        raw_text = f"{AVC_LINE}\n{connectto_line}"

        result = parse_offline_denials(raw_text)

        assert result.total == 2
        assert result.denials[0].permission == "read"
        assert result.denials[1].permission == "connectto"
        assert result.denials[1].target_class == "unix_stream_socket"

    def test_empty_string(self):
        result = parse_offline_denials("")

        assert result.total == 0
        assert result.denials == []

    def test_no_avc_lines(self):
        result = parse_offline_denials("just some random text\nanother line\n")

        assert result.total == 0

    def test_mixed_content(self):
        raw_text = f"non-avc line\n{AVC_LINE}\nanother non-avc\n"

        result = parse_offline_denials(raw_text)

        assert result.total == 1
        assert result.denials[0].permission == "read"
