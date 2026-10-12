# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""Tests for fapolicyd parsers."""

from linux_mcp_server.parsers import parse_fapolicyd_status
from linux_mcp_server.parsers import parse_fapolicyd_trust_check


class TestParseFapolicydStatus:
    def test_parses_enforcing(self):
        stdout = """\
Permissive: 0
Trust db size: 89234
Rules:   2450"""

        result = parse_fapolicyd_status(stdout)

        assert result.active is True
        assert result.mode == "enforcing"
        assert result.rules_count == 2450
        assert result.trust_db_size == 89234

    def test_parses_permissive(self):
        stdout = """\
Permissive: 1
Trust db size: 12000
Rules:   100"""

        result = parse_fapolicyd_status(stdout)

        assert result.mode == "permissive"
        assert result.rules_count == 100
        assert result.trust_db_size == 12000

    def test_handles_empty_input(self):
        result = parse_fapolicyd_status("")

        assert result.active is False
        assert result.mode == ""

    def test_handles_missing_fields(self):
        stdout = "Permissive: 0"

        result = parse_fapolicyd_status(stdout)

        assert result.active is True
        assert result.mode == "enforcing"
        assert result.rules_count == 0
        assert result.trust_db_size == 0


class TestParseFapolicydTrustCheck:
    def test_trusted_with_source(self):
        stdout = "/usr/bin/bash is trusted (rpm)\n"

        result = parse_fapolicyd_trust_check(stdout, "/usr/bin/bash")

        assert result.trusted is True
        assert result.trust_source == "rpm"
        assert result.path == "/usr/bin/bash"

    def test_not_trusted(self):
        stdout = "/tmp/malware is not trusted\n"

        result = parse_fapolicyd_trust_check(stdout, "/tmp/malware")

        assert result.trusted is False
        assert result.trust_source == ""

    def test_trusted_file_source(self):
        stdout = "/opt/app/binary is trusted (file)\n"

        result = parse_fapolicyd_trust_check(stdout, "/opt/app/binary")

        assert result.trusted is True
        assert result.trust_source == "file"

    def test_handles_empty_output(self):
        result = parse_fapolicyd_trust_check("", "/some/path")

        assert result.trusted is False
