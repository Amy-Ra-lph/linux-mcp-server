# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""Tests for hardened parser wrapper."""

from unittest.mock import patch

import pytest

import linux_mcp_server.hardened_parsers as hp

from linux_mcp_server.hardened_parsers import parse_selinux_booleans
from linux_mcp_server.hardened_parsers import parse_selinux_ports
from linux_mcp_server.hardened_parsers import parse_sestatus


SESTATUS_OUTPUT = """\
SELinux status:                 enabled
Current mode:                   enforcing
Loaded policy name:             targeted
Policy MLS status:              enabled"""

GETSEBOOL_OUTPUT = """\
httpd_can_network_connect --> on
allow_console_login --> off"""

SEMANAGE_OUTPUT = """\
SELinux Port Type              Proto    Port Number

http_port_t                    tcp      80, 443"""


class TestHardenedParsers:
    def test_parse_sestatus(self):
        result = parse_sestatus(SESTATUS_OUTPUT)
        assert result.mode == "enforcing"
        assert result.policy == "targeted"

    def test_parse_selinux_booleans(self):
        result = parse_selinux_booleans(GETSEBOOL_OUTPUT)
        assert result.total == 2
        assert result.booleans[0].name == "httpd_can_network_connect"

    def test_parse_selinux_ports(self):
        result = parse_selinux_ports(SEMANAGE_OUTPUT)
        assert result.total == 1

    def test_hardened_flag_set_when_library_installed(self):
        assert hp.HARDENED is True

    def test_null_byte_rejected(self):
        with pytest.raises(ValueError, match="null bytes"):
            parse_sestatus("SELinux status: enabled\x00injected")

    def test_validate_called_when_hardened(self):
        with patch.object(hp, "_validate", wraps=hp._validate) as mock_validate:
            parse_sestatus(SESTATUS_OUTPUT)
            mock_validate.assert_called_once_with(SESTATUS_OUTPUT, "parse_sestatus")

    def test_falls_back_without_hardening(self):
        with patch.object(hp, "HARDENED", False):
            result = parse_sestatus(SESTATUS_OUTPUT)
            assert result.mode == "enforcing"

    def test_null_bytes_pass_without_hardening(self):
        with patch.object(hp, "HARDENED", False):
            result = hp.parse_selinux_denials("no denials here\x00\n")
            assert result.total == 0
