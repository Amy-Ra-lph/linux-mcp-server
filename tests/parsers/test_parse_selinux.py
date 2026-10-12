# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""Tests for SELinux parsers."""

import pytest

from linux_mcp_server.parsers import parse_selinux_booleans
from linux_mcp_server.parsers import parse_selinux_denials
from linux_mcp_server.parsers import parse_selinux_file_context
from linux_mcp_server.parsers import parse_selinux_ports
from linux_mcp_server.parsers import parse_sesearch_output
from linux_mcp_server.parsers import parse_sestatus


class TestParseSestatus:
    def test_parses_enforcing_status(self):
        stdout = """\
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

        result = parse_sestatus(stdout)

        assert result.mode == "enforcing"
        assert result.policy == "targeted"
        assert result.mls_status == "enabled"
        assert result.policy_deny_unknown == "allowed"
        assert result.memory_protection == "actual (secure)"
        assert result.max_kernel_policy_version == "33"

    def test_parses_permissive_status(self):
        stdout = """\
SELinux status:                 enabled
Current mode:                   permissive
Loaded policy name:             targeted
Policy MLS status:              enabled"""

        result = parse_sestatus(stdout)

        assert result.mode == "permissive"
        assert result.policy == "targeted"

    def test_parses_disabled_status(self):
        stdout = "SELinux status:                 disabled"

        result = parse_sestatus(stdout)

        assert result.mode == ""
        assert result.policy == ""

    def test_handles_empty_input(self):
        result = parse_sestatus("")
        assert result.mode == ""

    def test_uses_policy_from_config_as_fallback(self):
        stdout = """\
SELinux status:                 enabled
Current mode:                   enforcing
Policy from config:             mls"""

        result = parse_sestatus(stdout)
        assert result.policy == "mls"


class TestParseSelinuxBooleans:
    def test_parses_booleans(self):
        stdout = """\
abrt_anon_write --> off
abrt_handle_event --> off
allow_console_login --> on
httpd_can_network_connect --> on"""

        result = parse_selinux_booleans(stdout)

        assert result.total == 4
        assert result.booleans[0].name == "abrt_anon_write"
        assert result.booleans[0].state == "off"
        assert result.booleans[3].name == "httpd_can_network_connect"
        assert result.booleans[3].state == "on"

    def test_handles_empty_input(self):
        result = parse_selinux_booleans("")
        assert result.total == 0
        assert result.booleans == []

    def test_skips_malformed_lines(self):
        stdout = """\
valid_bool --> on
not a valid line
another_bool --> off"""

        result = parse_selinux_booleans(stdout)
        assert result.total == 2


class TestParseSelinuxFileContext:
    def test_parses_file_context(self):
        stdout = "system_u:object_r:etc_t:s0 /etc/passwd"

        result = parse_selinux_file_context(stdout)

        assert result.context == "system_u:object_r:etc_t:s0"
        assert result.path == "/etc/passwd"

    def test_parses_directory_context(self):
        stdout = "system_u:object_r:var_log_t:s0 /var/log"

        result = parse_selinux_file_context(stdout)

        assert result.context == "system_u:object_r:var_log_t:s0"
        assert result.path == "/var/log"

    def test_handles_context_only(self):
        stdout = "unlabeled_t"

        result = parse_selinux_file_context(stdout)

        assert result.path == "unlabeled_t"
        assert result.context == ""


class TestParseSelinuxDenials:
    def test_parses_avc_denials(self):
        stdout = """\
Oct 10 14:23:01 host audit[1234]: AVC avc:  denied  { read } for  pid=5678 comm="httpd" name="index.html" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:user_home_t:s0
Oct 10 14:23:02 host kernel: audit: non-avc message
Oct 10 14:23:03 host audit[1235]: AVC avc:  denied  { write } for  pid=5679 comm="nginx" scontext=system_u:system_r:httpd_t:s0"""

        result = parse_selinux_denials(stdout)

        assert result.total == 2
        assert "denied" in result.denials[0].raw
        assert "httpd" in result.denials[0].raw

    def test_handles_no_denials(self):
        stdout = """\
Oct 10 14:23:01 host kernel: audit: some other message
Oct 10 14:23:02 host systemd[1]: Starting service"""

        result = parse_selinux_denials(stdout)
        assert result.total == 0

    def test_handles_empty_input(self):
        result = parse_selinux_denials("")
        assert result.total == 0
        assert result.denials == []


class TestParseSelinuxPorts:
    def test_parses_port_listing(self):
        stdout = """\
SELinux Port Type              Proto    Port Number

http_port_t                    tcp      80, 81, 443, 488, 8008, 8009, 8443, 9000
ssh_port_t                     tcp      22
dns_port_t                     tcp      53
dns_port_t                     udp      53"""

        result = parse_selinux_ports(stdout)

        assert result.total == 4
        assert result.ports[0].type == "http_port_t"
        assert result.ports[0].protocol == "tcp"
        assert "80" in result.ports[0].ports
        assert result.ports[1].type == "ssh_port_t"

    def test_handles_empty_input(self):
        result = parse_selinux_ports("")
        assert result.total == 0

    def test_skips_header_and_separator(self):
        stdout = """\
SELinux Port Type              Proto    Port Number
---------------------------------------------------------
http_port_t                    tcp      80, 443"""

        result = parse_selinux_ports(stdout)
        assert result.total == 1
        assert result.ports[0].type == "http_port_t"


SESEARCH_OUTPUT = """\
allow httpd_t httpd_config_t:file { getattr ioctl lock open read };
allow httpd_t httpd_log_t:file { append create getattr ioctl lock open read write };
allow httpd_t http_port_t:tcp_socket { name_bind name_connect };
allow httpd_t self:capability { dac_override setgid setuid };"""

SESEARCH_WITH_BOOLEAN = """\
allow httpd_t http_cache_port_t:tcp_socket { name_bind name_connect }; [ httpd_can_network_connect ]:True
allow httpd_t smtp_port_t:tcp_socket { name_connect }; [ httpd_can_sendmail ]:True"""

SESEARCH_EMPTY = "Found 0 semantic av rules."


class TestParseSesearchOutput:
    def test_parses_allow_rules(self):
        result = parse_sesearch_output(SESEARCH_OUTPUT)
        assert result.total == 4
        assert result.rules[0].source == "httpd_t"
        assert result.rules[0].target == "httpd_config_t"
        assert result.rules[0].tclass == "file"
        assert "read" in result.rules[0].permissions
        assert "open" in result.rules[0].permissions

    def test_parses_conditional_rules(self):
        result = parse_sesearch_output(SESEARCH_WITH_BOOLEAN)
        assert result.total == 2
        assert result.rules[0].conditional == "httpd_can_network_connect"
        assert result.rules[1].conditional == "httpd_can_sendmail"

    def test_handles_empty_output(self):
        result = parse_sesearch_output(SESEARCH_EMPTY)
        assert result.total == 0
        assert result.rules == []

    def test_handles_blank_input(self):
        result = parse_sesearch_output("")
        assert result.total == 0

    def test_extracts_permissions_list(self):
        result = parse_sesearch_output(SESEARCH_OUTPUT)
        rule = result.rules[0]
        assert rule.permissions == ["getattr", "ioctl", "lock", "open", "read"]

    def test_rule_type_is_allow(self):
        result = parse_sesearch_output(SESEARCH_OUTPUT)
        for rule in result.rules:
            assert rule.rule_type == "allow"
