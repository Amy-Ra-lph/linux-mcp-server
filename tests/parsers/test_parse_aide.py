# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""Tests for AIDE parsers."""

from linux_mcp_server.parsers import parse_aide_check
from linux_mcp_server.parsers import parse_aide_version


class TestParseAideCheck:
    def test_parses_changes(self):
        stdout = """\
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

        result = parse_aide_check(stdout)

        assert result.total_entries == 62150
        assert result.added == 2
        assert result.removed == 0
        assert result.changed == 1
        assert len(result.changes) == 3
        assert result.changes[0].path == "/etc/new-config.conf"
        assert result.changes[0].change_type == "added"
        assert result.changes[1].path == "/opt/app/new-binary"
        assert result.changes[1].change_type == "added"
        assert result.changes[2].path == "/etc/hosts"
        assert result.changes[2].change_type == "changed"

    def test_parses_no_changes(self):
        stdout = """\
AIDE found NO differences between database and filesystem. Looks okay!!

Summary:
  Total number of entries:\t62150
  Added entries:\t\t0
  Removed entries:\t\t0
  Changed entries:\t\t0"""

        result = parse_aide_check(stdout)

        assert result.total_entries == 62150
        assert result.added == 0
        assert result.removed == 0
        assert result.changed == 0
        assert result.changes == []

    def test_handles_empty_input(self):
        result = parse_aide_check("")

        assert result.total_entries == 0
        assert result.changes == []

    def test_parses_removed_entries(self):
        stdout = """\
Summary:
  Total number of entries:\t100
  Added entries:\t\t0
  Removed entries:\t\t1
  Changed entries:\t\t0

---------------------------------------------------
Removed entries:
---------------------------------------------------
f-----------: /etc/old-config.conf"""

        result = parse_aide_check(stdout)

        assert result.removed == 1
        assert len(result.changes) == 1
        assert result.changes[0].change_type == "removed"


class TestParseAideVersion:
    def test_parses_version(self):
        stdout = """\
Aide 0.16.1

Compiled with the following options:"""

        result = parse_aide_version(stdout)

        assert result == "0.16.1"

    def test_parses_version_number_only(self):
        result = parse_aide_version("0.18")

        assert result == "0.18"

    def test_handles_empty_input(self):
        result = parse_aide_version("")

        assert result == ""

    def test_handles_no_version_found(self):
        result = parse_aide_version("no version info here")

        assert result == ""
