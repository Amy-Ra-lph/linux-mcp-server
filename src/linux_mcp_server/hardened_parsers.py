# Copyright Contributors to the linux-mcp-server project
# SPDX-License-Identifier: Apache-2.0
"""Optional hardened parser backend using enforcement-mcp-parsers.

When the ``hardened-parsers`` extra is installed, this module provides
input validation (10 MB size limit, null-byte rejection) on all parser
inputs before delegating to the standard parsers. This defends against
crafted output from compromised remote hosts.

Install with::

    pip install linux-mcp-server[hardened-parsers]

When not installed, all functions fall back to the standard parsers
with no validation overhead.
"""

from __future__ import annotations

import logging

from linux_mcp_server.models import SELinuxBooleans
from linux_mcp_server.models import SELinuxDenials
from linux_mcp_server.models import SELinuxFileContext
from linux_mcp_server.models import SELinuxPorts
from linux_mcp_server.models import SELinuxStatus
from linux_mcp_server.parsers import parse_selinux_booleans as _parse_selinux_booleans
from linux_mcp_server.parsers import parse_selinux_denials as _parse_selinux_denials
from linux_mcp_server.parsers import parse_selinux_file_context as _parse_selinux_file_context
from linux_mcp_server.parsers import parse_selinux_ports as _parse_selinux_ports
from linux_mcp_server.parsers import parse_sestatus as _parse_sestatus


logger = logging.getLogger("linux-mcp-server")

try:
    from enforcement_mcp_parsers.parsers._hardening import validate_input_size

    HARDENED = True
    logger.info("Hardened parser backend active (enforcement-mcp-parsers)")
except ImportError:
    HARDENED = False


def _validate(raw: str, name: str) -> None:
    """Validate input size and reject null bytes when hardened backend is available."""
    if not HARDENED:
        return
    validate_input_size(raw, name)
    if "\x00" in raw:
        raise ValueError(f"{name}: input contains null bytes")


def parse_sestatus(stdout: str) -> SELinuxStatus:
    """Parse sestatus output with optional input hardening."""
    _validate(stdout, "parse_sestatus")
    return _parse_sestatus(stdout)


def parse_selinux_booleans(stdout: str) -> SELinuxBooleans:
    """Parse getsebool -a output with optional input hardening."""
    _validate(stdout, "parse_selinux_booleans")
    return _parse_selinux_booleans(stdout)


def parse_selinux_file_context(stdout: str) -> SELinuxFileContext:
    """Parse ls -1dZ output with optional input hardening."""
    _validate(stdout, "parse_selinux_file_context")
    return _parse_selinux_file_context(stdout)


def parse_selinux_denials(stdout: str) -> SELinuxDenials:
    """Parse journalctl audit output with optional input hardening."""
    _validate(stdout, "parse_selinux_denials")
    return _parse_selinux_denials(stdout)


def parse_selinux_ports(stdout: str) -> SELinuxPorts:
    """Parse semanage port -l output with optional input hardening."""
    _validate(stdout, "parse_selinux_ports")
    return _parse_selinux_ports(stdout)
