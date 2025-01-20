#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import os
from logging import getLogger

import miniupnpc
import yaml
from moulinette import m18n
from moulinette.utils import process

from yunohost.utils.error import YunohostError, YunohostValidationError

FIREWALL_FILE = "/etc/yunohost/firewall.yml"
UPNP_CRON_JOB = "/etc/cron.d/yunohost-firewall-upnp"

# A UDP port to use for the SSDP discovery phase of UPNP.
# Assigned by IANA to "Fujitsu ICL Terminal Emulator Program A", so no-one else is
# likely to use it (unlike port 1900 which is used by SSDP servers such
# as miniupnpd)
SSDP_CLIENT_PORT = 1901
logger = getLogger("yunohost.firewall")


def firewall_allow(
    protocol,
    port,
    ipv4_only=False,
    ipv6_only=False,
    no_upnp=False,
    no_reload=False,
    reload_only_if_change=False,
):
    """
    Allow connections on a port

    Keyword arguments:
        protocol -- Protocol type to allow (TCP/UDP/Both)
        port -- Port or range of ports to open
        ipv4_only -- Only add a rule for IPv4 connections
        ipv6_only -- Only add a rule for IPv6 connections
        no_upnp -- Do not add forwarding of this port with UPnP
        no_reload -- Do not reload firewall rules

    """
    firewall = firewall_list(raw=True)

    # Validate port
    if not isinstance(port, int) and ":" not in port:
        port = int(port)

    # Validate protocols
    protocols = ["TCP", "UDP"]
    if protocol != "Both" and protocol in protocols:
        protocols = [
            protocol,
        ]

    # Validate IP versions
    ipvs = ["ipv4", "ipv6"]
    if ipv4_only and not ipv6_only:
        ipvs = [
            "ipv4",
        ]
    elif ipv6_only and not ipv4_only:
        ipvs = [
            "ipv6",
        ]

    changed = False

    for p in protocols:
        # Iterate over IP versions to add port
        for i in ipvs:
            if port not in firewall[i][p]:
                firewall[i][p].append(port)
                changed = True
            else:
                ipv = "IPv%s" % i[3]
                if not reload_only_if_change:
                    logger.warning(
                        m18n.n("port_already_opened", port=port, ip_version=ipv)
                    )
        # Add port forwarding with UPnP
        if not no_upnp and port not in firewall["uPnP"][p]:
            firewall["uPnP"][p].append(port)
            if (
                p + "_TO_CLOSE" in firewall["uPnP"]
                and port in firewall["uPnP"][p + "_TO_CLOSE"]
            ):
                firewall["uPnP"][p + "_TO_CLOSE"].remove(port)

    # Update and reload firewall
    _update_firewall_file(firewall)
    if (not reload_only_if_change and not no_reload) or (
        reload_only_if_change and changed
    ):
        return firewall_reload()


def firewall_disallow(
    protocol,
    port,
    ipv4_only=False,
    ipv6_only=False,
    upnp_only=False,
    no_reload=False,
    reload_only_if_change=False,
):
    """
    Disallow connections on a port

    Keyword arguments:
        protocol -- Protocol type to disallow (TCP/UDP/Both)
        port -- Port or range of ports to close
        ipv4_only -- Only remove the rule for IPv4 connections
        ipv6_only -- Only remove the rule for IPv6 connections
        upnp_only -- Only remove forwarding of this port with UPnP
        no_reload -- Do not reload firewall rules

    """
    firewall = firewall_list(raw=True)

    # Validate port
    if not isinstance(port, int) and ":" not in port:
        port = int(port)

    # Validate protocols
    protocols = ["TCP", "UDP"]
    if protocol != "Both" and protocol in protocols:
        protocols = [
            protocol,
        ]

    # Validate IP versions and UPnP
    ipvs = ["ipv4", "ipv6"]
    upnp = True
    if ipv4_only and ipv6_only:
        upnp = True  # automatically disallow UPnP
    elif ipv4_only:
        ipvs = [
            "ipv4",
        ]
        upnp = upnp_only
    elif ipv6_only:
        ipvs = [
            "ipv6",
        ]
        upnp = upnp_only
    elif upnp_only:
        ipvs = []

    changed = False

    for p in protocols:
        # Iterate over IP versions to remove port
        for i in ipvs:
            if port in firewall[i][p]:
                firewall[i][p].remove(port)
                changed = True
            else:
                ipv = "IPv%s" % i[3]
                if not reload_only_if_change:
                    logger.warning(
                        m18n.n("port_already_closed", port=port, ip_version=ipv)
                    )
        # Remove port forwarding with UPnP
        if upnp and port in firewall["uPnP"][p]:
            firewall["uPnP"][p].remove(port)
            if p + "_TO_CLOSE" not in firewall["uPnP"]:
                firewall["uPnP"][p + "_TO_CLOSE"] = []
            firewall["uPnP"][p + "_TO_CLOSE"].append(port)

    # Update and reload firewall
    _update_firewall_file(firewall)
    if (not reload_only_if_change and not no_reload) or (
        reload_only_if_change and changed
    ):
        return firewall_reload()


def firewall_list(raw=False, by_ip_version=False, list_forwarded=False):
    """
    List all firewall rules

    Keyword arguments:
        raw -- Return the complete YAML dict
        by_ip_version -- List rules by IP version
        list_forwarded -- List forwarded ports with UPnP

    """
    with open(FIREWALL_FILE) as f:
        firewall = yaml.safe_load(f)
    if raw:
        return firewall

    # Retrieve all ports for IPv4 and IPv6
    ports = {}
    for i in ["ipv4", "ipv6"]:
        f = firewall[i]
        # Combine TCP and UDP ports
        ports[i] = sorted(
            set(f["TCP"]) | set(f["UDP"]),
            key=lambda p: int(p.split(":")[0]) if isinstance(p, str) else p,
        )

    if not by_ip_version:
        # Combine IPv4 and IPv6 ports
        ports = sorted(
            set(ports["ipv4"]) | set(ports["ipv6"]),
            key=lambda p: int(p.split(":")[0]) if isinstance(p, str) else p,
        )

    # Format returned dict
    ret = {"opened_ports": ports}
    if list_forwarded:
        # Combine TCP and UDP forwarded ports
        ret["forwarded_ports"] = sorted(
            set(firewall["uPnP"]["TCP"]) | set(firewall["uPnP"]["UDP"]),
            key=lambda p: int(p.split(":")[0]) if isinstance(p, str) else p,
        )
    return ret


def firewall_reload(skip_upnp=False):
    """
    Reload all firewall rules

    Keyword arguments:
        skip_upnp -- Do not refresh port forwarding using UPnP

    """
    from yunohost.hook import hook_callback
    from yunohost.service import _run_service_command

    reloaded = False
    errors = False

    # Check if SSH port is allowed
    ssh_port = _get_ssh_port()
    if ssh_port not in firewall_list()["opened_ports"]:
        firewall_allow("TCP", ssh_port, no_reload=True)

    # Retrieve firewall rules and UPnP status
    firewall = firewall_list(raw=True)
    upnp = firewall_upnp(no_refresh=True)["enabled"] if not skip_upnp else False

    # IPv4
    try:
        process.check_output("iptables -n -w -L")
    except process.CalledProcessError as e:
        logger.debug(
            "iptables seems to be not available, it outputs:\n%s",
            e.output.decode().strip(),
        )
        logger.warning(m18n.n("iptables_unavailable"))
    else:
        rules = [
            "iptables -w -F",
            "iptables -w -X",
            "iptables -w -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
        ]
        # Iterate over ports and add rule
        for protocol in ["TCP", "UDP"]:
            for port in firewall["ipv4"][protocol]:
                rules.append(
                    "iptables -w -A INPUT -p %s --dport %s -j ACCEPT"
                    % (protocol, process.quote(str(port)))
                )
        rules += [
            "iptables -w -A INPUT -i lo -j ACCEPT",
            "iptables -w -A INPUT -p icmp -j ACCEPT",
            "iptables -w -P INPUT DROP",
        ]

        # Execute each rule
        if process.run_commands(rules, callback=_on_rule_command_error):
            errors = True
        reloaded = True

    # IPv6
    try:
        process.check_output("ip6tables -n -L")
    except process.CalledProcessError as e:
        logger.debug(
            "ip6tables seems to be not available, it outputs:\n%s",
            e.output.decode().strip(),
        )
        logger.warning(m18n.n("ip6tables_unavailable"))
    else:
        rules = [
            "ip6tables -w -F",
            "ip6tables -w -X",
            "ip6tables -w -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
        ]
        # Iterate over ports and add rule
        for protocol in ["TCP", "UDP"]:
            for port in firewall["ipv6"][protocol]:
                rules.append(
                    "ip6tables -w -A INPUT -p %s --dport %s -j ACCEPT"
                    % (protocol, process.quote(str(port)))
                )
        rules += [
            "ip6tables -w -A INPUT -i lo -j ACCEPT",
            "ip6tables -w -A INPUT -p icmpv6 -j ACCEPT",
            "ip6tables -w -P INPUT DROP",
        ]

        # Execute each rule
        if process.run_commands(rules, callback=_on_rule_command_error):
            errors = True
        reloaded = True

    if not reloaded:
        raise YunohostError("firewall_reload_failed")

    hook_callback(
        "post_iptable_rules", args=[upnp, os.path.exists("/proc/net/if_inet6")]
    )

    if upnp:
        # Refresh port forwarding with UPnP
        firewall_upnp(no_refresh=False)

    _run_service_command("restart", "fail2ban")

    if errors:
        logger.warning(m18n.n("firewall_rules_cmd_failed"))
    else:
        logger.success(m18n.n("firewall_reloaded"))
    return firewall_list()


def firewall_upnp(action="status", no_refresh=False):
    """
    Manage port forwarding using UPnP

    Note: 'reload' action is deprecated and will be removed in the near
    future. You should use 'status' instead - which retrieve UPnP status
    and automatically refresh port forwarding if 'no_refresh' is False.

    Keyword argument:
        action -- Action to perform
        no_refresh -- Do not refresh port forwarding

    """
    firewall = firewall_list(raw=True)

    if action == "status":
        enabled = firewall["uPnP"]["enabled"]
    elif action == "enable":
        # Add cron job
        with open(UPNP_CRON_JOB, "w+") as f:
            f.write(
                "*/12 * * * * root "
                "/usr/bin/yunohost firewall upnp status >>/dev/null\n"
            )
        enabled = True
    elif action == "disable":
        try:
            # Remove cron job
            os.remove(UPNP_CRON_JOB)
        except Exception:
            pass
        enabled = False
    else:
        raise YunohostValidationError("action_invalid", action=action)

    # Refresh port mapping
    refresh_success = True
    if not no_refresh:
        # Open port to receive discovery message
        process.run_commands(
            ["iptables -w -A INPUT -p udp --dport %d -j ACCEPT" % SSDP_CLIENT_PORT],
            callback=_on_rule_command_error,
        )
        upnpc = miniupnpc.UPnP(localport=SSDP_CLIENT_PORT)
        upnpc.discoverdelay = 3000
        # Discover UPnP device(s)
        logger.debug("discovering UPnP devices...")
        try:
            nb_dev = upnpc.discover()
        except Exception:
            logger.warning("Failed to find any UPnP device on the network")
            nb_dev = -1
            enabled = False

        logger.debug("found %d UPnP device(s)", int(nb_dev))
        # Close discovery port
        process.run_commands(
            ["iptables -w -D INPUT -p udp --dport %d -j ACCEPT" % SSDP_CLIENT_PORT],
            callback=_on_rule_command_error,
        )

        if nb_dev < 1:
            logger.error(m18n.n("upnp_dev_not_found"))
            refresh_success = False
        else:
            try:
                # Select UPnP device
                upnpc.selectigd()
            except Exception:
                logger.debug("unable to select UPnP device", exc_info=1)
                refresh_success = False
            else:
                # Iterate over ports
                for protocol in ["TCP", "UDP"]:
                    if protocol + "_TO_CLOSE" in firewall["uPnP"]:
                        for port in firewall["uPnP"][protocol + "_TO_CLOSE"]:
                            if not isinstance(port, int):
                                # FIXME : how should we handle port ranges ?
                                logger.warning("Can't use UPnP to close '%s'" % port)
                                continue

                            # Clean the mapping of this port
                            if upnpc.getspecificportmapping(port, protocol):
                                try:
                                    upnpc.deleteportmapping(port, protocol)
                                except Exception:
                                    pass
                        del firewall["uPnP"][protocol + "_TO_CLOSE"]

                    for port in firewall["uPnP"][protocol]:
                        if not isinstance(port, int):
                            # FIXME : how should we handle port ranges ?
                            logger.warning("Can't use UPnP to open '%s'" % port)
                            continue

                        # Clean the mapping of this port
                        if upnpc.getspecificportmapping(port, protocol):
                            try:
                                upnpc.deleteportmapping(port, protocol)
                            except Exception:
                                pass
                        if not enabled:
                            continue
                        try:
                            # Add new port mapping
                            upnpc.addportmapping(
                                port,
                                protocol,
                                upnpc.lanaddr,
                                port,
                                "yunohost firewall: port %d" % port,
                                "",
                            )
                        except Exception:
                            logger.debug(
                                "unable to add port %d using UPnP", port, exc_info=1
                            )
                            refresh_success = False
                if refresh_success:
                    logger.debug("UPnP port refresh successful")
                    if action == "enable":
                        logger.success(m18n.n("upnp_enabled"))
                    elif action == "disable":
                        logger.success(m18n.n("upnp_disabled"))

    # Save state always (note that refreshing can change the "TO_CLOSE" states)
    firewall["uPnP"]["enabled"] = enabled
    _update_firewall_file(firewall)
    return {"enabled": enabled}


def firewall_stop():
    """
    Stop iptables and ip6tables


    """

    if os.system("iptables -w -P INPUT ACCEPT") != 0:
        raise YunohostError("iptables_unavailable")

    os.system("iptables -w -F")
    os.system("iptables -w -X")

    if os.path.exists("/proc/net/if_inet6"):
        os.system("ip6tables -P INPUT ACCEPT")
        os.system("ip6tables -F")
        os.system("ip6tables -X")


def _get_ssh_port(default=22):
    """Return the SSH port to use

    Retrieve the SSH port from the sshd_config file or used the default
    one if it's not defined.
    """
    from moulinette.utils.text import searchf

    try:
        m = searchf(r"^Port[ \t]+([0-9]+)$", "/etc/ssh/sshd_config", count=-1)
        if m:
            return int(m)
    except Exception:
        pass
    return default


def _update_firewall_file(rules):
    """Make a backup and write new rules to firewall file"""
    os.system("cp {0} {0}.old".format(FIREWALL_FILE))
    with open(FIREWALL_FILE, "w") as f:
        yaml.safe_dump(rules, f, default_flow_style=False)


def _on_rule_command_error(returncode, cmd, output):
    """Callback for rules commands error"""
    # Log error and continue commands execution
    logger.debug(
        '"%s" returned non-zero exit status %d:\n%s',
        cmd,
        returncode,
        output.decode().strip(),
    )
    return True
