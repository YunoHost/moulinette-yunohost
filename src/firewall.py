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
import shutil
from typing import Any
from pathlib import Path
from logging import getLogger

import miniupnpc
import yaml
from moulinette import m18n

from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.regenconf import regen_conf


logger: Any = getLogger("yunohost.firewall")


class YunoFirewall:
    FIREWALL_FILE = Path("/etc/yunohost/firewall.yml")

    def __init__(self) -> None:
        self.need_reload = False

        # This is a workaround for when we need to actively close UPnP ports
        self.upnp_to_close: list[tuple[str, int | str]] = []

        self.read()

    def read(self) -> None:
        self.config = yaml.safe_load(self.FIREWALL_FILE.read_text())

    def write(self) -> None:
        old_file = self.FIREWALL_FILE.parent / (self.FIREWALL_FILE.name + ".old")
        shutil.copyfile(self.FIREWALL_FILE, old_file)
        self.FIREWALL_FILE.write_text(yaml.dump(self.config))

    def list(self, protocol: str, forwarded: bool = False) -> list[int]:
        protocol, _ = self._validate_port(protocol, 0)
        return [
            port
            for port, status in self.config[protocol].items()
            if (status["forwarded"] if forwarded else status["open"])
        ]

    @staticmethod
    def _validate_port(protocol: str, port: int | str) -> tuple[str, int | str]:
        if isinstance(port, str) and ":" not in port:
            port = int(port)
        if protocol not in ["tcp", "udp"]:
            raise ValueError(f"protocol should be tcp or udp, not {protocol}")
        return protocol, port

    def open_port(
        self, protocol: str, port: int | str, comment: str, upnp: bool = False
    ) -> None:
        protocol, port = self._validate_port(protocol, port)

        if port not in self.config[protocol]:
            self.config[protocol][port] = {
                "open": False,
                "upnp": False,
                "comment": comment,
            }

        # Keep existing comment if the one passed is empty
        if comment:
            self.config[protocol][port]["comment"] = comment

        if not self.config[protocol][port]["open"]:
            self.config[protocol][port]["open"] = True
            self.need_reload = True

        if self.config[protocol][port]["upnp"] != upnp:
            self.config[protocol][port]["upnp"] = upnp
            self.need_reload = True
        self.write()

    def close_port(
        self, protocol: str, port: int | str, upnp_only: bool = False
    ) -> None:
        protocol, port = self._validate_port(protocol, port)

        if port not in self.config[protocol]:
            return

        if self.config[protocol][port]["upnp"]:
            self.config[protocol][port]["upnp"] = False
            # not need_reload, it's only upnp
            self.upnp_to_close.append((protocol, port))

        if upnp_only:
            self.write()
            return

        if self.config[protocol][port]["open"]:
            self.config[protocol][port]["open"] = False
            self.need_reload = True
        self.write()

    def delete_port(self, protocol: str, port: int | str) -> None:
        protocol, port = self._validate_port(protocol, port)

        if port not in self.config[protocol]:
            return

        self.close_port(protocol, port, False)

        del self.config[protocol][port]
        self.need_reload = True
        self.write()

    def apply(self, upnp: bool = True) -> bool:
        # FIXME: Ensure SSH is allowed
        self.open_port("tcp", _get_ssh_port(), "SSH port", upnp=True)

        # Just leverage regen_conf that will regen the nftables files, reload nftables
        try:
            regen_conf(["nftables"], force=True)
        except YunohostError:
            return False

        self.need_reload = False

        # Refresh port forwarding with UPnP
        if self.config["router_forwarding_upnp"] and upnp:
            YunoUPnP(self).refresh(self)
        return True

    def clear(self) -> None:
        os.system("systemctl stop nftables")


class YunoUPnP:
    UPNP_PORT = 55354  # Picked at random, this port has no real meaning
    UPNP_PORT_COMMENT = "YunoHost UPnP firewall configurator"
    UPNP_CRON_JOB = Path("/etc/cron.d/yunohost-firewall-upnp")

    def __init__(self, firewall: "YunoFirewall") -> None:
        self.firewall = firewall
        self.upnpc: miniupnpc.UPnP | None = None

    def enabled(self, new_status: bool | None = None) -> bool:
        if new_status is not None:
            self.firewall.config["router_forwarding_upnp"] = new_status
        self.firewall.write()
        return self.firewall.config["router_forwarding_upnp"]

    def ensure_listen_port(self) -> None:
        self.firewall.open_port("udp", self.UPNP_PORT, self.UPNP_PORT_COMMENT)

    def find_gid(self) -> bool:
        upnpc = miniupnpc.UPnP()
        upnpc.localport = self.UPNP_PORT
        upnpc.discoverdelay = 3000
        # Discover UPnP device(s)
        logger.debug("discovering UPnP devices...")
        try:
            nb_dev = upnpc.discover()
        except Exception:
            logger.warning("Failed to find any UPnP device on the network")
            nb_dev = -1
        if nb_dev < 1:
            logger.error(m18n.n("upnp_dev_not_found"))
            return False
        logger.debug("found %d UPnP device(s)", int(nb_dev))
        try:
            # Select UPnP device
            upnpc.selectigd()
        except Exception:
            logger.debug("unable to select UPnP device", exc_info=1)
            return False
        return True

    def open_port(self, protocol: str, port: int | str, comment: str) -> bool:
        if self.upnpc is None:
            self.find_gid()
        assert self.upnpc is not None

        # FIXME: how should we handle port ranges ?
        if not isinstance(port, int):
            logger.warning("Can't use UPnP to open '%s'" % port)
            return False

        # Clean the mapping of this port
        if self.upnpc.getspecificportmapping(port, protocol):
            try:
                self.upnpc.deleteportmapping(port, protocol)
            except Exception:
                return False

        # Add new port mapping
        desc = f"yunohost firewall: port {port} {comment}"
        try:
            self.upnpc.addportmapping(
                port, protocol, self.upnpc.lanaddr, port, desc, ""
            )
        except Exception:
            logger.debug("unable to add port %d using UPnP", port, exc_info=1)
            return False
        return True

    def close_port(self, protocol: str, port: int | str) -> bool:
        if self.upnpc is None:
            self.find_gid()
        assert self.upnpc is not None

        if self.upnpc.getspecificportmapping(port, protocol):
            try:
                self.upnpc.deleteportmapping(port, protocol)
            except Exception:
                return False
        return True

    def refresh(self, firewall: "YunoFirewall") -> bool:
        if not self.find_gid():
            return False

        status = True
        for protocol, port in firewall.upnp_to_close:
            status = status and self.close_port(protocol, port)

        for protocol in ["tcp", "udp"]:
            for port, info in firewall.config[protocol].items():
                if self.enabled():
                    status = status and self.open_port(protocol, port, info["comment"])
                else:
                    status = status and self.close_port(protocol, port)

        return status

    def enable(self) -> None:
        if not self.enabled():
            # Add cron job
            self.UPNP_CRON_JOB.write_text(
                "*/50 * * * * root /usr/bin/yunohost firewall upnp status >>/dev/null\n"
            )
            self.enabled(True)

    def disable(self) -> None:
        if self.enabled():
            # Remove cron job
            self.UPNP_CRON_JOB.unlink(missing_ok=True)
            self.enabled(False)


def firewall_is_open(
    port: int | str,
    protocol: str,
) -> bool:
    """
    Returns whether the specified port is open.

    Keyword arguments:
        port -- Port or range of ports to open
        protocol -- Protocol type to allow (tcp/udp)

    """
    return port in firewall_list(raw=False, protocol=protocol, forwarded=False)


def firewall_open(
    port: int | str,
    protocol: str,
    comment: str,
    upnp: bool = False,
    no_reload: bool = False,
    reload_if_changed: bool = False,
) -> None:
    """
    Allow connections on a port

    Keyword arguments:
        port -- Port or range of ports to open
        protocol -- Protocol type to allow (tcp/udp)
        comment -- A reason for the port to be open
        no_upnp -- Do not add forwarding of this port with UPnP
        no_reload -- Do not reload firewall rules
    """
    firewall = YunoFirewall()

    # Add a readable comment if none was passed but we're handling an app
    app_id = os.environ.get("YNH_APP_ID", "")
    if not comment:
        if app_id:
            if port == 53:
                comment = f"DNS for {app_id}"
            elif port == 67:
                comment = f"DHCP for {app_id}"
            elif port == 445:
                comment = f"SMB for {app_id}"
            elif port == 1900:
                comment = f"UPnP for {app_id}"
            else:
                comment = f"For {app_id}"
        else:
            comment = "Manually set without comment"

    firewall.open_port(protocol, port, comment, upnp)
    if not reload_if_changed and not firewall.need_reload:
        logger.warning(m18n.n("port_already_opened", port=port))

    will_reload = (firewall.need_reload and reload_if_changed) or (
        not no_reload and not reload_if_changed
    )
    if will_reload:
        if firewall.apply():
            logger.success(m18n.n("firewall_reloaded"))
        else:
            logger.error(m18n.n("firewall_reload_failed"))


def firewall_close(
    port: int | str,
    protocol: str,
    upnp_only: bool = False,
    no_reload: bool = False,
    reload_if_changed: bool = False,
) -> None:
    """
    Disallow connections on a port

    Keyword arguments:
        port -- Port or range of ports to close
        protocol -- Protocol type to disallow (tcp/udp)
        upnp_only -- Only remove forwarding of this port with UPnP
        no_reload -- Do not reload firewall rules
    """
    firewall = YunoFirewall()

    firewall.close_port(protocol, port, upnp_only=upnp_only)
    if not firewall.need_reload and not reload_if_changed:
        logger.warning(m18n.n("port_already_closed", port=port))

    will_reload = (firewall.need_reload and reload_if_changed) or (
        not no_reload and not reload_if_changed
    )
    if will_reload:
        if firewall.apply():
            logger.success(m18n.n("firewall_reloaded"))
        else:
            logger.error(m18n.n("firewall_reload_failed"))


# Legacy APIs
def firewall_allow(
    protocol: str,
    port: int | str,
    ipv4_only: bool = False,
    ipv6_only: bool = False,
    no_upnp: bool = False,
    no_reload: bool = False,
    reload_only_if_change: bool = False,
) -> None:
    return firewall_open(
        port, protocol.lower(), "", not no_upnp, no_reload, reload_only_if_change
    )


def firewall_disallow(
    protocol: str,
    port: int | str,
    ipv4_only: bool = False,
    ipv6_only: bool = False,
    upnp_only: bool = False,
    no_reload: bool = False,
    reload_only_if_change: bool = False,
) -> None:
    firewall_close(port, protocol.lower(), upnp_only, no_reload, reload_only_if_change)

    if os.environ.get("YNH_APP_ACTION", "") == "remove":
        ports_to_keep = [53, 1900]
        if port not in ports_to_keep:
            firewall_delete(port, protocol.lower(), no_reload, reload_only_if_change)


def firewall_delete(
    port: int | str,
    protocol: str,
    no_reload: bool = False,
    reload_if_changed: bool = False,
) -> None:
    """
    Delete a port from YunoHost's config

    Keyword arguments:
        protocol -- Protocol type to disallow (tcp/udp)
        port -- Port or range of ports to close
        no_reload -- Do not reload firewall rules
    """
    firewall = YunoFirewall()
    firewall.delete_port(protocol, port)

    if not firewall.need_reload and not reload_if_changed:
        logger.warning(m18n.n("port_already_closed", port=port))

    will_reload = (firewall.need_reload and reload_if_changed) or (
        not no_reload and not reload_if_changed
    )
    if will_reload:
        if firewall.apply():
            logger.success(m18n.n("firewall_reloaded"))
        else:
            logger.error(m18n.n("firewall_reload_failed"))


def firewall_list(
    raw: bool = False, protocol: str = "tcp", forwarded: bool = False
) -> dict[str, Any]:
    """
    List all firewall rules

    Keyword arguments:
        raw -- Return the complete YAML dict
        tcp -- If not raw, list TCP ports
        udp -- If not raw, list UDP ports
        forwarded -- If not raw, list UPnP forwarded ports instead of open ports
    """
    firewall = YunoFirewall()
    return firewall.config if raw else {protocol: firewall.list(protocol, forwarded)}


def firewall_reload(skip_upnp: bool = False) -> None:
    """
    Reload all firewall rules

    Keyword arguments:
        skip_upnp -- Do not refresh port forwarding using UPnP
    """
    firewall = YunoFirewall()
    if firewall.apply(upnp=not skip_upnp):
        logger.success(m18n.n("firewall_reloaded"))
    else:
        logger.error(m18n.n("firewall_reload_failed"))


def firewall_upnp(action: str = "status", no_refresh: bool = False) -> dict[str, bool]:
    """
    Manage port forwarding using UPnP

    Available actions are status, enable, disable.
    All actions will refresh port forwarding unless 'no_refresh' is False.

    Keyword argument:
        action -- Action to perform
        no_refresh -- Do not refresh port forwarding
    """
    if action not in ["status", "enable", "disable"]:
        raise YunohostValidationError("action_invalid", action=action)

    firewall = YunoFirewall()
    upnp = YunoUPnP(firewall)

    if action == "enable":
        upnp.enable()
    if action == "disable":
        upnp.disable()
    if no_refresh:
        # Only return current state
        return {"enabled": upnp.enabled()}

    if upnp.refresh(firewall):
        # Display success message if needed
        logger.success(
            m18n.n("upnp_enabled") if upnp.enabled() else m18n.n("upnp_disabled")
        )
    else:
        # FIXME: Do not update the config file to let a refresh handle the failure?
        raise YunohostError("upnp_port_open_failed")

    return {"enabled": upnp.enabled()}


def firewall_stop() -> None:
    """
    Stop nftables
    """
    if os.system("nft list ruleset") != 0:
        raise YunohostError("nftables_unavailable")
    YunoFirewall().clear()


def _get_ssh_port(default: int = 22) -> int:
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
