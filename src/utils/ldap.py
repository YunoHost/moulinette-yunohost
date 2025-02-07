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

import atexit
import logging
import os
import time
from typing import Optional

import ldap
import ldap.modlist as modlist
import ldap.sasl
from moulinette import m18n
from moulinette.core import MoulinetteError

from yunohost.utils.error import YunohostError

logger = logging.getLogger("yunohost.utils.ldap")

# We use a global variable to do some caching
# to avoid re-authenticating in case we call _get_ldap_authenticator multiple times
_ldap_interface: Optional["LDAPInterface"] = None


def _get_ldap_interface():
    global _ldap_interface

    if _ldap_interface is None:
        _ldap_interface = LDAPInterface()

    return _ldap_interface


# We regularly want to extract stuff like 'bar' in ldap path like
# foo=bar,dn=users.example.org,ou=example.org,dc=org so this small helper allow
# to do this without relying of dozens of mysterious string.split()[0]
#
# e.g. using _ldap_path_extract(path, "foo") on the previous example will
# return bar
def _ldap_path_extract(path, info):
    for element in path.split(","):
        if element.startswith(info + "="):
            return element[len(info + "="):]


# Add this to properly close / delete the ldap interface / authenticator
# when Python exits ...
# Otherwise there's a risk that some funky error appears at the very end
# of the command due to Python stuff being unallocated in wrong order.
def _destroy_ldap_interface():
    global _ldap_interface
    if _ldap_interface is not None:
        del _ldap_interface


atexit.register(_destroy_ldap_interface)

URI = "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi"
BASEDN = "dc=yunohost,dc=org"
ROOTDN = "gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"
USERDN = "uid={username},ou=users,dc=yunohost,dc=org"


class LDAPInterface:

    def __init__(self, user=None, password=None):

        if user is None:
            if os.getuid() == 0:
                logger.debug("initializing root ldap interface")
                self.userdn = ROOTDN
                self._connect = lambda con: con.sasl_non_interactive_bind_s("EXTERNAL")
            else:
                logger.debug("initializing anonymous ldap interface")
                self.userdn = ""
                self._connect = lambda con: None
        else:
            logger.debug("initializing user ldap interface")
            self.userdn = USERDN.format(username=user)
            self._connect = lambda con: con.simple_bind_s(self.userdn, password)

        self.connect()

    def connect(self):

        def _reconnect():
            con = ldap.ldapobject.ReconnectLDAPObject(URI, retry_max=10, retry_delay=2)
            self._connect(con)
            return con

        try:
            con = _reconnect()
        except ldap.SERVER_DOWN:
            # ldap is down, attempt to restart it before really failing
            logger.warning(m18n.n("ldap_server_is_down_restart_it"))
            os.system("systemctl restart slapd")
            time.sleep(10)  # waits 10 secondes so we are sure that slapd has restarted
            try:
                con = _reconnect()
            except ldap.SERVER_DOWN:
                raise YunohostError(
                    "Service slapd is not running but is required to perform this action ... "
                    "You can try to investigate what's happening with 'systemctl status slapd'",
                    raw_msg=True,
                )

        # Check that we are indeed logged in with the right identity
        try:
            # whoami_s return dn:..., then delete these 3 characters
            who = con.whoami_s()[3:]
        except Exception as e:
            logger.warning("Error during ldap authentication process: %s", e)
            raise
        else:
            if who != self.userdn:
                raise MoulinetteError("Not logged in with the expected userdn ?!")
            else:
                self.con = con

    def __del__(self):
        """Disconnect and free ressources"""
        if hasattr(self, "con") and self.con:
            self.con.unbind_s()

    def search(self, base=None, filter="(objectClass=*)", attrs=["dn"]):
        """Search in LDAP base

        Perform an LDAP search operation with given arguments and return
        results as a list.

        Keyword arguments:
            - base -- The dn to search into
            - filter -- A string representation of the filter to apply
            - attrs -- A list of attributes to fetch

        Returns:
            A list of all results

        """
        if not base:
            base = BASEDN
        else:
            base = base + "," + BASEDN

        try:
            result = self.con.search_s(base, ldap.SCOPE_SUBTREE, filter, attrs)
        except ldap.SERVER_DOWN as e:
            raise e
        except Exception as e:
            raise MoulinetteError(
                "error during LDAP search operation with: base='%s', "
                "filter='%s', attrs=%s and exception %s" % (base, filter, attrs, e),
                raw_msg=True,
            )

        result_list = []
        if not attrs or "dn" not in attrs:
            result_list = [entry for dn, entry in result]
        else:
            for dn, entry in result:
                entry["dn"] = [dn]
                result_list.append(entry)

        def decode(value):
            if isinstance(value, bytes):
                value = value.decode("utf-8")
            return value

        # result_list is for example :
        # [{'virtualdomain': [b'test.com']}, {'virtualdomain': [b'yolo.test']},
        for stuff in result_list:
            if isinstance(stuff, dict):
                for key, values in stuff.items():
                    stuff[key] = [decode(v) for v in values]

        return result_list

    def add(self, rdn, attr_dict):
        """
        Add LDAP entry

        Keyword arguments:
            rdn         -- DN without domain
            attr_dict   -- Dictionnary of attributes/values to add

        Returns:
            Boolean | MoulinetteError

        """
        dn = f"{rdn},{BASEDN}"
        ldif = modlist.addModlist(attr_dict)
        for i, (k, v) in enumerate(ldif):
            if isinstance(v, list):
                v = [a.encode("utf-8") for a in v]
            elif isinstance(v, str):
                v = [v.encode("utf-8")]
            ldif[i] = (k, v)

        try:
            self.con.add_s(dn, ldif)
        except Exception as e:
            raise MoulinetteError(
                "error during LDAP add operation with: rdn='%s', "
                "attr_dict=%s and exception %s" % (rdn, attr_dict, e),
                raw_msg=True,
            )
        else:
            return True

    def remove(self, rdn):
        """
        Remove LDAP entry

        Keyword arguments:
            rdn         -- DN without domain

        Returns:
            Boolean | MoulinetteError

        """
        dn = f"{rdn},{BASEDN}"
        try:
            self.con.delete_s(dn)
        except Exception as e:
            raise MoulinetteError(
                "error during LDAP delete operation with: rdn='%s' and exception %s"
                % (rdn, e),
                raw_msg=True,
            )
        else:
            return True

    def update(self, rdn, attr_dict, new_rdn=False):
        """
        Modify LDAP entry

        Keyword arguments:
            rdn         -- DN without domain
            attr_dict   -- Dictionnary of attributes/values to add
            new_rdn     -- New RDN for modification

        Returns:
            Boolean | MoulinetteError

        """
        dn = f"{rdn},{BASEDN}"
        actual_entry = self.search(rdn, attrs=None)
        ldif = modlist.modifyModlist(actual_entry[0], attr_dict, ignore_oldexistent=1)

        if ldif == []:
            logger.debug("Nothing to update in LDAP")
            return True

        try:
            if new_rdn:
                self.con.rename_s(dn, new_rdn)
                new_base = dn.split(",", 1)[1]
                dn = new_rdn + "," + new_base

            for i, (a, k, vs) in enumerate(ldif):
                if isinstance(vs, list):
                    vs = [v.encode("utf-8") for v in vs]
                elif isinstance(vs, str):
                    vs = [vs.encode("utf-8")]
                ldif[i] = (a, k, vs)

            self.con.modify_ext_s(dn, ldif)
        except Exception as e:
            raise MoulinetteError(
                "error during LDAP update operation with: rdn='%s', "
                "attr_dict=%s, new_rdn=%s and exception: %s"
                % (rdn, attr_dict, new_rdn, e),
                raw_msg=True,
            )
        else:
            return True

    def validate_uniqueness(self, value_dict):
        """
        Check uniqueness of values

        Keyword arguments:
            value_dict -- Dictionnary of attributes/values to check

        Returns:
            Boolean | MoulinetteError

        """
        attr_found = self.get_conflict(value_dict)
        if attr_found:
            logger.info(
                "attribute '%s' with value '%s' is not unique",
                attr_found[0],
                attr_found[1],
            )
            raise YunohostError(
                "ldap_attribute_already_exists",
                attribute=attr_found[0],
                value=attr_found[1],
            )
        return True

    def get_conflict(self, value_dict, base_dn=None):
        """
        Check uniqueness of values

        Keyword arguments:
            value_dict -- Dictionnary of attributes/values to check

        Returns:
            None | tuple with Fist conflict attribute name and value

        """
        for attr, value in value_dict.items():
            if not self.search(base=base_dn, filter=attr + "=" + value):
                continue
            else:
                return (attr, value)
        return None
