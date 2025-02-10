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
import re
import time
from collections import OrderedDict
from difflib import SequenceMatcher
from logging import getLogger

from moulinette import Moulinette, m18n
from moulinette.utils.filesystem import mkdir, read_file, read_toml, write_to_file

from yunohost.domain import (
    _assert_domain_exists,
    _get_domain_settings,
    _get_parent_domain_of,
    _list_subdomains_of,
    _set_domain_settings,
    domain_config_get,
)
from yunohost.hook import hook_callback
from yunohost.log import is_unit_operation
from yunohost.utils.dns import dig, is_special_use_tld, is_yunohost_dyndns_domain
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.network import get_public_ip

logger = getLogger("yunohost.domain")

DOMAIN_REGISTRAR_LIST_PATH = "/usr/share/yunohost/registrar_list.toml"


def domain_dns_suggest(domain):
    """
    Generate DNS configuration for a domain

    Keyword argument:
        domain -- Domain name

    """

    if is_special_use_tld(domain):
        return m18n.n("domain_dns_conf_special_use_tld")

    _assert_domain_exists(domain)

    dns_conf = _build_dns_conf(domain)

    result = ""

    if dns_conf["basic"]:
        result += "; Basic ipv4/ipv6 records"
        for record in dns_conf["basic"]:
            result += "\n{name} {ttl} IN {type} {value}".format(**record)

    if dns_conf["mail"]:
        result += "\n\n"
        result += "; Mail"
        for record in dns_conf["mail"]:
            result += "\n{name} {ttl} IN {type} {value}".format(**record)
        result += "\n\n"

    if dns_conf["extra"]:
        result += "\n\n"
        result += "; Extra"
        for record in dns_conf["extra"]:
            result += "\n{name} {ttl} IN {type} {value}".format(**record)

    for name, record_list in dns_conf.items():
        if name not in ("basic", "mail", "extra") and record_list:
            result += "\n\n"
            result += "; " + name
            for record in record_list:
                result += "\n{name} {ttl} IN {type} {value}".format(**record)

    if Moulinette.interface.type == "cli":
        # FIXME Update this to point to our "dns push" doc
        logger.info(m18n.n("domain_dns_conf_is_just_a_recommendation"))

    return result


def _build_dns_conf(base_domain, include_empty_AAAA_if_no_ipv6=False):
    """
    Internal function that will returns a data structure containing the needed
    information to generate/adapt the dns configuration

    Arguments:
        domains -- List of a domain and its subdomains

    The returned datastructure will have the following form:
    {
        "basic": [
            # if ipv4 available
            {"type": "A", "name": "@", "value": "123.123.123.123", "ttl": 3600},
            # if ipv6 available
            {"type": "AAAA", "name": "@", "value": "valid-ipv6", "ttl": 3600},
        ],
        "mail": [
            {"type": "MX", "name": "@", "value": "10 domain.tld.", "ttl": 3600},
            {"type": "TXT", "name": "@", "value": "\"v=spf1 a mx ip4:123.123.123.123 ipv6:valid-ipv6 -all\"", "ttl": 3600 },
            {"type": "TXT", "name": "mail._domainkey", "value": "\"v=DKIM1; k=rsa; p=some-super-long-key\"", "ttl": 3600},
            {"type": "TXT", "name": "_dmarc", "value": "\"v=DMARC1; p=none\"", "ttl": 3600}
        ],
        "extra": [
            # if ipv4 available
            {"type": "A", "name": "*", "value": "123.123.123.123", "ttl": 3600},
            # if ipv6 available
            {"type": "AAAA", "name": "*", "value": "valid-ipv6", "ttl": 3600},
            {"type": "CAA", "name": "@", "value": "0 issue \"letsencrypt.org\"", "ttl": 3600},
            {"type": "CAA", "name": "@", "value": "0 issuewild \"letsencrypt.org\"", "ttl": 3600},
        ],
        "example_of_a_custom_rule": [
            {"type": "SRV", "name": "_matrix", "value": "domain.tld.", "ttl": 3600}
        ],
    }
    """

    from yunohost.settings import settings_get

    basic = []
    mail = []
    extra = []
    ipv4 = get_public_ip()
    ipv6 = get_public_ip(6)

    # If this is a ynh_dyndns_domain, we're not gonna include all the subdomains in the conf
    # Because dynette only accept a specific list of name/type
    # And the wildcard */A already covers the bulk of use cases
    if is_yunohost_dyndns_domain(base_domain):
        subdomains = []
    else:
        subdomains = _list_subdomains_of(base_domain)

    domains_settings = {
        domain: domain_config_get(domain, export=True)
        for domain in [base_domain] + subdomains
    }

    base_dns_zone = _get_dns_zone_for_domain(base_domain)

    for domain, settings in domains_settings.items():
        #   Domain           #   Base DNS zone   # Basename  #  Suffix  #
        # ------------------ # ----------------- # --------- # -------- #
        #         domain.tld #       domain.tld  #        @  #          #
        #     sub.domain.tld #       domain.tld  #      sub  # .sub     #
        # foo.sub.domain.tld #       domain.tld  #  foo.sub  # .foo.sub #
        #     sub.domain.tld #   sub.domain.tld  #        @  #          #
        # foo.sub.domain.tld #   sub.domain.tld  #      foo  # .foo     #
        basename = _get_relative_name_for_dns_zone(domain, base_dns_zone)
        suffix = f".{basename}" if basename != "@" else ""

        # ttl = settings["ttl"]
        ttl = 3600

        ###########################
        # Basic ipv4/ipv6 records #
        ###########################
        if ipv4 and settings_get("misc.network.dns_exposure") in ["both", "ipv4"]:
            basic.append([basename, ttl, "A", ipv4])

        if ipv6:
            basic.append([basename, ttl, "AAAA", ipv6])
        elif include_empty_AAAA_if_no_ipv6:
            basic.append([basename, ttl, "AAAA", None])

        #########
        # Email #
        #########
        if settings["mail_in"]:
            mail.append([basename, ttl, "MX", f"10 {domain}."])

        if settings["mail_out"]:
            mail.append([basename, ttl, "TXT", '"v=spf1 a mx -all"'])

            # DKIM/DMARC record
            dkim_host, dkim_publickey = _get_DKIM(domain)

            if dkim_host:
                mail += [
                    [f"{dkim_host}{suffix}", ttl, "TXT", dkim_publickey],
                    [f"_dmarc{suffix}", ttl, "TXT", '"v=DMARC1; p=none"'],
                ]

        #########
        # Extra #
        #########

        # Only recommend wildcard and CAA for the top level
        if domain == base_domain:
            if ipv4 and settings_get("misc.network.dns_exposure") in ["both", "ipv4"]:
                extra.append([f"*{suffix}", ttl, "A", ipv4])

            if ipv6:
                extra.append([f"*{suffix}", ttl, "AAAA", ipv6])
            elif include_empty_AAAA_if_no_ipv6:
                extra.append([f"*{suffix}", ttl, "AAAA", None])

            extra.append([basename, ttl, "CAA", '0 issue "letsencrypt.org"'])
            extra.append([basename, ttl, "CAA", '0 issuewild "letsencrypt.org"'])

        ####################
        # Standard records #
        ####################

    records = {
        "basic": [
            {"name": name, "ttl": ttl_, "type": type_, "value": value}
            for name, ttl_, type_, value in basic
        ],
        "mail": [
            {"name": name, "ttl": ttl_, "type": type_, "value": value}
            for name, ttl_, type_, value in mail
        ],
        "extra": [
            {"name": name, "ttl": ttl_, "type": type_, "value": value}
            for name, ttl_, type_, value in extra
        ],
    }

    ##################
    # Custom records #
    ##################

    # Defined by custom hooks shipped in apps for example ...
    hook_results = hook_callback(
        "custom_dns_rules", env={"base_domain": base_domain, "suffix": suffix}
    )
    for hook_name, results in hook_results.items():
        #
        # There can be multiple results per hook name, so results look like
        # {'/some/path/to/hook1':
        #       { 'state': 'succeed',
        #         'stdreturn': [{'type': 'SRV',
        #                        'name': 'stuff.foo.bar.',
        #                        'value': 'yoloswag',
        #                        'ttl': 3600}]
        #       },
        #  '/some/path/to/hook2':
        #       { ... },
        #  [...]
        #
        # Loop over the sub-results
        custom_records = [
            v["stdreturn"] for v in results.values() if v and v["stdreturn"]
        ]

        records[hook_name] = []
        for record_list in custom_records:
            # Check that record_list is indeed a list of dict
            # with the required keys
            if (
                not isinstance(record_list, list)
                or any(not isinstance(record, dict) for record in record_list)
                or any(
                    key not in record
                    for record in record_list
                    for key in ["name", "ttl", "type", "value"]
                )
            ):
                # Display an error, mainly for app packagers trying to implement a hook
                logger.warning(
                    "Ignored custom record from hook '%s' because the data is not a *list* of dict with keys name, ttl, type and value. Raw data : %s"
                    % (hook_name, record_list)
                )
                continue

            records[hook_name].extend(record_list)

    return records


def _get_DKIM(domain):
    DKIM_file = f"/etc/dkim/{domain}.mail.txt"

    if not os.path.isfile(DKIM_file):
        return (None, None)

    with open(DKIM_file) as f:
        dkim_content = f.read()

    # Gotta manage two formats :
    #
    # Legacy
    # -----
    #
    # mail._domainkey IN      TXT     ( "v=DKIM1; k=rsa; "
    #           "p=<theDKIMpublicKey>" )
    #
    # New
    # ------
    #
    # mail._domainkey IN  TXT ( "v=DKIM1; h=sha256; k=rsa; "
    #           "p=<theDKIMpublicKey>" )

    is_legacy_format = " h=sha256; " not in dkim_content

    # Legacy DKIM format
    if is_legacy_format:
        dkim = re.match(
            (
                r"^(?P<host>[a-z_\-\.]+)[\s]+([0-9]+[\s]+)?IN[\s]+TXT[\s]+"
                r'[^"]*"v=(?P<v>[^";]+);'
                r'[\s"]*k=(?P<k>[^";]+);'
                r'[\s"]*p=(?P<p>[^";]+)'
            ),
            dkim_content,
            re.M | re.S,
        )
    else:
        dkim = re.match(
            (
                r"^(?P<host>[a-z_\-\.]+)[\s]+([0-9]+[\s]+)?IN[\s]+TXT[\s]+"
                r'[^"]*"v=(?P<v>[^";]+);'
                r'[\s"]*h=(?P<h>[^";]+);'
                r'[\s"]*k=(?P<k>[^";]+);'
                r'[\s"]*p=(?P<p>[^";]+)'
            ),
            dkim_content,
            re.M | re.S,
        )

    if not dkim:
        return (None, None)

    if is_legacy_format:
        return (
            dkim.group("host"),
            '"v={v}; k={k}; p={p}"'.format(
                v=dkim.group("v"), k=dkim.group("k"), p=dkim.group("p")
            ),
        )
    else:
        return (
            dkim.group("host"),
            '"v={v}; h={h}; k={k}; p={p}"'.format(
                v=dkim.group("v"),
                h=dkim.group("h"),
                k=dkim.group("k"),
                p=dkim.group("p"),
            ),
        )


def _get_dns_zone_for_domain(domain):
    """
    Get the DNS zone of a domain

    Keyword arguments:
        domain -- The domain name

    """

    # First, check if domain is a nohost.me / noho.st / ynh.fr
    # This is mainly meant to speed up things for "dyndns update"
    # ... otherwise we end up constantly doing a bunch of dig requests
    if is_yunohost_dyndns_domain(domain):
        # Keep only foo.nohost.me even if we have subsub.sub.foo.nohost.me
        return ".".join(domain.rsplit(".", 3)[-3:])

    # Same thing with .local, .test, ... domains
    if is_special_use_tld(domain):
        # Keep only foo.local even if we have subsub.sub.foo.local
        return ".".join(domain.rsplit(".", 2)[-2:])

    # Check cache
    cache_folder = "/var/cache/yunohost/dns_zones"
    cache_file = f"{cache_folder}/{domain}"
    cache_duration = 3600  # one hour
    if (
        os.path.exists(cache_file)
        and abs(os.path.getctime(cache_file) - time.time()) < cache_duration
    ):
        dns_zone = read_file(cache_file).strip()
        if dns_zone:
            return dns_zone

    # Check cache for parent domain
    # This is another strick to try to prevent this function from being
    # a bottleneck on system with 1 main domain + 10ish subdomains
    # when building the dns conf for the main domain (which will call domain_config_get, etc...)
    parent_domain = _get_parent_domain_of(domain)
    if parent_domain:
        parent_cache_file = f"{cache_folder}/{parent_domain}"
        if (
            os.path.exists(parent_cache_file)
            and abs(os.path.getctime(parent_cache_file) - time.time()) < cache_duration
        ):
            dns_zone = read_file(parent_cache_file).strip()
            if dns_zone:
                return dns_zone

    # For foo.bar.baz.gni we want to scan all the parent domains
    # (including the domain itself)
    # foo.bar.baz.gni
    #     bar.baz.gni
    #         baz.gni
    #             gni
    # Until we find the first one that has a NS record
    parent_list = [domain.split(".", i)[-1] for i, _ in enumerate(domain.split("."))]

    # We don't wan't to do A NS request on the tld
    for parent in parent_list[0:-1]:
        # Check if there's a NS record for that domain
        answer = dig(parent, rdtype="NS", full_answers=True, resolvers="force_external")

        if answer[0] != "ok":
            # Some domains have a SOA configured but NO NS record !!!
            # See https://github.com/YunoHost/issues/issues/1980
            answer = dig(
                parent, rdtype="SOA", full_answers=True, resolvers="force_external"
            )

        if answer[0] == "ok":
            mkdir(cache_folder, parents=True, force=True)
            write_to_file(cache_file, parent)
            return parent

    if len(parent_list) >= 2:
        zone = parent_list[-2]
    else:
        zone = parent_list[-1]

    # Adding this otherwise the CI is flooding about those ...
    if domain not in [
        "example.tld",
        "sub.example.tld",
        "domain.tld",
        "sub.domain.tld",
        "domain_a.dev",
        "domain_b.dev",
    ]:
        logger.warning(
            f"Could not identify correctly the dns zone for domain {domain}, returning {zone}"
        )
    return zone


def _get_relative_name_for_dns_zone(domain, base_dns_zone):
    # Strip the base dns zone name from a domain such that it's suitable for DNS manipulation relative to a defined zone
    # For example, assuming base_dns_zone is "example.tld":
    #    example.tld -> @
    #    foo.example.tld -> foo
    #    .foo.example.tld -> foo
    #    bar.foo.example.tld -> bar.foo
    return (
        re.sub(r"\.?" + base_dns_zone.replace(".", r"\.") + "$", "", domain.strip("."))
        or "@"
    )


def _get_registrar_config_section(domain):
    from lexicon.providers.auto import _relevant_provider_for_domain

    registrar_infos = OrderedDict(
        {
            "name": m18n.n(
                "registrar_infos"
            ),  # This is meant to name the config panel section, for proper display in the webadmin
            "registrar": OrderedDict(
                {
                    "readonly": True,
                    "visible": False,
                    "default": None,
                }
            ),
            "infos": OrderedDict(
                {
                    "type": "alert",
                    "style": "info",
                }
            ),
        }
    )

    dns_zone = _get_dns_zone_for_domain(domain)

    # If parent domain exists in yunohost
    parent_domain = _get_parent_domain_of(domain, topest=True)
    if parent_domain:
        # Dirty hack to have a link on the webadmin
        if Moulinette.interface.type == "api":
            parent_domain_link = f"[{parent_domain}](#/domains/{parent_domain}/dns)"
        else:
            parent_domain_link = parent_domain

        registrar_infos["registrar"]["default"] = "parent_domain"
        registrar_infos["infos"]["ask"] = m18n.n(
            "domain_dns_registrar_managed_in_parent_domain",
            parent_domain=parent_domain,
            parent_domain_link=parent_domain_link,
        )
        return registrar_infos

    # TODO big project, integrate yunohost's dynette as a registrar-like provider
    # TODO big project, integrate other dyndns providers such as netlib.re, or cf the list of dyndns providers supported by cloudron...
    if is_yunohost_dyndns_domain(dns_zone):
        registrar_infos["registrar"]["default"] = "yunohost"
        registrar_infos["infos"]["style"] = "success"
        registrar_infos["infos"]["ask"] = m18n.n("domain_dns_registrar_yunohost")
        registrar_infos["recovery_password"] = OrderedDict(
            {
                "type": "password",
                "ask": m18n.n("ask_dyndns_recovery_password"),
                "default": "",
            }
        )

        return registrar_infos

    elif is_special_use_tld(dns_zone):
        registrar_infos["infos"]["ask"] = m18n.n("domain_dns_conf_special_use_tld")

        return registrar_infos

    try:
        registrar = _relevant_provider_for_domain(dns_zone)[0]
    except ValueError:
        registrar_infos["registrar"]["default"] = None
        registrar_infos["infos"]["ask"] = m18n.n("domain_dns_registrar_not_supported")
        registrar_infos["infos"]["style"] = "warning"
    else:
        registrar_infos["registrar"]["default"] = registrar
        registrar_infos["infos"]["ask"] = m18n.n(
            "domain_dns_registrar_supported", registrar=registrar
        )

        TESTED_REGISTRARS = ["ovh", "gandi"]
        if registrar not in TESTED_REGISTRARS:
            registrar_infos["experimental_disclaimer"] = OrderedDict(
                {
                    "type": "alert",
                    "style": "danger",
                    "ask": m18n.n(
                        "domain_dns_registrar_experimental", registrar=registrar
                    ),
                }
            )

        # TODO : add a help tip with the link to the registar's API doc (c.f. Lexicon's README)
        registrar_list = read_toml(DOMAIN_REGISTRAR_LIST_PATH)
        registrar_credentials = registrar_list.get(registrar)
        if registrar_credentials is None:
            logger.warning(
                f"Registrar {registrar} unknown / Should be added to YunoHost's registrar_list.toml by the development team!"
            )
            registrar_credentials = {}
        else:
            registrar_infos["use_auto_dns"] = {
                "type": "boolean",
                "ask": m18n.n("domain_dns_registrar_use_auto"),
                "default": True,
            }
        for credential, infos in registrar_credentials.items():
            infos["default"] = infos.get("default", "")
            infos["visible"] = "use_auto_dns == true"
        registrar_infos.update(registrar_credentials)

    return registrar_infos


def _get_registar_settings(domain):
    _assert_domain_exists(domain)

    settings = domain_config_get(domain, key="dns.registrar", export=True)

    registrar = settings.pop("registrar")

    if "experimental_disclaimer" in settings:
        settings.pop("experimental_disclaimer")

    return registrar, settings


@is_unit_operation()
def domain_dns_push(operation_logger, domain, dry_run=False, force=False, purge=False):
    """
    Send DNS records to the previously-configured registrar of the domain.
    """

    from lexicon.client import Client as LexiconClient
    from lexicon.config import ConfigResolver as LexiconConfigResolver

    registrar, registrar_credentials = _get_registar_settings(domain)

    _assert_domain_exists(domain)

    if is_special_use_tld(domain):
        raise YunohostValidationError("domain_dns_conf_special_use_tld")

    if not registrar or registrar == "None":  # yes it's None as a string
        raise YunohostValidationError("domain_dns_push_not_applicable", domain=domain)

    # FIXME: in the future, properly unify this with yunohost dyndns update
    if registrar == "yunohost":
        from yunohost.dyndns import dyndns_update

        dyndns_update(domain=domain, force=force)
        return {}

    if registrar == "parent_domain":
        parent_domain = _get_parent_domain_of(domain, topest=True)
        registrar, registrar_credentials = _get_registar_settings(parent_domain)
        if any(registrar_credentials.values()):
            raise YunohostValidationError(
                "domain_dns_push_managed_in_parent_domain",
                domain=domain,
                parent_domain=parent_domain,
            )
        else:
            new_parent_domain = ".".join(parent_domain.split(".")[-3:])
            registrar, registrar_credentials = _get_registar_settings(new_parent_domain)
            if registrar == "yunohost":
                raise YunohostValidationError(
                    "domain_dns_push_managed_in_parent_domain",
                    domain=domain,
                    parent_domain=new_parent_domain,
                )
            else:
                raise YunohostValidationError(
                    "domain_registrar_is_not_configured", domain=parent_domain
                )

    if not all(registrar_credentials.values()):
        raise YunohostValidationError(
            "domain_registrar_is_not_configured", domain=domain
        )

    base_dns_zone = _get_dns_zone_for_domain(domain)

    # Convert the generated conf into a format that matches what we'll fetch using the API
    # Makes it easier to compare "wanted records" with "current records on remote"
    wanted_records = []
    for records in _build_dns_conf(domain).values():
        for record in records:
            # Make sure the name is a FQDN
            name = (
                f"{record['name']}.{base_dns_zone}"
                if record["name"] != "@"
                else base_dns_zone
            )
            type_ = record["type"]
            content = record["value"]

            # Make sure the content is also a FQDN (with trailing . ?)
            if content == "@" and record["type"] == "CNAME":
                content = base_dns_zone + "."

            wanted_records.append(
                {"name": name, "type": type_, "ttl": record["ttl"], "content": content}
            )

    # FIXME Lexicon does not support CAA records
    # See https://github.com/AnalogJ/lexicon/issues/282 and https://github.com/AnalogJ/lexicon/pull/371
    # They say it's trivial to implement it!
    # And yet, it is still not done/merged
    # Update by Aleks: it works - at least with Gandi ?!
    # wanted_records = [record for record in wanted_records if record["type"] != "CAA"]

    if purge:
        wanted_records = []
        force = True

    # Construct the base data structure to use lexicon's API.

    base_config = {
        "provider_name": registrar,
        "domain": base_dns_zone,
        registrar: registrar_credentials,
    }

    # Ugly hack to be able to fetch all record types at once:
    # we initialize a LexiconClient with a dummy type "all"
    # (which lexicon doesnt actually understands)
    # then trigger ourselves the authentication + list_records
    # instead of calling .execute()
    query = (
        LexiconConfigResolver()
        .with_dict(dict_object=base_config)
        .with_dict(dict_object={"action": "list", "type": "all"})
    )
    client = LexiconClient(query)
    try:
        client.provider.authenticate()
    except Exception as e:
        raise YunohostValidationError(
            "domain_dns_push_failed_to_authenticate", domain=domain, error=str(e)
        )

    try:
        current_records = client.provider.list_records()
    except Exception as e:
        raise YunohostError("domain_dns_push_failed_to_list", error=str(e))

    managed_dns_records_hashes = _get_managed_dns_records_hashes(domain)

    # Keep only records for relevant types: A, AAAA, MX, TXT, CNAME, SRV
    relevant_types = ["A", "AAAA", "MX", "TXT", "CNAME", "SRV", "CAA"]
    current_records = [r for r in current_records if r["type"] in relevant_types]

    # Ignore records which are for a higher-level domain
    # i.e. we don't care about the records for domain.tld when pushing yuno.domain.tld
    current_records = [
        r
        for r in current_records
        if r["name"].endswith(f".{domain}") or r["name"] == domain
    ]

    for record in current_records:
        # Try to get rid of weird stuff like ".domain.tld" or "@.domain.tld"
        record["name"] = record["name"].strip("@").strip(".")

        # Some API return '@' in content and we shall convert it to absolute/fqdn
        record["content"] = (
            record["content"]
            .replace("@.", base_dns_zone + ".")
            .replace("@", base_dns_zone + ".")
        )

        if record["type"] == "TXT":
            if not record["content"].startswith('"'):
                record["content"] = '"' + record["content"]
            if not record["content"].endswith('"'):
                record["content"] = record["content"] + '"'

        # Check if this record was previously set by YunoHost
        record["managed_by_yunohost"] = (
            _hash_dns_record(record) in managed_dns_records_hashes
        )

    # Step 0 : Get the list of unique (type, name)
    # And compare the current and wanted records
    #
    # i.e. we want this kind of stuff:
    #                         wanted             current
    # (A, .domain.tld)        1.2.3.4           1.2.3.4
    # (A, www.domain.tld)     1.2.3.4           5.6.7.8
    # (A, foobar.domain.tld)  1.2.3.4
    # (AAAA, .domain.tld)                      2001::abcd
    # (MX, .domain.tld)      10 domain.tld     [10 mx1.ovh.net, 20 mx2.ovh.net]
    # (TXT, .domain.tld)     "v=spf1 ..."      ["v=spf1", "foobar"]
    # (SRV, .domain.tld)                       0 5 5269 domain.tld
    changes = {"delete": [], "update": [], "create": [], "unchanged": []}

    type_and_names = sorted(
        {(r["type"], r["name"]) for r in current_records + wanted_records}
    )
    comparison = {
        type_and_name: {"current": [], "wanted": []} for type_and_name in type_and_names
    }

    for record in current_records:
        comparison[(record["type"], record["name"])]["current"].append(record)

    for record in wanted_records:
        comparison[(record["type"], record["name"])]["wanted"].append(record)

    for type_and_name, records in comparison.items():
        #
        # Step 1 : compute a first "diff" where we remove records which are the same on both sides
        #
        wanted_contents = [r["content"] for r in records["wanted"]]
        current_contents = [r["content"] for r in records["current"]]

        current = [r for r in records["current"] if r["content"] not in wanted_contents]
        wanted = [r for r in records["wanted"] if r["content"] not in current_contents]

        #
        # Step 2 : simple case: 0 record on one side, 0 on the other
        #           -> either nothing do (0/0) or creations (0/N) or deletions (N/0)
        #
        if len(current) == 0 and len(wanted) == 0:
            # No diff, nothing to do
            changes["unchanged"].extend(records["current"])
            continue

        elif len(wanted) == 0:
            changes["delete"].extend(current)
            continue

        elif len(current) == 0:
            changes["create"].extend(wanted)
            continue

        #
        # Step 3 : N record on one side, M on the other
        #
        # Fuzzy matching strategy:
        # For each wanted record, try to find a current record which looks like the wanted one
        #   -> if found, trigger an update
        #   -> if no match found, trigger a create
        #
        for record in wanted:

            def likeliness(r):
                # We compute this only on the first 100 chars, to have a high value even for completely different DKIM keys
                return SequenceMatcher(
                    None, r["content"][:100], record["content"][:100]
                ).ratio()

            matches = sorted(current, key=lambda r: likeliness(r), reverse=True)
            if matches and likeliness(matches[0]) > 0.50:
                match = matches[0]
                # Remove the match from 'current' so that it's not added to the removed stuff later
                current.remove(match)
                match["old_content"] = match["content"]
                match["content"] = record["content"]
                changes["update"].append(match)
            else:
                changes["create"].append(record)

        #
        # For all other remaining current records:
        #        -> trigger deletions
        #
        for record in current:
            changes["delete"].append(record)

    def human_readable_record(action, record):
        name = record["name"]
        name = _get_relative_name_for_dns_zone(record["name"], base_dns_zone)
        name = name[:20]
        t = record["type"]

        if not force and action in ["update", "delete"]:
            ignored = (
                ""
                if record["managed_by_yunohost"]
                else "(ignored, won't be changed by Yunohost unless forced)"
            )
        else:
            ignored = ""

        if action == "create":
            new_content = record.get("content", "(None)")[:30]
            return f"{name:>20} [{t:^5}] {new_content:^30}  {ignored}"
        elif action == "update":
            old_content = record.get("old_content", "(None)")[:30]
            new_content = record.get("content", "(None)")[:30]
            return (
                f"{name:>20} [{t:^5}] {old_content:^30} -> {new_content:^30}  {ignored}"
            )
        elif action == "unchanged":
            old_content = record.get("content", "(None)")[:30]
            return f"{name:>20} [{t:^5}] {old_content:^30}"
        else:
            old_content = record.get("content", "(None)")[:30]
            return f"{name:>20} [{t:^5}] {old_content:^30} {ignored}"

    if dry_run:
        if Moulinette.interface.type == "api":
            for records in changes.values():
                for record in records:
                    record["name"] = _get_relative_name_for_dns_zone(
                        record["name"], base_dns_zone
                    )
            return changes
        else:
            out = {"delete": [], "create": [], "update": [], "unchanged": []}
            for action in ["delete", "create", "update", "unchanged"]:
                for record in changes[action]:
                    out[action].append(human_readable_record(action, record))

            return out

    # If --force ain't used, we won't delete/update records not managed by yunohost
    if not force:
        for action in ["delete", "update"]:
            changes[action] = [r for r in changes[action] if r["managed_by_yunohost"]]

    def progress(info=""):
        progress.nb += 1
        width = 20
        bar = int(progress.nb * width / progress.total)
        bar = "[" + "#" * bar + "." * (width - bar) + "]"
        if info:
            bar += " > " + info
        if progress.old == bar:
            return
        progress.old = bar
        logger.info(bar)

    progress.nb = 0
    progress.old = ""
    progress.total = len(changes["delete"] + changes["create"] + changes["update"])

    if progress.total == 0:
        logger.success(m18n.n("domain_dns_push_already_up_to_date"))
        return {}

    #
    # Actually push the records
    #

    operation_logger.start()
    logger.info(m18n.n("domain_dns_pushing"))

    new_managed_dns_records_hashes = [_hash_dns_record(r) for r in changes["unchanged"]]
    results = {"warnings": [], "errors": []}

    for action in ["delete", "create", "update"]:
        for record in changes[action]:
            relative_name = _get_relative_name_for_dns_zone(
                record["name"], base_dns_zone
            )
            progress(
                f"{action} {record['type']:^5} / {relative_name}"
            )  # FIXME: i18n but meh

            # Apparently Lexicon yields us some 'id' during fetch
            # But wants 'identifier' during push ...
            if "id" in record:
                record["identifier"] = record["id"]
                del record["id"]

            if registrar == "godaddy":
                if record["name"] == base_dns_zone:
                    record["name"] = "@." + record["name"]
                if record["type"] in ["MX", "SRV", "CAA"]:
                    logger.warning(
                        f"Pushing {record['type']} records is not properly supported by Lexicon/Godaddy."
                    )
                    results["warnings"].append(
                        f"Pushing {record['type']} records is not properly supported by Lexicon/Godaddy."
                    )
                    continue
            elif registrar == "gandi":
                if record["name"] == base_dns_zone:
                    record["name"] = "@." + record["name"]

            record["action"] = action
            query = (
                LexiconConfigResolver()
                .with_dict(dict_object=base_config)
                .with_dict(dict_object=record)
            )

            try:
                result = LexiconClient(query).execute()
            except Exception as e:
                msg = m18n.n(
                    "domain_dns_push_record_failed",
                    action=action,
                    type=record["type"],
                    name=record["name"],
                    error=str(e),
                )
                logger.error(msg)
                results["errors"].append(msg)
            else:
                if result:
                    new_managed_dns_records_hashes.append(_hash_dns_record(record))
                else:
                    msg = m18n.n(
                        "domain_dns_push_record_failed",
                        action=action,
                        type=record["type"],
                        name=record["name"],
                        error="unkonwn error?",
                    )
                    logger.error(msg)
                    results["errors"].append(msg)

    _set_managed_dns_records_hashes(domain, new_managed_dns_records_hashes)

    # Everything succeeded
    if len(results["errors"]) + len(results["warnings"]) == 0:
        logger.success(m18n.n("domain_dns_push_success"))
        return {}
    # Everything failed
    elif len(results["errors"]) + len(results["warnings"]) == progress.total:
        logger.error(m18n.n("domain_dns_push_failed"))
    else:
        logger.warning(m18n.n("domain_dns_push_partial_failure"))

    return results


def _get_managed_dns_records_hashes(domain: str) -> list:
    return _get_domain_settings(domain).get("managed_dns_records_hashes", [])


def _set_managed_dns_records_hashes(domain: str, hashes: list) -> None:
    settings = _get_domain_settings(domain)
    settings["managed_dns_records_hashes"] = hashes or []
    _set_domain_settings(domain, settings)


def _hash_dns_record(record: dict) -> int:
    fields = ["name", "type", "content"]
    record_ = {f: record.get(f) for f in fields}

    return hash(frozenset(record_.items()))
