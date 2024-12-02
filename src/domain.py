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
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Optional, Union
from collections import OrderedDict
from logging import getLogger

from moulinette import m18n, Moulinette
from moulinette.core import MoulinetteError
from moulinette.utils.filesystem import (
    read_json,
    read_yaml,
    rm,
    read_file,
    write_to_file,
    write_to_json,
    write_to_yaml,
)

from yunohost.regenconf import regen_conf, _force_clear_hashes, _process_regen_conf
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.log import is_unit_operation

if TYPE_CHECKING:
    from pydantic.typing import AbstractSetIntStr, MappingIntStrAny

    from yunohost.utils.configpanel import RawConfig
    from yunohost.utils.form import FormModel, ConfigPanelModel
    from yunohost.utils.configpanel import RawSettings

logger = getLogger("yunohost.domain")

DOMAIN_SETTINGS_DIR = "/etc/yunohost/domains"

# Lazy dev caching to avoid re-query ldap every time we need the domain list
# The cache automatically expire every 15 seconds, to prevent desync between
#  yunohost CLI and API which run in different processes
domain_list_cache: List[str] = []
domain_list_cache_timestamp = 0
main_domain_cache: Optional[str] = None
main_domain_cache_timestamp = 0
DOMAIN_CACHE_DURATION = 15


def _get_maindomain():
    global main_domain_cache
    global main_domain_cache_timestamp
    if (
        not main_domain_cache
        or abs(main_domain_cache_timestamp - time.time()) > DOMAIN_CACHE_DURATION
    ):
        with open("/etc/yunohost/current_host", "r") as f:
            main_domain_cache = f.readline().rstrip()
        main_domain_cache_timestamp = time.time()

    return main_domain_cache


def _get_domains(exclude_subdomains=False):
    global domain_list_cache
    global domain_list_cache_timestamp
    if (
        not domain_list_cache
        or abs(domain_list_cache_timestamp - time.time()) > DOMAIN_CACHE_DURATION
    ):
        from yunohost.utils.ldap import _get_ldap_interface

        ldap = _get_ldap_interface()
        result = [
            entry["virtualdomain"][0]
            for entry in ldap.search("ou=domains", "virtualdomain=*", ["virtualdomain"])
        ]

        def cmp_domain(domain):
            # Keep the main part of the domain and the extension together
            # eg: this.is.an.example.com -> ['example.com', 'an', 'is', 'this']
            domain = domain.split(".")
            domain[-1] = domain[-2] + domain.pop()
            return list(reversed(domain))

        domain_list_cache = sorted(result, key=cmp_domain)
        domain_list_cache_timestamp = time.time()

    if exclude_subdomains:
        return [
            domain for domain in domain_list_cache if not _get_parent_domain_of(domain)
        ]

    return domain_list_cache


def _get_domain_portal_dict():

    domains = _get_domains()
    out = OrderedDict()

    for domain in domains:

        parent = None

        # Use the topest parent domain if any
        for d in out.keys():
            if domain.endswith(f".{d}"):
                parent = d
                break

        out[domain] = f"{parent or domain}/yunohost/sso"

    # By default, redirect to $host/yunohost/admin for domains not listed in the dict
    # maybe in the future, we can allow to tweak this
    out["default"] = "/yunohost/admin"

    return dict(out)


def domain_list(exclude_subdomains=False, tree=False, features=[]):
    """
    List domains

    Keyword argument:
        exclude_subdomains -- Filter out domains that are subdomains of other declared domains
        tree -- Display domains as a hierarchy tree

    """

    domains = _get_domains(exclude_subdomains)
    main = _get_maindomain()

    if features:
        domains_filtered = []
        for domain in domains:
            config = domain_config_get(domain, key="feature", export=True)
            if any(config.get(feature) == 1 for feature in features):
                domains_filtered.append(domain)
        domains = domains_filtered

    if not tree:
        return {"domains": domains, "main": main}

    if tree and exclude_subdomains:
        return {
            "domains": OrderedDict({domain: {} for domain in domains}),
            "main": main,
        }

    def get_parent_dict(tree, child):
        # If parent exists it should be the last added (see `_get_domains` ordering)
        possible_parent = next(reversed(tree)) if tree else None
        if possible_parent and child.endswith(f".{possible_parent}"):
            return get_parent_dict(tree[possible_parent], child)
        return tree

    result = OrderedDict()
    for domain in domains:
        parent = get_parent_dict(result, domain)
        parent[domain] = OrderedDict()

    return {"domains": result, "main": main}


def domain_info(domain):
    """
    Print aggregate data for a specific domain

    Keyword argument:
        domain     -- Domain to be checked
    """

    from yunohost.app import app_info, _installed_apps, _get_app_settings
    from yunohost.dns import _get_registar_settings
    from yunohost.certificate import certificate_status

    _assert_domain_exists(domain)

    registrar, _ = _get_registar_settings(domain)
    certificate = certificate_status([domain], full=True)["certificates"][domain]

    apps = []
    for app in _installed_apps():
        settings = _get_app_settings(app)
        if settings.get("domain") == domain:
            apps.append(
                {
                    "name": app_info(app)["name"],
                    "id": app,
                    "path": settings.get("path", ""),
                }
            )

    return {
        "certificate": certificate,
        "registrar": registrar,
        "apps": apps,
        "main": _get_maindomain() == domain,
        "topest_parent": _get_parent_domain_of(domain, topest=True),
        # TODO : add parent / child domains ?
    }


def _assert_domain_exists(domain):
    if domain not in _get_domains():
        raise YunohostValidationError("domain_unknown", domain=domain)


def _list_subdomains_of(parent_domain):
    _assert_domain_exists(parent_domain)

    out = []
    for domain in _get_domains():
        if domain.endswith(f".{parent_domain}"):
            out.append(domain)

    return out


def _get_parent_domain_of(domain, return_self=False, topest=False):
    domains = _get_domains(exclude_subdomains=topest)

    domain_ = domain
    while "." in domain_:
        domain_ = domain_.split(".", 1)[1]
        if domain_ in domains:
            return domain_

    return domain if return_self else None


@is_unit_operation(exclude=["dyndns_recovery_password"])
def domain_add(
    operation_logger,
    domain,
    dyndns_recovery_password=None,
    ignore_dyndns=False,
    install_letsencrypt_cert=False,
    skip_tos=False,
):
    """
    Create a custom domain

    Keyword argument:
        domain -- Domain name to add
        dyndns -- Subscribe to DynDNS
        dyndns_recovery_password -- Password used to later unsubscribe from DynDNS
        ignore_dyndns -- If we want to just add the DynDNS domain to the list, without subscribing
        install_letsencrypt_cert -- If adding a subdomain of an already added domain, try to install a Let's Encrypt certificate
    """
    from yunohost.hook import hook_callback
    from yunohost.app import app_ssowatconf
    from yunohost.utils.ldap import _get_ldap_interface
    from yunohost.utils.password import assert_password_is_strong_enough
    from yunohost.certificate import (
        _certificate_install_letsencrypt,
        _certificate_install_selfsigned,
        certificate_status,
    )
    from yunohost.utils.dns import is_yunohost_dyndns_domain

    if dyndns_recovery_password:
        operation_logger.data_to_redact.append(dyndns_recovery_password)

    ldap = _get_ldap_interface()

    try:
        ldap.validate_uniqueness({"virtualdomain": domain})
    except MoulinetteError:
        raise YunohostValidationError("domain_exists")

    # Lower domain to avoid some edge cases issues
    # See: https://forum.yunohost.org/t/invalid-domain-causes-diagnosis-web-to-fail-fr-on-demand/11765
    domain = domain.lower()

    # Non-latin characters (e.g. café.com => xn--caf-dma.com)
    domain = domain.encode("idna").decode("utf-8")

    # Detect if this is a DynDNS domain ( and not a subdomain of a DynDNS domain )
    dyndns = (
        not ignore_dyndns
        and is_yunohost_dyndns_domain(domain)
        and len(domain.split(".")) == 3
    )
    if dyndns:
        from yunohost.app import _ask_confirmation
        from yunohost.dyndns import is_subscribing_allowed

        # Do not allow to subscribe to multiple dyndns domains...
        if not is_subscribing_allowed():
            raise YunohostValidationError("domain_dyndns_already_subscribed")

        if not skip_tos and Moulinette.interface.type == "cli" and os.isatty(1):
            Moulinette.display(m18n.n("tos_dyndns_acknowledgement"), style="warning")
            _ask_confirmation("confirm_tos_acknowledgement", kind="soft")

        if dyndns_recovery_password:
            assert_password_is_strong_enough("admin", dyndns_recovery_password)

    operation_logger.start()

    if dyndns:
        domain_dyndns_subscribe(
            domain=domain, recovery_password=dyndns_recovery_password
        )

    _certificate_install_selfsigned([domain], force=True)

    try:
        attr_dict = {
            "objectClass": ["mailDomain", "top"],
            "virtualdomain": domain,
        }

        try:
            ldap.add(f"virtualdomain={domain},ou=domains", attr_dict)
        except Exception as e:
            raise YunohostError("domain_creation_failed", domain=domain, error=e)
        finally:
            global domain_list_cache
            domain_list_cache = []

        # Don't regen these conf if we're still in postinstall
        if os.path.exists("/etc/yunohost/installed"):
            # Sometime we have weird issues with the regenconf where some files
            # appears as manually modified even though they weren't touched ...
            # There are a few ideas why this happens (like backup/restore nginx
            # conf ... which we shouldnt do ...). This in turns creates funky
            # situation where the regenconf may refuse to re-create the conf
            # (when re-creating a domain..)
            # So here we force-clear the has out of the regenconf if it exists.
            # This is a pretty ad hoc solution and only applied to nginx
            # because it's one of the major service, but in the long term we
            # should identify the root of this bug...
            _force_clear_hashes([f"/etc/nginx/conf.d/{domain}.conf"])
            regen_conf(
                names=[
                    "nginx",
                    "dnsmasq",
                    "postfix",
                    "mdns",
                    "dovecot",
                ]
            )
            app_ssowatconf()

    except Exception as e:
        # Force domain removal silently
        try:
            domain_remove(domain, force=True)
        except Exception:
            pass
        raise e

    failed_letsencrypt_cert_install = False
    if install_letsencrypt_cert:
        parent_domain = _get_parent_domain_of(domain)
        can_install_letsencrypt = (
            parent_domain
            and certificate_status([parent_domain], full=True)["certificates"][
                parent_domain
            ]["has_wildcards"]
        )

        if can_install_letsencrypt:
            try:
                _certificate_install_letsencrypt([domain], force=True, no_checks=True)
            except Exception:
                failed_letsencrypt_cert_install = True
        else:
            logger.warning(
                "Skipping Let's Encrypt certificate attempt because there's no wildcard configured on the parent domain's DNS records."
            )
            failed_letsencrypt_cert_install = True

    hook_callback("post_domain_add", args=[domain])

    logger.success(m18n.n("domain_created"))

    if failed_letsencrypt_cert_install:
        logger.warning(m18n.n("certmanager_cert_install_failed", domains=domain))


@is_unit_operation(exclude=["dyndns_recovery_password"])
def domain_remove(
    operation_logger,
    domain,
    remove_apps=False,
    force=False,
    dyndns_recovery_password=None,
    ignore_dyndns=False,
):
    """
    Delete domains

    Keyword argument:
        domain -- Domain to delete
        remove_apps -- Remove applications installed on the domain
        force -- Force the domain removal and don't not ask confirmation to
                 remove apps if remove_apps is specified
        dyndns_recovery_password -- Recovery password used at the creation of the DynDNS domain
        ignore_dyndns -- If we just remove the DynDNS domain, without unsubscribing
    """
    import glob
    from yunohost.hook import hook_callback
    from yunohost.app import (
        app_ssowatconf,
        app_info,
        app_remove,
        _get_app_settings,
        _installed_apps,
    )
    from yunohost.utils.ldap import _get_ldap_interface
    from yunohost.utils.dns import is_yunohost_dyndns_domain

    if dyndns_recovery_password:
        operation_logger.data_to_redact.append(dyndns_recovery_password)

    # the 'force' here is related to the exception happening in domain_add ...
    # we don't want to check the domain exists because the ldap add may have
    # failed
    if not force:
        _assert_domain_exists(domain)

    # Check domain is not the main domain
    if domain == _get_maindomain():
        other_domains = _get_domains()
        other_domains.remove(domain)

        if other_domains:
            raise YunohostValidationError(
                "domain_cannot_remove_main",
                domain=domain,
                other_domains="\n * " + ("\n * ".join(other_domains)),
            )
        else:
            raise YunohostValidationError(
                "domain_cannot_remove_main_add_new_one", domain=domain
            )

    # Check if apps are installed on the domain
    apps_on_that_domain = []

    for app in _installed_apps():
        settings = _get_app_settings(app)
        label = app_info(app)["name"]
        if settings.get("domain") == domain:
            apps_on_that_domain.append(
                (
                    app,
                    (
                        f"    - {app} \"{label}\" on https://{domain}{settings['path']}"
                        if "path" in settings
                        else app
                    ),
                )
            )

    if apps_on_that_domain:
        if remove_apps:
            if Moulinette.interface.type == "cli" and not force:
                answer = Moulinette.prompt(
                    m18n.n(
                        "domain_remove_confirm_apps_removal",
                        apps="\n".join([x[1] for x in apps_on_that_domain]),
                        answers="y/N",
                    ),
                    color="yellow",
                )
                if answer.upper() != "Y":
                    raise YunohostError("aborting")

            for app, _ in apps_on_that_domain:
                app_remove(app)
        else:
            raise YunohostValidationError(
                "domain_uninstall_app_first",
                apps="\n".join([x[1] for x in apps_on_that_domain]),
            )

    # Detect if this is a DynDNS domain ( and not a subdomain of a DynDNS domain )
    dyndns = (
        not ignore_dyndns
        and is_yunohost_dyndns_domain(domain)
        and len(domain.split(".")) == 3
    )

    operation_logger.start()

    ldap = _get_ldap_interface()
    try:
        ldap.remove("virtualdomain=" + domain + ",ou=domains")
    except Exception as e:
        raise YunohostError("domain_deletion_failed", domain=domain, error=e)
    finally:
        global domain_list_cache
        domain_list_cache = []

    # If a password is provided, delete the DynDNS record
    if dyndns:
        try:
            # Actually unsubscribe
            domain_dyndns_unsubscribe(
                domain=domain, recovery_password=dyndns_recovery_password
            )
        except Exception as e:
            logger.warning(str(e))

    rm(f"/etc/yunohost/certs/{domain}", force=True, recursive=True)
    for key_file in glob.glob(f"/etc/yunohost/dyndns/K{domain}.+*"):
        rm(key_file, force=True)
    rm(f"{DOMAIN_SETTINGS_DIR}/{domain}.yml", force=True)

    # Sometime we have weird issues with the regenconf where some files
    # appears as manually modified even though they weren't touched ...
    # There are a few ideas why this happens (like backup/restore nginx
    # conf ... which we shouldnt do ...). This in turns creates funky
    # situation where the regenconf may refuse to re-create the conf
    # (when re-creating a domain..)
    #
    # So here we force-clear the has out of the regenconf if it exists.
    # This is a pretty ad hoc solution and only applied to nginx
    # because it's one of the major service, but in the long term we
    # should identify the root of this bug...
    _force_clear_hashes([f"/etc/nginx/conf.d/{domain}.conf"])
    # And in addition we even force-delete the file Otherwise, if the file was
    # manually modified, it may not get removed by the regenconf which leads to
    # catastrophic consequences of nginx breaking because it can't load the
    # cert file which disappeared etc..
    if os.path.exists(f"/etc/nginx/conf.d/{domain}.conf"):
        _process_regen_conf(
            f"/etc/nginx/conf.d/{domain}.conf", new_conf=None, save=True
        )

    regen_conf(names=["nginx", "dnsmasq", "postfix", "mdns"])
    app_ssowatconf()

    hook_callback("post_domain_remove", args=[domain])

    logger.success(m18n.n("domain_deleted"))


def domain_dyndns_subscribe(*args, **kwargs):
    """
    Subscribe to a DynDNS domain
    """
    from yunohost.dyndns import dyndns_subscribe

    dyndns_subscribe(*args, **kwargs)


def domain_dyndns_unsubscribe(*args, **kwargs):
    """
    Unsubscribe from a DynDNS domain
    """
    from yunohost.dyndns import dyndns_unsubscribe

    dyndns_unsubscribe(*args, **kwargs)


def domain_dyndns_list():
    """
    Returns all currently subscribed DynDNS domains
    """
    from yunohost.dyndns import dyndns_list

    return dyndns_list()


def domain_dyndns_update(*args, **kwargs):
    """
    Update a DynDNS domain
    """
    from yunohost.dyndns import dyndns_update

    dyndns_update(*args, **kwargs)


def domain_dyndns_set_recovery_password(*args, **kwargs):
    """
    Set a recovery password for an already registered dyndns domain
    """
    from yunohost.dyndns import dyndns_set_recovery_password

    dyndns_set_recovery_password(*args, **kwargs)


@is_unit_operation()
def domain_main_domain(operation_logger, new_main_domain=None):
    """
    Check the current main domain, or change it

    Keyword argument:
        new_main_domain -- The new domain to be set as the main domain

    """
    from yunohost.tools import _set_hostname

    # If no new domain specified, we return the current main domain
    if not new_main_domain:
        return {"current_main_domain": _get_maindomain()}

    old_main_domain = _get_maindomain()

    # Check domain exists
    _assert_domain_exists(new_main_domain)

    operation_logger.related_to.append(("domain", new_main_domain))
    operation_logger.start()

    # Apply changes to ssl certs
    try:
        write_to_file("/etc/yunohost/current_host", new_main_domain)
        global main_domain_cache
        main_domain_cache = new_main_domain
        _set_hostname(new_main_domain)
    except Exception as e:
        logger.warning(str(e), exc_info=1)
        raise YunohostError("main_domain_change_failed")

    # Regen configurations
    if os.path.exists("/etc/yunohost/installed"):
        regen_conf()

        from yunohost.user import _update_admins_group_aliases

        _update_admins_group_aliases(
            old_main_domain=old_main_domain, new_main_domain=new_main_domain
        )

    logger.success(m18n.n("main_domain_changed"))


def domain_url_available(domain, path):
    """
    Check availability of a web path

    Keyword argument:
        domain -- The domain for the web path (e.g. your.domain.tld)
        path -- The path to check (e.g. /coffee)
    """

    from yunohost.app import _get_conflicting_apps

    return len(_get_conflicting_apps(domain, path)) == 0


def _get_raw_domain_settings(domain):
    """Get domain settings directly from file.
    Be carefull, domain settings are saved in `"diff"` mode (i.e. default settings are not saved)
    so the file may be completely empty
    """
    _assert_domain_exists(domain)
    # NB: this corresponds to save_path_tpl in DomainConfigPanel
    path = f"{DOMAIN_SETTINGS_DIR}/{domain}.yml"
    if os.path.exists(path):
        return read_yaml(path)

    return {}


def domain_config_get(domain, key="", full=False, export=False):
    """
    Display a domain configuration
    """

    if full and export:
        raise YunohostValidationError(
            "You can't use --full and --export together.", raw_msg=True
        )

    if full:
        mode = "full"
    elif export:
        mode = "export"
    else:
        mode = "classic"

    DomainConfigPanel = _get_DomainConfigPanel()
    config = DomainConfigPanel(domain)
    return config.get(key, mode)


@is_unit_operation()
def domain_config_set(
    operation_logger, domain, key=None, value=None, args=None, args_file=None
):
    """
    Apply a new domain configuration
    """
    from yunohost.utils.form import BaseOption

    DomainConfigPanel = _get_DomainConfigPanel()
    BaseOption.operation_logger = operation_logger
    config = DomainConfigPanel(domain)
    return config.set(key, value, args, args_file, operation_logger=operation_logger)


def _get_DomainConfigPanel():
    from yunohost.utils.configpanel import ConfigPanel
    from yunohost.dns import _set_managed_dns_records_hashes

    class DomainConfigPanel(ConfigPanel):
        entity_type = "domain"
        save_path_tpl = f"{DOMAIN_SETTINGS_DIR}/{{entity}}.yml"
        save_mode = "diff"

        # i18n: domain_config_cert_renew_help
        # i18n: domain_config_default_app_help

        def _get_raw_config(self) -> "RawConfig":
            # TODO add mechanism to share some settings with other domains on the same zone
            raw_config = super()._get_raw_config()

            any_filter = all(self.filter_key)
            panel_id, section_id, option_id = self.filter_key

            # Portal settings are only available on "topest" domains
            if _get_parent_domain_of(self.entity, topest=True) is not None:
                del raw_config["feature"]["portal"]

            # Optimize wether or not to load the DNS section,
            # e.g. we don't want to trigger the whole _get_registary_config_section
            # when just getting the current value from the feature section
            if not any_filter or panel_id == "dns":
                from yunohost.dns import _get_registrar_config_section

                raw_config["dns"]["registrar"] = _get_registrar_config_section(
                    self.entity
                )

            # Cert stuff
            if not any_filter or panel_id == "cert":
                from yunohost.certificate import certificate_status

                status = certificate_status([self.entity], full=True)["certificates"][
                    self.entity
                ]

                raw_config["cert"]["cert_"]["cert_summary"]["style"] = status["style"]

                # i18n: domain_config_cert_summary_expired
                # i18n: domain_config_cert_summary_selfsigned
                # i18n: domain_config_cert_summary_abouttoexpire
                # i18n: domain_config_cert_summary_ok
                # i18n: domain_config_cert_summary_letsencrypt
                raw_config["cert"]["cert_"]["cert_summary"]["ask"] = m18n.n(
                    f"domain_config_cert_summary_{status['summary']}"
                )

                for option_id, status_key in [
                    ("cert_validity", "validity"),
                    ("cert_issuer", "CA_type"),
                    ("acme_eligible", "ACME_eligible"),
                    # FIXME not sure why "summary" was injected in settings values
                    # ("summary", "summary")
                ]:
                    raw_config["cert"]["cert_"][option_id]["default"] = status[
                        status_key
                    ]

                # Other specific strings used in config panels
                # i18n: domain_config_cert_renew_help

            return raw_config

        def _get_raw_settings(self) -> "RawSettings":
            raw_settings = super()._get_raw_settings()

            custom_css = Path(
                f"/usr/share/yunohost/portal/customassets/{self.entity}.custom.css"
            )
            if custom_css.exists():
                raw_settings["custom_css"] = read_file(str(custom_css))

            return raw_settings

        def _apply(
            self,
            form: "FormModel",
            config: "ConfigPanelModel",
            previous_settings: dict[str, Any],
            exclude: Union["AbstractSetIntStr", "MappingIntStrAny", None] = None,
        ) -> None:
            next_settings = {
                k: v
                for k, v in form.model_dump().items()
                if previous_settings.get(k) != v
            }

            if "default_app" in next_settings:
                from yunohost.app import app_map

                if "/" in app_map(raw=True).get(self.entity, {}):
                    raise YunohostValidationError(
                        "app_make_default_location_already_used",
                        app=next_settings["default_app"],
                        domain=self.entity,
                        other_app=app_map(raw=True)[self.entity]["/"]["id"],
                    )

            if next_settings.get("recovery_password", None):
                domain_dyndns_set_recovery_password(
                    self.entity, next_settings["recovery_password"]
                )

            # NB: this is subtlely different from just checking `next_settings.get("use_auto_dns") since we want to find the exact situation where the admin *disables* the autodns`
            remove_auto_dns_feature = (
                "use_auto_dns" in next_settings and not next_settings["use_auto_dns"]
            )
            if remove_auto_dns_feature:
                # disable auto dns by reseting every registrar form values
                options = [
                    option
                    for option in config.get_section("registrar").options
                    if not option.readonly
                    and option.id != "use_auto_dns"
                    and hasattr(form, option.id)
                ]
                for option in options:
                    setattr(form, option.id, option.default)

            if "custom_css" in next_settings:
                write_to_file(
                    f"/usr/share/yunohost/portal/customassets/{self.entity}.custom.css",
                    next_settings.pop("custom_css", "").strip(),
                )
            # Make sure the value doesnt get written in the yml
            if hasattr(form, "custom_css"):
                form.custom_css = ""

            portal_options = [
                "enable_public_apps_page",
                "show_other_domains_apps",
                "portal_title",
                "portal_logo",
                "portal_theme",
                "portal_tile_theme",
                "search_engine",
                "search_engine_name",
                "portal_user_intro",
                "portal_public_intro",
            ]

            if _get_parent_domain_of(self.entity, topest=True) is None and any(
                option in next_settings for option in portal_options
            ):
                from yunohost.portal import PORTAL_SETTINGS_DIR

                # Portal options are also saved in a `domain.portal.yml` file
                # that can be read by the portal API.
                # FIXME remove those from the config panel saved values?

                portal_values = form.model_dump(include=set(portal_options))
                # Remove logo from values else filename will replace b64 content
                if "portal_logo" in portal_values:
                    portal_values.pop("portal_logo")

                if "portal_logo" in next_settings:
                    if previous_settings.get("portal_logo"):
                        try:
                            os.remove(previous_settings["portal_logo"])
                        except FileNotFoundError:
                            logger.warning(
                                f"Coulnd't remove previous logo file, maybe the file was already deleted, path: {previous_settings['portal_logo']}"
                            )
                        finally:
                            portal_values["portal_logo"] = ""

                    if next_settings["portal_logo"]:
                        portal_values["portal_logo"] = Path(
                            next_settings["portal_logo"]
                        ).name

                portal_settings_path = Path(f"{PORTAL_SETTINGS_DIR}/{self.entity}.json")
                portal_settings: dict[str, Any] = {"apps": {}}

                if portal_settings_path.exists():
                    portal_settings.update(read_json(str(portal_settings_path)))

                # Merge settings since this config file is shared with `app_ssowatconf()` which populate the `apps` key.
                portal_settings.update(portal_values)
                write_to_json(
                    str(portal_settings_path), portal_settings, sort_keys=True, indent=4
                )

            super()._apply(
                form, config, previous_settings, exclude={"recovery_password"}
            )

            # Also remove `managed_dns_records_hashes` in settings which are not handled by the config panel
            if remove_auto_dns_feature:
                _set_managed_dns_records_hashes(self.entity, [])

            # Reload ssowat if default app changed
            if (
                "default_app" in next_settings
                or "enable_public_apps_page" in next_settings
            ):
                from yunohost.app import app_ssowatconf

                app_ssowatconf()

            stuff_to_regen_conf = set()
            if "mail_in" in next_settings or "mail_out" in next_settings:
                stuff_to_regen_conf.update({"nginx", "postfix", "dovecot"})

            if stuff_to_regen_conf:
                regen_conf(names=list(stuff_to_regen_conf))

    return DomainConfigPanel


def domain_action_run(domain, action, args=None):
    import urllib.parse

    if action == "cert.cert_.cert_install":
        from yunohost.certificate import certificate_install as action_func
    elif action == "cert.cert_.cert_renew":
        from yunohost.certificate import certificate_renew as action_func

    args = dict(urllib.parse.parse_qsl(args or "", keep_blank_values=True))
    no_checks = args["cert_no_checks"] in ("y", "yes", "on", "1")

    action_func([domain], force=True, no_checks=no_checks)


def _get_domain_settings(domain: str) -> dict:
    _assert_domain_exists(domain)

    if os.path.exists(f"{DOMAIN_SETTINGS_DIR}/{domain}.yml"):
        return read_yaml(f"{DOMAIN_SETTINGS_DIR}/{domain}.yml") or {}
    else:
        return {}


def _set_domain_settings(domain: str, settings: dict) -> None:
    _assert_domain_exists(domain)

    write_to_yaml(f"{DOMAIN_SETTINGS_DIR}/{domain}.yml", settings)


#
#
# Stuff managed in other files
#
#


def domain_cert_status(domain_list, full=False):
    from yunohost.certificate import certificate_status

    return certificate_status(domain_list, full)


def domain_cert_install(domain_list, force=False, no_checks=False, self_signed=False):
    from yunohost.certificate import certificate_install

    return certificate_install(domain_list, force, no_checks, self_signed)


def domain_cert_renew(domain_list, force=False, no_checks=False, email=False):
    from yunohost.certificate import certificate_renew

    return certificate_renew(domain_list, force, no_checks, email)


def domain_dns_suggest(domain):
    from yunohost.dns import domain_dns_suggest

    return domain_dns_suggest(domain)


def domain_dns_push(domain, dry_run, force, purge):
    from yunohost.dns import domain_dns_push

    return domain_dns_push(domain, dry_run, force, purge)
