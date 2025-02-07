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

import json
import os
import shutil
import socket
import string

import pytest
import requests

from yunohost.app import (
    APPS_SETTING_PATH,
    _get_app_settings,
    _installed_apps,
    _set_app_settings,
    app_change_url,
    app_install,
    app_map,
    app_remove,
    app_upgrade,
)
from yunohost.domain import _get_maindomain, domain_add, domain_list, domain_remove
from yunohost.permission import (
    permission_create,
    permission_delete,
    permission_url,
    user_permission_list,
    user_permission_update,
)
from yunohost.user import (
    user_create,
    user_delete,
    user_group_delete,
    user_group_list,
    user_list,
)

from .conftest import get_test_apps_dir, message, raiseYunohostError

# Get main domain
maindomain = ""
other_domains = []
dummy_password = "test123Ynh"

# Dirty patch of DNS resolution. Force the DNS to 127.0.0.1 address even if dnsmasq have the public address.
# Mainly used for 'can_access_webpage' function

prv_getaddrinfo = socket.getaddrinfo


def _permission_create_with_dummy_app(
    permission,
    allowed=None,
    url=None,
    additional_urls=None,
    auth_header=True,
    show_tile=False,
    protected=True,
    sync_perm=True,
    domain=None,
    path=None,
):
    app = permission.split(".")[0]
    if app not in _installed_apps():
        app_setting_path = os.path.join(APPS_SETTING_PATH, app)
        if not os.path.exists(app_setting_path):
            os.makedirs(app_setting_path)
        settings = {"id": app, "dummy_permission_app": True}
        if domain:
            settings["domain"] = domain
        if path:
            settings["path"] = path
        _set_app_settings(app, settings)

        with open(os.path.join(APPS_SETTING_PATH, app, "manifest.json"), "w") as f:
            json.dump(
                {
                    "name": app,
                    "id": app,
                    "description": {"en": "Dummy app to test permissions"},
                    "arguments": {"install": []},
                },
                f,
            )
    permission_create(
        permission=permission,
        allowed=allowed,
        url=url,
        additional_urls=additional_urls,
        auth_header=auth_header,
        show_tile=show_tile,
        protected=protected,
        sync_perm=sync_perm,
    )


def _clear_dummy_app_settings():
    # Clean dummy app settings
    for app in _installed_apps():
        if _get_app_settings(app).get("dummy_permission_app", False):
            app_setting_path = os.path.join(APPS_SETTING_PATH, app)
            if os.path.exists(app_setting_path):
                shutil.rmtree(app_setting_path)


def clean_user_groups_permission():
    for u in user_list()["users"]:
        user_delete(u, force=True)

    for g in user_group_list()["groups"]:
        if g not in ["all_users", "visitors", "admins"]:
            user_group_delete(g)

    for p in user_permission_list()["permissions"]:
        if any(
            p.startswith(name)
            for name in ["wiki", "blog", "site", "web", "permissions_app"]
        ):
            permission_delete(p, force=True, sync_perm=False)
    socket.getaddrinfo = prv_getaddrinfo


def setup_function(function):
    clean_user_groups_permission()

    global maindomain
    global other_domains
    maindomain = _get_maindomain()

    markers = {
        m.name: {"args": m.args, "kwargs": m.kwargs}
        for m in function.__dict__.get("pytestmark", [])
    }

    if "other_domains" in markers:
        other_domains = [
            "domain_%s.dev" % string.ascii_lowercase[number]
            for number in range(markers["other_domains"]["kwargs"]["number"])
        ]
        for domain in other_domains:
            if domain not in domain_list()["domains"]:
                domain_add(domain)

    # Dirty patch of DNS resolution. Force the DNS to 127.0.0.1 address even if dnsmasq have the public address.
    # Mainly used for 'can_access_webpage' function
    dns_cache = {(maindomain, 443, 0, 1): [(2, 1, 6, "", ("127.0.0.1", 443))]}
    for domain in other_domains:
        dns_cache[(domain, 443, 0, 1)] = [(2, 1, 6, "", ("127.0.0.1", 443))]

    def new_getaddrinfo(*args):
        try:
            return dns_cache[args]
        except KeyError:
            res = prv_getaddrinfo(*args)
            dns_cache[args] = res
            return res

    socket.getaddrinfo = new_getaddrinfo

    user_create("alice", maindomain, dummy_password, fullname="Alice White", admin=True)
    user_create("bob", maindomain, dummy_password, fullname="Bob Snow")
    _permission_create_with_dummy_app(
        permission="wiki.main",
        url="/",
        additional_urls=["/whatever", "/idontnow"],
        auth_header=False,
        show_tile=True,
        allowed=["all_users"],
        protected=False,
        sync_perm=False,
        domain=maindomain,
        path="/wiki",
    )
    _permission_create_with_dummy_app(
        permission="blog.main",
        url="/",
        auth_header=True,
        show_tile=False,
        protected=False,
        sync_perm=False,
        allowed=["alice"],
        domain=maindomain,
        path="/blog",
    )
    _permission_create_with_dummy_app(
        permission="blog.api", allowed=["visitors"], protected=True, sync_perm=True
    )


def teardown_function(function):
    clean_user_groups_permission()
    global other_domains
    for domain in other_domains:
        domain_remove(domain)
    other_domains = []

    _clear_dummy_app_settings()

    try:
        app_remove("permissions_app")
    except Exception:
        pass
    try:
        app_remove("legacy_app")
    except Exception:
        pass


def teardown_module(module):
    global other_domains
    for domain in other_domains:
        domain_remove(domain)


@pytest.fixture(autouse=True)
def check_LDAP_db_integrity_call():
    check_LDAP_db_integrity()
    yield
    check_LDAP_db_integrity()


def check_LDAP_db_integrity():
    # Here we check that all attributes in all object are sychronized.
    # Here is the list of attributes per object:
    # user : memberOf, permission
    # group : member
    # permission : inheritPermission
    #
    # The idea is to check that all attributes on all sides of object are sychronized.
    # One part should be done automatically by the "memberOf" overlay of LDAP.
    # The other part is done by the the "_sync_permissions_with_ldap" function of the permission module

    from yunohost.utils.ldap import _get_ldap_interface, _ldap_path_extract

    ldap = _get_ldap_interface()

    user_search = ldap.search(
        "ou=users",
        "(&(objectclass=person)(!(uid=root))(!(uid=nobody)))",
        ["uid", "memberOf", "permission"],
    )
    group_search = ldap.search(
        "ou=groups",
        "(objectclass=groupOfNamesYnh)",
        ["cn", "member", "memberUid"],
    )
    permission_search = ldap.search(
        "ou=permission",
        "(objectclass=permissionYnh)",
        ["cn", "inheritPermission", "memberUid"],
    )

    user_map = {u["uid"][0]: u for u in user_search}
    group_map = {g["cn"][0]: g for g in group_search}
    permission_map = {p["cn"][0]: p for p in permission_search}

    for user in user_search:
        user_dn = f"uid={user['uid'][0]},ou=users,dc=yunohost,dc=org"
        group_list = [_ldap_path_extract(m, "cn") for m in user.get("memberOf", [])]
        permission_list = [
            _ldap_path_extract(m, "cn") for m in user.get("permission", [])
        ]

        # This user's DN sould be found in all groups it is a member of
        for group in group_list:
            assert user_dn in group_map[group]["member"]

        # This user's DN should be found in all perms it has access to
        for permission in permission_list:
            assert user_dn in permission_map[permission]["inheritPermission"]

    for permission in permission_search:
        permission_dn = f"cn={permission['cn'][0]},ou=permission,dc=yunohost,dc=org"

        # inheritPermission uid's should match memberUids
        user_list = [
            _ldap_path_extract(m, "uid")
            for m in permission.get("inheritPermission", [])
        ]
        assert set(user_list) == set(permission.get("memberUid", []))

        # This perm's DN should be found on all related users it is related to
        for user in user_list:
            assert permission_dn in user_map[user]["permission"]

    for group in group_search:
        group_dn = f"cn={group['cn'][0]},ou=groups,dc=yunohost,dc=org"

        user_list = [_ldap_path_extract(m, "uid") for m in group.get("member", [])]
        # For primary groups, we should find that :
        #    - len(user_list) is 1 (a primary group has only 1 member)
        #    - the group name should be an existing yunohost user
        #    - memberUid is empty (meaning no other member than the corresponding user)
        if group["cn"][0] in user_list:
            assert len(user_list) == 1
            assert group["cn"][0] in user_map
            assert group.get("memberUid", []) == []
        # Otherwise, user_list and memberUid should have the same content
        else:
            assert set(user_list) == set(group.get("memberUid", []))

        # For all users members, this group should be in the "memberOf" on the other side
        for user in user_list:
            assert group_dn in user_map[user]["memberOf"]


def check_permission_for_apps():
    # We check that the for each installed apps we have at last the "main" permission
    # and we don't have any permission linked to no apps. The only exception who is not liked to an app
    # is mail, and sftp

    app_perms = user_permission_list(ignore_system_perms=True)["permissions"].keys()

    # Keep only the prefix so that
    # ["foo.main", "foo.pwet", "bar.main"]
    # becomes
    # {"bar", "foo"}
    # and compare this to the list of installed apps ...

    app_perms_prefix = {p.split(".")[0] for p in app_perms}

    assert set(_installed_apps()) == app_perms_prefix


def can_access_webpage(webpath, logged_as=None):
    webpath = webpath.rstrip("/")
    login_endpoint = f"https://{maindomain}/yunohost/portalapi/login"

    # Anonymous access
    if not logged_as:
        r = requests.get(webpath, verify=False)
    # Login as a user using dummy password
    else:
        with requests.Session() as session:
            r = session.post(
                login_endpoint,
                data={"credentials": f"{logged_as}:{dummy_password}"},
                headers={
                    "X-Requested-With": "",
                },
                verify=False,
            )
            # We should have some cookies related to authentication now
            assert session.cookies
            r = session.get(webpath, verify=False)

    # If we can't access it, we got redirected to the SSO
    # with `r=<base64_callback_url>` for anonymous access because they're encouraged to log-in,
    # and `msg=access_denied` if we are logged but not allowed for this url
    # with `r=
    sso_url = f"https://{maindomain}/yunohost/sso/"
    if not logged_as:
        sso_url += "?r="
    else:
        sso_url += "?msg=access_denied"

    return not r.url.startswith(sso_url)


#
# List functions
#


def test_permission_list():
    res = user_permission_list(full=True)["permissions"]

    assert "mail.main" in res

    assert "wiki.main" in res
    assert "blog.main" in res
    assert "blog.api" in res

    assert res["wiki.main"]["allowed"] == ["all_users"]
    assert res["blog.main"]["allowed"] == ["alice"]
    assert res["blog.api"]["allowed"] == ["visitors"]
    assert set(res["wiki.main"]["corresponding_users"]) == {"alice", "bob"}
    assert res["blog.main"]["corresponding_users"] == ["alice"]
    assert res["blog.api"]["corresponding_users"] == []
    assert res["wiki.main"]["url"] == "/"
    assert res["blog.main"]["url"] == "/"
    assert res["blog.api"]["url"] is None
    assert set(res["wiki.main"]["additional_urls"]) == {"/whatever", "/idontnow"}
    assert res["wiki.main"]["protected"] is False
    assert res["blog.main"]["protected"] is False
    assert res["blog.api"]["protected"] is True
    assert res["wiki.main"]["label"] == "Wiki"
    assert res["blog.main"]["label"] == "Blog"
    assert res["blog.api"]["label"] == "Blog (api)"
    assert res["wiki.main"]["show_tile"] is True
    assert res["blog.main"]["show_tile"] is False
    assert res["blog.api"]["show_tile"] is False
    assert res["wiki.main"]["auth_header"] is False
    assert res["blog.main"]["auth_header"] is True
    assert res["blog.api"]["auth_header"] is True

    res = user_permission_list(full=True, absolute_urls=True)["permissions"]
    assert res["wiki.main"]["url"] == maindomain + "/wiki"
    assert res["blog.main"]["url"] == maindomain + "/blog"
    assert res["blog.api"]["url"] is None
    assert set(res["wiki.main"]["additional_urls"]) == {
        maindomain + "/wiki/whatever",
        maindomain + "/wiki/idontnow",
    }
    assert res["blog.main"]["additional_urls"] == []
    assert res["blog.api"]["additional_urls"] == []


#
# Create - Remove functions
#


def test_permission_create_main():
    with message("permission_created", permission="site.main"):
        _permission_create_with_dummy_app("site.main", allowed=["all_users"], protected=False)

    res = user_permission_list(full=True)["permissions"]
    assert "site.main" in res
    assert res["site.main"]["allowed"] == ["all_users"]
    assert set(res["site.main"]["corresponding_users"]) == {"alice", "bob"}
    assert res["site.main"]["protected"] is False


def test_permission_create_extra():
    with message("permission_created", permission="site.test"):
        _permission_create_with_dummy_app("site.test", protected=None)

    res = user_permission_list(full=True)["permissions"]
    assert "site.test" in res
    # all_users is only enabled by default on .main perms
    assert "all_users" not in res["site.test"]["allowed"]
    assert res["site.test"]["corresponding_users"] == []
    assert res["site.test"]["protected"] is False


def test_permission_create_with_specific_user():
    with message("permission_created", permission="site.test"):
        _permission_create_with_dummy_app("site.test", allowed=["alice"])

    res = user_permission_list(full=True)["permissions"]
    assert "site.test" in res
    assert res["site.test"]["allowed"] == ["alice"]


def test_permission_create_with_tile_management():
    with message("permission_created", permission="site.main"):
        _permission_create_with_dummy_app(
            "site.main",
            allowed=["all_users"],
            show_tile=False,
            domain=maindomain,
            path="/site",
        )

    res = user_permission_list(full=True)["permissions"]
    assert "site.main" in res
    assert res["site.main"]["label"] == "Site"
    assert res["site.main"]["show_tile"] is False


def test_permission_create_with_tile_management_with_main_default_value():
    with message("permission_created", permission="site.main"):
        _permission_create_with_dummy_app(
            "site.main",
            allowed=["all_users"],
            show_tile=True,
            url="/",
            domain=maindomain,
            path="/site",
        )

    res = user_permission_list(full=True)["permissions"]
    assert "site.main" in res
    assert res["site.main"]["label"] == "Site"
    assert res["site.main"]["show_tile"] is True


def test_permission_create_with_tile_management_with_not_main_default_value():
    with message("permission_created", permission="wiki.api"):
        _permission_create_with_dummy_app(
            "wiki.api",
            allowed=["all_users"],
            show_tile=True,
            url="/",
            domain=maindomain,
            path="/site",
        )

    res = user_permission_list(full=True)["permissions"]
    assert "wiki.api" in res
    assert res["wiki.api"]["label"] == "Wiki (api)"
    assert res["wiki.api"]["show_tile"] is True


def test_permission_create_with_urls_management_without_url():
    with message("permission_created", permission="wiki.api"):
        _permission_create_with_dummy_app(
            "wiki.api", allowed=["all_users"], domain=maindomain, path="/site"
        )

    res = user_permission_list(full=True)["permissions"]
    assert "wiki.api" in res
    assert res["wiki.api"]["url"] is None
    assert res["wiki.api"]["additional_urls"] == []
    assert res["wiki.api"]["auth_header"] is True


def test_permission_create_with_urls_management_simple_domain():
    with message("permission_created", permission="site.main"):
        _permission_create_with_dummy_app(
            "site.main",
            allowed=["all_users"],
            url="/",
            additional_urls=["/whatever", "/idontnow"],
            auth_header=False,
            domain=maindomain,
            path="/site",
        )

    res = user_permission_list(full=True, absolute_urls=True)["permissions"]
    assert "site.main" in res
    assert res["site.main"]["url"] == maindomain + "/site"
    assert set(res["site.main"]["additional_urls"]) == {
        maindomain + "/site/whatever",
        maindomain + "/site/idontnow",
    }
    assert res["site.main"]["auth_header"] is False


@pytest.mark.other_domains(number=2)
def test_permission_create_with_urls_management_multiple_domain():
    with message("permission_created", permission="site.main"):
        _permission_create_with_dummy_app(
            "site.main",
            allowed=["all_users"],
            url=maindomain + "/site/something",
            additional_urls=[other_domains[0] + "/blabla", other_domains[1] + "/ahh"],
            auth_header=True,
            domain=maindomain,
            path="/site",
        )

    res = user_permission_list(full=True, absolute_urls=True)["permissions"]
    assert "site.main" in res
    assert res["site.main"]["url"] == maindomain + "/site/something"
    assert set(res["site.main"]["additional_urls"]) == {
        other_domains[0] + "/blabla",
        other_domains[1] + "/ahh",
    }
    assert res["site.main"]["auth_header"] is True


def test_permission_delete():
    with message("permission_deleted", permission="wiki.main"):
        permission_delete("wiki.main", force=True)

    res = user_permission_list()["permissions"]
    assert "wiki.main" not in res

    with message("permission_deleted", permission="blog.api"):
        permission_delete("blog.api", force=False)

    res = user_permission_list()["permissions"]
    assert "blog.api" not in res


#
# Error on create - remove function
#


def test_permission_create_already_existing(mocker):
    with raiseYunohostError(mocker, "permission_already_exist"):
        permission_create("wiki.main")


def test_permission_delete_doesnt_existing(mocker):
    with raiseYunohostError(mocker, "permission_not_found"):
        permission_delete("doesnt.exist", force=True)

    res = user_permission_list()["permissions"]
    assert "wiki.main" in res
    assert "blog.main" in res
    assert "mail.main" in res


def test_permission_delete_main_without_force(mocker):
    with raiseYunohostError(mocker, "permission_cannot_remove_main"):
        permission_delete("blog.main")

    res = user_permission_list()["permissions"]
    assert "blog.main" in res


#
# Update functions
#

# user side functions


def test_permission_add_group():
    with message("permission_updated", permission="wiki.main"):
        user_permission_update("wiki.main", add="alice")

    res = user_permission_list(full=True)["permissions"]
    assert set(res["wiki.main"]["allowed"]) == {"all_users", "alice"}
    assert set(res["wiki.main"]["corresponding_users"]) == {"alice", "bob"}


def test_permission_add_group_to_system_perm():
    res = user_permission_list(full=True)["permissions"]
    assert set(res["sftp.main"]["allowed"]) == set()

    with message("permission_updated", permission="sftp.main"):
        user_permission_update("sftp.main", add="alice")

    res = user_permission_list(full=True)["permissions"]
    assert set(res["sftp.main"]["allowed"]) == {"alice"}


def test_permission_remove_group():
    with message("permission_updated", permission="blog.main"):
        user_permission_update("blog.main", remove="alice")

    res = user_permission_list(full=True)["permissions"]
    assert res["blog.main"]["allowed"] == []
    assert res["blog.main"]["corresponding_users"] == []


def test_permission_add_and_remove_group():
    with message("permission_updated", permission="wiki.main"):
        user_permission_update("wiki.main", add="alice", remove="all_users")

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["allowed"] == ["alice"]
    assert res["wiki.main"]["corresponding_users"] == ["alice"]


def test_permission_add_group_already_allowed():
    with message("permission_already_allowed", permission="blog.main", group="alice"):
        user_permission_update("blog.main", add="alice")

    res = user_permission_list(full=True)["permissions"]
    assert res["blog.main"]["allowed"] == ["alice"]
    assert res["blog.main"]["corresponding_users"] == ["alice"]


def test_permission_remove_group_already_not_allowed():
    with message("permission_already_disallowed", permission="blog.main", group="bob"):
        user_permission_update("blog.main", remove="bob")

    res = user_permission_list(full=True)["permissions"]
    assert res["blog.main"]["allowed"] == ["alice"]
    assert res["blog.main"]["corresponding_users"] == ["alice"]


def test_permission_change_label():
    with message("permission_updated", permission="wiki.main"):
        user_permission_update("wiki.main", label="New Wiki")

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["label"] == "New Wiki"


def test_permission_change_label_with_same_value():
    with message("permission_updated", permission="wiki.main"):
        user_permission_update("wiki.main", label="Wiki")

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["label"] == "Wiki"


def test_permission_switch_show_tile():
    # Note that from the actionmap the value is passed as string, not as bool
    # Try with lowercase
    with message("permission_updated", permission="wiki.main"):
        user_permission_update("wiki.main", show_tile="false")

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["show_tile"] is False

    # Try with uppercase
    with message("permission_updated", permission="wiki.main"):
        user_permission_update("wiki.main", show_tile="TRUE")

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["show_tile"] is True


def test_permission_switch_show_tile_with_same_value():
    # Note that from the actionmap the value is passed as string, not as bool
    with message("permission_updated", permission="wiki.main"):
        user_permission_update("wiki.main", show_tile="True")

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["show_tile"] is True


#
# Error on update function
#


def test_permission_add_group_that_doesnt_exist(mocker):
    with raiseYunohostError(mocker, "group_unknown"):
        user_permission_update("blog.main", add="doesnt_exist")

    res = user_permission_list(full=True)["permissions"]
    assert res["blog.main"]["allowed"] == ["alice"]
    assert res["blog.main"]["corresponding_users"] == ["alice"]


def test_permission_update_permission_that_doesnt_exist(mocker):
    with raiseYunohostError(mocker, "permission_not_found"):
        user_permission_update("doesnt.exist", add="alice")


def test_permission_protected_update(mocker):
    res = user_permission_list(full=True)["permissions"]
    assert res["blog.api"]["allowed"] == ["visitors"]

    with raiseYunohostError(mocker, "permission_protected"):
        user_permission_update("blog.api", remove="visitors")

    res = user_permission_list(full=True)["permissions"]
    assert res["blog.api"]["allowed"] == ["visitors"]

    user_permission_update("blog.api", remove="visitors", force=True)
    res = user_permission_list(full=True)["permissions"]
    assert res["blog.api"]["allowed"] == []

    with raiseYunohostError(mocker, "permission_protected"):
        user_permission_update("blog.api", add="visitors")

    res = user_permission_list(full=True)["permissions"]
    assert res["blog.api"]["allowed"] == []


# Permission url management


def test_permission_redefine_url():
    permission_url("blog.main", url="/pwet")

    res = user_permission_list(full=True)["permissions"]
    assert res["blog.main"]["url"] == "/pwet"


def test_permission_remove_url():
    permission_url("blog.main", clear_urls=True)

    res = user_permission_list(full=True)["permissions"]
    assert res["blog.main"]["url"] is None


def test_permission_main_url_regex():
    permission_url("blog.main", url="re:/[a-z]+reboy/.*")

    res = user_permission_list(full=True)["permissions"]
    assert res["blog.main"]["url"] == "re:/[a-z]+reboy/.*"

    res = user_permission_list(full=True, absolute_urls=True)["permissions"]
    assert res["blog.main"]["url"] == "re:%s/blog/[a-z]+reboy/.*" % maindomain.replace(
        ".", r"\."
    )


def test_permission_main_url_bad_regex(mocker):
    with raiseYunohostError(mocker, "invalid_regex"):
        permission_url("blog.main", url="re:/[a-z]+++reboy/.*")


@pytest.mark.other_domains(number=1)
def test_permission_add_additional_url():
    permission_url("wiki.main", add_url=[other_domains[0] + "/heyby", "/myhouse"])

    res = user_permission_list(full=True, absolute_urls=True)["permissions"]
    assert res["wiki.main"]["url"] == maindomain + "/wiki"
    assert set(res["wiki.main"]["additional_urls"]) == {
        maindomain + "/wiki/whatever",
        maindomain + "/wiki/idontnow",
        other_domains[0] + "/heyby",
        maindomain + "/wiki/myhouse",
    }


def test_permission_add_additional_regex():
    permission_url("blog.main", add_url=["re:/[a-z]+reboy/.*"])

    res = user_permission_list(full=True)["permissions"]
    assert res["blog.main"]["additional_urls"] == ["re:/[a-z]+reboy/.*"]

    res = user_permission_list(full=True, absolute_urls=True)["permissions"]
    assert res["blog.main"]["additional_urls"] == [
        "re:%s/blog/[a-z]+reboy/.*" % maindomain.replace(".", r"\.")
    ]


def test_permission_add_additional_bad_regex(mocker):
    with raiseYunohostError(mocker, "invalid_regex"):
        permission_url("blog.main", add_url=["re:/[a-z]+++reboy/.*"])


def test_permission_remove_additional_url():
    permission_url("wiki.main", remove_url=["/whatever"])

    res = user_permission_list(full=True, absolute_urls=True)["permissions"]
    assert res["wiki.main"]["url"] == maindomain + "/wiki"
    assert res["wiki.main"]["additional_urls"] == [maindomain + "/wiki/idontnow"]


def test_permssion_add_additional_url_already_exist():
    permission_url("wiki.main", add_url=["/whatever", "/myhouse"])
    permission_url("wiki.main", add_url=["/whatever"])

    res = user_permission_list(full=True, absolute_urls=True)["permissions"]
    assert res["wiki.main"]["url"] == maindomain + "/wiki"
    assert set(res["wiki.main"]["additional_urls"]) == {
        maindomain + "/wiki/whatever",
        maindomain + "/wiki/idontnow",
        maindomain + "/wiki/myhouse",
    }


def test_permission_remove_additional_url_dont_exist():
    permission_url("wiki.main", remove_url=["/shouldntexist", "/whatever"])
    permission_url("wiki.main", remove_url=["/shouldntexist"])

    res = user_permission_list(full=True, absolute_urls=True)["permissions"]
    assert res["wiki.main"]["url"] == maindomain + "/wiki"
    assert res["wiki.main"]["additional_urls"] == [maindomain + "/wiki/idontnow"]


def test_permission_clear_additional_url():
    permission_url("wiki.main", clear_urls=True)

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["url"] is None
    assert res["wiki.main"]["additional_urls"] == []


def test_permission_switch_auth_header():
    permission_url("wiki.main", auth_header=True)

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["auth_header"] is True

    permission_url("wiki.main", auth_header=False)

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["auth_header"] is False


def test_permission_switch_auth_header_with_same_value():
    permission_url("wiki.main", auth_header=False)

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["auth_header"] is False


# Permission protected


def test_permission_switch_protected():
    user_permission_update("wiki.main", protected=True)

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["protected"] is True

    user_permission_update("wiki.main", protected=False)

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["protected"] is False


def test_permission_switch_protected_with_same_value():
    user_permission_update("wiki.main", protected=False)

    res = user_permission_list(full=True)["permissions"]
    assert res["wiki.main"]["protected"] is False


# Test SSOWAT conf generation


def test_ssowat_conf():
    with open("/etc/ssowat/conf.json") as f:
        res = json.load(f)

    permissions = res["permissions"]
    assert "wiki.main" in permissions
    assert "blog.main" in permissions
    assert (
        "blog.api" not in permissions
    )  # blog.api has no url/additional url defined and therefore is not added to ssowat conf

    assert set(permissions["wiki.main"]["users"]) == {"alice", "bob"}
    assert permissions["blog.main"]["users"] == ["alice"]

    assert permissions["wiki.main"]["uris"][0] == maindomain + "/wiki"

    assert set(permissions["wiki.main"]["uris"]) == {
        maindomain + "/wiki",
        maindomain + "/wiki/whatever",
        maindomain + "/wiki/idontnow",
    }
    assert permissions["blog.main"]["uris"] == [maindomain + "/blog"]

    assert permissions["wiki.main"]["public"] is False
    assert permissions["blog.main"]["public"] is False

    assert permissions["wiki.main"]["auth_header"] is False
    assert permissions["blog.main"]["auth_header"] == "basic-with-password"


def test_show_tile_cant_be_enabled():
    _permission_create_with_dummy_app(
        permission="site.main",
        auth_header=False,
        show_tile=True,
        allowed=["all_users"],
        protected=False,
        sync_perm=False,
        domain=maindomain,
        path="/site",
    )

    _permission_create_with_dummy_app(
        permission="web.main",
        url="re:/[a-z]{3}/bla",
        auth_header=False,
        show_tile=True,
        allowed=["all_users"],
        protected=False,
        sync_perm=True,
        domain=maindomain,
        path="/web",
    )

    permissions = user_permission_list(full=True)["permissions"]

    assert permissions["site.main"]["show_tile"] is False
    assert permissions["web.main"]["show_tile"] is False


#
# Application interaction
#


def test_permission_app_install():
    app_install(
        os.path.join(get_test_apps_dir(), "permissions_app_ynh"),
        args="domain=%s&domain_2=%s&path=%s&is_public=0&admin=%s"
        % (maindomain, maindomain, "/urlpermissionapp", "alice"),
        force=True,
    )

    res = user_permission_list(full=True)["permissions"]
    assert "permissions_app.main" in res
    assert "permissions_app.admin" in res
    assert "permissions_app.dev" in res
    assert res["permissions_app.main"]["url"] == "/"
    assert res["permissions_app.admin"]["url"] == "/admin"
    assert res["permissions_app.dev"]["url"] == "/dev"

    assert res["permissions_app.main"]["allowed"] == ["all_users"]
    assert set(res["permissions_app.main"]["corresponding_users"]) == {"alice", "bob"}

    assert res["permissions_app.admin"]["allowed"] == ["alice"]
    assert res["permissions_app.admin"]["corresponding_users"] == ["alice"]

    assert res["permissions_app.dev"]["allowed"] == []
    assert set(res["permissions_app.dev"]["corresponding_users"]) == set()

    # Check that we get the right stuff in app_map, which is used to generate the ssowatconf
    assert maindomain + "/urlpermissionapp" in app_map(user="alice").keys()
    user_permission_update("permissions_app.main", remove="all_users", add="bob")
    assert maindomain + "/urlpermissionapp" not in app_map(user="alice").keys()
    assert maindomain + "/urlpermissionapp" in app_map(user="bob").keys()


def test_permission_app_remove():
    app_install(
        os.path.join(get_test_apps_dir(), "permissions_app_ynh"),
        args="domain=%s&domain_2=%s&path=%s&is_public=0&admin=%s"
        % (maindomain, maindomain, "/urlpermissionapp", "alice"),
        force=True,
    )
    app_remove("permissions_app")

    # Check all permissions for this app got deleted
    res = user_permission_list(full=True)["permissions"]
    assert not any(p.startswith("permissions_app.") for p in res.keys())


def test_permission_app_change_url():
    app_install(
        os.path.join(get_test_apps_dir(), "permissions_app_ynh"),
        args="domain=%s&domain_2=%s&path=%s&is_public=1&admin=%s"
        % (maindomain, maindomain, "/urlpermissionapp", "alice"),
        force=True,
    )

    # FIXME : should rework this test to look for differences in the generated app map / app tiles ...
    res = user_permission_list(full=True)["permissions"]
    assert res["permissions_app.main"]["url"] == "/"
    assert res["permissions_app.admin"]["url"] == "/admin"
    assert res["permissions_app.dev"]["url"] == "/dev"

    app_change_url("permissions_app", maindomain, "/newchangeurl")

    res = user_permission_list(full=True)["permissions"]
    assert res["permissions_app.main"]["url"] == "/"
    assert res["permissions_app.admin"]["url"] == "/admin"
    assert res["permissions_app.dev"]["url"] == "/dev"


def test_permission_protection_management_by_helper():
    app_install(
        os.path.join(get_test_apps_dir(), "permissions_app_ynh"),
        args="domain=%s&domain_2=%s&path=%s&is_public=1&admin=%s"
        % (maindomain, maindomain, "/urlpermissionapp", "alice"),
        force=True,
    )

    res = user_permission_list(full=True)["permissions"]
    assert res["permissions_app.main"]["protected"] is False
    assert res["permissions_app.admin"]["protected"] is True
    assert res["permissions_app.dev"]["protected"] is False

    app_upgrade(
        ["permissions_app"],
        file=os.path.join(get_test_apps_dir(), "permissions_app_ynh"),
    )

    res = user_permission_list(full=True)["permissions"]
    assert res["permissions_app.main"]["protected"] is False
    assert res["permissions_app.admin"]["protected"] is False
    assert res["permissions_app.dev"]["protected"] is True


def test_permission_app_propagation_on_ssowat():
    app_install(
        os.path.join(get_test_apps_dir(), "permissions_app_ynh"),
        args="domain=%s&domain_2=%s&path=%s&is_public=1&admin=%s"
        % (maindomain, maindomain, "/urlpermissionapp", "alice"),
        force=True,
    )

    res = user_permission_list(full=True)["permissions"]
    assert "visitors" in res["permissions_app.main"]["allowed"]
    assert "all_users" in res["permissions_app.main"]["allowed"]

    app_webroot = "https://%s/urlpermissionapp" % maindomain
    assert can_access_webpage(app_webroot, logged_as=None)
    assert can_access_webpage(app_webroot, logged_as="alice")

    user_permission_update(
        "permissions_app.main", remove=["visitors", "all_users"], add="bob"
    )
    res = user_permission_list(full=True)["permissions"]

    assert not can_access_webpage(app_webroot, logged_as=None)
    assert not can_access_webpage(app_webroot, logged_as="alice")
    assert can_access_webpage(app_webroot, logged_as="bob")

    # Test admin access, as configured during install, only alice should be able to access it

    # alice gotta be allowed on the main permission to access the admin tho
    user_permission_update("permissions_app.main", remove="bob", add="all_users")

    assert not can_access_webpage(app_webroot + "/admin", logged_as=None)
    assert can_access_webpage(app_webroot + "/admin", logged_as="alice")
    assert not can_access_webpage(app_webroot + "/admin", logged_as="bob")


def test_permission_legacy_app_propagation_on_ssowat():
    app_install(
        os.path.join(get_test_apps_dir(), "legacy_app_ynh"),
        args="domain=%s&domain_2=%s&path=%s&is_public=0"
        % (maindomain, maindomain, "/legacy"),
        force=True,
    )

    # App is configured as public by default using the legacy unprotected_uri mechanics
    # It should automatically be migrated during the install
    res = user_permission_list(full=True)["permissions"]
    assert "visitors" not in res["legacy_app.main"]["allowed"]
    assert "all_users" in res["legacy_app.main"]["allowed"]

    app_webroot = "https://%s/legacy" % maindomain

    assert not can_access_webpage(app_webroot, logged_as=None)
    assert can_access_webpage(app_webroot, logged_as="alice")

    # Try to update the permission and check that permissions are still consistent
    user_permission_update(
        "legacy_app.main", remove=["visitors", "all_users"], add="bob"
    )

    assert not can_access_webpage(app_webroot, logged_as=None)
    assert not can_access_webpage(app_webroot, logged_as="alice")
    assert can_access_webpage(app_webroot, logged_as="bob")
