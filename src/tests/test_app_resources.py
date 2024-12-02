import os
import pytest

from moulinette.utils.process import check_output

from yunohost.app import app_setting
from yunohost.domain import _get_maindomain
from yunohost.utils.resources import (
    AppResource,
    AppResourceManager,
    AppResourceClassesByType,
)
from yunohost.permission import user_permission_list, permission_delete
from yunohost.firewall import firewall_list

dummyfile = "/tmp/dummyappresource-testapp"


class DummyAppResource(AppResource):
    type = "dummy"

    default_properties = {
        "file": "/tmp/dummyappresource-__APP__",
        "content": "foo",
    }

    def provision_or_update(self, context):
        open(self.file, "w").write(self.content)

        if self.content == "forbiddenvalue":
            raise Exception("Emeged you used the forbidden value!1!£&")

    def deprovision(self, context):
        os.system(f"rm -f {self.file}")


AppResourceClassesByType["dummy"] = DummyAppResource


def setup_function(function):
    clean()

    os.system("mkdir /etc/yunohost/apps/testapp")
    os.system("echo 'id: testapp' > /etc/yunohost/apps/testapp/settings.yml")
    os.system("echo 'packaging_format = 2' > /etc/yunohost/apps/testapp/manifest.toml")
    os.system("echo 'id = \"testapp\"' >> /etc/yunohost/apps/testapp/manifest.toml")
    os.system(
        "echo 'description.en = \"A dummy app to test app resources\"' >> /etc/yunohost/apps/testapp/manifest.toml"
    )


def teardown_function(function):
    clean()


def clean():
    os.system(f"rm -f {dummyfile}")
    os.system("rm -rf /etc/yunohost/apps/testapp")
    os.system("rm -rf /var/www/testapp")
    os.system("rm -rf /home/yunohost.app/testapp")
    os.system("apt remove lolcat sl nyancat influxdb2 >/dev/null 2>/dev/null")
    os.system("userdel testapp 2>/dev/null")

    for p in user_permission_list()["permissions"]:
        if p.startswith("testapp."):
            permission_delete(p, force=True, sync_perm=False)


def test_provision_dummy():
    current = {"resources": {}}
    wanted = {"resources": {"dummy": {}}}

    assert not os.path.exists(dummyfile)
    AppResourceManager("testapp", current=current, wanted=wanted).apply(
        rollback_and_raise_exception_if_failure=False
    )
    assert open(dummyfile).read().strip() == "foo"


def test_deprovision_dummy():
    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    AppResourceManager("testapp", current=current, wanted=wanted).apply(
        rollback_and_raise_exception_if_failure=False
    )
    assert not os.path.exists(dummyfile)


def test_provision_dummy_nondefaultvalue():
    current = {"resources": {}}
    wanted = {"resources": {"dummy": {"content": "bar"}}}

    assert not os.path.exists(dummyfile)
    AppResourceManager("testapp", current=current, wanted=wanted).apply(
        rollback_and_raise_exception_if_failure=False
    )
    assert open(dummyfile).read().strip() == "bar"


def test_update_dummy():
    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {"dummy": {"content": "bar"}}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    AppResourceManager("testapp", current=current, wanted=wanted).apply(
        rollback_and_raise_exception_if_failure=False
    )
    assert open(dummyfile).read().strip() == "bar"


def test_update_dummy_failwithrollback():
    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {"dummy": {"content": "forbiddenvalue"}}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    with pytest.raises(Exception):
        AppResourceManager("testapp", current=current, wanted=wanted).apply(
            rollback_and_raise_exception_if_failure=True
        )
    assert open(dummyfile).read().strip() == "foo"


def test_resource_system_user():
    r = AppResourceClassesByType["system_user"]

    conf = {}

    assert os.system("getent passwd testapp 2>/dev/null") != 0

    r(conf, "testapp").provision_or_update()

    assert os.system("getent passwd testapp >/dev/null") == 0
    assert os.system("groups testapp | grep -q 'sftp.app'") != 0

    conf["allow_sftp"] = True
    r(conf, "testapp").provision_or_update()

    assert os.system("getent passwd testapp >/dev/null") == 0
    assert os.system("groups testapp | grep -q 'sftp.app'") == 0

    r(conf, "testapp").deprovision()

    assert os.system("getent passwd testapp 2>/dev/null") != 0


def test_resource_install_dir():
    r = AppResourceClassesByType["install_dir"]
    conf = {"owner": "nobody:rx", "group": "nogroup:rx"}

    # FIXME: should also check settings ?
    # FIXME: should also check automigrate from final_path
    # FIXME: should also test changing the install folder location ?

    assert not os.path.exists("/var/www/testapp")

    r(conf, "testapp").provision_or_update()

    assert os.path.exists("/var/www/testapp")
    unixperms = check_output("ls -ld /var/www/testapp").split()
    assert unixperms[0] == "dr-xr-x---"
    assert unixperms[2] == "nobody"
    assert unixperms[3] == "nogroup"

    conf["owner"] = "nobody:rwx"
    conf["group"] = "www-data:x"

    r(conf, "testapp").provision_or_update()

    assert os.path.exists("/var/www/testapp")
    unixperms = check_output("ls -ld /var/www/testapp").split()
    assert unixperms[0] == "drwx--x---"
    assert unixperms[2] == "nobody"
    assert unixperms[3] == "www-data"

    r(conf, "testapp").deprovision()

    assert not os.path.exists("/var/www/testapp")


def test_resource_data_dir():
    r = AppResourceClassesByType["data_dir"]
    conf = {"owner": "nobody:rx", "group": "nogroup:rx"}

    assert not os.path.exists("/home/yunohost.app/testapp")

    r(conf, "testapp").provision_or_update()

    assert os.path.exists("/home/yunohost.app/testapp")
    unixperms = check_output("ls -ld /home/yunohost.app/testapp").split()
    assert unixperms[0] == "dr-xr-x---"
    assert unixperms[2] == "nobody"
    assert unixperms[3] == "nogroup"

    conf["owner"] = "nobody:rwx"
    conf["group"] = "www-data:x"

    r(conf, "testapp").provision_or_update()

    assert os.path.exists("/home/yunohost.app/testapp")
    unixperms = check_output("ls -ld /home/yunohost.app/testapp").split()
    assert unixperms[0] == "drwx--x---"
    assert unixperms[2] == "nobody"
    assert unixperms[3] == "www-data"

    r(conf, "testapp").deprovision()

    # FIXME : implement and check purge option
    # assert not os.path.exists("/home/yunohost.app/testapp")


def test_resource_ports():
    r = AppResourceClassesByType["ports"]
    conf = {}

    assert not app_setting("testapp", "port")

    r(conf, "testapp").provision_or_update()

    assert app_setting("testapp", "port")

    r(conf, "testapp").deprovision()

    assert not app_setting("testapp", "port")


def test_resource_ports_several():
    r = AppResourceClassesByType["ports"]
    conf = {"main": {"default": 12345}, "foobar": {"default": 23456}}

    assert not app_setting("testapp", "port")
    assert not app_setting("testapp", "port_foobar")

    r(conf, "testapp").provision_or_update()

    assert app_setting("testapp", "port")
    assert app_setting("testapp", "port_foobar")

    r(conf, "testapp").deprovision()

    assert not app_setting("testapp", "port")
    assert not app_setting("testapp", "port_foobar")


def test_resource_ports_firewall():
    r = AppResourceClassesByType["ports"]
    conf = {"main": {"default": 12345}}

    r(conf, "testapp").provision_or_update()

    assert 12345 not in firewall_list()["opened_ports"]

    conf = {"main": {"default": 12345, "exposed": "TCP"}}

    r(conf, "testapp").provision_or_update()

    assert 12345 in firewall_list()["opened_ports"]

    r(conf, "testapp").deprovision()

    assert 12345 not in firewall_list()["opened_ports"]


def test_resource_database():
    r = AppResourceClassesByType["database"]
    conf = {"type": "mysql"}

    assert os.system("mariadb-show 'testapp' >/dev/null 2>/dev/null") != 0
    assert not app_setting("testapp", "db_name")
    assert not app_setting("testapp", "db_user")
    assert not app_setting("testapp", "db_pwd")

    r(conf, "testapp").provision_or_update()

    assert os.system("mariadb-show 'testapp' >/dev/null 2>/dev/null") == 0
    assert app_setting("testapp", "db_name")
    assert app_setting("testapp", "db_user")
    assert app_setting("testapp", "db_pwd")

    r(conf, "testapp").deprovision()

    assert os.system("mariadb-show 'testapp' >/dev/null 2>/dev/null") != 0
    assert not app_setting("testapp", "db_name")
    assert not app_setting("testapp", "db_user")
    assert not app_setting("testapp", "db_pwd")


def test_resource_apt():
    r = AppResourceClassesByType["apt"]
    conf = {
        "packages": "nyancat, sl",
        "extras": {
            "influxdb": {
                "repo": "deb https://repos.influxdata.com/debian stable main",
                "key": "https://repos.influxdata.com/influxdata-archive_compat.key",
                "packages": "influxdb2",
            }
        },
    }

    assert os.system("dpkg --list | grep -q 'ii *nyancat '") != 0
    assert os.system("dpkg --list | grep -q 'ii *sl '") != 0
    assert os.system("dpkg --list | grep -q 'ii *influxdb2 '") != 0
    assert os.system("dpkg --list | grep -q 'ii *lolcat '") != 0
    assert os.system("dpkg --list | grep -q 'ii *testapp-ynh-deps '") != 0

    r(conf, "testapp").provision_or_update()

    assert os.system("dpkg --list | grep -q 'ii *nyancat '") == 0
    assert os.system("dpkg --list | grep -q 'ii *sl '") == 0
    assert os.system("dpkg --list | grep -q 'ii *influxdb2 '") == 0
    assert (
        os.system("dpkg --list | grep -q 'ii *lolcat '") != 0
    )  # Lolcat shouldnt be installed yet
    assert os.system("dpkg --list | grep -q 'ii *testapp-ynh-deps '") == 0

    conf["packages"] += ", lolcat"
    r(conf, "testapp").provision_or_update()

    assert os.system("dpkg --list | grep -q 'ii *nyancat '") == 0
    assert os.system("dpkg --list | grep -q 'ii *sl '") == 0
    assert os.system("dpkg --list | grep -q 'ii *influxdb2 '") == 0
    assert os.system("dpkg --list | grep -q 'ii *lolcat '") == 0
    assert os.system("dpkg --list | grep -q 'ii *testapp-ynh-deps '") == 0

    r(conf, "testapp").deprovision()

    assert os.system("dpkg --list | grep -q 'ii *nyancat '") != 0
    assert os.system("dpkg --list | grep -q 'ii *sl '") != 0
    assert os.system("dpkg --list | grep -q 'ii *influxdb2 '") != 0
    assert os.system("dpkg --list | grep -q 'ii *lolcat '") != 0
    assert os.system("dpkg --list | grep -q 'ii *testapp-ynh-deps '") != 0


def test_resource_permissions():
    maindomain = _get_maindomain()
    os.system(f"echo 'domain: {maindomain}' >> /etc/yunohost/apps/testapp/settings.yml")
    os.system("echo 'path: /testapp' >> /etc/yunohost/apps/testapp/settings.yml")

    # A manager object is required to set the label of the app...
    manager = AppResourceManager("testapp", current={}, wanted={"name": "Test App"})
    r = AppResourceClassesByType["permissions"]
    conf = {
        "main": {
            "url": "/",
            "allowed": "visitors",
            # TODO: test protected?
        },
    }

    res = user_permission_list(full=True)["permissions"]
    assert not any(key.startswith("testapp.") for key in res)

    r(conf, "testapp", manager).provision_or_update()

    res = user_permission_list(full=True)["permissions"]
    assert "testapp.main" in res
    assert "visitors" in res["testapp.main"]["allowed"]
    assert res["testapp.main"]["url"] == "/"
    assert "testapp.admin" not in res

    conf["admin"] = {"url": "/admin", "allowed": ""}

    r(conf, "testapp", manager).provision_or_update()

    res = user_permission_list(full=True)["permissions"]

    assert "testapp.main" in list(res.keys())
    assert "visitors" in res["testapp.main"]["allowed"]
    assert res["testapp.main"]["url"] == "/"

    assert "testapp.admin" in res
    assert not res["testapp.admin"]["allowed"]
    assert res["testapp.admin"]["url"] == "/admin"

    conf["admin"]["url"] = "/adminpanel"

    r(conf, "testapp", manager).provision_or_update()

    res = user_permission_list(full=True)["permissions"]

    assert res["testapp.admin"]["url"] == "/adminpanel"

    r(conf, "testapp").deprovision()

    res = user_permission_list(full=True)["permissions"]
    assert "testapp.main" not in res
