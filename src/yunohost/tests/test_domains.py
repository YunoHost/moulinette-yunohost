import pytest
import os

from moulinette.core import MoulinetteError

from yunohost.utils.error import YunohostValidationError
from yunohost.domain import (
    DOMAIN_SETTINGS_DIR,
    _get_maindomain,
    domain_add,
    domain_remove,
    domain_list,
    domain_main_domain,
    domain_config_get,
    domain_config_set,
)

TEST_DOMAINS = ["example.tld", "sub.example.tld", "other-example.com"]


def setup_function(function):

    # Save domain list in variable to avoid multiple calls to domain_list()
    domains = domain_list()["domains"]

    # First domain is main domain
    if not TEST_DOMAINS[0] in domains:
        domain_add(TEST_DOMAINS[0])
    else:
        # Reset settings if any
        os.system(f"rm -rf {DOMAIN_SETTINGS_DIR}/{TEST_DOMAINS[0]}.yml")

    if not _get_maindomain() == TEST_DOMAINS[0]:
        domain_main_domain(TEST_DOMAINS[0])

    # Clear other domains
    for domain in domains:
        if domain not in TEST_DOMAINS or domain == TEST_DOMAINS[2]:
            # Clean domains not used for testing
            domain_remove(domain)
        elif domain in TEST_DOMAINS:
            # Reset settings if any
            os.system(f"rm -rf {DOMAIN_SETTINGS_DIR}/{domain}.yml")

    # Create classical second domain of not exist
    if TEST_DOMAINS[1] not in domains:
        domain_add(TEST_DOMAINS[1])

    # Third domain is not created

    clean()


def teardown_function(function):

    clean()


def clean():
    pass


# Domains management testing
def test_domain_add():
    assert TEST_DOMAINS[2] not in domain_list()["domains"]
    domain_add(TEST_DOMAINS[2])
    assert TEST_DOMAINS[2] in domain_list()["domains"]


def test_domain_add_existing_domain():
    with pytest.raises(MoulinetteError):
        assert TEST_DOMAINS[1] in domain_list()["domains"]
        domain_add(TEST_DOMAINS[1])


def test_domain_remove():
    assert TEST_DOMAINS[1] in domain_list()["domains"]
    domain_remove(TEST_DOMAINS[1])
    assert TEST_DOMAINS[1] not in domain_list()["domains"]


def test_main_domain():
    current_main_domain = _get_maindomain()
    assert domain_main_domain()["current_main_domain"] == current_main_domain


def test_main_domain_change_unknown():
    with pytest.raises(YunohostValidationError):
        domain_main_domain(TEST_DOMAINS[2])


def test_change_main_domain():
    assert _get_maindomain() != TEST_DOMAINS[1]
    domain_main_domain(TEST_DOMAINS[1])
    assert _get_maindomain() == TEST_DOMAINS[1]


# Domain settings testing
def test_domain_config_get_default():
    assert domain_config_get(TEST_DOMAINS[0], "feature.xmpp.xmpp") == 1
    assert domain_config_get(TEST_DOMAINS[1], "feature.xmpp.xmpp") == 0


def test_domain_config_get_export():

    assert domain_config_get(TEST_DOMAINS[0], export=True)["xmpp"] == 1
    assert domain_config_get(TEST_DOMAINS[1], export=True)["xmpp"] == 0


def test_domain_config_set():
    assert domain_config_get(TEST_DOMAINS[1], "feature.xmpp.xmpp") == 0
    domain_config_set(TEST_DOMAINS[1], "feature.xmpp.xmpp", "yes")
    assert domain_config_get(TEST_DOMAINS[1], "feature.xmpp.xmpp") == 1


def test_domain_configs_unknown():
    with pytest.raises(YunohostValidationError):
        domain_config_get(TEST_DOMAINS[2], "feature.xmpp.xmpp.xmpp")
