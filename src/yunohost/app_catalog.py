import os
import re

from moulinette import m18n
from moulinette.utils.log import getActionLogger
from moulinette.utils.network import download_json
from moulinette.utils.filesystem import (
    read_json,
    read_yaml,
    write_to_json,
    write_to_yaml,
    mkdir,
)

from yunohost.utils.i18n import _value_for_locale
from yunohost.utils.error import YunohostError

logger = getActionLogger("yunohost.app_catalog")

APPS_CATALOG_CACHE = "/var/cache/yunohost/repo"
APPS_CATALOG_CONF = "/etc/yunohost/apps_catalog.yml"
APPS_CATALOG_API_VERSION = 2
APPS_CATALOG_DEFAULT_URL = "https://app.yunohost.org/default"


# Old legacy function...
def app_fetchlist():
    logger.warning(
        "'yunohost app fetchlist' is deprecated. Please use 'yunohost tools update --apps' instead"
    )
    from yunohost.tools import tools_update

    tools_update(target="apps")


def app_catalog(full=False, with_categories=False):
    """
    Return a dict of apps available to installation from Yunohost's app catalog
    """

    from yunohost.app import _installed_apps, _set_default_ask_questions

    # Get app list from catalog cache
    catalog = _load_apps_catalog()
    installed_apps = set(_installed_apps())

    # Trim info for apps if not using --full
    for app, infos in catalog["apps"].items():
        infos["installed"] = app in installed_apps

        infos["manifest"]["description"] = _value_for_locale(
            infos["manifest"]["description"]
        )

        if not full:
            catalog["apps"][app] = {
                "description": infos["manifest"]["description"],
                "level": infos["level"],
            }
        else:
            infos["manifest"]["arguments"] = _set_default_ask_questions(
                infos["manifest"].get("arguments", {})
            )

    # Trim info for categories if not using --full
    for category in catalog["categories"]:
        category["title"] = _value_for_locale(category["title"])
        category["description"] = _value_for_locale(category["description"])
        for subtags in category.get("subtags", []):
            subtags["title"] = _value_for_locale(subtags["title"])

    if not full:
        catalog["categories"] = [
            {"id": c["id"], "description": c["description"]}
            for c in catalog["categories"]
        ]

    if not with_categories:
        return {"apps": catalog["apps"]}
    else:
        return {"apps": catalog["apps"], "categories": catalog["categories"]}


def app_search(string):
    """
    Return a dict of apps whose description or name match the search string
    """

    # Retrieve a simple dict listing all apps
    catalog_of_apps = app_catalog()

    # Selecting apps according to a match in app name or description
    matching_apps = {"apps": {}}
    for app in catalog_of_apps["apps"].items():
        if re.search(string, app[0], flags=re.IGNORECASE) or re.search(
            string, app[1]["description"], flags=re.IGNORECASE
        ):
            matching_apps["apps"][app[0]] = app[1]

    return matching_apps


def _initialize_apps_catalog_system():
    """
    This function is meant to intialize the apps_catalog system with YunoHost's default app catalog.
    """

    default_apps_catalog_list = [{"id": "default", "url": APPS_CATALOG_DEFAULT_URL}]

    try:
        logger.debug(
            "Initializing apps catalog system with YunoHost's default app list"
        )
        write_to_yaml(APPS_CATALOG_CONF, default_apps_catalog_list)
    except Exception as e:
        raise YunohostError(
            "Could not initialize the apps catalog system... : %s" % str(e)
        )

    logger.success(m18n.n("apps_catalog_init_success"))


def _read_apps_catalog_list():
    """
    Read the json corresponding to the list of apps catalogs
    """

    try:
        list_ = read_yaml(APPS_CATALOG_CONF)
        # Support the case where file exists but is empty
        # by returning [] if list_ is None
        return list_ if list_ else []
    except Exception as e:
        raise YunohostError("Could not read the apps_catalog list ... : %s" % str(e))


def _actual_apps_catalog_api_url(base_url):

    return "{base_url}/v{version}/apps.json".format(
        base_url=base_url, version=APPS_CATALOG_API_VERSION
    )


def _update_apps_catalog():
    """
    Fetches the json for each apps_catalog and update the cache

    apps_catalog_list is for example :
     [   {"id": "default", "url": "https://app.yunohost.org/default/"}  ]

    Then for each apps_catalog, the actual json URL to be fetched is like :
       https://app.yunohost.org/default/vX/apps.json

    And store it in :
        /var/cache/yunohost/repo/default.json
    """

    apps_catalog_list = _read_apps_catalog_list()

    logger.info(m18n.n("apps_catalog_updating"))

    # Create cache folder if needed
    if not os.path.exists(APPS_CATALOG_CACHE):
        logger.debug("Initialize folder for apps catalog cache")
        mkdir(APPS_CATALOG_CACHE, mode=0o750, parents=True, uid="root")

    for apps_catalog in apps_catalog_list:
        apps_catalog_id = apps_catalog["id"]
        actual_api_url = _actual_apps_catalog_api_url(apps_catalog["url"])

        # Fetch the json
        try:
            apps_catalog_content = download_json(actual_api_url)
        except Exception as e:
            raise YunohostError(
                "apps_catalog_failed_to_download",
                apps_catalog=apps_catalog_id,
                error=str(e),
            )

        # Remember the apps_catalog api version for later
        apps_catalog_content["from_api_version"] = APPS_CATALOG_API_VERSION

        # Save the apps_catalog data in the cache
        cache_file = "{cache_folder}/{list}.json".format(
            cache_folder=APPS_CATALOG_CACHE, list=apps_catalog_id
        )
        try:
            write_to_json(cache_file, apps_catalog_content)
        except Exception as e:
            raise YunohostError(
                "Unable to write cache data for %s apps_catalog : %s"
                % (apps_catalog_id, str(e))
            )

    logger.success(m18n.n("apps_catalog_update_success"))


def _load_apps_catalog():
    """
    Read all the apps catalog cache files and build a single dict (merged_catalog)
    corresponding to all known apps and categories
    """

    merged_catalog = {"apps": {}, "categories": []}

    for apps_catalog_id in [L["id"] for L in _read_apps_catalog_list()]:

        # Let's load the json from cache for this catalog
        cache_file = "{cache_folder}/{list}.json".format(
            cache_folder=APPS_CATALOG_CACHE, list=apps_catalog_id
        )

        try:
            apps_catalog_content = (
                read_json(cache_file) if os.path.exists(cache_file) else None
            )
        except Exception as e:
            raise YunohostError(
                "Unable to read cache for apps_catalog %s : %s" % (cache_file, e),
                raw_msg=True,
            )

        # Check that the version of the data matches version ....
        # ... otherwise it means we updated yunohost in the meantime
        # and need to update the cache for everything to be consistent
        if (
            not apps_catalog_content
            or apps_catalog_content.get("from_api_version") != APPS_CATALOG_API_VERSION
        ):
            logger.info(m18n.n("apps_catalog_obsolete_cache"))
            _update_apps_catalog()
            apps_catalog_content = read_json(cache_file)

        del apps_catalog_content["from_api_version"]

        # Add apps from this catalog to the output
        for app, info in apps_catalog_content["apps"].items():

            # (N.B. : there's a small edge case where multiple apps catalog could be listing the same apps ...
            #         in which case we keep only the first one found)
            if app in merged_catalog["apps"]:
                logger.warning(
                    "Duplicate app %s found between apps catalog %s and %s"
                    % (app, apps_catalog_id, merged_catalog["apps"][app]["repository"])
                )
                continue

            info["repository"] = apps_catalog_id
            merged_catalog["apps"][app] = info

        # Annnnd categories
        merged_catalog["categories"] += apps_catalog_content["categories"]

    return merged_catalog
