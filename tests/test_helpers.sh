#!/usr/bin/env bash

VERSION=${1:-2}

readonly NORMAL=$(printf '\033[0m')
readonly BOLD=$(printf '\033[1m')
readonly RED=$(printf '\033[31m')
readonly GREEN=$(printf '\033[32m')
# shellcheck disable=SC2034
readonly ORANGE=$(printf '\033[33m')

function log_test()
{
    echo -n "${BOLD}$1${NORMAL} ... "
}

function log_passed()
{
    echo "${BOLD}${GREEN}✔ Passed${NORMAL}"
}

function log_failed()
{
    echo "${BOLD}${RED}✘ Failed${NORMAL}"
}

# shellcheck disable=SC2317
function cleanup()
{
    if [ -n "$HTTPSERVER" ]; then
        kill "$HTTPSERVER"
    fi
    if [ -d "$HTTPSERVER_DIR" ]; then
        rm -rf "$HTTPSERVER_DIR"
    fi
    if [ -d "$VAR_WWW" ]; then
        rm -rf "$VAR_WWW"
    fi
}
trap cleanup EXIT SIGINT

# =========================================================

export YNH_STDINFO=1
export YNH_ARCH=$(dpkg --print-architecture)

# Dummy http server, to serve archives for ynh_setup_source
HTTPSERVER_DIR=$(mktemp -d)
HTTPSERVER_PORT=1312
pushd "$HTTPSERVER_DIR" >/dev/null
python3 -m http.server $HTTPSERVER_PORT --bind 127.0.0.1 &>/dev/null &
HTTPSERVER="$!"
popd >/dev/null

VAR_WWW=$(mktemp -d)/var/www
mkdir -p "$VAR_WWW"

# Needed to check the permission behavior in ynh_add_config x_x
getent passwd ynhtest &>/dev/null || useradd --system ynhtest

# =========================================================

for TEST_SUITE in "test_helpers.v$VERSION.d"/*; do
    # shellcheck disable=SC1090
    source "$TEST_SUITE"
done

# Hack to list all known function, keep only those starting by ynhtest_
TESTS=$(declare -F | grep ' ynhtest_' | awk '{print $3}')

global_result=0

run_test() {
    (
        test=$1
        pushd "$(mktemp -d)"
        mkdir conf
        mkdir scripts
        cd scripts
        export YNH_HELPERS_VERSION=$VERSION
        # shellcheck disable=SC1091
        source /usr/share/yunohost/helpers
        app=ynhtest
        # shellcheck disable=SC2034
        YNH_APP_ID=$app
        set -eux
        "$test"
    )
}

for TEST in $TESTS; do
    log_test "$TEST"

    if run_test "$TEST" > ./test.log 2>&1; then
        log_passed
    else
        echo -e "\n----------"
        cat ./test.log
        echo -e "----------"
        log_failed
        global_result=1
    fi
done

exit $global_result
