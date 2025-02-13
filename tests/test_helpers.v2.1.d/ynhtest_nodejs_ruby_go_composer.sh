#!/usr/bin/env bash

ynhtest_nodejs_install() {
    local install_dir="$(mktemp -d -p "$VAR_WWW")"

    nodejs_version=20
    ynh_nodejs_install

    node --version | grep -q '^v20\.'

    pushd $install_dir
        # Install a random simple package to validate npm is in the path and working
        npm install ansi-styles
        # FIXME: should test installing as non-root with ynh_exec_as_app to validate PATH propagation ?
        test -d ./node_modules
    popd
}

ynhtest_ruby_install() {
    local install_dir="$(mktemp -d -p "$VAR_WWW")"

    ruby_version=3.3.5
    ynh_ruby_install

    ruby --version
    ruby --version | grep '^3\.3\.5'

    pushd $install_dir
        # FIXME: should test installing as non-root with ynh_exec_as_app to validate PATH propagation ?
        gem install bundler passenger --no-document
        bundle config set --local without 'development test'
    popd
}

ynhtest_go_install() {
    local install_dir="$(mktemp -d -p "$VAR_WWW")"

    go_version=1.22
    ynh_go_install

    go version
    go version | grep 'go1.22 linux'

    pushd $install_dir
        # FIXME: should test building as non-root with ynh_exec_as_app to validate PATH propagation ?
        cat << EOF > helloworld.go
package main
import "fmt"
func main() { fmt.Println("hello world") }
EOF
        go build helloworld.go
        test -e helloworld
        ./helloworld | grep "hello world"
    popd
}

ynhtest_composer_install() {
    local install_dir="$(mktemp -d -p "$VAR_WWW")"

    composer_version="2.8.3"
    php_version=8.2

    install_dir="$(mktemp -d -p "$VAR_WWW")"
    pushd $install_dir
        ynh_composer_install
        # FIXME: should test installing as non-root with ynh_exec_as_app to validate PATH propagation ?
        # Install a random simple package to validate npm is in the path and working
        ynh_composer_exec require symfony/polyfill-mbstring 1.31.0
    popd
}
