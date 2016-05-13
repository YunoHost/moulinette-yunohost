# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2013-2016 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

""" yunohost_domain.py

    Manage domains
"""
import os
import re
import json
import yaml
import errno
import shutil
import requests

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

from yunohost.service import service_regen_conf
from yunohost.hook import hook_callback
from yunohost.dyndns import dyndns_subscribe
from yunohost.app import app_ssowatconf

logger = getActionLogger('yunohost.domain')


def domain_list(auth, filter=None, limit=None, offset=None):
    """
    List domains

    Keyword argument:
        filter -- LDAP filter used to search
        offset -- Starting number for domain fetching
        limit -- Maximum number of domain fetched

    """
    result_list = []

    # Set default arguments values
    if offset is None:
        offset = 0
    if limit is None:
        limit = 1000
    if filter is None:
        filter = 'virtualdomain=*'

    result = auth.search('ou=domains,dc=yunohost,dc=org', filter, ['virtualdomain'])

    if len(result) > offset and limit > 0:
        for domain in result[offset:offset+limit]:
            result_list.append(domain['virtualdomain'][0])

    return { 'domains': result_list }


def domain_add(auth, domain, dyndns=False):
    """
    Create a custom domain

    Keyword argument:
        domain -- Domain name to add
        dyndns -- Subscribe to DynDNS

    """

    attr_dict = { 'objectClass' : ['mailDomain', 'top'] }

    if domain in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EEXIST, m18n.n('domain_exists'))

    # DynDNS domain
    if dyndns:
        if len(domain.split('.')) < 3:
            raise MoulinetteError(errno.EINVAL, m18n.n('domain_dyndns_invalid'))

        try:
            r = requests.get('https://dyndns.yunohost.org/domains')
        except requests.ConnectionError:
            pass
        else:
            dyndomains = json.loads(r.text)
            dyndomain  = '.'.join(domain.split('.')[1:])
            if dyndomain in dyndomains:
                if os.path.exists('/etc/cron.d/yunohost-dyndns'):
                    raise MoulinetteError(errno.EPERM,
                                          m18n.n('domain_dyndns_already_subscribed'))
                dyndns_subscribe(domain=domain)
            else:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('domain_dyndns_root_unknown'))

    try:
        # Commands
        ssl_dir = '/usr/share/yunohost/yunohost-config/ssl/yunoCA'
        ssl_domain_path  = '/etc/yunohost/certs/%s' % domain
        with open('%s/serial' % ssl_dir, 'r') as f:
            serial = f.readline().rstrip()
        try: os.listdir(ssl_domain_path)
        except OSError: os.makedirs(ssl_domain_path)

        command_list = [
            'cp %s/openssl.cnf %s'                               % (ssl_dir, ssl_domain_path),
            'sed -i "s/yunohost.org/%s/g" %s/openssl.cnf'        % (domain, ssl_domain_path),
            'openssl req -new -config %s/openssl.cnf -days 3650 -out %s/certs/yunohost_csr.pem -keyout %s/certs/yunohost_key.pem -nodes -batch'
            % (ssl_domain_path, ssl_dir, ssl_dir),
            'openssl ca -config %s/openssl.cnf -days 3650 -in %s/certs/yunohost_csr.pem -out %s/certs/yunohost_crt.pem -batch'
            % (ssl_domain_path, ssl_dir, ssl_dir),
            'ln -s /etc/ssl/certs/ca-yunohost_crt.pem %s/ca.pem' % ssl_domain_path,
            'cp %s/certs/yunohost_key.pem    %s/key.pem'         % (ssl_dir, ssl_domain_path),
            'cp %s/newcerts/%s.pem %s/crt.pem'                   % (ssl_dir, serial, ssl_domain_path),
            'chmod 755 %s'                                       % ssl_domain_path,
            'chmod 640 %s/key.pem'                               % ssl_domain_path,
            'chmod 640 %s/crt.pem'                               % ssl_domain_path,
            'chmod 600 %s/openssl.cnf'                           % ssl_domain_path,
            'chown root:metronome %s/key.pem'                    % ssl_domain_path,
            'chown root:metronome %s/crt.pem'                    % ssl_domain_path,
            'cat %s/ca.pem >> %s/crt.pem'                        % (ssl_domain_path, ssl_domain_path)
        ]

        for command in command_list:
            if os.system(command) != 0:
                raise MoulinetteError(errno.EIO,
                                      m18n.n('domain_cert_gen_failed'))

        try:
            auth.validate_uniqueness({ 'virtualdomain': domain })
        except MoulinetteError:
            raise MoulinetteError(errno.EEXIST, m18n.n('domain_exists'))


        attr_dict['virtualdomain'] = domain

        if not auth.add('virtualdomain=%s,ou=domains' % domain, attr_dict):
            raise MoulinetteError(errno.EIO, m18n.n('domain_creation_failed'))

        try:
            with open('/etc/yunohost/installed', 'r') as f:
                service_regen_conf(names=[
                    'nginx', 'metronome', 'dnsmasq', 'rmilter'])
                app_ssowatconf(auth)
        except IOError: pass
    except:
        # Force domain removal silently
        try:
            domain_remove(auth, domain, True)
        except:
            pass
        raise

    hook_callback('post_domain_add', args=[domain])

    logger.success(m18n.n('domain_created'))


def domain_remove(auth, domain, force=False):
    """
    Delete domains

    Keyword argument:
        domain -- Domain to delete
        force -- Force the domain removal

    """
    if not force and domain not in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EINVAL, m18n.n('domain_unknown'))

    # Check if apps are installed on the domain
    for app in os.listdir('/etc/yunohost/apps/'):
        with open('/etc/yunohost/apps/' + app +'/settings.yml') as f:
            try:
                app_domain = yaml.load(f)['domain']
            except:
                continue
            else:
                if app_domain == domain:
                    raise MoulinetteError(errno.EPERM,
                                          m18n.n('domain_uninstall_app_first'))

    if auth.remove('virtualdomain=' + domain + ',ou=domains') or force:
        shutil.rmtree('/etc/yunohost/certs/%s' % domain)
    else:
        raise MoulinetteError(errno.EIO, m18n.n('domain_deletion_failed'))

    service_regen_conf(names=['nginx', 'metronome', 'dnsmasq'])
    app_ssowatconf(auth)

    hook_callback('post_domain_remove', args=[domain])

    logger.success(m18n.n('domain_deleted'))


def domain_dns_conf(domain, ttl=None):
    """
    Generate DNS configuration for a domain

    Keyword argument:
        domain -- Domain name
        ttl -- Time to live

    """
    ttl = 3600 if ttl is None else ttl
    ip4 = ip6 = None

    # A/AAAA records
    ip4 = get_public_ip()
    result = (
        "@ {ttl} IN A {ip4}\n"
        "* {ttl} IN A {ip4}\n"
    ).format(ttl=ttl, ip4=ip4)

    try:
        ip6 = get_public_ip(6)
    except:
        pass
    else:
        result += (
            "@ {ttl} IN AAAA {ip6}\n"
            "* {ttl} IN AAAA {ip6}\n"
        ).format(ttl=ttl, ip6=ip6)

    # Jabber/XMPP
    result += ("\n"
        "_xmpp-client._tcp {ttl} IN SRV 0 5 5222 {domain}.\n"
        "_xmpp-server._tcp {ttl} IN SRV 0 5 5269 {domain}.\n"
        "muc {ttl} IN CNAME @\n"
        "pubsub {ttl} IN CNAME @\n"
        "vjud {ttl} IN CNAME @\n"
    ).format(ttl=ttl, domain=domain)

    # Email
    result += ('\n'
        '@ {ttl} IN MX 10 {domain}.\n'
        '@ {ttl} IN TXT "v=spf1 a mx ip4:{ip4}'
    ).format(ttl=ttl, domain=domain, ip4=ip4)
    if ip6 is not None:
        result += ' ip6:{ip6}'.format(ip6=ip6)
    result += ' -all"'

    # DKIM
    try:
        with open('/etc/dkim/{domain}.mail.txt'.format(domain=domain)) as f:
            dkim_content = f.read()
    except IOError:
        pass
    else:
        dkim = re.match((
            r'^(?P<host>[a-z_\-\.]+)[\s]+([0-9]+[\s]+)?IN[\s]+TXT[\s]+[^"]*'
            '(?=.*(;[\s]*|")v=(?P<v>[^";]+))'
            '(?=.*(;[\s]*|")k=(?P<k>[^";]+))'
            '(?=.*(;[\s]*|")p=(?P<p>[^";]+))'), dkim_content, re.M|re.S
        )
        if dkim:
            result += '\n{host} {ttl} IN TXT "v={v}; k={k}; p={p}"'.format(
                host='{0}.{1}'.format(dkim.group('host'), domain), ttl=ttl,
                v=dkim.group('v'), k=dkim.group('k'), p=dkim.group('p')
            )

            # If DKIM is set, add dummy DMARC support
            result += '\n_dmarc {ttl} IN TXT "v=DMARC1; p=none"'.format(
                ttl=ttl
            )

    return result


def get_public_ip(protocol=4):
    """Retrieve the public IP address from ip.yunohost.org"""
    if protocol == 4:
        url = 'https://ip.yunohost.org'
    elif protocol == 6:
        # FIXME: Let's Encrypt does not support IPv6-only hosts yet
        url = 'http://ip6.yunohost.org'
    else:
        raise ValueError("invalid protocol version")
    try:
        return requests.get(url).content.strip()
    except IOError:
        logger.debug('cannot retrieve public IPv%d' % protocol, exc_info=1)
        raise MoulinetteError(errno.ENETUNREACH,
                              m18n.n('no_internet_connection'))
