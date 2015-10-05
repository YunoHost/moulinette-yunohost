# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2013 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see https://www.gnu.org/licenses

"""

""" yunohost_dyndns.py

    Subscribe and Update DynDNS Hosts
"""
import os
import sys
import requests
import re
import json
import glob
import base64
import errno
import subprocess

from moulinette.core import MoulinetteError


class IPRouteLine(object):
    """ Utility class to parse an ip route output line

    The output of ip ro is variable and hard to parse completly, it would
    require a real parser, not just a regexp, so do minimal parsing here...

    >>> a = IPRouteLine('2001:: from :: via fe80::c23f:fe:1e:cafe dev eth0  src 2000:de:beef:ca:0:fe:1e:cafe  metric 0')
    >>> a.src_addr
    "2000:de:beef:ca:0:fe:1e:cafe"
    """
    regexp = re.compile(
        r'(?P<unreachable>unreachable)?.*src\s+(?P<src_addr>[0-9a-f:]+).*')

    def __init__(self, line):
        self.m = self.regexp.match(line)
        if not self.m:
            raise ValueError("Not a valid ip route get line")

        # make regexp group available as object attributes
        for k, v in self.m.groupdict().items():
            setattr(self, k, v)


def dyndns_subscribe(subscribe_host="dyndns.yunohost.org", domain=None, key=None):
    """
    Subscribe to a DynDNS service

    Keyword argument:
        domain -- Full domain to subscribe with
        key -- Public DNS key
        subscribe_host -- Dynette HTTP API to subscribe to

    """
    if domain is None:
        with open('/etc/yunohost/current_host', 'r') as f:
            domain = f.readline().rstrip()

    # Verify if domain is available
    try:
        if requests.get('https://%s/test/%s' % (subscribe_host, domain)).status_code != 200:
            raise MoulinetteError(errno.EEXIST, m18n.n('dyndns_unavailable'))
    except requests.ConnectionError:
        raise MoulinetteError(errno.ENETUNREACH, m18n.n('no_internet_connection'))

    if key is None:
        if len(glob.glob('/etc/yunohost/dyndns/*.key')) == 0:
            os.makedirs('/etc/yunohost/dyndns')

            msignals.display(m18n.n('dyndns_key_generating'))

            os.system('cd /etc/yunohost/dyndns && ' \
                      'dnssec-keygen -a hmac-md5 -b 128 -n USER %s' % domain)
            os.system('chmod 600 /etc/yunohost/dyndns/*.key /etc/yunohost/dyndns/*.private')

        key_file = glob.glob('/etc/yunohost/dyndns/*.key')[0]
        with open(key_file) as f:
            key = f.readline().strip().split(' ')[-1]

    # Send subscription
    try:
        r = requests.post('https://%s/key/%s' % (subscribe_host, base64.b64encode(key)), data={ 'subdomain': domain })
    except ConnectionError:
        raise MoulinetteError(errno.ENETUNREACH, m18n.n('no_internet_connection'))
    if r.status_code != 201:
        try:    error = json.loads(r.text)['error']
        except: error = "Server error"
        raise MoulinetteError(errno.EPERM,
                              m18n.n('dyndns_registration_failed', error))

    msignals.display(m18n.n('dyndns_registered'), 'success')

    dyndns_installcron()


def dyndns_update(dyn_host="dynhost.yunohost.org", domain=None, key=None, ip=None, ipv6=None):
    """
    Update IP on DynDNS platform

    Keyword argument:
        domain -- Full domain to subscribe with
        dyn_host -- Dynette DNS server to inform
        key -- Public DNS key
        ip -- IP address to send
        ipv6 -- IPv6 address to send

    """
    if domain is None:
        with open('/etc/yunohost/current_host', 'r') as f:
            domain = f.readline().rstrip()

    # IPv4
    if ip is None:
        try:
            new_ip = requests.get('http://ip.yunohost.org').text
        except ConnectionError:
            raise MoulinetteError(errno.ENETUNREACH, m18n.n('no_internet_connection'))
    else:
        new_ip = ip

    try:
        with open('/etc/yunohost/dyndns/old_ip', 'r') as f:
            old_ip = f.readline().rstrip()
    except IOError:
        old_ip = '0.0.0.0'

    # IPv6
    if ipv6 is None:
        new_ipv6 = None
        try:
            ip_route_out = subprocess.check_output(
                ['ip', 'route', 'get', '2000::']).split('\n')

            if len(ip_route_out) > 0:
                route = IPRouteLine(ip_route_out[0])
                if not route.unreachable:
                    new_ipv6 = route.src_addr

        except (OSError, ValueError) as e:
            # Unlikely case "ip route" does not return status 0
            # or produces unexpected output
            raise MoulinetteError(errno.EBADMSG,
                                  "ip route cmd error : {}".format(e))

        if new_ipv6 is None:
            msignals.display(m18n.n('no_ipv6_connectivity'), 'warning')

    else:
        new_ipv6 = ipv6

    try:
        with open('/etc/yunohost/dyndns/old_ipv6', 'r') as f:
            old_ipv6 = f.readline().rstrip()
    except IOError:
        old_ipv6 = '0000:0000:0000:0000:0000:0000:0000:0000'

    if old_ip != new_ip or old_ipv6 != new_ipv6:
        host = domain.split('.')[1:]
        host = '.'.join(host)
        lines = [
            'server %s' % dyn_host,
            'zone %s' % host,
            'update delete %s. A'        % domain,
            'update delete %s. AAAA'     % domain,
            'update delete %s. MX'       % domain,
            'update delete %s. TXT'      % domain,
            'update delete pubsub.%s. A' % domain,
            'update delete pubsub.%s. AAAA' % domain,
            'update delete muc.%s. A'    % domain,
            'update delete muc.%s. AAAA' % domain,
            'update delete vjud.%s. A'   % domain,
            'update delete vjud.%s. AAAA' % domain,
            'update delete _xmpp-client._tcp.%s. SRV' % domain,
            'update delete _xmpp-server._tcp.%s. SRV' % domain,
            'update add %s. 1800 A %s'      % (domain, new_ip),
            'update add %s. 14400 MX 5 %s.' % (domain, domain),
            'update add %s. 14400 TXT "v=spf1 a mx -all"' % domain,
            'update add pubsub.%s. 1800 A %s'    % (domain, new_ip),
            'update add muc.%s. 1800 A %s'       % (domain, new_ip),
            'update add vjud.%s. 1800 A %s'      % (domain, new_ip),
            'update add _xmpp-client._tcp.%s. 14400 SRV 0 5 5222 %s.' % (domain, domain),
            'update add _xmpp-server._tcp.%s. 14400 SRV 0 5 5269 %s.' % (domain, domain)
        ]
        if new_ipv6 is not None:
            lines += [
                'update add %s. 1800 AAAA %s'   % (domain, new_ipv6),
                'update add pubsub.%s. 1800 AAAA %s' % (domain, new_ipv6),
                'update add muc.%s. 1800 AAAA %s'    % (domain, new_ipv6),
                'update add vjud.%s. 1800 AAAA %s'   % (domain, new_ipv6),
            ]
        lines += [
            'show',
            'send'
        ]
        with open('/etc/yunohost/dyndns/zone', 'w') as zone:
            for line in lines:
                zone.write(line + '\n')

        if key is None:
            private_key_file = glob.glob('/etc/yunohost/dyndns/*.private')[0]
        else:
            private_key_file = key
        if os.system('/usr/bin/nsupdate -k %s /etc/yunohost/dyndns/zone' % private_key_file) == 0:
            msignals.display(m18n.n('dyndns_ip_updated'), 'success')
            with open('/etc/yunohost/dyndns/old_ip', 'w') as f:
                f.write(new_ip)
            if new_ipv6 is not None:
                with open('/etc/yunohost/dyndns/old_ipv6', 'w') as f:
                    f.write(new_ipv6)
        else:
            os.system('rm -f /etc/yunohost/dyndns/old_ip')
            os.system('rm -f /etc/yunohost/dyndns/old_ipv6')
            raise MoulinetteError(errno.EPERM,
                                  m18n.n('dyndns_ip_update_failed'))


def dyndns_installcron():
    """
    Install IP update cron


    """
    with open('/etc/cron.d/yunohost-dyndns', 'w+') as f:
        f.write('*/2 * * * * root yunohost dyndns update >> /dev/null\n')

    msignals.display(m18n.n('dyndns_cron_installed'), 'success')


def dyndns_removecron():
    """
    Remove IP update cron


    """
    try:
        os.remove("/etc/cron.d/yunohost-dyndns")
    except:
        raise MoulinetteError(errno.EIO, m18n.n('dyndns_cron_remove_failed'))

    msignals.display(m18n.n('dyndns_cron_removed'), 'success')
