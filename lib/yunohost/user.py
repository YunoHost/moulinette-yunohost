# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2014 YUNOHOST.ORG

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

""" yunohost_user.py

    Manage users
"""
import os
import sys
import crypt
import random
import string
import json
import errno

from moulinette.core import MoulinetteError


def user_list(auth, fields=None, filter=None, limit=None, offset=None):
    """
    List users

    Keyword argument:
        filter -- LDAP filter used to search
        offset -- Starting number for user fetching
        limit -- Maximum number of user fetched
        fields -- fields to fetch

    """
    user_attrs = { 'uid': 'username',
                   'cn': 'fullname',
                   'mail': 'mail',
                   'maildrop': 'mail-forward' }
    attrs = []
    result_list = []

    # Set default arguments values
    if offset is None:
        offset = 0
    if limit is None:
        limit = 1000
    if filter is None:
        filter = '(&(objectclass=person)(!(uid=root))(!(uid=nobody)))'
    if fields:
        keys = user_attrs.keys()
        for attr in fields:
            if attr in keys:
                attrs.append(attr)
            else:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('field_invalid', attr))
    else:
        attrs = [ 'uid', 'cn', 'mail' ]

    result = auth.search('ou=users,dc=yunohost,dc=org', filter, attrs)

    if len(result) > offset and limit > 0:
        for user in result[offset:offset+limit]:
            entry = {}
            for attr, values in user.items():
                try:
                    entry[user_attrs[attr]] = values[0]
                except:
                    pass
            result_list.append(entry)
    return { 'users' : result_list }


def user_create(auth, username, firstname, lastname, mail, password):
    """
    Create user

    Keyword argument:
        firstname
        lastname
        username -- Must be unique
        mail -- Main mail address must be unique
        password

    """
    import pwd
    from yunohost.domain import domain_list
    from yunohost.hook import hook_callback
    from yunohost.app import app_ssowatconf

    # Validate uniqueness of username and mail in LDAP
    auth.validate_uniqueness({
        'uid'       : username,
        'mail'      : mail
    })

    # Validate uniqueness of username in system users
    try:
        pwd.getpwnam(username)
    except KeyError:
        pass
    else:
        raise MoulinetteError(errno.EEXIST, m18n.n('system_username_exists'))

    # Check that the mail domain exists
    if mail[mail.find('@')+1:] not in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('mail_domain_unknown',
                                     mail[mail.find('@')+1:]))

    # Get random UID/GID
    uid_check = gid_check = 0
    while uid_check == 0 and gid_check == 0:
        uid = str(random.randint(200, 99999))
        uid_check = os.system("getent passwd %s" % uid)
        gid_check = os.system("getent group %s" % uid)

    # Adapt values for LDAP
    fullname = '%s %s' % (firstname, lastname)
    rdn = 'uid=%s,ou=users' % username
    char_set = string.ascii_uppercase + string.digits
    salt = ''.join(random.sample(char_set,8))
    salt = '$1$' + salt + '$'
    pwd = '{CRYPT}' + crypt.crypt(str(password), salt)
    attr_dict = {
        'objectClass'   : ['mailAccount', 'inetOrgPerson', 'posixAccount'],
        'givenName'     : firstname,
        'sn'            : lastname,
        'displayName'   : fullname,
        'cn'            : fullname,
        'uid'           : username,
        'mail'          : mail,
        'maildrop'      : username,
        'userPassword'  : pwd,
        'gidNumber'     : uid,
        'uidNumber'     : uid,
        'homeDirectory' : '/home/' + username,
        'loginShell'    : '/bin/false'
    }

    # If it is the first user, add some aliases
    if not auth.search(base='ou=users,dc=yunohost,dc=org', filter='uid=*'):
        with open('/etc/yunohost/current_host') as f:
            main_domain = f.readline().rstrip()
        aliases = [
            'root@'+ main_domain,
            'admin@'+ main_domain,
            'webmaster@'+ main_domain,
            'postmaster@'+ main_domain,
        ]
        attr_dict['mail'] = [ attr_dict['mail'] ] + aliases

        # If exists, remove the redirection from the SSO
        try:
            with open('/etc/ssowat/conf.json.persistent') as json_conf:
                ssowat_conf = json.loads(str(json_conf.read()))

            if 'redirected_urls' in ssowat_conf and '/' in ssowat_conf['redirected_urls']:
                del ssowat_conf['redirected_urls']['/']

            with open('/etc/ssowat/conf.json.persistent', 'w+') as f:
                json.dump(ssowat_conf, f, sort_keys=True, indent=4)

        except IOError: pass


    if auth.add(rdn, attr_dict):
        # Update SFTP user group
        memberlist = auth.search(filter='cn=sftpusers', attrs=['memberUid'])[0]['memberUid']
        memberlist.append(username)
        if auth.update('cn=sftpusers,ou=groups', { 'memberUid': memberlist }):
            os.system("su - %s -c ''" % username)
            app_ssowatconf(auth)
            #TODO: Send a welcome mail to user
            msignals.display(m18n.n('user_created'), 'success')
            hook_callback('post_user_create',
                          args=[username, mail, password, firstname, lastname])

            return { 'fullname' : fullname, 'username' : username, 'mail' : mail }

    raise MoulinetteError(169, m18n.n('user_creation_failed'))


def user_delete(auth, username, purge=False):
    """
    Delete user

    Keyword argument:
        username -- Username to delete
        purge

    """
    from yunohost.app import app_ssowatconf

    if auth.remove('uid=%s,ou=users' % username):
        # Update SFTP user group
        memberlist = auth.search(filter='cn=sftpusers', attrs=['memberUid'])[0]['memberUid']
        try: memberlist.remove(username)
        except: pass
        if auth.update('cn=sftpusers,ou=groups', { 'memberUid': memberlist }):
            if purge:
                os.system('rm -rf /home/%s' % username)
    else:
        raise MoulinetteError(169, m18n.n('user_deletion_failed'))

    app_ssowatconf(auth)
    msignals.display(m18n.n('user_deleted'), 'success')


def user_update(auth, username, firstname=None, lastname=None, mail=None, change_password=None, add_mailforward=None, remove_mailforward=None, add_mailalias=None, remove_mailalias=None):
    """
    Update user informations

    Keyword argument:
        lastname
        mail
        firstname
        add_mailalias -- Mail aliases to add
        remove_mailforward -- Mailforward addresses to remove
        username -- Username of user to update
        add_mailforward -- Mailforward addresses to add
        change_password -- New password to set
        remove_mailalias -- Mail aliases to remove

    """
    from yunohost.domain import domain_list
    from yunohost.app import app_ssowatconf

    attrs_to_fetch = ['givenName', 'sn', 'mail', 'maildrop']
    new_attr_dict = {}
    domains = domain_list(auth)['domains']

    # Populate user informations
    result = auth.search(base='ou=users,dc=yunohost,dc=org', filter='uid=' + username, attrs=attrs_to_fetch)
    if not result:
        raise MoulinetteError(errno.EINVAL, m18n.n('user_unknown'))
    user = result[0]

    # Get modifications from arguments
    if firstname:
        new_attr_dict['givenName'] = firstname # TODO: Validate
        new_attr_dict['cn'] = new_attr_dict['displayName'] = firstname + ' ' + user['sn'][0]

    if lastname:
        new_attr_dict['sn'] = lastname # TODO: Validate
        new_attr_dict['cn'] = new_attr_dict['displayName'] = user['givenName'][0] + ' ' + lastname

    if lastname and firstname:
        new_attr_dict['cn'] = new_attr_dict['displayName'] = firstname + ' ' + lastname

    if change_password:
        char_set = string.ascii_uppercase + string.digits
        salt = ''.join(random.sample(char_set,8))
        salt = '$1$' + salt + '$'
        new_attr_dict['userPassword'] = '{CRYPT}' + crypt.crypt(str(change_password), salt)

    if mail:
        auth.validate_uniqueness({ 'mail': mail })
        if mail[mail.find('@')+1:] not in domains:
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('mail_domain_unknown',
                                          mail[mail.find('@')+1:]))
        del user['mail'][0]
        new_attr_dict['mail'] = [mail] + user['mail']

    if add_mailalias:
        if not isinstance(add_mailalias, list):
            add_mailalias = [ add_mailalias ]
        for mail in add_mailalias:
            auth.validate_uniqueness({ 'mail': mail })
            if mail[mail.find('@')+1:] not in domains:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('mail_domain_unknown',
                                             mail[mail.find('@')+1:]))
            user['mail'].append(mail)
        new_attr_dict['mail'] = user['mail']

    if remove_mailalias:
        if not isinstance(remove_mailalias, list):
            remove_mailalias = [ remove_mailalias ]
        for mail in remove_mailalias:
            if len(user['mail']) > 1 and mail in user['mail'][1:]:
                user['mail'].remove(mail)
            else:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('mail_alias_remove_failed', mail))
        new_attr_dict['mail'] = user['mail']

    if add_mailforward:
        if not isinstance(add_mailforward, list):
            add_mailforward = [ add_mailforward ]
        for mail in add_mailforward:
            if mail in user['maildrop'][1:]:
                continue
            user['maildrop'].append(mail)
        new_attr_dict['maildrop'] = user['maildrop']

    if remove_mailforward:
        if not isinstance(remove_mailforward, list):
            remove_mailforward = [ remove_mailforward ]
        for mail in remove_mailforward:
            if len(user['maildrop']) > 1 and mail in user['maildrop'][1:]:
                user['maildrop'].remove(mail)
            else:
                raise MoulinetteError(errno.EINVAL,
                                      m18n.n('mail_forward_remove_failed', mail))
        new_attr_dict['maildrop'] = user['maildrop']

    if auth.update('uid=%s,ou=users' % username, new_attr_dict):
       msignals.display(m18n.n('user_updated'), 'success')
       app_ssowatconf(auth)
       return user_info(auth, username)
    else:
       raise MoulinetteError(169, m18n.n('user_update_failed'))


def user_info(auth, username):
    """
    Get user informations

    Keyword argument:
        username -- Username or mail to get informations

    """
    user_attrs = ['cn', 'mail', 'uid', 'maildrop', 'givenName', 'sn']

    if len(username.split('@')) is 2:
        filter = 'mail='+ username
    else:
        filter = 'uid='+ username

    result = auth.search('ou=users,dc=yunohost,dc=org', filter, user_attrs)

    if result:
        user = result[0]
    else:
        raise MoulinetteError(errno.EINVAL, m18n.n('user_unknown'))

    result_dict = {
        'username': user['uid'][0],
        'fullname': user['cn'][0],
        'firstname': user['givenName'][0],
        'lastname': user['sn'][0],
        'mail': user['mail'][0]
    }

    if len(user['mail']) > 1:
        result_dict['mail-aliases'] = user['mail'][1:]

    if len(user['maildrop']) > 1:
        result_dict['mail-forward'] = user['maildrop'][1:]

    if result:
        return result_dict
    else:
        raise MoulinetteError(167, m18n.n('user_info_failed'))
