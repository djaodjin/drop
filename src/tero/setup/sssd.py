# Copyright (c) 2023, DjaoDjin inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from __future__ import unicode_literals

import logging, os

from . import stage_file, postinst, SetupTemplate


class sssdSetup(SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(sssdSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['sssd']

    def run(self, context):
        complete = super(sssdSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        ldap_host = context.value('ldapHost')
        company_domain = context.value('companyDomain')
        if not (ldap_host and company_domain):
            logging.warning('ldapHost(%s) or companyDomain(%s) are undefined.'\
                ' skipping configuration of sssd.',
                ldap_host, company_domain)
            return complete

        domain_parts = tuple(company_domain.split('.'))
        if len(domain_parts) < 2:
            logging.warning('companyDomain(%s) cannot be split in 2 parts.',
                company_domain)
            return complete

        ldap_cert_path = os.path.join(context.value('etcDir'),
            'pki', 'tls', 'certs', '%s.crt' % ldap_host)
        names = {
            'ldapHost': ldap_host,
            'domainNat': domain_parts[0],
            'domainTop': domain_parts[1],
            'ldapCertPath': ldap_cert_path
        }

        sssd_conf = os.path.join(context.value('etcDir'), 'sssd', 'sssd.conf')
        _, new_config_path = stage_file(sssd_conf, context)
        with open(new_config_path, 'w') as new_config:
            new_config.write("""[sssd]
config_file_version = 2
reconnection_retries = 3
services = nss, pam, sudo
# SSSD will not start if you do not configure any domains.
# Add new domain configurations as [domain/] sections, and
# then add the list of domains (in the order you want them to be
# queried) to the "domains" attribute below and uncomment it.
domains = LDAP

[nss]
filter_users = root,ldap,named,avahi,haldaemon,dbus,radiusd,news,nscd
reconnection_retries = 3

[pam]
reconnection_retries = 3

[sudo]

[domain/LDAP]
# Debugging:
debug_level = 1

ldap_tls_reqcert = demand
# Note that enabling enumeration will have a moderate performance impact.
# Consequently, the default value for enumeration is FALSE.
# Refer to the sssd.conf man page for full details.
enumerate = true
auth_provider = ldap
# ldap_schema can be set to "rfc2307", which stores group member names in the
# "memberuid" attribute, or to "rfc2307bis", which stores group member DNs in
# the "member" attribute. If you do not know this value, ask your LDAP
# administrator.
#ldap_schema = rfc2307bis
ldap_schema = rfc2307
ldap_search_base = dc=%(domainNat)s,dc=%(domainTop)s
ldap_group_member = uniquemember
id_provider = ldap
ldap_id_use_start_tls = False
chpass_provider = ldap
ldap_uri = ldaps://%(ldapHost)s/
ldap_chpass_uri = ldaps://%(ldapHost)s/
# Allow offline logins by locally storing password hashes (default: false).
cache_credentials = True
ldap_tls_cacert = %(ldapCertPath)s
entry_cache_timeout = 600
ldap_network_timeout = 3
sudo_provider = ldap
ldap_sudo_search_base = ou=sudoers,dc=%(domainNat)s,dc=%(domainTop)s
ldap_sudo_full_refresh_interval=86400
ldap_sudo_smart_refresh_interval=3600
# Enable group mapping otherwise only the user's primary group will map
# correctly. Without this defined group membership won't work
ldap_group_object_class = posixGroup
ldap_group_search_base = ou=groups,dc=%(domainNat)s,dc=%(domainTop)s
ldap_group_name = cn
ldap_group_member = memberUid
""" % names)

        postinst.shell_command(['chmod', '600', sssd_conf])
        postinst.shell_command(['authconfig',
            '--update', '--enablesssd', '--enablesssdauth'])
        postinst.shell_command(['setsebool',
            '-P', 'authlogin_nsswitch_use_ldap', '1'])
        return complete
