# Copyright (c) 2015, DjaoDjin inc.
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

import binascii, os

from tero.setup import modify_config, stageFile, postinst, SetupTemplate


class openldap_serversSetup(SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(openldap_serversSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['slapd']

    def create_syslogng_conf(self, context):
        _, conf_path = stageFile(os.path.join(context.SYSCONFDIR,
            'syslog-ng', 'conf.d', 'slapd.conf'), context=context)
        with open(conf_path, 'w') as conf_file:
            conf_file.write(
"""destination d_ldap      { file("/var/log/slapd.log"); };
filter f_ldap           { program(slapd); };
log { source(s_sys); filter(f_ldap); destination(d_ldap); };
""")

    def _update_crc32(self, pathname):
        with open(pathname) as new_config:
            lines = new_config.readlines()
        lines[1] = '# CRC32 %08x\n' % (
            binascii.crc32(''.join(lines[2:])) & 0xffffffff)
        with open(pathname, 'w') as new_config:
            new_config.write(''.join(lines))

    def run(self, context):
        complete = super(openldap_serversSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete
        domain = 'dbs.internal'
        company_domain = context.value('domainName')
        password_hash = context.value('ldapPasswordHash')
        priv_key = os.path.join(context.SYSCONFDIR,
            'pki', 'tls', 'private', '%s.key' % domain)
        config_path = os.path.join(context.SYSCONFDIR,
            'openldap', 'slapd.d', 'cn=config.ldif')
        _, new_config_path = stageFile(config_path, context)
        modify_config(config_path,
            sep=': ', context=context,
            settings={
                'olcTLSCACertificatePath': os.path.join(
                    context.SYSCONFDIR, 'pki', 'tls', 'certs'),
                'olcTLSCertificateFile': os.path.join(context.SYSCONFDIR,
                    'pki', 'tls', 'certs', '%s.crt' % domain),
                'olcTLSCertificateKeyFile': priv_key
            })
        self._update_crc32(new_config_path)

        domain_parts = tuple(company_domain.split('.'))
        config_path = os.path.join(context.SYSCONFDIR,
            'openldap', 'slapd.d', 'cn=config', 'olcDatabase={0}config.ldif')
        _, new_config_path = stageFile(config_path, context)
        modify_config(config_path,
            sep=': ', enter_block_sep=None, exit_block_sep=None,
            one_per_line=True, context=context, settings={
               'olcRootPW': '{SSHA}%s' % password_hash
            })
        self._update_crc32(new_config_path)
        config_path = os.path.join(context.SYSCONFDIR,
            'openldap', 'slapd.d', 'cn=config', 'olcDatabase={2}mdb.ldif')
        _, new_config_path = stageFile(config_path, context)
        modify_config(config_path,
            sep=': ', enter_block_sep=None, exit_block_sep=None,
            one_per_line=True, context=context, settings={
               'olcSuffix': 'dc=%s,dc=%s' % domain_parts,
               'olcRootDN': 'cn=Manager,dc=%s,dc=%s' % domain_parts,
               'olcRootPW': '{SSHA}%s' % password_hash,
               'olcAccess': [
                   '{0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break',
                   '{0}to attrs=userPassword by self write by dn.base="cn=Manager,dc=%s,dc=%s" write by anonymous auth by * none' % domain_parts,
                   '{1}to * by dn.base="cn=Manager,dc=%s,dc=%s" write by self write by * read"' % domain_parts]
            })
        self._update_crc32(new_config_path)

        postinst.shellCommand(['chmod', '750', os.path.dirname(priv_key)])
        postinst.shellCommand(['chgrp', 'ldap', os.path.dirname(priv_key)])
        postinst.shellCommand(['chmod', '640', priv_key])
        postinst.shellCommand(['chgrp', 'ldap', priv_key])

        self.create_syslogng_conf(context)
        postinst.shellCommand([
            'systemctl', 'enable', 'slapd.service'])

        postinst.shellCommand(['ldapadd', '-x', '-W', '-H', 'ldap:///', '-f',
            '/etc/openldap/schema/cosine.ldif', '-D', '"cn=config"'])
        postinst.shellCommand(['ldapadd', '-x', '-W', '-H', 'ldap:///', '-f',
            '/etc/openldap/schema/inetorgperson.ldif', '-D', '"cn=config"'])

        return complete


class openldap_clientsSetup(SetupTemplate):
    """
    Extra configuration for the LDAP clients.
    """

    def __init__(self, name, files, **kwargs):
        super(openldap_clientsSetup, self).__init__(name, files, **kwargs)

    def run(self, context):
        complete = super(openldap_clientsSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        domain = 'dbs.internal'
        modify_config(os.path.join(context.SYSCONFDIR,
            'openldap', 'ldap.conf'), sep=' ', context=context,
            settings={
                'TLS_CACERT': os.path.join(
                    context.SYSCONFDIR, 'pki', 'tls', 'certs',
                    '%s.crt' % domain),
                'TLS_REQCERT': 'demand'})

        return complete
