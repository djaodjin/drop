# Copyright (c) 2016, DjaoDjin inc.
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

    backup_script = [
        "slapcat -v -l /var/backups/people.ldif",
        "chmod 600 /var/backups/people.ldif"]

    def __init__(self, name, files, **kwargs):
        super(openldap_serversSetup, self).__init__(name, files, **kwargs)

    def create_cron_conf(self, context):
        """
        Create a cron job to backup the database to a flat text file.
        """
        _, new_conf_path = stageFile(os.path.join(
            context.SYSCONFDIR, 'cron.daily', 'ldap_backup'), context)
        with open(new_conf_path, 'w') as new_conf:
            new_conf.write("""#!/bin/sh

%(backup_script)s
"""  % {'backup_script': '\n'.join(self.backup_script)})

    def create_logrotate_conf(self, context):
        """
        Rotate flat file backups.
        """
        _, new_conf_path = stageFile(os.path.join(
            context.SYSCONFDIR, 'logrotate.d', 'ldap_backup'), context)
        with open(new_conf_path, 'w') as new_conf:
            new_conf.write("""/var/backups/people.ldif
{
    create 0600 root root
    daily
    rotate 7
    missingok
    notifempty
    compress
    sharedscripts
    postrotate
        %(backup_script)s
    endscript
}
""" % {'backup_script': '\n        '.join(self.backup_script)})

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
        ldapHost = context.value('ldapHost')
        company_domain = context.value('domainName')
        password_hash = context.value('ldapPasswordHash')
        priv_key = os.path.join(context.SYSCONFDIR,
            'pki', 'tls', 'private', '%s.key' % ldapHost)
        config_path = os.path.join(context.SYSCONFDIR,
            'openldap', 'slapd.d', 'cn=config.ldif')
        _, new_config_path = stageFile(config_path, context)
        modify_config(config_path,
            sep=': ', context=context,
            settings={
                'olcTLSCACertificatePath': os.path.join(
                    context.SYSCONFDIR, 'pki', 'tls', 'certs'),
                'olcTLSCertificateFile': os.path.join(context.SYSCONFDIR,
                    'pki', 'tls', 'certs', '%s.crt' % ldapHost),
                'olcTLSCertificateKeyFile': priv_key
            })
        self._update_crc32(new_config_path)

        domain_parts = tuple(company_domain.split('.'))
        db_config_path = os.path.join(context.SYSCONFDIR,
            'openldap', 'slapd.d', 'cn=config', 'olcDatabase={0}config.ldif')
        _, new_config_path = stageFile(db_config_path, context)
        modify_config(db_config_path,
            sep=': ', enter_block_sep=None, exit_block_sep=None,
            one_per_line=True, context=context, settings={
               'olcRootPW': '%s' % password_hash
            })
        self._update_crc32(new_config_path)
        db_hdb_path = os.path.join(context.SYSCONFDIR,
            'openldap', 'slapd.d', 'cn=config', 'olcDatabase={2}hdb.ldif')
        _, new_config_path = stageFile(db_hdb_path, context)
        modify_config(db_hdb_path,
            sep=': ', enter_block_sep=None, exit_block_sep=None,
            one_per_line=True, context=context, settings={
               'olcSuffix': 'dc=%s,dc=%s' % domain_parts,
               'olcRootDN': 'cn=Manager,dc=%s,dc=%s' % domain_parts,
               'olcRootPW': '%s' % password_hash,
               'olcAccess': [
                   '{0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break',
                   '{0}to attrs=userPassword by self write by dn.base="cn=Manager,dc=%s,dc=%s" write by anonymous auth by * none' % domain_parts,
                   '{1}to * by dn.base="cn=Manager,dc=%s,dc=%s" write by self write by * read"' % domain_parts]
            })
        self._update_crc32(new_config_path)

        schema_path = os.path.join(context.SYSCONFDIR,
            'openldap', 'schema', 'openssh-ldap.ldif')
        _, new_schema_path = stageFile(schema_path, context)
        with open(new_schema_path, 'w') as schema_file:
            schema_file.write("""dn: cn=openssh-openldap,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: openssh-openldap
olcAttributeTypes: {0}( 1.3.6.1.4.1.24552.500.1.1.1.13 NAME 'sshPublicKey' DES
 C 'MANDATORY: OpenSSH Public key' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.
 1.1466.115.121.1.40 )
olcObjectClasses: {0}( 1.3.6.1.4.1.24552.500.1.1.2.0 NAME 'ldapPublicKey' DESC
  'MANDATORY: OpenSSH LPK objectclass' SUP top AUXILIARY MUST ( sshPublicKey $
  uid ) )
""")

        self.create_cron_conf(context)
        self.create_syslogng_conf(context)

        postinst.create_certificate(ldapHost)
        postinst.shellCommand(['chmod', '750', os.path.dirname(priv_key)])
        postinst.shellCommand(['chgrp', 'ldap', os.path.dirname(priv_key)])
        postinst.shellCommand(['chmod', '640', priv_key])
        postinst.shellCommand(['chgrp', 'ldap', priv_key])
        postinst.shellCommand(['chmod', '750', os.path.dirname(priv_key)])
        postinst.shellCommand(['chown', 'ldap:ldap',
            config_path, db_config_path, db_hdb_path])
        postinst.shellCommand(['chmod', '600',
            config_path, db_config_path, db_hdb_path])

        # We need to start the server before adding the schemas.
        postinst.shellCommand(['service', 'slapd', 'restart'])
        postinst.shellCommand(['systemctl','enable', 'slapd.service'])
        postinst.shellCommand(['ldapadd', '-Y','EXTERNAL', '-H', 'ldapi:///',
            '-f', '/etc/openldap/schema/cosine.ldif', '-D', '"cn=config"'])
        postinst.shellCommand(['ldapadd', '-Y','EXTERNAL', '-H', 'ldapi:///',
            '-f', '/etc/openldap/schema/nis.ldif', '-D', '"cn=config"'])
        postinst.shellCommand(['ldapadd', '-Y','EXTERNAL', '-H', 'ldapi:///',
          '-f', '/etc/openldap/schema/inetorgperson.ldif', '-D', '"cn=config"'])
        postinst.shellCommand(['ldapadd', '-Y','EXTERNAL', '-H', 'ldapi:///',
          '-f', '/etc/openldap/schema/openssh-ldap.ldif', '-D', '"cn=config"'])

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

        ldapHost = context.value('ldapHost')
        modify_config(os.path.join(context.SYSCONFDIR,
            'openldap', 'ldap.conf'), sep=' ', context=context,
            settings={
                'TLS_CACERT': os.path.join(
                    context.SYSCONFDIR, 'pki', 'tls', 'certs',
                    '%s.crt' % ldapHost),
                'TLS_REQCERT': 'demand'})

        return complete
