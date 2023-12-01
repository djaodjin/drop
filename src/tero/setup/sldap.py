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

import binascii, os, re, sys, subprocess, tempfile

from . import modify_config, stage_file, postinst, SetupTemplate


class openldap_serversSetup(SetupTemplate):

    backup_script = [
        "slapcat -v -l /var/migrate/ldap/dumps/people.ldif",
        "chmod 600 /var/migrate/ldap/dumps/people.ldif"
    ]

    def __init__(self, name, files, **kwargs):
        super(openldap_serversSetup, self).__init__(name, files, **kwargs)

    def create_cron_conf(self, context):
        """
        Create a cron job to backup the database to a flat text file.
        """
        _, new_conf_path = stage_file(os.path.join(
            context.value('etcDir'), 'cron.daily', 'ldap_backup'), context)
        with open(new_conf_path, 'w') as new_conf:
            new_conf.write("""#!/bin/sh

%(backup_script)s
"""  % {'backup_script': '\n'.join(self.backup_script)})

    def create_logrotate_conf(self, context):
        """
        Rotate flat file backups.
        """
        _, new_conf_path = stage_file(os.path.join(
            context.value('etcDir'), 'logrotate.d', 'ldap_backup'), context)
        with open(new_conf_path, 'w') as new_conf:
            new_conf.write("""/var/migrate/ldap/dumps/people.ldif
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
        _, conf_path = stage_file(os.path.join(context.value('etcDir'),
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
        data = ''.join(lines[2:])
        if hasattr(data, 'encode'):
            data = data.encode('utf8')
        lines[1] = '# CRC32 %08x\n' % (binascii.crc32(data) & 0xffffffff)
        with open(pathname, 'w') as new_config:
            new_config.write(''.join(lines))

    @staticmethod
    def restore(filename, domain=None):
        """
        Restore a LDAP database from file.
        """
        with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(filename)) as tmpfile:
            tmpfilename = tmpfile.name
            with open(filename) as backup:
                for line in backup.readlines():
                    look = re.match('^(\S+): (.*)', line)
                    if look:
                        key = look.group(1)
                        value = look.group(2)
                        if not key in ('structuralObjectClass', 'entryUUID',
                            'creatorsName', 'createTimestamp', 'entryCSN',
                            'modifiersName', 'modifyTimestamp'):
                            config_line = "%s: %s\n" % (key, value)
                            if hasattr(config_line, 'encode'):
                                config_line = config_line.encode('utf-8')
                            tmpfile.write(config_line)
                    else:
                        if hasattr(line, 'encode'):
                            line = line.encode('utf-8')
                        tmpfile.write(line)
            domain_dn = ',dc='.join(domain.split('.'))
            cmd = ['ldapadd', '-Y', 'EXTERNAL', '-H', 'ldapi:///',
                   '-f', tmpfilename, '-D', 'cn=Manager,dc=%s' % domain_dn]
            sys.stdout.write("%s\n" % ' '.join(cmd))
            subprocess.check_call(cmd)

    def run(self, context):
        complete = super(openldap_serversSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete
        ldap_host = context.value('ldapHost')
        company_domain = context.value('companyDomain')
        password_hash = context.value('ldapPasswordHash')
        priv_key = os.path.join(context.value('etcDir'),
            'pki', 'tls', 'private', '%s.key' % ldap_host)
        config_path = os.path.join(context.value('etcDir'),
            'openldap', 'slapd.d', 'cn=config.ldif')
        _, new_config_path = stage_file(config_path, context)
        modify_config(config_path,
            sep=': ', context=context,
            settings={
                'olcTLSCACertificatePath': os.path.join(
                    context.value('etcDir'), 'pki', 'tls', 'certs'),
                'olcTLSCertificateFile': os.path.join(context.value('etcDir'),
                    'pki', 'tls', 'certs', '%s.crt' % ldap_host),
                'olcTLSCertificateKeyFile': priv_key
            })
        self._update_crc32(new_config_path)

        domain_parts = tuple(company_domain.split('.'))
        db_config_path = os.path.join(context.value('etcDir'),
            'openldap', 'slapd.d', 'cn=config', 'olcDatabase={0}config.ldif')
        _, new_config_path = stage_file(db_config_path, context)
        modify_config(db_config_path,
            sep=': ', enter_block_sep=None, exit_block_sep=None,
            one_per_line=True, context=context, settings={
               'olcRootPW': '%s' % password_hash
            })
        self._update_crc32(new_config_path)
        # XXX using hdb on Fedora27 with an encrypted EBS will lead
        #     to a `BDB0126 mmap: Invalid argument` error. just delete the file!
        #pylint:disable=line-too-long
        for db_path in ['olcDatabase={2}hdb.ldif', 'olcDatabase={2}mdb.ldif']:
            db_path = os.path.join(context.value('etcDir'),
                'openldap', 'slapd.d', 'cn=config', db_path)
            if os.path.exists(db_path):
                _, new_config_path = stage_file(db_path, context)
                modify_config(db_path,
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

        schema_path = os.path.join(context.value('etcDir'),
            'openldap', 'schema', 'openssh-ldap.ldif')
        _, new_schema_path = stage_file(schema_path, context)
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

        postinst.create_certificate(ldap_host)
        postinst.shell_command(['chmod', '750', os.path.dirname(priv_key)])
        postinst.shell_command(['chgrp', 'ldap', os.path.dirname(priv_key)])
        postinst.shell_command(['chmod', '640', priv_key])
        postinst.shell_command(['chgrp', 'ldap', priv_key])
        postinst.shell_command(['chmod', '750', os.path.dirname(priv_key)])

        sysconfig_path = os.path.join(
            context.value('etcDir'), 'sysconfig', 'slapd')
        _, new_sysconfig_path = stage_file(sysconfig_path, context)
        modify_config(sysconfig_path, context=context, settings={
               'SLAPD_URLS': "ldaps:/// ldap:/// ldapi:///"
            })

        # Resets user and permissions
        ldap_paths = [config_path, db_config_path]
        for db_path in ['olcDatabase={2}hdb.ldif', 'olcDatabase={2}mdb.ldif']:
            db_path = os.path.join(context.value('etcDir'),
                'openldap', 'slapd.d', 'cn=config', db_path)
            if os.path.exists(db_path):
                ldap_paths += [db_path]
        postinst.shell_command(['chown', 'ldap:ldap'] + ldap_paths)
        postinst.shell_command(['chmod', '600'] + ldap_paths)
        # XXX seems necessary after executing on CentOS7?
        postinst.shell_command(['chown', '-R', 'ldap:ldap', '/var/lib/ldap'])

        # We need to start the server before adding the schemas.
        postinst.service_restart('slapd')
        postinst.service_enable('slapd')
        postinst.shell_command(['ldapadd', '-Y', 'EXTERNAL', '-H', 'ldapi:///',
            '-f', '/etc/openldap/schema/cosine.ldif', '-D', '"cn=config"'])
        postinst.shell_command(['ldapadd', '-Y', 'EXTERNAL', '-H', 'ldapi:///',
            '-f', '/etc/openldap/schema/nis.ldif', '-D', '"cn=config"'])
        postinst.shell_command(['ldapadd', '-Y', 'EXTERNAL', '-H', 'ldapi:///',
          '-f', '/etc/openldap/schema/inetorgperson.ldif', '-D', '"cn=config"'])
        postinst.shell_command(['ldapadd', '-Y', 'EXTERNAL', '-H', 'ldapi:///',
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

        ldap_host = context.value('ldapHost')
        ldap_cert_path = os.path.join(context.value('etcDir'),
            'pki', 'tls', 'certs', '%s.crt' % ldap_host)
        modify_config(os.path.join(context.value('etcDir'),
            'openldap', 'ldap.conf'), sep=' ', context=context,
            settings={
                'TLS_CACERT': ldap_cert_path,
                'TLS_REQCERT': 'demand'})

        return complete
