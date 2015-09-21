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

import os

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

    def run(self, context):
        complete = super(openldap_serversSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete
        domain = 'dbs.internal'
        priv_key = os.path.join(context.SYSCONFDIR,
            'pki', 'tls', 'private', '%s.key' % domain)
        modify_config(os.path.join(context.SYSCONFDIR,
            'openldap', 'slapd.d', 'cn=config.ldif'), sep=': ', context=context,
            settings={
                'olcTLSCACertificatePath': os.path.join(
                    context.SYSCONFDIR, 'pki', 'tls', 'certs'),
                'olcTLSCertificateFile': os.path.join(context.SYSCONFDIR,
                    'pki', 'tls', 'certs', '%s.crt' % domain),
                'olcTLSCertificateKeyFile': priv_key
            })

        postinst.shellCommand(['chmod', '750', os.path.dirname(priv_key)])
        postinst.shellCommand(['chgrp', 'ldap', os.path.dirname(priv_key)])
        postinst.shellCommand(['chmod', '640', priv_key])
        postinst.shellCommand(['chgrp', 'ldap', priv_key])

        self.create_syslogng_conf(context)
        postinst.shellCommand([
            'systemctl', 'enable', 'slapd.service'])

        return complete
