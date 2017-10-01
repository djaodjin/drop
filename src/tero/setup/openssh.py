# Copyright (c) 2017, DjaoDjin inc.
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

import six

from tero import APT_DISTRIBS, DNF_DISTRIBS, CONTEXT
from tero.setup import (SetupTemplate, modify_config,
    stageDir, stageFile, postinst)


class openssh_serverSetup(SetupTemplate):
    '''Setup the ssh daemon

    Note:
    AllowTcpForwarding
       Specifies whether TCP forwarding is permitted.  The default is
       ``yes''.  Note that disabling TCP forwarding does not improve
       security unless users are also denied shell access, as they can
       always install their own forwarders.'''

    ldap_conf = os.path.join(CONTEXT.value('etcDir'), 'ssh', 'ldap.conf')
    sshd_conf = os.path.join(CONTEXT.value('etcDir'), 'ssh', 'sshd_config')

    def __init__(self, name, files, **kwargs):
        super(openssh_serverSetup, self).__init__(name, files, **kwargs)
        self.configfiles = [self.sshd_conf, self.ldap_conf]
        self.daemons = ['sshd']

    def run(self, context):
        complete = super(openssh_serverSetup, self).run(context)
        ldapHost = context.value('ldapHost')
        domain_parts = tuple(context.value('domainName').split('.'))
        banner = os.path.join(context.value('etcDir'), 'issue.net')
        _, new_banner_path = stageFile(
            banner, context=context)
        with open(new_banner_path, 'w') as new_banner:
            new_banner.write(
                'This server is private property. Authorized use only.\n')
        settings = {'Banner': banner}
        for key, vals in six.iteritems(
                self.managed['openssh-server']['files']):
            if key == self.sshd_conf:
                settings.update(vals[0][0])
        modify_config(self.sshd_conf,
            settings=settings, sep=' ', context=context)

        ldapCertPath = os.path.join(context.value('etcDir'),
            'pki', 'tls', 'certs', '%s.crt' % ldapHost)
        names = {
            'ldapHost': ldapHost,
            'domainNat': domain_parts[0],
            'domainTop': domain_parts[1],
            'ldapCertPath': ldapCertPath
        }
        modify_config(self.ldap_conf,
            settings={
                'URI': 'ldaps://%(ldapHost)s' % names,
                'BASE': 'ou=people,dc=%(domainNat)s,dc=%(domainTop)s' % names,
                'TLS_CACERT': ldapCertPath,
                'TLS_REQCERT': 'demand',
                'TIMELIMIT': '15',
                'TIMEOUT': '20'
            }, sep=' ', context=context)

        config_path = os.path.join(
            '/usr', 'libexec', 'openssh', 'ssh-ldap-wrapper')
        _, new_config_path = stageFile(config_path, context)
        with open(new_config_path, 'w') as new_config:
            new_config.write(
"""#!/bin/sh
if [ "$1" == "fedora" ] ; then
    exit 1
fi
exec /usr/libexec/openssh/ssh-ldap-helper -s "$1"
""")
        postinst.shellCommand(['chmod', '755', config_path])
        postinst.shellCommand(['chmod', '644', self.ldap_conf])
        return complete
