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

import argparse, os, sys

import tero
from . import stage_file, SetupTemplate


class dovecotSetup(SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(dovecotSetup, self).__init__(name, files, **kwargs)

    def run(self, context):
        complete = super(dovecotSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        # XXX TODO Update the config files
        old_conf_path, new_conf_path = stage_file(os.path.join(
            context.value('etcDir'), 'dovecot', 'conf.d', '10-auth.conf'),
            context)
        #-#!include auth-system.conf.ext
        #+!include auth-system.conf.ext
        # #!include auth-sql.conf.ext
        #-!include auth-ldap.conf.ext
        #+#!include auth-ldap.conf.ext

        old_conf_path, new_conf_path = stage_file(os.path.join(
            context.value('etcDir'), 'dovecot', 'conf.d', '10-mail.conf'),
            context)
        #-mail_location = maildir:/var/db/mail/vhosts/%d/%n
        #+#mail_location =

        old_conf_path, new_conf_path = stage_file(os.path.join(
            context.value('etcDir'), 'dovecot', 'conf.d', '10-master.conf'),
            context)
        #-  unix_listener /var/spool/postfix/private/auth {
        #-    mode = 0666
        #-    user = postfix
        #-    group = postfix
        #-  }
        #+  #unix_listener /var/spool/postfix/private/auth {
        #+  #  mode = 0666
        #+  #}

        old_conf_path, new_conf_path = stage_file(os.path.join(
            context.value('etcDir'), 'dovecot', 'conf.d', '10-ssl.conf'),
            context)
        #-ssl_cert = </etc/letsencrypt/live/mail.*domainname*/fullchain.pem
        #-ssl_key = </etc/letsencrypt/live/mail.*domainname*/privkey.pem
        #+ssl_cert = </etc/pki/dovecot/certs/dovecot.pem
        #+ssl_key = </etc/pki/dovecot/private/dovecot.pem

        old_conf_path, new_conf_path = stage_file(os.path.join(
            context.value('etcDir'), 'dovecot', 'conf.d', 'auth-ldap.conf.ext'),
            context)
        #-#userdb {
        #-#  driver = ldap
        #-#  args = /etc/dovecot/dovecot-ldap.conf.ext
        #+userdb {
        #+  driver = ldap
        #+  args = /etc/dovecot/dovecot-ldap.conf.ext
        #
        #   #default_fields = home=/home/virtual/%u
        #-#}
        #+}
        #
        #-userdb {
        #-  driver = static
        #-  args = uid=vmail gid=vmail home=/var/db/mail/vhosts/%d/%n
        #-}
        #+#userdb {
        #+  #driver = static
        #+  #args = uid=vmail gid=vmail home=/var/vmail/%u
        #+#}

        old_conf_path, new_conf_path = stage_file(os.path.join(
            context.value('etcDir'), 'dovecot', 'conf.d',
            'dovecot-ldap.conf.ext'), context)

        return complete


def main(args):
    parser = argparse.ArgumentParser(usage='%(prog)s [options]')
    parser.add_argument('-D', dest='defines', action='append', default=[],
                      help='Add a (key,value) definition to use in templates.')
    options = parser.parse_args(args[1:])
    defines = dict([item.split('=') for item in options.defines])

    tero.CONTEXT = tero.Context()
    for define in options.defines:
        key, value = define.split('=')
        tero.CONTEXT.environ[key] = value

    tero.CONTEXT.locate()

    setup = dovecotSetup('dovecot', {})
    setup.run(tero.CONTEXT)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
