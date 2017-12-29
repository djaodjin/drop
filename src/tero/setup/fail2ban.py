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

from tero import Error
from tero.setup import SetupTemplate, modify_config


class fail2banSetup(SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(fail2banSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['fail2ban']

    def run(self, context):
        complete = super(fail2banSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        jail_conf = os.path.join(
            context.value('etcDir'), 'fail2ban', 'jail.conf')
        # XXX in filter.d/apache-badbots.conf:
        # ^<HOST> -.*"(GET|POST).*(\.php|\.asp|\.exe|\.pl).*HTTP.*".*$
        # jail.conf:
        # apache-badbots: /var/log/nginx/*-access.log

        # XXX /etc/fail2ban/jail.conf
        # 1. sendmail-whois[name=SSH, dest=root, sender=root@fortylines.com]
        # 2. add fail2ban user or use root.
        # XXX nginx settings!
        jail_settings = {
            'apache': {'enabled': 'true'},
            'apache-noscript': {'enabled': 'true'},
            'apache-overflows': {'enabled': 'true'},
            'ssh-iptables': {'maxretry': '3'},
            'spamassassin': {
                    'enabled': 'true',
                    'bantime': '3600',
                    'port': 'http,https,smtp,ssmtp',
                    'filter': 'spamassassin',
                    'logpath': '/var/log/mail.log'}}
        try:
            notify_email = context.value('notifyEmail')
            jail_settings.update({
                'destemail': notify_email,
                'sender': notify_email
            })
        except Error:
            # We don't have an e-mail to send notification to
            pass

        modify_config(jail_conf, settings=jail_settings, context=context)
        # XXX http://blog.darkseer.org/wordpress/?p=149
        # Add in /etc/fail2ban/filter.d/sshd.conf
        # ^%(__prefix_line)sReceived disconnect from <HOST>: \
        # 11: Bye Bye \[preauth\]\s*$
        return complete
