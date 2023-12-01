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

import os

from tero.setup import modify_config, postinst, SetupTemplate


class sstmpSetup(SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(sstmpSetup, self).__init__(name, files, **kwargs)

    def run(self, context):
        complete = super(sstmpSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        revaliases_conf = os.path.join(
            context.value('etcDir'), 'ssmtp', 'revaliases')
        sstmp_conf = os.path.join(
            context.value('etcDir'), 'ssmtp', 'ssmtp.conf')

        domain = context.value('domainName')
        notify_email = context.value('notifyEmail')
        if notify_email:
            email_host = context.value('emailHost')
            email_port = context.value('emailPort')
            email_host_user = context.value('emailHostUser')
            email_host_password = context.value('emailHostPassword')
            modify_config(sstmp_conf, settings={
                'root': notify_email,
                'mailhub': email_host,
                'RewriteDomain': domain,
                'Hostname': domain,
                'FromLineOverride': "NO",
                'UseSTARTTLS': "YES",
                'UseTLS': "YES",
                'AuthUser': email_host_user,
                'AuthPass': email_host_password
            }, sep='=', context=context)
            modify_config(revaliases_conf, settings={
                'root': notify_email
            }, sep=':', context=context)

        postinst.shell_command([
            'alternatives', '--set mta', '/usr/sbin/sendmail.ssmtp'])

        return complete
