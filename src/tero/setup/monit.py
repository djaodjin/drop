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

from tero import setup

class monitSetup(setup.SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(monitSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['monit']

    def run(self, context):
        complete = super(monitSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        # XXX Monit wants to talk directly to the mail server and so far
        #     we are using ssmtp instead of a local maildrop.
        monit_conf = os.path.join(context.value('etcDir'), 'monitrc')
        notify_email = context.value('notifyEmail')
        if notify_email:
            email_host = context.value('emailHost')
            email_port = context.value('emailPort')
            email_host_user = context.value('emailHostUser')
            email_host_password = context.value('emailHostPassword')
            setup.modify_config(monit_conf, settings={
                'mailserver': "%(email_host)s port %(email_port)s,"\
            " username %(email_host_user)s password %(email_host_password)s"\
            " using tlsv1" % {'email_host': email_host,
                              'email_port': email_port,
                              'email_host_user': email_host_user,
                              'email_host_password': email_host_password,
                             },
                'mail-format': "{ from: %s }" % notify_email,
                'alert': notify_email
            }, context=context)

        return complete
