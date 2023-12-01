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

import os

import six

from . import SetupTemplate, modify_config, stage_file

def add_entry(filename, command,
              username='root', minutes='0', hours='19', dom='*', months='*',
              dow='*', sysconf_dir='/etc', context=None):
    '''Add a new cron job.'''
    _, cron_path = stage_file(
        os.path.join(sysconf_dir, 'cron.d', filename), context)
    with open(cron_path, 'w') as cron:
        cron.write('# m  h dom mon dow user command\n')
        cron.write('%s %s %s %s %s %s %s\n'
                   % (minutes, hours, dom, months, dow, username, command))


class cronSetup(SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(cronSetup, self).__init__(name, files, **kwargs)
        self.jobs = {}

    def run(self, context):
        complete = super(cronSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        anacrontab_conf = os.path.join(context.value('etcDir'), 'anacrontab')
        crontab_conf = os.path.join(context.value('etcDir'), 'crontab')
        notify_email = context.value('notifyEmail')
        if notify_email:
            modify_config(anacrontab_conf,
                settings={'MAILTO': notify_email}, context=context)
            modify_config(crontab_conf,
                settings={'MAILTO': notify_email}, context=context)

        for key, vals in six.iteritems(
                self.managed['iptables']['files']):
            if key.startswith('/etc/cron.d'):
                for cmds in vals:
                    lines = cmds[0]
                    _, cron_path = stage_file(key, context=context)
                    with open(cron_path, 'w') as cronfile:
                        cronfile.write('# m  h dom mon dow command\n')
                        cronfile.write(lines)
        return complete
