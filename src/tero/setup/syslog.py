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

import os, re

import six

from . import modify_config, postinst, stage_file, SetupTemplate


class syslog_ngSetup(SetupTemplate):

    BEFORE_ACTIONS = 0
    IN_ACTIONS = 1
    IN_LAST_ACTION = 2

    #pylint:disable=line-too-long
    te_templates = {
        'syslog_te_config_template': {
            'filename': 'syslog-ng.te',
            'comment': 'Configure SELinux to run syslog-ng.',
            'template': """module syslog-ng 1.0;

require {
	type httpd_sys_content_t;
	type kernel_t;
	type init_t;
	type syslogd_t;
	type device_t;
	class file read;
	class unix_stream_socket { read write };
	class sock_file { getattr unlink };
	class lnk_file unlink;
	class process execmem;
}

#============= syslogd_t ==============

allow syslogd_t device_t:lnk_file unlink;
allow syslogd_t device_t:sock_file getattr;
allow syslogd_t device_t:sock_file unlink;
allow syslogd_t self:process execmem;

#============= init_t ==============
allow init_t httpd_sys_content_t:file read;
allow init_t kernel_t:unix_stream_socket { read write };
"""
        },
        'syslog_domaintrans_logrotate_template': {
            'filename': 'syslog-domaintrans-logrotate.te',
            'comment': 'Configure SELinux to allow syslog-ng to run logrotate in a destination hook.',
            'template':  """module syslog-domaintrans-logrotate 2.0;

require {
	type syslogd_t;
	type logrotate_exec_t;
	type logrotate_t;
	class process { transition signal sigchld };
	class file { execute getattr open read };
	class fifo_file { read ioctl getattr};
}

#============= syslogd_t ==============

allow syslogd_t logrotate_t:process { transition signal };
allow syslogd_t logrotate_exec_t:file { execute getattr open read };
type_transition syslogd_t logrotate_exec_t : process logrotate_t;

#============= logrotate_t ==============
allow logrotate_t syslogd_t:process sigchld;
allow logrotate_t syslogd_t:fifo_file { getattr read ioctl };
"""
        }
    }

    def __init__(self, name, files, **kwargs):
        super(syslog_ngSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['syslog-ng']

    def modify_logrotate_conf(self, context, additional_lognames=None):
        """
        Rotate log files generated by syslog
        """
        if not additional_lognames:
            additional_lognames = []
        additional_lognames = [] + additional_lognames
        if 'logsLocation' not in context.environ:
            return
        logsLocation = context.value('logsLocation')
        lastaction_commands = [
            'LOGS=$1\n',
            'LOG_SUFFIX=`curl -s http://instance-data/latest/meta-data/instance-id | sed -e s/i-/-/`\n',
            '/usr/local/bin/dcopylogs --quiet --location %s --logsuffix=$LOG_SUFFIX $LOGS\n' % logsLocation
        ]
        syslog_logrotate_conf = os.path.join(
            context.value('etcDir'), 'logrotate.d', 'syslog')
        org_conf_path, new_conf_path = stage_file(
            syslog_logrotate_conf, context)
        inserted = False
        state = self.BEFORE_ACTIONS
        with open(new_conf_path, 'w') as new_conf:
            with open(org_conf_path) as org_conf:
                for line in org_conf.readlines():
                    if state == self.IN_LAST_ACTION:
                        look = re.match(r'endscript', line)
                        if look:
                            new_conf.write('        ')
                            new_conf.write('        '.join(lastaction_commands))
                            inserted = True
                            new_conf.write(line)
                            state = self.IN_ACTIONS
                    elif state == self.BEFORE_ACTIONS:
                        if line.startswith('{'):
                            # write additional logs to process
                            if additional_lognames:
                                new_conf.write('\n'.join(additional_lognames))
                                new_conf.write('\n')
                            state = self.IN_ACTIONS
                        else:
                            try:
                                additional_lognames.remove(line.strip())
                            except ValueError:
                                pass
                        new_conf.write(line)
                    elif line.startswith('}'):
                        if not inserted:
                            new_conf.write('    lastaction\n')
                            new_conf.write('        ')
                            new_conf.write('        '.join(lastaction_commands))
                            new_conf.write('    endscript\n')
                        new_conf.write(line)
                    else:
                        look = re.match(r'lastaction', line)
                        if look:
                            state = self.IN_LAST_ACTION
                        new_conf.write(line)


    def run(self, context):
        complete = super(syslog_ngSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        journald_conf = "/etc/systemd/journald.conf"
        modify_config(journald_conf,
            settings={'ForwardToSyslog': "yes"},
            sep='=', context=context)

        # Make sure we disable rsyslog, we are using sylog-ng here.
        postinst.service_disable('rsyslog')

        # Rotate and upload all logs which have been written through syslog
        additional_lognames = []
        for name, vals in six.iteritems(
                self.managed['syslog-ng'].get('files', {})):
            if name.startswith('/var/log'):
                additional_lognames += [name]
        self.modify_logrotate_conf(
            context, additional_lognames=additional_lognames)

        # Configure SELinux to run syslog-ng and run logrotate executables
        for te_template in six.iteritems(self.te_templates):
            syslog_te = os.path.join(
                os.path.dirname(postinst.postinst_run_path),
                self.te_templates[te_template]['filename'])
            _, syslog_te_path = stage_file(syslog_te, context)
            with open(syslog_te_path, 'w') as syslog_te_file:
                syslog_te_file.write(self.te_templates[te_template]['template'])
            postinst.install_selinux_module(syslog_te,
                self.te_templates[te_template]['comment'])

        return complete
