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
from tero.setup import stageFile


class syslog_ngSetup(setup.SetupTemplate):

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

    500err_template = { 
            'filename': 'docker.conf',
            'comment': 'Syslog-ng filters for catching 500 errors',
            'template': """filter f_docker { program("docker") or tags("docker"); };
filter f_5xxERR-hook { filter(f_docker) and message("HTTP\/.{3,20}[[:space:]]5[[:digit:]]{2}[[:space:]]"); };

destination d_docker { file("/var/log/docker.log"); };
destination d_5xxERR-hook { program("/usr/local/bin/logrotatehook-500error.sh"); };

log { source(s_sys); filter(f_docker); destination(d_docker); };
log { source(s_sys); filter(f_5xxERR-hook); destination(d_5xxERR-hook); };
"""
    }

    def __init__(self, name, files, **kwargs):
        super(syslog_ngSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['syslog-ng']

    def run(self, context):
        complete = super(syslog_ngSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        journald_conf = "/etc/systemd/journald.conf"
        setup.modify_config(journald_conf,
            settings={'ForwardToSyslog': "yes"},
            sep='=', context=context)

        setup.postinst.shellCommand(
            ['rm', '-f', '/etc/systemd/system/syslog.service'])

        #Install 500 error filter config for docker.log
        _, 500err_template_path = stageFile(
            os.path.join(
                os.path.dirname("/etc/syslog-ng/conf.d"),
                500err_template.name),
            context)
        with open(500err_template_path, 'w') as 500err_template_file:
            500err_template_file.write(500err_template.template)
        
        # Configure SELinux to run syslog-ng and run logrotate executables
        for te_template in te_templates:
            syslog_te = os.path.join(
                os.path.dirname(setup.postinst.postinst_run_path), te_template.filename)
            _, syslog_te_path = stageFile(syslog_te, context)
            with open(syslog_te_path, 'w') as syslog_te_file:
                syslog_te_file.write(te_template.template)
            setup.postinst.install_selinux_module(syslog_te,
                te_template.comment)
            setup.postinst.shellCommand(['systemctl', 'reload', 'syslog-ng']


        return complete
