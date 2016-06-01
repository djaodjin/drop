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

from tero import setup
from tero.setup import stageFile, postinst


class syslog_ngSetup(setup.SetupTemplate):

    syslog_te_config_template = """module syslog-ng 1.0;

require {
	type syslogd_t;
	type device_t;
	class sock_file { getattr unlink };
	class lnk_file unlink;
}

#============= syslogd_t ==============

allow syslogd_t device_t:lnk_file unlink;
allow syslogd_t device_t:sock_file getattr;
allow syslogd_t device_t:sock_file unlink;
"""

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

        setup.postinst.shellCommand(
            ['rm', '-f', '/etc/systemd/system/syslog.service'])

        # Configure SELinux to run syslog-ng
        syslog_te = os.path.join(
            os.path.dirname(setup.postinst.postinst_run_path), 'syslog-ng.te')
        with open(syslog_te, 'w') as syslog_te_file:
            syslog_te_file.write(self.syslog_te_config_template)
        setup.postinst.install_selinux_module(syslog_te,
            comment="Configure SELinux to run syslog-ng.")

        return complete
