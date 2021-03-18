# Copyright (c) 2021, DjaoDjin inc.
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


class logrotateSetup(setup.SetupTemplate):

    logrotate_docker_log_template = {
            filename = 'docker',
            comment = 'Enable logrotate and dcopylogs to send docker logs to S3',
            template = """/var/log/docker.log {
    create 0600 root root
    daily
    rotate 70
    missingok
    notifempty
    sharedscripts
    postrotate
        set -x;
        INSTANCE_ID=`wget -v -O - http://instance-data/latest/meta-data/instance-id | sed -e s/i-/-/`
        LOGS=$1
        ROTATEDFILE=`ls -t /var/log/docker.log* | head -n3 | grep -v '\.log\$' | grep -v '\.gz\$' | head -n1`
        TIMESTAMP=`stat -c %Y $ROTATEDFILE`
        mv -nv $ROTATEDFILE ${ROTATEDFILE/\.log*/.log-$TIMESTAMP}
        /bin/gzip -v9 ${ROTATEDFILE/\.log*/.log-$TIMESTAMP} 
        /usr/local/bin/dcopylogs --location s3://djaoapp-logs/docker --logsuffix=$INSTANCE_ID $LOGS
    endscript
    lastaction
        /bin/sh -c 'syslog-ng-ctl reopen 2>/dev/null || kill -HUP `pgrep syslog-ng 2>/dev/null` 2>/dev/null || true'
    endscript
}
"""
    }

    def __init__(self, name, files, **kwargs):
        super(logrotateSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['logrotate']

    def run(self, context):
        complete = super(logrotateSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        # Install logrotate config file for docker.log
        logrotate_docker_log_conf = os.path.join(
            os.path.dirname("/etc/logrotate.d"),
            logrotate_docker_log_template.filename)

        _, logrotate_docker_log_conf_path = stageFile(logrotate_docker_log_conf, context)
        with open(logrotate_docker_log_conf_path, 'w') as logrotate_docker_log_conf_file:
            logrotate_docker_log_conf_file.write(logrotate_docker_log_template.template)

        return complete
