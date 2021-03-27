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

from tero import setup


class dockerSetup(setup.SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(dockerSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['docker']

    def run(self, context):
        complete = super(dockerSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete
        setup.modify_config('/etc/sysconfig/docker', settings={'OPTIONS': '--selinux-enabled --log-driver syslog --log-opt labels="{{.ID}}" --log-opt tag=".{{.ID}}" --signature-verification=false\'', 'LOGROTATE': 'false\''}, sep='=\'')
        setup.postinst.shellCommand(
                ['LIVECONTAINERS=`docker', 'ps', '--format={{.Names}}`;', 'systemctl', 'restart', 'docker', '&&', 'docker', 'start', '$LIVECONTAINERS'])
        ### The previous line needs to be small shell script that records the name of the currently running instances into a variable, then uses those name to start the containters after docker gets restarted. Restarting them by name won't work.
        # XXX
        # $ sudo groupadd docker
        # $ sudo usermod -a -G docker $USER
        # $ sudo service docker restart
        return complete
