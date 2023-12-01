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

import six

from . import modify_config, stage_file, SetupTemplate


class dockerSetup(SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(dockerSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['docker']

    def create_syslog_conf(self, context):
        """
        Create configuration for syslog
        """
        appname = 'djaoapp'
        syslog_conf = os.path.join(
            context.value('etcDir'), 'syslog-ng', 'conf.d', 'docker.conf')
        templates_dir = os.path.dirname(os.path.abspath(__file__))
        _, new_conf_path = stage_file(syslog_conf, context)
        with open(os.path.join(
                templates_dir, 'webapp-syslog.tpl')) as conf_file:
            conf_template = conf_file.read()
        with open(new_conf_path, 'w') as new_conf:
            new_conf.write(conf_template % {'appname': appname})

    @staticmethod
    def create_container_systemd_service(context, name, location, port,
                                         description=None):
        if not description:
            description = "%s container" % name
        conf_template = """[Unit]
Description=%(description)s
After=docker.target network.target remote-fs.target nss-lookup.target
Requires=docker.service

[Service]
TimeoutStartSec=0
#Restart=always
ExecStartPre=-/usr/bin/docker stop %(name)s
ExecStartPre=-/usr/bin/docker rm %(name)s
ExecStartPre=/usr/bin/docker pull %(location)s
ExecStart=/usr/bin/docker run --rm --name %(name)s -p %(port)s:80  %(location)s
ExecStop=/usr/bin/docker stop %(name)s

[Install]
WantedBy=multi-user.target
"""
        service_conf = os.path.join('/usr', 'lib', 'systemd', 'system',
            name + '.service')
        _, new_conf_path = stage_file(service_conf, context)
        with open(new_conf_path, 'w') as new_conf:
            new_conf.write(conf_template % {
            'name': name,
            'location': location,
            'port': port,
            'description': description
        })

    def run(self, context):
        complete = super(dockerSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        docker_conf = os.path.join(
            context.value('etcDir'), 'sysconfig', 'docker')
        #pylint:disable=line-too-long
        modify_config(docker_conf, settings={
            'OPTIONS': '--selinux-enabled --log-driver syslog --log-opt labels="{{.ID}}" --log-opt tag=".{{.ID}}"\'',
            'LOGROTATE': 'false\''
        }, sep='=\'', context=context)

        self.create_syslog_conf(context)

        for name, vals in six.iteritems(self.managed['docker']['files']):
            for elem in vals:
                settings = elem[0]
                if isinstance(settings, dict):
                    location = settings.get('location')
                    port = settings.get('port')
                    description = settings.get('description')
                    self.create_container_systemd_service(
                        context, name, location, port,
                        description=description)
                    self.daemons += [name]

        # The following command is useful to restart the running containers
        # after the docker daemon is itself restarted.
        #
        #     LIVECONTAINERS=`docker ps --format={{.Names}}`; systemctl restart docker.service && docker start $LIVECONTAINERS
        #
        # XXX We should technically put the above command in the `daemons` variable.
        # ps. Restarting containers by name won't work.

        # XXX
        # $ sudo groupadd docker
        # $ sudo usermod -a -G docker $USER
        # $ sudo service docker restart
        return complete
