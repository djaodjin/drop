# Copyright (c) 2025, DjaoDjin inc.
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

import argparse, logging, re, os, subprocess, sys

import six

import tero
from tero.setup import (after_daemon_start, modify_config, postinst, stage_file,
    SetupTemplate)
from tero.setup.cron import add_entry as cron_add_entry


class gitlab_eeSetup(SetupTemplate):

    service_candidates = ['/usr/lib/systemd/system/gitlab-ee.service']

    def __init__(self, name, files, **kwargs):
        super(gitlab_eeSetup, self).__init__(name, files, **kwargs)

    @property
    def daemons(self):
        if not hasattr(self, '_daemons'):
            service = self.locate_config('service', self.service_candidates)
            self._daemons = [os.path.splitext(os.path.basename(service))[0]]
        return self._daemons


    @staticmethod
    def locate_config(name, candidates):
        found = None
        for candidate in candidates:
            if os.path.exists(candidate):
                found = candidate
                break
        if not found:
            raise RuntimeError("couldn't locate %s in %s!" % (name, candidates))
        return found


    def run(self, context):
        complete = super(gitlab_eeSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        return complete


def main(args):
    parser = argparse.ArgumentParser(usage='%(prog)s [options]')
    parser.add_argument('-D', dest='defines', action='append', default=[],
                      help='Add a (key,value) definition to use in templates.')
    options = parser.parse_args(args[1:])
    defines = dict([item.split('=') for item in options.defines])

    tero.CONTEXT = tero.Context()
    tero.CONTEXT.environ['vpc_cidr'] = tero.Variable('vpc_cidr',
             {'description': 'CIDR allowed to create remote connections',
              'default': defines.get('vpc_cidr', '192.168.144.0/24')})
    for define in options.defines:
        key, value = define.split('=')
        tero.CONTEXT.environ[key] = value

    tero.CONTEXT.locate()

    setup = gitlab_eeSetup('gitlab-ee', {})
    setup.run(tero.CONTEXT)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
