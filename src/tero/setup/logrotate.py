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

from . import stage_file, SetupTemplate


class logrotateSetup(SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(logrotateSetup, self).__init__(name, files, **kwargs)
        self.daemons = []

    def run(self, context):
        #pylint:disable=too-many-locals
        complete = super(logrotateSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        logrotate_conf = os.path.join(
            context.value('etcDir'), 'logrotate.conf')
        # If the `dateformat` option is not specified, we insert it
        # right after the `dateext` option.
        org_config_path, new_config_path = stage_file(
            logrotate_conf, context)
        with open(org_config_path) as conf_file:
            conf_lines = conf_file.readlines()
        new_config_lines = []
        dateext_linenum = None
        dateformat_linenum = None
        dateformat = "dateformat -%Y%m%d-%s\n"
        for linenum, line in enumerate(conf_lines):
            look = re.match(r'dateformat', line)
            if look:
                dateformat_linenum = linenum
            else:
                look = re.match(r'dateext', line)
                if look:
                    dateext_linenum = linenum
        inserted = False
        for linenum, line in enumerate(conf_lines):
            if not inserted:
                if not dateformat_linenum and not dateext_linenum:
                    new_config_lines += [line]
                    new_config_lines += ['dateext']
                    new_config_lines += [dateformat]
                    inserted = True
                elif not dateformat_linenum and linenum == dateext_linenum:
                    new_config_lines += [line]
                    new_config_lines += [dateformat]
                    inserted = True
                elif linenum == dateformat_linenum:
                    new_config_lines += [dateformat]
                    inserted = True
                else:
                    new_config_lines += [line]
            else:
                new_config_lines += [line]
        with open(new_config_path, 'wt') as conf_file:
            conf_file.write(''.join(new_config_lines))

        return complete
