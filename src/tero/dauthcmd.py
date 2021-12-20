#!/usr/bin/env python
#
# Copyright (c) 2019, DjaoDjin inc.
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

# Validate the ssh commands to execute on the server.

import os, sys

RSYNC = '/usr/bin/rsync'
FORWARDTO = '/opt/gitlab/embedded/service/gitlab-shell/bin/gitlab-shell'

def synctree(cmd):
    """Download files from this local machine to a remote machine."""
    err = 1
    sudo = False
    executable = cmd.pop(0)
    if executable == 'sudo':
        executable = cmd.pop(0)
        sudo = True
    if executable == RSYNC:
        # Only allow download from the server on sudo, no upload.
        if sudo and not(('--server' in cmd) and ('--sender' in cmd)):
            return err
        err = os.system(os.environ['SSH_ORIGINAL_COMMAND'])
    return err

def pullapp(cmd, args):
    """Pull git repo and fetch resources for a webapp."""
    err = 1
    executable = cmd.pop(0)
    if executable.startswith('git'):
        forward_cmdline = FORWARDTO + ' ' + ' '.join(args[1:])
        sys.stderr.write("debug: forward_cmdline=%s\n" % forward_cmdline)
        err = os.system(forward_cmdline)
    return err

def main(args):
    if not 'SSH_ORIGINAL_COMMAND' in os.environ:
        sys.stderr.write('error: no ssh command specified.\n')
        sys.exit(1)

    # Make sure we are not trying to login.
    if len(os.environ['SSH_ORIGINAL_COMMAND']) == 0:
        sys.exit(1)

    ssh_original_command = os.getenv('SSH_ORIGINAL_COMMAND')
    sys.stderr.write("debug: SSH_ORIGINAL_COMMAND=%s\n" % ssh_original_command)
    err = 1
    cmd = ssh_original_command.split(' ')
    for part in cmd:
        if '&' in part or '|' in part or ';' in part:
            sys.exit(1)

    if cmd[0].startswith('git'):
        err = pullapp(cmd, args)
    else:
        err = synctree(cmd)
    sys.exit(err)

if __name__ == '__main__':
    main(sys.argv)

