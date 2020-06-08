# Copyright (c) 2020, DjaoDjin inc.
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

import getpass, os, socket, sys

import tero, tero.dstamp


def check_permissions(paths, owner, group, mode):
    for path in paths:
        stat = os.stat(path)
        if stat.st_uid != owner:
            sys.stderr.write('onwer mismatch: ' + path + '\n')
        if stat.st_gid != group:
            sys.stderr.write('group mismatch: ' + path + '\n')
        if stat.st_mode != mode:
            sys.stderr.write('mode mismatch: ' + path + '\n')


def create_archives(backup_dir, backup_tops):
    '''Create an archive out of each backup_top.'''
    os.chdir(backup_dir)
    for backup_top in backup_tops:
        basename = os.path.basename(backup_top)
        archive = tero.stampfile(basename)
        tero.shell_command(['tar', '--bzip2', '-cf', archive,
                          '-C', os.path.dirname(backup_top),
                          '--exclude', 'build/',
                          basename])
    tero.dstamp.cleanup_aged_files(backup_dir)


def fingerprint_fs(context, log_path_prefix, exclude_tops=None):
    '''Uses mtree to take a fingerprint of the filesystem and output
       the specification file in "*log_path_prefix*.mtree".
       If an *exclude_tops* file exists, it contains patterns used to skip
       over parts of the filesystem to fingerprint.'''

    if not exclude_tops and os.path.exists(exclude_tops):
        exclude_tops_flags = " -X " + exclude_tops
    else:
        exclude_tops_flags = ""
        tero.shell_command([os.path.join(context.value('binDir'), 'mtree'),
                          ' -c -K sha1digest -p /',
                          exclude_tops_flags,
                          ' > ' + os.path.abspath(log_path_prefix + '.mtree')])


def find_privileged_executables(log_path_prefix):
    '''Look through the filesystem for executables that have the suid bit
       turned on and executables that can be executed as remote commands.'''
    # find suid privileged executables
    suid_results = log_path_prefix + '.suid'
    try:
        tero.shell_command(['/usr/bin/find', '/', '-type f',
                          '\\( -perm -04000 -or -perm -02000 \\) -ls',
                          ' > ' + suid_results])
    except RuntimeError:
        # It is ok to get an exception here. We cannot exclude /dev, etc.
        # when searching from root.
        pass
    # find rcmd executables
    rcmd_results = log_path_prefix + getpass.getuser() + '.rcmd'
    try:
        tero.shell_command(['/usr/bin/find', '/',
                          '| grep -e ".rhosts" -e "hosts.equiv"',
                          ' > ' + rcmd_results])
    except RuntimeError:
        # It is ok to get an exception here. We cannot exclude /dev, etc.
        # when searching from root.
        pass


def find_running_processes(log_path_prefix, dist_host):
    '''List running processes into "*log_path_prefix*.processes"'''
    log_path = os.path.abspath(log_path_prefix + '.processes')
    ps_cmd = ['/bin/ps', '-ej']
    if not dist_host.endswith('Darwin'):
        ps_cmd += ['HF']
    tero.shell_command(ps_cmd, log_path, True)


def find_open_ports(log_path_prefix, dist_host):
    '''List processes listening on open ports into "*log_path_prefix*.ports"'''
    log_path = os.path.abspath(log_path_prefix + '.ports')
    if dist_host.endswith('Darwin'):
        tero.shell_command(['/usr/sbin/lsof', '-i', '-P'], log_path, True)
    else:
        tero.shell_command(['/bin/netstat', '-atp'], log_path, True)
        tero.shell_command(['/bin/netstat', '-n', '-atp'], log_path, True)
    # Open ports as listed by nmap
    tero.shell_command(['nmap', 'localhost'], log_path, True)


def fingerprint(context, log_path_prefix, skip_filesystem=False,
                skip_privileged_executables=False, skip_processes=False,
                skip_ports=False):
    """
    Record a fingerprint of the running system.
    """
    dist_host = context.value('distHost')
    if not skip_filesystem:
        fingerprint_fs(context, log_path_prefix,
            os.path.join(context.value('etcDir'),
                'excludes-' + socket.gethostname()))
    if not skip_privileged_executables:
        find_privileged_executables(log_path_prefix)
    if not skip_processes:
        find_running_processes(log_path_prefix, dist_host)
    if not skip_ports:
        find_open_ports(log_path_prefix, dist_host)
