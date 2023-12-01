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

"""
Entry point for the code executed on the machine triggering the setup
of a remote host.
"""

import imp, logging, os, re, shutil, subprocess, sys, time, tempfile

import fabric.api as fab
from fabric.context_managers import settings as fab_settings
import six

from tero import (__version__, find_rsync, shell_command,
    build_subcommands_parser, filter_subcommand_args)


CLOUD_BACKEND = None
DEFAULT_REMOTE_PATH = '~/build'
TIMEOUT_DURATION = 30

ENV_USER = None
ENV_PASSWORD = None
ENV_KEY_FILENAME = None


def _load_backend(path):
    """
    Load a specific backend.
    """
    dot_pos = path.rfind('.')
    module, attr = path[:dot_pos], path[dot_pos + 1:]
    try:
        __import__(module)
        mod = sys.modules[module]
    except ImportError as err:
        raise RuntimeError(
            'Importing backend %s: "%s"' % (path, err))
    try:
        cls = getattr(mod, attr)
    except AttributeError:
        raise RuntimeError(
            'Module "%s" does not define a "%s"' % (module, attr))
    return cls()


def copy_setup(profiles, host, remote_path, settings=None):
    """
    Copy scripts needed for configuration onto the remote machine.
    """
    if settings is None:
        settings = {}
    pythondir = os.path.dirname(os.path.dirname(__file__))
    basedir = os.path.dirname(os.path.dirname(os.path.dirname(pythondir)))
    bindir = os.path.join(basedir, 'bin')
    etcdir = os.path.join(basedir, 'etc')
    sharedir = os.path.join(basedir, 'share')
    profilesdir = os.path.join(sharedir, 'tero', 'profiles')
    files = [os.path.join(pythondir, 'tero'),
             os.path.join(pythondir, 'dws'),
             os.path.join(bindir, 'dservices'),
             os.path.join(bindir, 'dbldpkg'),
             os.path.join(bindir, 'dws'),
             os.path.join(sharedir, 'dws'),
             os.path.join(sharedir, 'tero'),
             os.path.join(etcdir, 'tero', 'config')]
    prefix = os.path.commonprefix(files)
    dirpath = tempfile.mkdtemp()
    stage_top = os.path.join(dirpath, os.path.basename(remote_path))
    stage_profile_dir = os.path.join(
        stage_top, 'share', 'tero', 'profiles')

    for staged in files:
        stage_path = staged.replace(prefix, stage_top + os.sep)
        if not os.path.exists(os.path.dirname(stage_path)):
            os.makedirs(os.path.dirname(stage_path))
        if os.path.isdir(staged):
            shutil.copytree(staged, stage_path)
        else:
            shutil.copy(staged, stage_path)

    for profile_name in profiles:
        look = re.match(r'\w+@(\w+.)+\w+:\S+', profile_name)
        if not look:
            # This does not look like a profile on a remote machine
            # so let's assume it is local file.
            profile_abs_path = os.path.abspath(profile_name)
            if not os.path.isfile(profile_abs_path):
                profile_abs_path = os.path.join(
                    profilesdir, profile_name + '.xml')
            if not os.path.isfile(profile_abs_path):
                raise ValueError('cannot find profile "%s"' % profile_name)
            if not profile_abs_path.startswith(profilesdir):
                # We are setting up a profile which is not in the default set,
                # so let's copy it to the machine being setup as well.
                shutil.copy(profile_abs_path, stage_profile_dir)

    if ENV_PASSWORD:
        # We will need a sudo password to install packages and configure
        # them according to a profile.
        askpass_path = os.path.join(stage_top, 'bin', 'askpass')
        with open(askpass_path, 'w') as askpass:
            askpass.write('#!/bin/sh\n')
            askpass.write('echo %s\n' % ENV_PASSWORD)
        import stat
        os.chmod(askpass_path, stat.S_IRWXU)

    if True:
        # XXX Either implementation is asking for password
        # XXX admin=True otherwise we cannot create directory in /var/www.
        cmdline, prefix = find_rsync(
            host, relative=False, admin=False, key=ENV_KEY_FILENAME)
        cmdline += ['--exclude=".git"', dirpath + '/*']
        dest = host + ':' + os.path.dirname(remote_path)
        if ENV_USER:
            dest = ENV_USER + '@' + dest
        cmdline += [dest]
        shell_command(cmdline)
    else:
        import fabric.contrib.project
        fabric.contrib.project.rsync_project(
            local_dir=dirpath + '/*',
            remote_dir=os.path.dirname(remote_path),
            exclude=['.git'])

    if not os.path.isdir(dirpath):
        shutil.rmtree(dirpath)


def run_dservices(profile_names, host, remote_path, settings=None):
    """
    Run the configuration script on the remote machine.
    """
    # Create a list of variables (name, value) to pass to the script run
    # on the remote machine.
    defines = []
    if settings:
        for key, value in six.iteritems(settings):
            defines += ['-D"%s"="%s"' % (key, value)]
    profiles = []
    for profile_name in profile_names:
        profile = os.path.basename(profile_name)
        if not profile.endswith('.xml'):
            profile = profile + '.xml'
        profiles += ['share/tero/profiles/' + profile]
    with fab_settings(abort_on_prompts=True, host_string=host):
        fab.cd(remote_path):
        cmdline = ['./bin/dservices'] + defines + profiles
        fab.run(' '.join(cmdline))


def pub_boot(vm_list, image=None, macaddr=None):
    '''Boot a new virtual machine on VMware Fusion.'''
    if len(vm_list) == 0:
        sys.stderr.write("warning: no target instances to boot.\n")
    for vm_name in vm_list:
        guest = CLOUD_BACKEND.boot(vm_name, image, macaddr, ENV_KEY_FILENAME)
        sys.stdout.write("booted %s\n" % guest)


def pub_deploy(hosts, profiles=[], identities=[], settings={}):
    """
    Setup a machine with a specified set of profiles.
    """
    remote_paths = []
    for host_path in hosts:
        parts = host_path.split(':')
        remote_paths += [parts[1]] if len(parts) > 1 else [DEFAULT_REMOTE_PATH]
    hosts = [host_path.split(':')[0] for host_path in hosts]
    host_ips = CLOUD_BACKEND.network_ip(hosts)
    for host, ipaddr in six.iteritems(host_ips):
        if not ipaddr:
            logging.error('cannot find IP for %s', host)
    fab.env.hosts = list(host_ips.values())
    for host, remote_path in zip(fab.env.hosts, remote_paths):
        fab.env.host_string = host
        if identities:
            rsync, prefix = find_rsync(host, relative=True, admin=True,
                username=ENV_USER, key=ENV_KEY_FILENAME)
            for src_path in identities:
                cmdline = rsync + [src_path + '/./*', prefix + '/']
                shell_command(cmdline)
        copy_setup(profiles, host, remote_path, settings=settings)
        run_dservices(profiles, host, remote_path, settings=settings)


def pub_list(settings=None):
    """
    List all running virtual machines.
    """
    vms = CLOUD_BACKEND.list_vms()
    # Display results
    sys.stdout.write('%s | %s | %s\n' % ('ip_addr', 'mac_addr', 'vm_name'))
    for name, ipaddr, mac in vms:
        sys.stdout.write('%s | %s | %s\n' % (ipaddr, mac, name))


def pub_ssh(vm_list, port=22, keyfile=None, login=None, available=False):
    """Execute an SSH command to a virtual machine (*vm_name*)."""
    if len(vm_list) > 1:
        raise RuntimeError("More than one virtual machine to ssh into.")
    vm_name = vm_list[0]
    hostname = CLOUD_BACKEND.get_ip_addr(vm_name)
    logging.info('ipaddr for %s: %s', vm_name, hostname)
    if hostname:
        # Connect to the Virtual Machine
        cmdline = ['ssh']
        if keyfile:
            cmdline += ['-i', keyfile]
        if login:
            cmdline += ['-l', login]
        cmdline += [hostname]
        cmd = subprocess.Popen(' '.join(cmdline),
                         shell=True,
                         stdout=None,
                         stderr=subprocess.STDOUT,
                         close_fds=True)
        cmd.wait()
        if cmd.returncode != None and cmd.returncode != 0:
            raise subprocess.CalledProcessError(cmd.returncode, cmdline)


def pub_stage(src_path, host):
    '''Copy a directory tree from the local machine to the staged machine
    root directory. This is often used to copy credentials before running
    a deploy command.'''
    rsync, prefix = find_rsync(host, relative=True, admin=True,
        username=ENV_USER, key=ENV_KEY_FILENAME)
    cmdline = rsync + [src_path + '/./*', prefix + '/']
    shell_command(cmdline)


def pub_start(vm_list):
    '''Start a virtual machine on VMware Fusion.'''
    started = {}
    sys.stdout.write('%s | %s | %s\n' % ('ip_addr', 'mac_addr', 'vm_name'))
    for vm_name in vm_list:
        CLOUD_BACKEND.start(vm_name)
        # Wait until we get an IP address for the virtual machine.
        start_time = time.time()
        current_time = time.time()
        ipaddr = None
        macaddr = None
        while not ipaddr and (current_time - start_time) < TIMEOUT_DURATION:
            import tero.vmware
            vms = tero.vmware.list_vms()
            for name, curip, mac in vms:
                if name == vm_name:
                    ipaddr = curip
                    macaddr = mac
                    break
            if not ipaddr:
                time.sleep(10)
            current_time = time.time()
        started[vm_name] = ipaddr
        sys.stdout.write('%s | %s | %s\n' % (ipaddr, macaddr, vm_name))
    return started


def pub_stop(hosts):
    """
    Stops a cloud of virtual machines.
    """
    for vm_name in hosts:
        sys.stdout.write('Stopping %s ...\n' % vm_name)
        CLOUD_BACKEND.stop(vm_name)


def main(args, settings_path=None):
    """
    Main Entry Point.
    """
    import argparse
    parser = argparse.ArgumentParser(\
            usage='%(prog)s [options] command\n\nVersion\n  %(prog)s version ' \
                + str(__version__))
    parser.add_argument('--version', action='version',
                        version='%(prog)s ' + str(__version__))
    parser.add_argument('-c', '--cloud', dest='cloud', default='vmware')
    parser.add_argument('-u', '--user', dest='user', default='vagrant')
    parser.add_argument('-p', '--password', dest='password', default='vagrant')
    parser.add_argument('-k', '--keyfile', dest='keyfile',
        default=os.path.join(os.getenv('HOME'), '.ssh/vagrant_rsa'))
    if args and args[0].endswith('dintegrity'):
        from .setup import integrity
        build_subcommands_parser(parser, integrity)
    else:
        build_subcommands_parser(parser, sys.modules[__name__])

    if len(args) <= 1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args(args[1:])
    global ENV_USER, ENV_PASSWORD, ENV_KEY_FILENAME
    ENV_USER = options.user
    ENV_PASSWORD = options.password
    ENV_KEY_FILENAME = options.keyfile
    fab.env.user = ENV_USER
    fab.env.password = ENV_PASSWORD
    fab.env.key_filename = ENV_KEY_FILENAME

    global CLOUD_BACKEND
    CLOUD_BACKEND = _load_backend('tero.%s.Backend' % options.cloud)

    if not settings_path and os.path.exists('/etc/tero/config'):
            settings_path = '/etc/tero/config'
    if settings_path:
        settings = imp.load_source('settings', settings_path)

    # Filter out options with are not part of the function prototype.
    func_args = filter_subcommand_args(options.func, options)
    options.func(**func_args)
