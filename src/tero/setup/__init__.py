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

import logging, os, re, subprocess, sys

import six

from .. import (APT_DISTRIBS, CONTEXT, REDHAT_DISTRIBS,
    Error, SetupStep, log_info, shell_command)

postinst = None
ssl = None
after_statements = {}


class SSLKeysMixin(object):

    def key_paths(self, domain, dist_host, localstatedir='/var'):
        """
        Return a pair (public, private) to files that hold a public
        certificate and private key for a domain.
        """
        if dist_host in APT_DISTRIBS:
            conf_paths = {
                'key_file': os.path.join('ssl', 'private', domain + '.key'),
                'cert_file': os.path.join('ssl', 'certs', domain + '.pem')
                }
        elif dist_host in REDHAT_DISTRIBS:
            # XXX Not sure where those go on Fedora. searching through
            # the web is unclear.
            conf_paths = {
                'key_file': os.path.join('ssl', 'private', domain + '.key'),
                'cert_file': os.path.join('ssl', 'certs', domain + '.pem')
                }
        return (os.path.join(localstatedir, conf_paths['cert_file']),
                os.path.join(localstatedir, conf_paths['key_file']))


class installScript(object):

    def __init__(self, script_path, mod_sysconfdir=None):
        self.script = open(script_path, 'w')
        self.mod_sysconfdir = mod_sysconfdir

    def write(self, line):
        self.script.write(line)

    def install(self, packagename, force=False, postinst_script=None):
        if packagename.endswith('.tar.bz2'):
            self.script.write(
'tar --no-overwrite-dir --no-same-owner --numeric-owner --owner=0 -C / -jxvf %s\n'
                % packagename)
            self.script.write(
               '[ -f %(postinst_script)s ] && (%(postinst_script)s || exit 1)\n'
        % {'postinst_script': postinst_script.replace(self.mod_sysconfdir, '')})


class debianInstallScript(installScript):

    def install(self, packagename, force=False, postinst_script=None):
        if packagename.endswith('.tar.bz2'):
            super(debianInstallScript, self).install(
                packagename, force, postinst_script)
        else:
            if force:
                self.script.write('dpkg -i --force-overwrite %s\n'
                    % packagename)
            else:
                self.script.write('dpkg -i %s\n' % packagename)


class redhatInstallScript(installScript):

    jetty_webapps_dir = '/var/lib/jetty/webapps'
    jenkins_plugins_home = '/usr/share/jetty/.jenkins/plugins'

    def __init__(self, script_path, mod_sysconfdir=None):
        super(redhatInstallScript, self).__init__(
            script_path, mod_sysconfdir=mod_sysconfdir)
        self.jenkins_plugins_install = False

    def install(self, packagename,
                force=False, postinst_script=None):
        if packagename.endswith('.tar.bz2'):
            super(redhatInstallScript, self).install(
                packagename, force, postinst_script)
        elif packagename.endswith('.war'):
            self.script.write(
                '/usr/bin/install -p -m 644 %s %s\n'
                % (packagename, self.jetty_webapps_dir))
        elif packagename.endswith('.hpi') or packagename.endswith('.jpi'):
            if not self.jenkins_plugins_install:
                self.script.write('/usr/bin/install -d %s'
                    % self.jenkins_plugins_home)
                self.jenkins_plugins_install = True
            install_plugin_name = os.path.splitext(
                os.path.basename(packagename))[0] + '.jpi'
            self.script.write(
            '/usr/bin/install -p -m 644 %s %s/%s\n'
                % (packagename, self.jenkins_plugins_home, install_plugin_name))
        else:
            # --nodeps because rpm is stupid and can't figure out that
            # the vcd package provides the libvcd.so required by the executable.
            if force:
                self.script.write('rpm -i --force %s --nodeps\n' % packagename)
            else:
                self.script.write('rpm -i %s --nodeps\n' % packagename)


class PostinstScript(object):

    def __init__(self, project_name, dist, mod_sysconfdir):
        self.dist = dist
        self.sysconfdir = '/etc'
        self.scriptfile = None
        if self.dist in APT_DISTRIBS:
            self.postinst_run_path = 'debian/postinst'
            self.postinst_path = os.path.join(
                mod_sysconfdir, self.postinst_run_path)
        elif self.dist in REDHAT_DISTRIBS:
            # On Fedora, use %pre and %post in the spec file
            # http://fedoraproject.org/wiki/Packaging:ScriptletSnippets
            self.postinst_run_path = '/usr/share/%s/postinst' % project_name
            self.postinst_path = os.path.join(
                mod_sysconfdir, self.postinst_run_path[1:])

    def service_disable(self, service):
        if self.dist in REDHAT_DISTRIBS:
            self.shell_command(['systemctl', 'stop', '%s.service' % service])
            self.shell_command(['systemctl', 'disable', '%s.service' % service])
        else:
            sys.stderr.write(
                "warning: how to enable services on '%s' is unknown" %
                self.dist)

    def service_enable(self, service):
        if self.dist in REDHAT_DISTRIBS:
            self.shell_command(['systemctl', 'enable', '%s.service' % service])
        else:
            sys.stderr.write(
                "warning: how to enable services on '%s' is unknown" %
                self.dist)

    def service_restart(self, service):
        if self.dist in APT_DISTRIBS:
            self.shell_command(
                [os.path.join(self.sysconfdir, 'init.d', service), 'restart'])
        elif self.dist in REDHAT_DISTRIBS:
            self.shell_command(['systemctl', 'restart', '%s.service' % service])
        else:
            sys.stderr.write(
                "warning: how to start services on '%s' is unknown" %
                self.dist)

    def shell_command(self, cmdline, comment=None):
        # Insure the postinst script file is open for writing commands into it.
        if not self.scriptfile:
            if (os.path.dirname(self.postinst_path)
                and not os.path.exists(os.path.dirname(self.postinst_path))):
                os.makedirs(os.path.dirname(self.postinst_path))
            self.scriptfile = open(self.postinst_path, 'wt')
            self.scriptfile.write('#!/bin/sh\n\nset -e\nset -x\n\n')
        # Write comment and actual command
        if comment:
            self.scriptfile.write('# ' + comment + '\n')
        self.scriptfile.write(' '.join(cmdline) + '\n')

    def create_certificate(self, certificate_name, comment=None):
        """
        Shell commands to create a key pair.
        """
        priv_key = '/etc/pki/tls/private/%s.key' % certificate_name
        sign_request = '/etc/pki/tls/certs/%s.csr' % certificate_name
        pub_cert = '/etc/pki/tls/certs/%s.crt' % certificate_name
        self.shell_command(['if [ ! -f %s ] ; then' % priv_key])
        self.shell_command(['echo', '-e',
            '"US\nCalifornia\nSan Francisco\nExample inc.\n'\
                '\nlocalhost\nsupport@example.com\n\n\n"', '|',
            'openssl', 'req', '-new', '-sha256',
            '-newkey', 'rsa:2048', '-nodes', '-keyout', priv_key,
            '-out', sign_request],
            comment=comment)
        self.shell_command(['openssl', 'x509', '-req', '-days', '365',
            '-in', sign_request, '-signkey', priv_key, '-out', pub_cert])
        self.shell_command(['fi'])

    def install_selinux_module(self, module_te, comment=None):
        """
        Shell commands to install a SELinux module.
        """
        module_mod = os.path.splitext(
            os.path.basename(module_te))[0] + '.mod'
        module_pp = os.path.splitext(
            os.path.basename(module_te))[0] + '.pp'
        self.shell_command(
            ['checkmodule', '-M', '-m', '-o', module_mod, module_te],
            comment=comment)
        self.shell_command(
            ['semodule_package', '-m', module_mod, '-o', module_pp])
        self.shell_command(
            ['semodule', '-i', module_pp])




class SetupTemplate(SetupStep):
    """
    Step responsible to configure part of the system (daemons, jobs,
    utilities) to provide a specifc service.
    """
    daemons = [] # Daemons that need to stay alive to provide the service
                 # and that will need to be restarted when configuration files
                 # are modified.

    def run(self, context):
        complete = super(SetupTemplate, self).run(context)
        return complete

    def preinstall(self):
        """
        Code that is run before the package (.deb) is built.
        """


def add_lines(pathname, lines, context=None):
    logging.info('configure %s...', pathname)
    org_config_path, new_config_path = stage_file(pathname, context=context)
    with open(new_config_path, 'w') as new_config:
        if os.path.exists(org_config_path):
            with open(org_config_path) as org_config:
                line = org_config.readline()
                while lines and line != '':
                    found = False
                    look = re.match(r'^\s*#'+ lines[0], line)
                    if look:
                        # The line was commented out, let's enable it.
                        new_config.write(lines[0] + '\n')
                        found = True
                    else:
                        look = re.match(
                            r'^' + lines[0].replace(
                                '*', r'\*').replace(
                                '[', r'\['), line)
                        if look:
                            found = True
                        new_config.write(line)
                    if found:
                        lines = lines[1:]
                    line = org_config.readline()
                # Copy remaining lines from the previous configuration file.
                while line != '':
                    new_config.write(line)
                    line = org_config.readline()
        # Copy remaining lines to add to the configuration file.
        if lines:
            new_config.write('\n'.join(lines))
            new_config.write('\n')


def add_user(username):
    '''Add a user to the system.'''
    postinst.shell_command(
        ['[ -z "$(getent passwd %(username)s)" ] && adduser '\
'--no-create-home %(username)s' % {'username': username}])


def after_daemon_start(daemon, cmdline):
    global after_statements
    if not daemon in after_statements:
        after_statements[daemon] = []
    if not cmdline in after_statements[daemon]:
        after_statements[daemon] += [cmdline]


def create_install_script(script_path, context=None):
    dist_host = context.host()
    if dist_host in APT_DISTRIBS:
        return debianInstallScript(
            script_path, mod_sysconfdir=context.modEtcDir)
    if dist_host in REDHAT_DISTRIBS:
        return redhatInstallScript(
            script_path, mod_sysconfdir=context.modEtcDir)
    raise NotImplementedError("unknown distribution '%s'" % dist_host)


def next_token_in_config(remain,
                         sep='=', enter_block_sep='{', exit_block_sep='}'):
    sep = sep.strip()
    if enter_block_sep and exit_block_sep:
        seps = [sep, enter_block_sep, exit_block_sep]
    else:
        seps = [sep]
    token = None
    # Skip whitespaces
    idx = 0
    while idx < len(remain) and remain[idx] in [' ', '\t', '\n']:
        idx = idx + 1
    indent = remain[:idx]
    remain = remain[idx:]
    if remain and remain[0] in seps:
        token = remain[0]
        remain = remain[1:]
    else:
        idx = 0
        while idx < len(remain) and not remain[idx] in [sep, ' ', '\t', '\n']:
            idx = idx + 1
        if remain[:idx]:
            token = remain[:idx]
        remain = remain[idx:]
    return indent, token, remain


def modify_ini_config(pathname, settings={}, sep='=', context=None):
    """
    Apply *settings* into an ini config file.

    ini config files have the following syntax:
          # comment
          [section]
          variable = value

          [section]
          variable = value
          ...
    """
    logging.info('configure %s...', pathname)
    org_config_path, new_config_path = stage_file(pathname, context)
    if os.path.exists(org_config_path):
        with open(new_config_path, 'w') as new_conf:
            with open(org_config_path) as org_conf:
                block = None
                line = org_conf.readline()
                while line != '':
                    if line.strip(' \n'):
                        look = re.match(r'\[(\S+)\]', line)
                        if look:
                            # We found a block
                            if block:
                                for key, val in six.iteritems(block):
                                    new_conf.write(
                                        '%(key)s%(sep)s%(val)s\n' % {
                                            'key': key, 'sep': sep, 'val': val})
                            new_conf.write('\n')
                            block = settings.get(look.group(1), None)
                        else:
                            look = re.match(r'^(\S+)%s(\S+)(#.*)' % sep, line)
                            if look:
                                key = look.group(1)
                                org_val = look.group(2)
                                new_val = block.get(key, None)
                                if new_val:
                                    del block[key]
                                    line = ('%(key)s%(sep)s%(val)s%(comment)s\n'
                                        % {'key': key, 'sep': sep,
                                           'val': new_val,
                                           'comment': look.group(3)})
                        new_conf.write(line)
                    line = org_conf.readline()


def modify_config(pathname, settings={},
                  sep=' = ', enter_block_sep='{', exit_block_sep='}',
                  one_per_line=False, context=None):
    # In the directory where the script is executed, the original configuration
    # file is saved into a "org" subdirectory while the updated configuration
    # is temporarly created into a "new" subdirectory before being copied
    # over the actual configuration.
    # The temporary files are created in the local directory and not in /tmp
    # because it does not seem a good idea to have important files such
    # as system configuration leaked outside a potentially encrypted drive.
    # The philosophy being the user is thus fully aware of what gets created
    # where and can thus make appropriate decisions about the commands he/she
    # runs.
    unchanged = {}
    logging.info('configure %s...', pathname)
    org_config_path, new_config_path = stage_file(pathname, context)
    if os.path.exists(org_config_path):
        with open(org_config_path) as org_config:
            with open(new_config_path, 'w') as new_config:
                unchanged = modify_config_file(
                    new_config, org_config, settings, sep=sep,
                    enter_block_sep=enter_block_sep,
                    exit_block_sep=exit_block_sep,
                    one_per_line=one_per_line)
    else:
        logging.warning('%s does not exists.', org_config_path)
        # Add lines that did not previously appear in the configuration file.
        with open(new_config_path, 'w') as new_config:
            write_settings(new_config, settings, [],
                sep=sep, one_per_line=one_per_line)
    return unchanged


def modify_config_file(output_file, input_file, settings={},
                       sep=' = ', enter_block_sep='{', exit_block_sep='}',
                       one_per_line=False):
    prefix = ''
    unchanged = {}
    modified = []
    config_stack = []
    if enter_block_sep and exit_block_sep:
        seps = [sep.strip(), enter_block_sep, exit_block_sep]
    else:
        seps = [sep.strip()]
    line = input_file.readline()
    while line != '':
        state = 0
        name = None
        value = None
        remain = line
        commented = False
        exit_block = False
        enter_block = False
        look = re.match(r'^(?P<indent>\s*)#(?P<remain>\S+\s*%s.*)' % sep, line)
        if look:
            commented = True
            indent = look.group('indent')
            remain = look.group('remain')
        first_indent, token, remain = next_token_in_config(remain, sep=sep,
            enter_block_sep=enter_block_sep, exit_block_sep=exit_block_sep)
        if commented:
            first_indent = indent
        if token and re.match(r'^\s*#?\s*\[\S+\]$', line):
            # if the whole line is not a [] tag,
            # we might catch ipv6 addr by accident.
            name = token[1:len(token)-1]
            exit_block = True
            enter_block = True
            token = None
        while token is not None:
            if enter_block_sep and token == enter_block_sep:
                enter_block = True
            elif exit_block_sep and token == exit_block_sep:
                exit_block = True
            elif token == sep.strip():
                value = ''
                if state == 1:
                    state = 2
            elif not token in seps:
                if state == 0:
                    name = token
                    state = 1
                elif not sep.strip() or state == 2:
                    value = token
                    state = 3
                else:
                    if enter_block or exit_block:
                        enter_block = False
                        exit_block = False
                    # because we have comma separated lists
                    # in mail configuration files.
                    if value:
                        value += indent + token
            indent, token, remain = next_token_in_config(remain, sep=sep,
                enter_block_sep=enter_block_sep, exit_block_sep=exit_block_sep)
        if exit_block:
            if not enter_block:
                # Handles "[key]" blocks is different from "{...}" blocks
                write_settings(output_file, settings, modified,
                    sep, first_indent + '  ', prefix, one_per_line=one_per_line)
            if config_stack:
                prefix, settings, unchanged, present \
                        = config_stack.pop()
                if present and commented:
                    # Uncomment whenever possible
                    look = re.match(r'^(\s*)#(.*)', line)
                    output_file.write(look.group(1) + look.group(2) + '\n')
                elif not enter_block:
                    output_file.write(line)
        if enter_block:
            key = name
            if value:
                key = '_'.join([name, value])
            if prefix:
                prefixname = '.'.join([prefix, key])
            else:
                prefixname = key
            dive = (key in settings) and (prefixname not in modified)
            config_stack += [(prefix, settings, unchanged, dive)]
            if dive:
                prefix = prefixname
                modified += [prefix]
                settings = settings[key]
                if commented:
                    # Uncomment whenever possible
                    look = re.match(r'^(\s*)#(.*)', line)
                    output_file.write(look.group(1) + look.group(2) + '\n')
                else:
                    output_file.write(line)
            else:
                settings = {}
                output_file.write(line)
            unchanged = {}
        elif not enter_block and not exit_block:
            if name and value:
                if name in settings:
                    if prefix:
                        prefixname = '.'.join([prefix, name])
                    else:
                        prefixname = name
                    if prefixname not in modified:
                        # Sometimes, a comment includes an example
                        # that matches the setting of the variable
                        # and there is no way for the parser to know
                        # if it is an actual comment or commented-out code.
                        modified += [prefixname]
                        if value != settings[name]:
                            if isinstance(settings[name], list):
                                # because of apache NameVirtualHost,
                                # openldap olcAccess.
                                for val in settings[name]:
                                    output_file.write(first_indent + name
                                      + sep + str(val) + '\n')
                            else:
                                output_file.write(first_indent + name
                                      + sep + str(settings[name]) + '\n')
                        elif commented:
                            # Uncomment whenever possible
                            look = re.match(r'^(\s*)#(.*)', line)
                            output_file.write(
                                look.group(1) + look.group(2) + '\n')
                        else:
                            output_file.write(line)
                else:
                    if not commented:
                        unchanged[name] = value
                    output_file.write(line)
            else:
                output_file.write(line)
        line = input_file.readline()
    # Add lines that did not previously appear in the configuration file.
    write_settings(output_file, settings, modified,
        sep=sep, one_per_line=one_per_line)
    return unchanged


def stage_dir(pathname, context):
    new_dir = context.modEtcDir + pathname
    if not os.path.exists(new_dir):
        os.makedirs(new_dir)
    return new_dir


def stage_file(pathname, context):
    """
    Prepare a configuration file for modification. It involves making
    a copy of the previous version, then opening a temporary file for edition.
    """
    new_path = context.modEtcDir + pathname
    org_path = context.tplEtcDir + pathname
    log_info('stage %s\n  to %s\n  original at %s' % (
        pathname, new_path, org_path))
    if not os.path.exists(org_path):
        # We copy the original configuration file into the local build
        # directory before modifying it.
        # Note that we only do that the first time through so unless
        # the original (cache) directory is deleted, we donot overwrite
        # the original original files when the script is run a second time.
        #
        try:
            try:
                user_opt = ['-o', context.value('admin')]
            except Error:
                user_opt = []
            try:
                group_opt = ['-g', context.value('admin')]
            except Error:
                group_opt = []
            shell_command(['install', '-D', '-p'] + user_opt + group_opt +
                [pathname, org_path], admin=len(user_opt) > 0)
        except Error as err:
            # We sometimes need sudo access to make backup copies of config
            # files (even ones with no credentials). This is just a convoluted
            # way to achieve the first copy before modification.
            pass
    if (not os.path.exists(os.path.dirname(new_path))
        and len(os.path.dirname(new_path)) > 0):
        os.makedirs(os.path.dirname(new_path))
    return org_path, new_path


def unified_diff(pathname):
    '''Return a list of lines which is the unified diff between an original
    configuration file and the modified version.
    '''
    new_path = CONTEXT.modEtcDir + pathname
    org_path = CONTEXT.tplEtcDir + pathname
    cmdline = ' '.join(['diff', '-u', org_path, new_path])
    cmd = subprocess.Popen(cmdline,
                           shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    lines = cmd.stdout.readlines()
    cmd.wait()
    # We donot check error code here since the diff will complete
    # with a non-zero error code if we either modified the config file.
    return lines


def write_settings(config, settings, outs=[], sep='=', indent='', prefix=None,
                  one_per_line=False):
    for name in sorted(settings.keys()):
        if prefix:
            prefixname = '.'.join([prefix, name])
        else:
            prefixname = name
        if prefixname not in outs:
            if isinstance(settings[name], dict):
                config.write(indent + name.replace('_', ' ') + ' {\n')
                write_settings(config, settings[name], outs,
                    sep, indent + '\t', prefixname, one_per_line=one_per_line)
                config.write(indent + '}\n')
            elif isinstance(settings[name], list):
                if one_per_line:
                    for val in settings[name]:
                        config.write(indent + name + sep + str(val) + '\n')
                else:
                    config.write(
                        indent + name + sep + ' '.join(settings[name]) + '\n')
            else:
                config.write(indent + name + sep + str(settings[name]) + '\n')


def pretty_print(settings):
    for name in sorted(settings.keys()):
        if not settings[name]:
            logging.info('warning: %s has no associated value.', name)
        else:
            logging.info('%s %s', name, settings[name])
