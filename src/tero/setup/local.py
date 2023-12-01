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
"""
Entry Point to setting-up a local machine.
"""
from __future__ import unicode_literals

import datetime, os, shutil, socket, subprocess, sys
import imp # XXX deprecated, for `load_source`
import argparse, __main__

import six

import tero # for global variables (CONTEXT, etc.)
from .. import (__version__, Error, pub_build, pub_make,
    create_managed, shell_command,
    FilteredList, ordered_prerequisites, fetch, merge_unique,
    IndexProjects, Context, stampfile, create_index_pathname)
import tero.setup # for global variables (postinst)

from .integrity import check_systemd_services, fingerprint


def create_install_script(dgen, context, install_top):
    """
    Create custom packages and an install script that can be run
    to setup the local machine. After this step, the final directory
    can then be tar'ed up and distributed to the local machine.
    """
    #pylint:disable=too-many-locals
    # Create a package through the local package manager or alternatively
    # a simple archive of the configuration files and postinst script.
    prev = os.getcwd()
    share_dir = os.path.join(install_top, 'share')
    install_name = os.path.basename(context.value('modEtcDir'))
    package_dir = context.obj_dir(os.path.basename(context.value('modEtcDir')))
    if not os.path.exists(package_dir):
        os.makedirs(package_dir)
    make_simple_archive = True
    if make_simple_archive:
        os.chdir(context.value('modEtcDir'))
        package_path = os.path.join(package_dir,
            install_name + '-' + str(__version__) + '.tar.bz2')
        archived = []
        for dirname in ['etc', 'usr', 'var']:
            if os.path.exists(dirname):
                archived += [dirname]
        shell_command(['tar', 'jcf', package_path] + archived)
    else:
        os.chdir(package_dir)
        for bin_script in ['dws', 'dbldpkg']:
            build_bin_script = context.obj_dir(os.path.join('bin', bin_script))
            if os.path.islink(build_bin_script):
                os.remove(build_bin_script)
            os.symlink(os.path.join(install_top, 'bin', bin_script),
                       build_bin_script)
        build_share_drop = context.obj_dir(os.path.join('share', 'dws'))
        if os.path.islink(build_share_drop):
            os.remove(build_share_drop)
        if not os.path.isdir(os.path.dirname(build_share_drop)):
            os.makedirs(os.path.dirname(build_share_drop))
        os.symlink(os.path.join(share_dir, 'dws'), build_share_drop)
        pub_make(['dist'])
        with open(os.path.join(
                package_dir, '.packagename')) as package_name_file:
            package_path = package_name_file.read().strip()
    os.chdir(prev)

    # Create install script
    fetch_packages = FilteredList()
    tero.INDEX.parse(fetch_packages)
    for package in fetch_packages.fetches:
        tero.EXCLUDE_PATS += [os.path.basename(package).split('_')[0]]

    obj_dir = context.obj_dir(install_name)
    install_script_path = os.path.join(obj_dir, 'install.sh')
    install_script = tero.setup.create_install_script(
        install_script_path, context=context)
    install_script.write('''#!/bin/sh
# Script to setup the server

set -x
''')
    deps = ordered_prerequisites(dgen, tero.INDEX)
    for step in [dep for dep in deps if hasattr(dep, 'install_commands')]:
        if step.project in tero.EXCLUDE_PATS + dgen.roots:
            continue
        cmds = step.install_commands(step.get_installs(), tero.CONTEXT)
        for cmd, admin, noexecute in cmds:
            install_script.script.write("%s\n" % ' '.join(cmd))

    package_name = os.path.basename(package_path)
    local_package_path = os.path.join(obj_dir, package_name)
    if (not os.path.exists(local_package_path)
        or not os.path.samefile(package_path, local_package_path)):
        sys.stdout.write('copy %s to %s\n' % (package_path, local_package_path))
        shutil.copy(package_path, local_package_path)
    package_files = [os.path.join(install_name, package_name)]
    for name in fetch_packages.fetches:
        fullname = context.local_dir(name)
        package = os.path.basename(fullname)
        if not os.path.isfile(fullname):
            # If the package is not present (might happen if dws/semilla
            # are already installed on the system), let's download it.
            fetch(tero.CONTEXT,
                      {'https://djaodjin.com/resources/./%s/%s' # XXX
                       % (context.host(), package): None})
        shutil.copy(fullname, os.path.join(obj_dir, package))
        install_script.install(package, force=True)
        package_files += [os.path.join(install_name, package)]
    install_script.install(package_name, force=True,
                          postinst_script=tero.setup.postinst.postinst_path)
    install_script.write('echo done.\n')
    install_script.script.close()
    shell_command(['chmod', '755', install_script_path])

    package_path = os.path.join(
        os.path.dirname(obj_dir), install_name + '.tar.bz2')
    prev = os.getcwd()
    os.chdir(os.path.dirname(obj_dir))
    shell_command(['tar', 'jcf', package_path,
        os.path.join(install_name, 'install.sh')] + package_files)
    os.chdir(prev)
    return package_path


def create_postinst(start_timestamp, setups, context=None):
    """
    This routine will copy the updated config files on top of the existing
    ones in /etc and will issue necessary commands for the updated config
    to be effective. This routine thus requires to execute a lot of commands
    with admin privileges.
    """
    if not context:
        context = tero.CONTEXT

    # \todo how to do this better?
    with open(os.path.join(context.value('modEtcDir'), 'Makefile'), 'w') as mkfile:
        mkfile.write('''
# With dws, this Makefile will be invoked through
#     make -f *buildTop*/dws.mk *srcDir*/Makefile
#
# With rpmbuild, this Makefile will be invoked directly by rpmbuild like that:
#     make install DESTDIR=~/rpmbuild/BUILDROOT/*projectName*
#
# We thus need to accomodate bothe cases, hence the following "-include"
# directive.

-include dws.mk
include %(share_dir)s/dws/prefix.mk

DATAROOTDIR := /usr/share

install::
\tif [ -d ./etc ] ; then \\
\t\tinstall -d $(DESTDIR)$(SYSCONFDIR) && \\
\t\tcp -rpf ./etc/* $(DESTDIR)$(SYSCONFDIR) ;\\
\tfi
\tif [ -d ./var ] ; then \\
\t\tinstall -d $(DESTDIR)$(LOCALSTATEDIR) && \\
\t\tcp -rpf ./var/* $(DESTDIR)$(LOCALSTATEDIR) ; \\
\tfi
\tif [ -d ./usr/share ] ; then \\
\t\tinstall -d $(DESTDIR)$(DATAROOTDIR) && \\
\t\tcp -rpf ./usr/share/* $(DESTDIR)$(DATAROOTDIR) ; \\
\tfi
\tif [ -d ./usr/lib/systemd/system ] ; then \\
\t\tinstall -d $(DESTDIR)/usr/lib/systemd/system && \\
\t\tcp -rpf ./usr/lib/systemd/system/* $(DESTDIR)/usr/lib/systemd/system ; \\
\tfi

include %(share_dir)s/dws/suffix.mk
''' % {'share_dir': context.value('shareDir')})

    for pathname in ['/var/spool/cron/crontabs']:
        if not os.access(pathname, os.W_OK):
            try:
                tero.setup.postinst.shell_command(['[ -f ' + pathname + ' ]',
                    '&&', 'chown ', context.value('admin'), pathname])
            except Error:
                # We don't have an admin variable anyway...
                pass

    # Execute the extra steps necessary after installation
    # of the configuration files and before restarting the services.
    services = []
    for setup in setups:
        if setup:
            services = merge_unique(services, setup.daemons)

    # Enable all services before restarting them. In case we encounter
    # an transient error on restart, at least the services will be enabled.
    if tero.setup.postinst.scriptfile:
        tero.setup.postinst.scriptfile.write(
            "\n# Disable unused services\n")
        enabled_services = check_systemd_services()
        for service in ['rpcbind', 'postfix', 'firewalld']:
            if service in enabled_services:
                tero.setup.postinst.service_disable(service)
        tero.setup.postinst.scriptfile.write(
            "\n# Enable and restart services\n")
    for service in services:
        tero.setup.postinst.service_enable(service)
    for service in services:
        tero.setup.postinst.service_restart(service)
        if service in tero.setup.after_statements:
            for stmt in tero.setup.after_statements[service]:
                tero.setup.postinst.shell_command([stmt])
    if tero.setup.postinst.scriptfile:
        tero.setup.postinst.scriptfile.close()
        shell_command(['chmod', '755', tero.setup.postinst.postinst_path])


def prepare_local_system(context, project_name, profiles):
    """
    Install prerequisite packages onto the local system and create a project
    with the modified configuration files such that the machine can be
    reconfigured later by installing a native package (i.e. rpm or deb).
    """
    tero.setup.postinst = tero.setup.PostinstScript(
        project_name, context.host(), context.value('modEtcDir'))

    # XXX Implement this or deprecated?
    # Since they contain sensitive information, credentials file
    # are handled very specifically. They should never make it
    # into a package or copied around more than once.
    # We stage them into their expected place if not present
    # before any other setup takes place.

    # Starts setting-up the local machine, installing prerequisites packages
    # and updating the configuration files.

    # Write the profile file that contains information to turn
    # an ISO stock image into a specified server machine.
    tpl_index_file = os.path.join(
        tero.CONTEXT.value('modEtcDir'), '%s-tpl.xml' % project_name)
    create_index_pathname(tpl_index_file, profiles)
    index_path = os.path.join(context.value('modEtcDir'), '%s.xml' % project_name)
    if (os.path.dirname(index_path) and
        not os.path.exists(os.path.dirname(index_path))):
        os.makedirs(os.path.dirname(index_path))
    # matching code in driver.py ``copy_setup``
    with open(tpl_index_file, 'r') as profile_file:
        template_text = profile_file.read()
    with open(index_path, 'w') as profile_file:
        profile_file.write(template_text % context.environ)
    sys.stdout.write('deploying profile %s ...\n' % index_path)

    csteps = {}
    for module_path in os.listdir(os.path.dirname(tero.setup.__file__)):
        if module_path.endswith('.py') and module_path != '__init__.py':
            module = imp.load_source(
                os.path.splitext(module_path)[0],
                os.path.join(os.path.dirname(tero.setup.__file__), module_path))
            for gdef in module.__dict__:
                if gdef.endswith('Setup'):
                    csteps[gdef] = module.__dict__[gdef]

    tero.INDEX = IndexProjects(context)
    tero.CUSTOM_STEPS = csteps

    if not os.path.exists('/usr/bin/bzip2'):
        # XXX bzip2 is necessary for tar jcf, yet bzip2 --version
        # does not exits.
        bzip2 = create_managed('bzip2')
        bzip2.run(context)

    # Some magic to recompute paths correctly from ``index_path``.
    site_top = os.path.dirname(os.path.dirname(os.path.dirname(index_path)))
    index_path = index_path.replace(site_top, site_top + '/.')
    return pub_build([index_path])


def main(args):
    """
    Configure a machine to serve as a forum server, with ssh, e-mail
    and web daemons. Hook-up the server machine with a dynamic DNS server
    and make it reachable from the internet when necessary.
    """
    #pylint:disable=too-many-locals

    # We keep a starting time stamp such that we can later on
    # find out the services that need to be restarted. These are
    # the ones whose configuration files have a modification
    # later than *start_timestamp*.
    start_timestamp = datetime.datetime.now()
    prev = os.getcwd()

    bin_base = os.path.dirname(os.path.realpath(os.path.abspath(sys.argv[0])))

    parser = argparse.ArgumentParser(
        usage='%(prog)s [options] *profile*\n\nVersion:\n  %(prog)s version ' \
            + str(__version__))
    parser.add_argument('profiles', nargs='*',
        help='Profiles to use to configure the machine.')
    parser.add_argument('--version', action='version',
        version='%(prog)s ' + str(__version__))
    parser.add_argument('-D', dest='defines', action='append', default=[],
        help='Add a (key,value) definition to use in templates.')
    parser.add_argument('--fingerprint', dest='fingerprint',
        action='store_true', default=False,
        help='Fingerprint the system before making modifications')
    parser.add_argument('--skip-recurse', dest='install',
        action='store_false', default=True,
        help='Assumes all prerequisites to build the'\
' configuration package have been installed correctly. Generate'\
' a configuration package but donot install it.')
    parser.add_argument('--dyndns', dest='dyndns', action='store_true',
        help='Add configuration for dynamic DNS')
    parser.add_argument('--sshkey', dest='sshkey', action='store_true',
        help='Configure the ssh daemon to disable password login and use'\
' keys instead')
    options = parser.parse_args(args[1:])
    if len(options.profiles) < 1:
        parser.print_help()
        sys.exit(1)

    # siteTop where packages are built
    tero.ASK_PASS = os.path.join(bin_base, 'askpass')

    # -- Let's start the configuration --
    tero.USE_DEFAULT_ANSWER = True
    tero.CONTEXT = Context()
    tero.CONTEXT.locate()
    tero.CONTEXT.environ['version'] = __version__
    tero.CONTEXT.environ['etcDir'] = '/etc'

    # Configuration information
    # Add necessary variables in context, then parse a list of variable
    # definitions with format key=value from the command line and append
    # them to the context.
    for define in options.defines:
        key, value = define.split('=')
        tero.CONTEXT.environ[key] = value

    # More often than not, the wesite for the product is different
    # from the corporate (LDAP, e-mail, etc.) domains.
    if 'domainName' not in tero.CONTEXT.environ:
        tero.CONTEXT.environ['domainName'] = socket.gethostname()
    if ('domainName' in tero.CONTEXT.environ
        and 'companyDomain' not in tero.CONTEXT.environ):
        tero.CONTEXT.environ['companyDomain'] \
            = tero.CONTEXT.environ['domainName']

    if 'PROJECT_NAME' in tero.CONTEXT.environ:
        project_name = tero.CONTEXT.value('PROJECT_NAME')
    else:
        project_name = os.path.splitext(
            os.path.basename(options.profiles[0]))[0]

    log_path_prefix = stampfile(tero.CONTEXT.log_path(
            os.path.join(tero.CONTEXT.host(), socket.gethostname())))
    if options.fingerprint:
        fingerprint(tero.CONTEXT, log_path_prefix)

    if options.install:
        # \todo We ask sudo password upfront such that the non-interactive
        # install process does not bail out because it needs a password.
        try:
            shell_command(
                ['SUDO_ASKPASS="%s"' % tero.ASK_PASS, 'sudo', 'echo', 'hello'])
        except Error:
            # In case sudo requires a password, let's explicitely ask for it
            # and cache it now.
            sys.stdout.write("%s is asking to cache the sudo password such"\
" that it won\'t be asked in the non-interactive part of the script.\n"
                % sys.argv[0])
            shell_command(
                ['SUDO_ASKPASS="%s"' % tero.ASK_PASS, 'sudo', '-A', '-v'])

    setups = prepare_local_system(tero.CONTEXT, project_name, options.profiles)
    os.chdir(prev)
    try:
        with open(os.path.join(
                tero.CONTEXT.value('modEtcDir'), 'config.book'), 'w') as book:
            book.write('''<?xml version="1.0"?>
<section xmlns="http://docbook.org/ns/docbook"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     xmlns:xi="http://www.w3.org/2001/XInclude">
  <info>
    <title>Modification to configuration files</title>
  </info>
  <section>
<programlisting>''')
            cmd = subprocess.Popen(' '.join(['diff', '-rNu',
                tero.CONTEXT.value('tplEtcDir'),
                tero.CONTEXT.value('modEtcDir')]),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
            for line in cmd.stdout.readlines():
                if isinstance(line, six.string_types):
                    book.write(line)
                else:
                    book.write(line.decode('utf-8'))
            book.write('</programlisting>\n</section>\n')
    except Error:
        # We donot check error code here since the diff will complete
        # with a non-zero error code if we either modified the config file.
        pass

    # Create the postinst script
    create_postinst(start_timestamp, setups)
    dgen = tero.BuildGenerator([project_name], [],
        exclude_pats=tero.EXCLUDE_PATS, custom_steps=tero.CUSTOM_STEPS)
    final_install_package = create_install_script(dgen, tero.CONTEXT,
        install_top=os.path.dirname(bin_base))

    # Install the package as if it was a normal distribution package.
    if options.install:
        if not os.path.exists('install'):
            os.makedirs('install')
        shutil.copy(final_install_package, 'install')
        os.chdir('install')
        install_basename = os.path.basename(final_install_package)
        project_name = '.'.join(install_basename.split('.')[:-2])
        shell_command(['tar', 'jxf', os.path.basename(final_install_package)])
        sys.stdout.write('ATTENTION: A sudo password is required now.\n')
        os.chdir(project_name)
        shell_command(['./install.sh'], admin=True)


if __name__ == '__main__':
    main(sys.argv)
