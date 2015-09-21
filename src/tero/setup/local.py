# Copyright (c) 2015, DjaoDjin inc.
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

'''Entry Point to setting-up a local machine.'''

import datetime, os, re, socket, shutil, sys, subprocess

import tero # for global variables (CONTEXT, etc.)
from tero import (__version__, Error, log_info, pub_build, pub_make,
    create_managed, shell_command, validate_controls,
    FilteredList, ordered_prerequisites, fetch, merge_unique,
    IndexProjects, DerivedSetsGenerator, BuildGenerator, MakeGenerator,
    Context, Variable, Pathname, stampfile, create_index_pathname)
import tero.setup # for global variables (postinst)
from tero.setup import (modifyIniConfig, stageFile, unifiedDiff, writeSettings,
    prettyPrint)


def docModifs(routine, config_paths):
    '''Add the config modifications into the documentation.'''

    routine.__doc__ += '<programlisting>\n'
    for conf in config_paths:
        routine.__doc__ += ''.join(unifiedDiff(conf))
    routine.__doc__ += '</programlisting>\n</section>\n'


def mergeSettings(left, right):
    for setting in right:
        if setting in left:
            raise Error("duplicate settings for " + str(setting))
        left[setting] = right[setting]
    return left


def copyNewConfigs(base):
    for file_path in os.listdir(base):
        file_path = os.path.join(base, file_path)
        if os.path.isdir(file_path):
            if not os.path.exists(file_path[3:]):
                shell_command(['/usr/bin/install', '-d', file_path[3:]],
                              admin=True)
            copyNewConfigs(file_path)
        else:
            # remove the 'new" prefix to form the orginal pathname back.
            shell_command(['/usr/bin/install', '-p', file_path, file_path[3:]],
                          admin=True)


def createInstallScript(project_name, install_top):
    '''Create custom packages and an install script that can be run
    to setup the local machine. After this step, the final directory
    can then be tar'ed up and distributed to the local machine.
    '''
    # Create a package through the local package manager or alternatively
    # a simple archive of the configuration files and postinst script.
    context = tero.CONTEXT
    prev = os.getcwd()
    shareDir = os.path.join(install_top, 'share')
    project_name = os.path.basename(context.MOD_SYSCONFDIR)
    packageDir = context.obj_dir(os.path.basename(context.MOD_SYSCONFDIR))
    if not os.path.exists(packageDir):
        os.makedirs(packageDir)
    make_simple_archive = True
    if make_simple_archive:
        os.chdir(context.MOD_SYSCONFDIR)
        packagePath = os.path.join(packageDir,
            project_name + '-' + str(__version__) + '.tar.bz2')
        archived = []
        for dirname in ['etc', 'usr', 'var']:
            if os.path.exists(dirname):
                archived += [dirname]
        shell_command(['tar', 'jcf', packagePath] + archived)
    else:
        os.chdir(packageDir)
        for binScript in ['dws', 'dbldpkg']:
            buildBinScript = context.obj_dir(os.path.join('bin', binScript))
            if os.path.islink(buildBinScript):
                os.remove(buildBinScript)
            os.symlink(os.path.join(install_top, 'bin', binScript),
                       buildBinScript)
        buildShareDrop = context.obj_dir(os.path.join('share', 'dws'))
        if os.path.islink(buildShareDrop):
            os.remove(buildShareDrop)
        if not os.path.isdir(os.path.dirname(buildShareDrop)):
            os.makedirs(os.path.dirname(buildShareDrop))
        os.symlink(os.path.join(shareDir, 'dws'), buildShareDrop)
        pub_make(['dist'])
        packageNameFile = open(os.path.join(packageDir, '.packagename'), 'r')
        packagePath = packageNameFile.read().strip()
        packageNameFile.close()
    os.chdir(prev)

    # Create install script
    fetchPackages = FilteredList()
    tero.INDEX.parse(fetchPackages)
    for package in fetchPackages.fetches:
        tero.EXCLUDE_PATS += [os.path.basename(package).split('_')[0]]

    obj_dir = context.obj_dir(project_name)
    install_script_path = os.path.join(obj_dir, 'install.sh')
    install_script = tero.setup.create_install_script(
        install_script_path, context=context)
    install_script.write('''#!/bin/sh
# Script to setup the server

set -x
''')
    deps = ordered_prerequisites([project_name], tero.INDEX)
    for dep in tero.EXCLUDE_PATS + [project_name]:
        if dep in deps:
            deps.remove(dep)
    install_script.prerequisites(deps)
    packageName = os.path.basename(packagePath)
    localPackagePath = os.path.join(obj_dir, packageName)
    if (not os.path.exists(localPackagePath)
        or not os.path.samefile(packagePath, localPackagePath)):
        print 'copy %s to %s' % (packagePath, localPackagePath)
        shutil.copy(packagePath, localPackagePath)
    packageFiles = [os.path.join(project_name, packageName)]
    for name in fetchPackages.fetches:
        fullname = context.local_dir(name)
        package = os.path.basename(fullname)
        if not os.path.isfile(fullname):
            # If the package is not present (might happen if dws/semilla
            # are already installed on the system), let's download it.
            fetch(CONTEXT,
                      {'https://djaodjin.com/resources/./%s/%s' # XXX
                       % (context.host(), package): None})
        shutil.copy(fullname, os.path.join(obj_dir, package))
        install_script.install(package, force=True)
        packageFiles += [os.path.join(project_name, package)]
    install_script.install(packageName, force=True,
                          postinst_script=tero.setup.postinst.postinst_path)
    install_script.write('echo done.\n')
    install_script.script.close()
    shell_command(['chmod', '755', install_script_path])

    prev = os.getcwd()
    os.chdir(os.path.dirname(obj_dir))
    shell_command(['tar', 'jcf', project_name + '.tar.bz2',
                   os.path.join(project_name, 'install.sh')] + packageFiles)
    os.chdir(prev)
    return os.path.join(os.path.dirname(obj_dir), project_name + '.tar.bz2')


def createPostinst(startTimeStamp, setups, context=None):
    '''This routine will copy the updated config files on top of the existing
    ones in /etc and will issue necessary commands for the updated config
    to be effective. This routine thus requires to execute a lot of commands
    with admin privileges.'''

    if not context:
        context = tero.CONTEXT

    # \todo how to do this better?
    with open(os.path.join(context.MOD_SYSCONFDIR, 'Makefile'), 'w') as mkfile:
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
include %(shareDir)s/dws/prefix.mk

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

include %(shareDir)s/dws/suffix.mk
''' % {'shareDir': context.shareDir})

    for pathname in ['/var/spool/cron/crontabs']:
        if not os.access(pathname, os.W_OK):
            tero.setup.postinst.shellCommand(['[ -f ' + pathname + ' ]',
                '&&', 'chown ', context.value('admin'), pathname])

    # Execute the extra steps necessary after installation
    # of the configuration files and before restarting the services.
    daemons = []
    for setup in setups:
        if setup:
            daemons = merge_unique(daemons, setup.daemons)

    # Restart services
    if tero.setup.postinst.scriptfile:
        tero.setup.postinst.scriptfile.write('\n# Restart services\n')
    for daemon in daemons:
        tero.setup.postinst.serviceRestart(daemon)
        if daemon in tero.setup.after_statements:
            for stmt in tero.setup.after_statements[daemon]:
                tero.setup.postinst.shellCommand([stmt])
    if tero.setup.postinst.scriptfile:
        tero.setup.postinst.scriptfile.close()
        shell_command(['chmod', '755', tero.setup.postinst.postinst_path])


def prepareLocalSystem(context, project_name, profiles):
    """
    Install prerequisite packages onto the local system and create a project
    with the modified configuration files such that the machine can be
    reconfigured later by installing a native package (i.e. rpm or deb).
    """
    tero.setup.postinst = tero.setup.PostinstScript(
        project_name, context.host(), context.MOD_SYSCONFDIR)

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
    tplIndexFile = os.path.join(
        tero.CONTEXT.MOD_SYSCONFDIR, '%s-tpl.xml' % project_name)
    create_index_pathname(tplIndexFile, profiles)
    indexFile = os.path.join(context.MOD_SYSCONFDIR, '%s.xml' % project_name)
    if (len(os.path.dirname(indexFile)) > 0 and
        not os.path.exists(os.path.dirname(indexFile))):
        os.makedirs(os.path.dirname(indexFile))
    # XXX we used to replace %()s by actual value in profile template.
    with open(tplIndexFile) as profile:
        profile_text = profile.read()
    for name, value in context.environ.iteritems():
        profile_text = profile_text.replace('%%(%s)s' % name, str(value))
    with open(indexFile, 'w') as confIndex:
        confIndex.write(profile_text)
    sys.stdout.write('deploying profile %s ...\n' % indexFile)

    import imp
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

    # Some magic to recompute paths correctly from ``indexFile``.
    site_top = os.path.dirname(os.path.dirname(os.path.dirname(indexFile)))
    index_path = indexFile.replace(site_top, site_top + '/.')
    print "XXX index_path=%s" % index_path
    return pub_build([index_path])


def main(args):
    '''Configure a machine to serve as a forum server, with ssh, e-mail
       and web daemons. Hook-up the server machine with a dynamic DNS server
       and make it reachable from the internet when necessary.'''

    import __main__
    import argparse

    # We keep a starting time stamp such that we can later on
    # find out the services that need to be restarted. These are
    # the ones whose configuration files have a modification
    # later than *startTimeStamp*.
    startTimeStamp = datetime.datetime.now()
    prev = os.getcwd()

    binBase = os.path.dirname(os.path.realpath(os.path.abspath(sys.argv[0])))

    parser = argparse.ArgumentParser(
        usage='%(prog)s [options] *profile*\n\nVersion:\n  %(prog)s version ' \
            + str(__version__))
    parser.add_argument('profiles', nargs='*',
                      help='Profiles to use to configure the machine.')
    parser.add_argument('--version', action='version',
                        version='%(prog)s ' + str(__version__))
    parser.add_argument('-D', dest='defines', action='append', default=[],
                      help='Add a (key,value) definition to use in templates.')
    parser.add_argument('--skip-recurse', dest='install', action='store_false',
                      default=True,
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
    confTop = os.getcwd()
    tero.ASK_PASS = os.path.join(binBase, 'askpass')

    # -- Let's start the configuration --
    if not os.path.isdir(confTop):
        os.makedirs(confTop)
    os.chdir(confTop)
    tero.USE_DEFAULT_ANSWER = True
    tero.CONTEXT = Context()
    tero.CONTEXT.config_filename = os.path.join(confTop, 'dws.mk')
    tero.CONTEXT.buildTopRelativeCwd \
        = os.path.dirname(tero.CONTEXT.config_filename)
    tero.CONTEXT.environ['version'] = __version__

    # Configuration information
    if not 'admin' in tero.CONTEXT.environ:
        tero.CONTEXT.environ['admin'] = Variable('admin',
            {'description': 'Login for the administrator account',
             'default': os.getenv("LOGNAME")})

    distHost = tero.CONTEXT.host() # calls HostPlatform.configure()
    dist_codename = tero.CONTEXT.environ['distHost'].dist_codename
    # TODO If staged files already exist in the orig directory, they
    #      won't be backed-up!
    # TODO Where original (pre-modified) system files will be stored

    # Parse a list of variable definitions with format key=value to append
    # to the tero.CONTEXT.
    for define in options.defines:
        key, value = define.split('=')
        tero.CONTEXT.environ[key] = value

    # Derive necessary variables if they haven't been initialized yet.
    if not 'DB_USER' in tero.CONTEXT.environ:
        tero.CONTEXT.environ['DB_USER'] = Variable('DB_USER',
        {'description': 'User to access databases.',
         'default': 'djaoapp'})
    if not 'DB_PASSWORD' in tero.CONTEXT.environ:
        tero.CONTEXT.environ['DB_PASSWORD'] = Variable('DB_PASSWORD',
        {'description': 'Password for user to access databases.',
         'default': 'djaoapp'})
    if not 'domainName' in tero.CONTEXT.environ:
        tero.CONTEXT.environ['domainName'] = Variable('domainName',
        {'description': 'Domain Name for the machine being configured.',
         'default': socket.gethostname()})
    if not 'PROJECT_NAME' in tero.CONTEXT.environ:
        tero.CONTEXT.environ['PROJECT_NAME'] = Variable('PROJECT_NAME',
        {'description': 'Project under which system modifications are stored.',
         'default': socket.gethostname().replace('.', '-')})
    if not 'SYSCONFDIR' in tero.CONTEXT.environ:
        tero.CONTEXT.environ['SYSCONFDIR'] = Pathname('SYSCONFDIR',
        {'description': 'system configuration directory.',
         'default': '/etc'})
    if not 'MOD_SYSCONFDIR' in tero.CONTEXT.environ:
        tero.CONTEXT.environ['MOD_SYSCONFDIR'] = Pathname('MOD_SYSCONFDIR',
        {'description':
         'directory where modified system configuration file are generated.',
         'base':'srcTop',
         'default': socket.gethostname().replace('.', '-')})
    if not 'TPL_SYSCONFDIR' in tero.CONTEXT.environ:
        tplDir = os.path.join(confTop, 'share', 'tero')
        if dist_codename:
            tplDir = os.path.join(tplDir, dist_codename)
        else:
            tplDir = os.path.join(tplDir, distHost)
        tero.CONTEXT.environ['TPL_SYSCONFDIR'] = Pathname('TPL_SYSCONFDIR',
        {'description':
         'directory root that contains the orignal system configuration files.',
         'default': tplDir})

    project_name = tero.CONTEXT.value('PROJECT_NAME')

    logPathPrefix = stampfile(tero.CONTEXT.log_path(
            os.path.join(tero.CONTEXT.host(), socket.gethostname())))

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

    if False:
        from tero.integrity import fingerprint
        fingerprint(tero.CONTEXT, logPathPrefix,
                    skipFilesystem=True,
                    skipPrivilegedExecutables=True,
                    skipProcesses=True,
                    skipPorts=True)

    setups = prepareLocalSystem(tero.CONTEXT, project_name, options.profiles)
    os.chdir(prev)
    try:
        book = open(os.path.join(tero.CONTEXT.MOD_SYSCONFDIR, 'config.book'), 'w')
        book.write('''<?xml version="1.0"?>
<section xmlns="http://docbook.org/ns/docbook"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     xmlns:xi="http://www.w3.org/2001/XInclude">
  <info>
    <title>Modification to configuration files</title>
  </info>
  <section>
<programlisting>''')
        cmd = subprocess.Popen(' '.join([
            'diff', '-rNu', tero.CONTEXT.TPL_SYSCONFDIR, tero.CONTEXT.MOD_SYSCONFDIR]),
                               shell=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
        book.write(''.join(cmd.stdout.readlines()))
        book.write('</programlisting>\n</section>\n')
        book.close()
    except Error, e:
        # We donot check error code here since the diff will complete
        # with a non-zero error code if we either modified the config file.
        pass

    # Create the postinst script
    createPostinst(startTimeStamp, setups)
    finalInstallPackage = createInstallScript(project_name,
        install_top=os.path.dirname(binBase))

    # Install the package as if it was a normal distribution package.
    if options.install:
        if not os.path.exists('install'):
            os.makedirs('install')
        shutil.copy(finalInstallPackage, 'install')
        os.chdir('install')
        installBasename = os.path.basename(finalInstallPackage)
        project_name = '.'.join(installBasename.split('.')[:-2])
        shell_command(['tar', 'jxf', os.path.basename(finalInstallPackage)])
        sys.stdout.write('ATTENTION: A sudo password is required now.\n')
        os.chdir(project_name)
        shell_command(['./install.sh'], admin=True)


if __name__ == '__main__':
    main(sys.argv)
