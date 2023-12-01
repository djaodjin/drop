#!/usr/bin/env python
#
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
Implements workspace management.

The workspace manager script is used to setup a local machine
with third-party prerequisites and source code under revision
control such that it is possible to execute a development cycle
(edit/build/run) on a local machine.

The script will email build reports when the --mailto command line option
is specified. There are no sensible default values for the following
variables thus those should be set in the shell environment before
invoking the script.
  dwsEmail=
  smtpHost=
  smtpPort=
  dwsSmtpLogin=
  dwsSmtpPasswd=
"""
from __future__ import unicode_literals

# Primary Author(s): Sebastien Mirolo <smirolo@djaodjin.com>
#
# Requires Python 2.7 or above.

__version__ = '1.0.0'

import datetime, getpass, hashlib, inspect, json, locale
import logging, logging.config
import re, optparse, os, shutil, socket, stat, subprocess, sys, tempfile
import xml.dom.minidom, xml.sax

# Minimal compatibility Python2 / Python3
PY3 = sys.version_info[0] == 3

if sys.stdout.isatty():
    DEFAULT_ENCODING = sys.stdout.encoding
else:
    DEFAULT_ENCODING = locale.getpreferredencoding()

try:
    from io import StringIO
except ImportError:
    from cStringIO import StringIO
try:
    from urllib.request import Request, urlopen
    from urllib.parse import urlparse, urlunparse
except ImportError:
    from urllib2 import Request, urlopen
    from urlparse import urlparse, urlunparse

if PY3:
    string_types = str,

    def _iteritems(dct, **kw):
        return iter(dct.items(**kw))
else:
    string_types = basestring, #pylint:disable=undefined-variable

    def _iteritems(dct, **kw):
        return dct.iteritems(**kw)

def _urlparse(location):
    return urlparse(location)


def _urlunparse(parts):
    return urlunparse(parts)


def prompt(message):
    '''If the script is run through a ssh command, the message would not
    appear if passed directly in raw_input.'''
    log_interactive(message)
    try:
        return raw_input("")
    except NameError:
        return input("")
# End of Python2 / Python3


# \todo executable used to return a password compatible with sudo. This is used
# temporarly while sudo implementation is broken when invoked with no tty.
ASK_PASS = ''
# filename for context configuration
CONTEXT_FILENAME = None
# Extensions for more complex prerequisite setup
CUSTOM_STEPS = None
# When True, all commands invoked through shell_command() are printed
# but not executed.
DO_NOT_EXECUTE = False
# Global variables that contain all encountered errors.
ERRORS = []
# When processing a project dependency index file, all project names matching
# one of the *EXCLUDE_PATS* will be considered non-existant.
EXCLUDE_PATS = []
# Log commands output
LOGGER = None
LOGGER_BUFFER = None
LOGGER_BUFFERING_COUNT = 0

# Pattern used to search for logs to report through email.
LOG_PAT = None
# When True, asset files are not fetched regardless if they are
# in the cache or not.
NO_FETCH = False
# When True, the log object is not used and output is only
# done on sys.stdout.
NO_LOG = False
# When True, we are not running Python within a virtualenv environment
NO_VIRTUALENV = False
# Address to email log reports to.
MAILTO = []
# When True, *find_lib* will prefer static libraries over dynamic ones if both
# exist for a specific libname. This should match .LIBPATTERNS in prefix.mk.
STATIC_LIB_FIRST = True
# When True, the script runs in batch mode and assumes the default answer
# for every question where it would have prompted the user for an answer.
USE_DEFAULT_ANSWER = False

# Directories where things get installed
INSTALL_DIRS = ['bin', 'include', 'lib', 'libexec', 'etc', 'share']

# distributions per native package managers
APT_DISTRIBS = ['Debian', 'Ubuntu']
DNF_DISTRIBS = ['Amazon', 'Fedora']
PORT_DISTRIBS = ['Darwin']
YUM_DISTRIBS = ['AmazonLinux2', 'CentOS', 'RedHat']
REDHAT_DISTRIBS = DNF_DISTRIBS + YUM_DISTRIBS
ALIAS_DISTRIBS = {
    'CentOS': 'RedHat',
    'Amazon': 'RedHat',
    'AmazonLinux2': 'RedHat',
    'Ubuntu': 'Debian'
}

# Real uid and gid when the -u,--user and/or -g,--group command
# line arguments are used.
USER = None
GROUP = None

CONTEXT = None
INDEX = None

class Error(RuntimeError):
    '''This type of exception is used to identify "expected"
    error condition and will lead to a useful message.
    Other exceptions are not caught when *__main__* executes,
    and an internal stack trace will be displayed. Exceptions
    which are not *Error*s are concidered bugs in the workspace
    management script.'''
    def __init__(self, msg='unknow error', code=1, project_name=None):
        RuntimeError.__init__(self)
        self.code = code
        self.msg = msg
        self.project_name = project_name

    def __str__(self):
        if self.project_name:
            return ':'.join([self.project_name, str(self.code), ' error']) \
                + ' ' + self.msg + '\n'
        return 'error: ' + self.msg + ' (error ' + str(self.code) + ')\n'


class CircleError(Error):
    '''Thrown when a circle has been detected while doing
    a topological traversal of a graph.'''
    def __init__(self, connected):
        Error.__init__(
            self, msg="detected a circle within %s" % ' '.join(connected))


class MissingError(Error):
    '''This error is thrown whenever a project has missing prerequisites.'''
    def __init__(self, project_name, prerequisites):
        Error.__init__(self, 'The following prerequisistes are missing: ' \
                           + ' '.join(prerequisites), 2, project_name)


class Context(object):
    '''The workspace configuration file contains environment variables used
    to update, build and package projects. The environment variables are roots
    of the general dependency graph as most other routines depend on srcTop
    and buildTop at the least.'''

    config_name = 'dws.mk'
    indexName = 'dws.xml'

    def __init__(self):
        # Two following variables are used by interactively change the make
        # command-line.
        self.nonative = False
        self.tunnel_point = None
        self.targets = []
        self.overrides = []
        site_top = Pathname('siteTop',
              {'description':
                    'Root of the tree where the website is generated\n'\
'                       and thus where *remoteSiteTop* is cached\n'\
'                       on the local system',
                'default':os.getcwd()})
        remote_site_top = Pathname('remoteSiteTop',
             {'description':
                   'Root of the remote tree that holds the published website\n'
'                       (ex: url:/var/cache).',
               'default':''})
        install_top = Pathname('installTop',
                    {'description':'Root of the tree for installed bin/,'\
' include/, lib/, ...',
                     'base':'siteTop', 'default':''})
        # We use installTop (previously siteTop), such that a command like
        # "dws build *remoteIndex* *siteTop*" run from a local build
        # directory creates intermediate and installed files there while
        # checking out the sources under siteTop.
        # It might just be my preference...
        build_top = Pathname('buildTop',
                    {'description':'Root of the tree where intermediate'\
' files are created.',
                     'base':'siteTop', 'default':'build'})
        src_top = Pathname('srcTop',
             {'description':
                   'Root of the tree where the source code under revision\n'
'                       control lives on the local machine.',
               'base': 'siteTop',
               'default':'reps'})
        dist = HostPlatform('-')
        dist.configure(None)
        self.environ = {'buildTop': build_top,
                        'srcTop' : src_top,
                        'patchTop': Pathname('patchTop',
             {'description':'Root of the tree where patches are stored',
              'base':'siteTop',
              'default':'patch'}),
                         'binDir': Pathname('binDir',
             {'description':'Root of the tree where executables are installed',
              'base':'installTop'}),
                         'installTop': install_top,
                         'includeDir': Pathname('includeDir',
            {'description':'Root of the tree where include files are installed',
             'base':'installTop'}),
                         'libDir': Pathname('libDir',
             {'description':'Root of the tree where libraries are installed',
              'base':'installTop'}),
                         'libexecDir': Pathname('libexecDir',
             {'description':'Root of the tree where executable helpers'\
' are installed',
              'base':'installTop'}),
                         'etcDir': Pathname('etcDir',
             {'description':
                  'Root of the tree where configuration files for the local\n'
'                       system are installed',
              'base':'installTop'}),
                         'shareDir': Pathname('shareDir',
             {'description':'Directory where the shared files are installed.',
              'base':'installTop'}),
                         'siteTop': site_top,
                         'logDir': Pathname('logDir',
             {'description':'Directory where the generated log files are'\
' created',
              'base':'siteTop',
              'default':'log'}),
                         'remoteSiteTop': remote_site_top,
                         'remoteSrcTop': Pathname('remoteSrcTop',
             {'description':
                  'Root of the tree on the remote machine where repositories\n'\
'                       are located.',
              'base':'remoteSiteTop',
              'default':'reps'}),
                         'remoteIndex': Pathname('remoteIndex',
             {'description':
                  'Url to the remote index file with projects dependencies\n'\
'                       information',
              'base':'remoteSiteTop',
              'default':'reps/drop.git/dws.xml'}),
                        'darwinTargetVolume': Single('darwinTargetVolume',
              {'description':
                    'Destination of installed packages on a Darwin local\n'\
'                       machine. Installing on the "LocalSystem" requires\n'\
'                       administrator privileges.',
              'choices': {'LocalSystem':
                         'install packages on the system root for all users',
                        'CurrentUserHomeDirectory':
                         'install packages for the current user only'}}),
                         'distHost': HostPlatform('distHost'),
                         'smtpHost': Variable('smtpHost',
             {'description':'Hostname for the SMTP server through'\
' which logs are sent.',
               'default':'localhost'}),
                         'smtpPort': Variable('smtpPort',
             {'description':'Port for the SMTP server through'\
' which logs are sent.',
               'default':'5870'}),
                         'dwsSmtpLogin': Variable('dwsSmtpLogin',
             {'description':
                   'Login on the SMTP server for the user through which\n'\
'                       logs are sent.'}),
                         'dwsSmtpPasswd': Variable('dwsSmtpPasswd',
             {'description':
                   'Password on the SMTP server for the user through which\n'\
'                       logs are sent.'}),
                         'dwsEmail': Variable('dwsEmail',
             {'description':
                   'dws occasionally emails build reports (see --mailto\n'
'                       command line option). This is the address that will\n'\
'                       be shown in the *From* field.',
               'default': runuser() + '@localhost'}),
       # Variables where modified and original sysconfig files are stored.
                        'modEtcDir': Pathname('modEtcDir',
             {'description':
'directory where modified system configuration file are generated.',
              'base':'srcTop',
              'default': socket.gethostname().replace('.', '-')}),
                        'tplEtcDir': Pathname('tplEtcDir',
            {'description':
'directory root that contains the orignal system configuration files.',
             'base':'srcTop',
             'default': os.path.join(
                 'share', 'tero', dist.dist_codename if dist.dist_codename
                 else dist.value)})
        }
        self.build_top_relative_cwd = None
        self.config_filename = None

    def __getattr__(self, name):
        return self.value(name)

    def base(self, name):
        '''Returns a basename of the uri/path specified in variable *name*.
        We do not use os.path.basename directly because it wasn't designed
        to handle uri nor does urlparse was designed to handle git/ssh locators.
        '''
        locator = self.value(name)
        look = re.match(r'\S+@\S+:(\S+)', locator)
        if look:
            return os.path.splitext(os.path.basename(look.group(1)))[0]
        look = re.match(r'https?:(\S+)', locator)
        if look:
            uri = _urlparse(locator)
            return os.path.splitext(os.path.basename(uri.path))[0]
        return os.path.splitext(os.path.basename(locator))[0]

    def bin_build_dir(self):
        '''Returns the bin/ directory located inside buildTop.'''
        return os.path.join(self.value('buildTop'), 'bin')

    @staticmethod
    def derived_helper(name):
        '''Absolute path to a file which is part of drop helper files
        located in the share/dws subdirectory. The absolute directory
        name to share/dws is derived from the path of the script
        being executed as such: dirname(sys.argv[0])/../share/dws.'''
        return os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))),
            'share', 'dws', name)
#       That code does not work when we are doing dws make (no recurse).
#       return os.path.join(self.value('buildTop'),'share','dws',name)

    def log_path(self, name):
        '''Absolute path to a file in the local system log
        directory hierarchy.'''
        return os.path.join(self.value('logDir'), name)

    def remote_src_path(self, name):
        '''Absolute path to access a repository on the remote machine.'''
        return os.path.join(self.value('remoteSrcTop'), name)

    def remote_host(self):
        '''Returns the host pointed by *remoteSiteTop*'''
        uri = _urlparse(self.value('remoteSiteTop'))
        hostname = uri.netloc
        if not uri.netloc:
            # If there is no protocol specified, the hostname
            # will be in uri.scheme (That seems like a bug in urlparse).
            hostname = uri.scheme
        return hostname

    def cwd_project(self):
        '''Returns a project name derived out of the current directory.'''
        if not self.build_top_relative_cwd:
            self.environ['buildTop'].default = os.path.dirname(os.getcwd())
            log_info("no workspace configuration file could be"\
               " found from %(cwd)s"\
               " all the way up to /. A new one, called %(config)s,"\
               " will be created in *buildTop* after that path is set."
               % {'cwd': os.getcwd(), 'config': self.config_name},
            context=self)
            self.config_filename = os.path.join(self.value('buildTop'),
                                                self.config_name)
            self.save()
            self.locate()
        if os.path.realpath(os.getcwd()).startswith(
            os.path.realpath(self.value('buildTop'))):
            top = os.path.realpath(self.value('buildTop'))
        elif os.path.realpath(os.getcwd()).startswith(
            os.path.realpath(self.value('srcTop'))):
            top = os.path.realpath(self.value('srcTop'))
        else:
            raise Error("You must run dws from within a subdirectory of "\
                        "buildTop or srcTop")
        prefix = os.path.commonprefix([top, os.getcwd()])
        return os.getcwd()[len(prefix) + 1:]

    def db_pathname(self):
        """
        Absolute pathname to the project index file.
        """
        # We always derive ``indexFile`` from ``remoteIndex`` such that we can
        # run two ``dws build`` with a different project index file in the same
        # directory.
        if not hasattr(self, '_index_file'):
            filtered = filter_rep_ext(self.value('remoteIndex'))
            if filtered != self.value('remoteIndex'):
                url_parts = _urlparse(filtered)
                normallized_url = _urlunparse((
                    url_parts.scheme, url_parts.netloc,
                    os.path.normpath(url_parts.path), url_parts.params,
                    url_parts.query, url_parts.fragment))
                prefix = self.value('remoteSrcTop')
                if not prefix.endswith(':') and not prefix.endswith(os.sep):
                    prefix = prefix + os.sep
                name = normallized_url.replace(prefix, '')
                if name == filtered:
                    # The url is not inside `remoteSrcTop`,
                    # let's try `remoteSiteTop`.
                    prefix = self.value('remoteSiteTop')
                    if not prefix.endswith(':') and not prefix.endswith(os.sep):
                        prefix = prefix + os.sep
                    name = normallized_url.replace(prefix, '')
                self._index_file = self.src_dir(name)
            else:
                self._index_file = self.local_dir(self.value('remoteIndex'))
        return self._index_file

    def host(self):
        """
        Returns the distribution of the local system
        on which the script is running.
        """
        return self.value('distHost')

    def local_dir(self, name):
        '''Returns the path on the local system to a directory.'''
        site_top = self.value('siteTop')
        pos = name.rfind('./')
        if pos >= 0:
            localname = os.path.join(site_top, name[pos + 2:])
        elif (str(self.environ['remoteSiteTop'])
              and name.startswith(self.value('remoteSiteTop'))):
            localname = filter_rep_ext(name)
            remote_site_top = self.value('remoteSiteTop')
            if remote_site_top.endswith(':'):
                site_top = site_top + '/'
            localname = localname.replace(remote_site_top, site_top)
        elif ':' in name:
            localname = os.path.join(
                site_top, 'resources', os.path.basename(name))
        elif not name.startswith(os.sep):
            localname = os.path.join(site_top, name)
        else:
            localname = name.replace(
                self.value('remoteSiteTop'), site_top)
        return localname

    def remote_dir(self, name):
        '''Returns the absolute path on the remote system that corresponds
        to *name*, the absolute path of a file or directory on the local
        system.'''
        if name.startswith(self.value('siteTop')):
            return name.replace(self.value('siteTop'),
                                self.value('remoteSiteTop'))
        return None

    def load_context(self, filename):
        site_top_found = False
        with open(filename) as config_file:
            line = config_file.readline()
            while line:
                look = re.match(r'(\S+)\s*=\s*(\S+)', line)
                if look != None:
                    if look.group(1) == 'siteTop':
                        site_top_found = True
                    if look.group(1) in self.environ:
                        # If variable was already resolved to a string, we won't
                        # override the value. That makes it possible to override
                        # the ``remoteIndex`` on the command line.
                        if isinstance(self.environ[look.group(1)], Variable):
                            self.environ[look.group(1)].value = look.group(2)
                    else:
                        self.environ[look.group(1)] = look.group(2)
                line = config_file.readline()
        return site_top_found


    def locate(self, config_filename=None):
        '''Locate the workspace configuration file and derive the project
        name out of its location.'''
        try:
            if config_filename:
                self.config_filename = config_filename
                self.config_name = os.path.basename(config_filename)
                self.build_top_relative_cwd = os.path.dirname(config_filename)
                self.load_context(self.config_filename)
            else:
                self.build_top_relative_cwd, self.config_filename \
                    = search_back_to_root(self.config_name)
        except IOError:
            self.build_top_relative_cwd = None
            self.environ['buildTop'].configure(self)
            build_top = str(self.environ['buildTop'])
            site_top = str(self.environ['siteTop'])
            if build_top.startswith(site_top):
                # When build_top is inside the site_top, we create the config
                # file in site_top for convinience so dws commands can be run
                # anywhere from within site_top (i.e. both build_top
                # and src_top).
                self.config_filename = os.path.join(site_top, self.config_name)
            else:
                # When we have a split hierarchy we can build the same src_top
                # multiple different ways but dws commands should exclusively
                # be run from within the build_top.
                self.config_filename = os.path.join(build_top, self.config_name)
            if not os.path.isfile(self.config_filename):
                self.save()
        if self.build_top_relative_cwd == '.':
            self.build_top_relative_cwd = os.path.basename(os.getcwd())
            # \todo is this code still relevent?
            look = re.match('([^-]+)-.*', self.build_top_relative_cwd)
            if look:
                # Change of project name in *indexName* on "make dist-src".
                # self.build_top_relative_cwd = look.group(1)
                pass
        # -- Read the environment variables set in the config file.
        if 'HOME' in os.environ:
            home_dir = os.environ['HOME']
            if 'SUDO_USER' in os.environ:
                home_dir = home_dir.replace(os.environ['SUDO_USER'], runuser())
            user_default_config = os.path.join(home_dir, '.dws')
            if os.path.exists(user_default_config):
                self.load_context(user_default_config)
        site_top_found = self.load_context(self.config_filename)
        if not site_top_found and not self.environ['siteTop'].value:
            # By default we set *siteTop* to be the directory
            # where the configuration file was found since basic paths
            # such as *buildTop* and *srcTop* defaults are based on it.
            self.environ['siteTop'].value = os.path.dirname(
                self.config_filename)

    def logname(self):
        '''Name of the XML tagged log file where sys.stdout is captured.'''
        filename = os.path.basename(self.config_name)
        filename = os.path.splitext(filename)[0] + '.log'
        filename = self.log_path(filename)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        return filename

    def logbuildname(self):
        '''Name of the log file for build summary.'''
        filename = os.path.basename(self.config_name)
        filename = os.path.splitext(filename)[0] + '-build.log'
        filename = self.log_path(filename)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        return filename

    def obj_dir(self, name):
        return os.path.join(self.value('buildTop'), name)

    def patch_dir(self, name):
        return os.path.join(self.value('patchTop'), name)

    def from_remote_index(self, remote_path, nonative=False):
        '''We need to set the *remoteIndex* to a realpath when we are dealing
        with a local file else links could end-up generating a different prefix
        than *remoteSiteTop* for *remoteIndex*/*indexName*.'''
        self.nonative = nonative
        if search_repo_pat(remote_path):
            remote_path = os.path.join(remote_path, self.indexName)
        # Set remoteIndex.value instead of remoteIndex.default because
        # we don't want to trigger a configure of logDir before we have
        # a chance to set the siteTop.
        look = re.match(r'(\S+@)?(\S+):(.*)', remote_path)
        if look:
            self.tunnel_point = look.group(2)
            src_base = look.group(3)
            site_base = src_base
            remote_path_list = look.group(3).split(os.sep)
            host_prefix = self.tunnel_point + ':'
            if look.group(1):
                host_prefix = look.group(1) + host_prefix
        else:
            # We compute *base* here through the same algorithm as done
            # in *local_dir*. We do not call *local_dir* because remoteSiteTop
            # is not yet defined at this point.
            src_base = os.path.dirname(remote_path)
            while not os.path.isdir(src_base):
                src_base = os.path.dirname(src_base)
            remote_path_list = remote_path.split(os.sep)
            site_base = os.path.dirname(src_base)
            host_prefix = ''
        for i in range(0, len(remote_path_list)):
            if remote_path_list[i] == '.':
                site_base = os.sep.join(remote_path_list[0:i])
                src_base = os.path.join(site_base, remote_path_list[i + 1])
                break
            look = search_repo_pat(remote_path_list[i])
            if look:
                # splitext does not return any extensions when the path
                # starts with dot.
                rep_ext = look.group(1)
                if not rep_ext.startswith('.'):
                    _, rep_ext = os.path.splitext(look.group(1))
                if remote_path_list[i] == rep_ext:
                    i = i - 1
                if i > 2:
                    src_base = os.sep.join(remote_path_list[0:i])
                    site_base = os.sep.join(remote_path_list[0:i-1])
                elif i > 1:
                    src_base = remote_path_list[0]
                    site_base = ''
                else:
                    src_base = ''
                    site_base = ''
                break
        if not self.tunnel_point:
            # We can't use realpath before we figured out where the '.'
            # delimiter is in remote_path.
            if src_base:
                remote_path = os.path.normpath(remote_path).replace(
                    src_base, os.path.realpath(src_base))
                src_base = os.path.realpath(src_base)
            else:
                remote_path = os.path.normpath(
                    os.path.join(os.getcwd(), remote_path))
                src_base = os.getcwd()
            if site_base:
                site_base = os.path.realpath(site_base)
            else:
                site_base = os.getcwd()
        self.environ['remoteIndex'] = remote_path
        self.environ['remoteSrcTop'].default = host_prefix + src_base
        # Note: We used to set the context[].default field which had for side
        # effect to print the value the first time the variable was used.
        # The problem is that we need to make sure remoteSiteTop is defined
        # before calling *local_dir*, otherwise the resulting indexFile value
        # will be different from the place the remoteIndex is fetched to.
        self.environ['remoteSiteTop'] = host_prefix + site_base

    def save(self):
        '''Write the config back to a file.'''
        if not self.config_filename:
            # No config_filename means we are still figuring out siteTop,
            # so we don't know where to store the config file.
            return
        if not os.path.exists(os.path.dirname(self.config_filename)):
            os.makedirs(os.path.dirname(self.config_filename))
        config_file = open(self.config_filename, 'w')
        keys = sorted(self.environ.keys())
        config_file.write('# configuration for development workspace\n\n')
        for key in keys:
            val = self.environ[key]
            if str(val):
                config_file.write(key + '=' + str(val) + '\n')
        config_file.close()

    def search_path(self, name, variant=None):
        """
        Derives a list of directory names based on the PATH
        environment variable, *name* and a *variant* triplet.
        """
        py_ver = python_version(self)
        candidates = []
        # We want the actual value of *name*Dir and not one derived from binDir
        dirname = CONTEXT.value(name + 'Dir')
        if os.path.isdir(dirname):
            # First look into variant and finally in no variant directory
            # because even though libraries are often in variant subdirectories,
            # executables often are not.
            if variant:
                if variant == 'python':
                    candidate = os.path.join(dirname, py_ver)
                    if (os.path.exists(candidate) and
                        (len(candidates) == 0 or candidates[-1] != candidate)):
                        candidates += [candidate]
                else:
                    candidate = os.path.join(dirname, variant)
                    if (os.path.exists(candidate) and
                        (len(candidates) == 0 or candidates[-1] != candidate)):
                        candidates += [candidate]
            if len(candidates) == 0 or candidates[-1] != dirname:
                candidates += [dirname]
        if variant and variant == 'python' and not NO_VIRTUALENV:
            # For pure Python modules, we are only looking into the virtualenv.
            return candidates
        candidates += os.environ['PATH'].split(':')
        for pgsql_version in [11, 12]:
            pgsql_path = "/usr/pgsql-%d/bin" % pgsql_version
            if os.path.exists(pgsql_path):
                candidates += [pgsql_path]
        dirs = []
        for path in candidates:
            base = os.path.dirname(path)
            if name == 'lib':
                # On mixed 32/64-bit system, libraries also get installed
                # in lib64/. This is also true for 64-bit native python modules.
                for subpath in [name, 'lib64']:
                    dirname = os.path.join(base, subpath)
                    if os.path.isdir(dirname):
                        if variant:
                            if variant == 'python':
                                candidate = os.path.join(dirname, py_ver)
                                if (os.path.exists(candidate) and
                                    (len(dirs) == 0 or dirs[-1] != candidate)):
                                    dirs += [candidate]
                            else:
                                candidate = os.path.join(dirname, variant)
                                if (os.path.exists(candidate) and
                                    (len(dirs) == 0 or dirs[-1] != candidate)):
                                    dirs += [candidate]
                        if len(dirs) == 0 or dirs[-1] != dirname:
                            dirs += [dirname]
            elif name == 'bin':
                # Especially on Fedora, /sbin, /usr/sbin, etc. are many times
                # not in the PATH.
                if os.path.isdir(path):
                    if len(dirs) == 0 or dirs[-1] != path:
                        dirs += [path]
                sbin = os.path.join(base, 'sbin')
                if (not sbin in os.environ['PATH'].split(':')
                    and os.path.isdir(sbin)):
                    if len(dirs) == 0 or dirs[-1] != path:
                        dirs += [sbin]
            else:
                dirname = os.path.join(base, name)
                if os.path.isdir(dirname):
                    if len(dirs) == 0 or dirs[-1] != dirname:
                        dirs += [dirname]
        if name == 'lib' and self.host() in PORT_DISTRIBS:
            # Just because python modules do not get installed
            # in /opt/local/lib/python2.7/site-packages
            dirs += [py_ver.replace('python',
                '/opt/local/Library/Frameworks/Python.framework/Versions/')]
        if name == 'share' and self.host() in APT_DISTRIBS:
            dirs += ['/var/lib/gems']
        return dirs

    def src_dir(self, name):
        return os.path.join(self.value('srcTop'), name)

    def value(self, name):
        '''returns the value of the workspace variable *name*. If the variable
        has no value yet, a prompt is displayed for it.'''
        if not name in self.environ:
            raise Error("Trying to read unknown variable " + name + ".")
        if (isinstance(self.environ[name], Variable)
            and self.environ[name].configure(self)):
            self.save()
        # recursively resolve any variables that might appear
        # in the variable value. We do this here and not while loading
        # the context because those names can have been defined later.
        value = str(self.environ[name])
        look = re.match(r'(.*)\${(\S+)}(.*)', value)
        while look:
            indirect = ''
            if look.group(2) in self.environ:
                indirect = self.value(look.group(2))
            elif look.group(2) in os.environ:
                indirect = os.environ[look.group(2)]
            value = look.group(1) + indirect + look.group(3)
            look = re.match(r'(.*)\${(\S+)}(.*)', value)
        return value


# Formats help for script commands. The necessity for this class
# can be understood by the following posts on the internet:
# - http://groups.google.com/group/comp.lang.python/browse_thread/thread/6df6e
# - http://www.alexonlinux.com/pythons-optparse-for-human-beings
#
# \todo The argparse (http://code.google.com/p/argparse/) might be part
#       of the standard python library and address the issue at some point.
class CommandsFormatter(optparse.IndentedHelpFormatter):
    def format_epilog(self, description):
        import textwrap
        result = ""
        if description:
            desc_width = self.width - self.current_indent
            bits = description.split('\n')
            formatted_bits = [
              textwrap.fill(bit,
                desc_width,
                initial_indent="",
                subsequent_indent="                       ")
              for bit in bits]
            result = result + "\n".join(formatted_bits) + "\n"
        return result


class IndexProjects(object):
    '''Index file containing the graph dependency for all projects.'''

    def __init__(self, context, source=None):
        self.context = context
        self.parser = XMLDbParser(context)
# XXX testing:        self.parser = YAMLikeParser(context)
        self.source = source

    def closure(self, dgen):
        '''Find out all dependencies from a root set of projects as defined
        by the dependency generator *dgen*.'''
        while dgen.more():
            self.parse(dgen)
        return dgen.topological()

    def parse(self, dgen):
        '''Parse the project index and generates callbacks to *dgen*'''
        self.validate()
        self.parser.parse(self.source, dgen)

    def validate(self, force=False):
        '''Create the project index file if it does not exist
        either by fetching it from a remote server or collecting
        projects indices locally.'''
        if not self.source:
            self.source = self.context.db_pathname()
        if not self.source.startswith('<?xml'):
            # The source is an actual string, thus we do not fetch any file.
            if not os.path.exists(self.source) or force:
                selection = ''
                if not force:
                    # index or copy.
                    selection = select_one(
                        'The project index file could not '
                        + 'be found at "' + self.source \
                        + '". It can be regenerated through one ' \
                        + 'of the two following method:',
                        [['fetching', 'from remote server'],
                         ['indexing', 'local projects in the workspace']],
                        False)
                if selection == 'indexing':
                    pub_collect([])
                elif selection == 'fetching' or force:
                    remote_index = self.context.value('remoteIndex')
                    vcs = Repository.associate(remote_index)
                    # XXX Does not matter here for rsync.
                    # What about other repos?
                    vcs.update(None, self.context)
            if not os.path.exists(self.source):
                raise Error(self.source + ' does not exist.')


class PdbHandler(object):
    '''Callback interface for a project index as generated by an *xmlDbParser*.
       The generic handler does not do anything. It is the responsability of
       implementing classes to filter callback events they care about.'''
    def __init__(self):
        pass

    def end_parse(self):
        pass

    def project(self, proj):
        pass


class Unserializer(PdbHandler):
    '''Builds *Project* instances for every project that matches *include_pats*
    and not *exclude_pats*. See *filters*() for implementation.'''

    def __init__(self, include_pats=None, exclude_pats=None, custom_steps=None):
        PdbHandler.__init__(self)
        self.projects = {}
        self.first_project = None
        if include_pats:
            self.include_pats = set(include_pats)
        # Project which either fullfil all prerequisites or that have been
        # explicitely excluded from installation by the user will be added
        # to *exclude_pats*.
        if exclude_pats:
            self.exclude_pats = set(exclude_pats)
        else:
            self.exclude_pats = set([])
        if custom_steps:
            self.custom_steps = dict(custom_steps)
        else:
            self.custom_steps = {}

    def as_project(self, name):
        if not name in self.projects:
            raise Error("unable to find " + name + " in the index file.",
                        project_name=name)
        return self.projects[name]

    def filters(self, project_name):
        for inc in self.include_pats:
            inc = inc.replace('+', '\\+')
            if re.match(inc, project_name):
                for exc in self.exclude_pats:
                    if re.match(exc.replace('+', '\\+'), project_name):
                        return False
                return True
        return False

    def project(self, proj_obj):
        '''Callback for the parser.'''
        if (not proj_obj.name in self.projects) and self.filters(proj_obj.name):
            if not self.first_project:
                self.first_project = proj_obj
            self.projects[proj_obj.name] = proj_obj


class DependencyGenerator(Unserializer):
    """
    *DependencyGenerator* implements a breath-first search of the project
    dependencies index with a specific twist.
    At each iteration, if all prerequisites for a project can be found
    on the local system, the dependency edge is cut from the next iteration.
    Missing prerequisite executables, headers and libraries require
    the installation of prerequisite projects as stated by the *missings*
    list of edges. The user will be prompt for *candidates*() and through
    the options available will choose to install prerequisites through
    compiling them out of a source controlled repository or a binary
    distribution package.
    *DependencyGenerator.end_parse*() is at the heart of the workspace
    bootstrapping and other "recurse" features.
    """

    def __init__(self, repositories, packages, exclude_pats=None,
                 custom_steps=None, force_update=False):
        '''*repositories* will be installed from compiling
        a source controlled repository while *packages* will be installed
        from a binary distribution package.
        *exclude_pats* is a list of projects which should be removed from
        the final topological order.'''
        self.roots = packages + repositories
        Unserializer.__init__(self, self.roots, exclude_pats, custom_steps)
        # When True, an exception will stop the recursive make
        # and exit with an error code, otherwise it moves on to
        # the next project.
        self.stop_make_after_error = False
        self.packages = set(packages)
        self.repositories = set(repositories)
        self.active_prerequisites = {}
        for prereq_name in repositories + packages:
            self.active_prerequisites[prereq_name] = (
                prereq_name, 0, TargetStep(0, prereq_name))
        self.levels = {}
        self.levels[0] = set([])
        for rep in repositories + packages:
            self.levels[0] |= set([TargetStep(0, rep)])
        # Vertices in the dependency tree
        self.vertices = {}
        self.force_update = force_update

    def __str__(self):
        return "vertices:\n%s" % str(self.vertices)

    def connect_to(self, name, step):
        if name in self.vertices:
            self.vertices[name].prerequisites += [step]

    def add_config_make(self, variant, configure, make, prerequisites):
        config = None
        config_name = ConfigureStep.genid(variant.project, variant.target)
        if not config_name in self.vertices:
            config = configure.associate(variant.target)
            self.vertices[config_name] = config
        else:
            config = self.vertices[config_name]
        make_name = BuildStep.genid(variant.project, variant.target)
        if not make_name in self.vertices:
            make = make.associate(variant.target)
            make.force_update = self.force_update
            self.vertices[make_name] = make
            for prereq in prerequisites:
                make.prerequisites += [prereq]
            if config:
                make.prerequisites += [config]
            setup_name = SetupStep.genid(variant.project, variant.target)
            self.connect_to(setup_name, make)
        return self.vertices[make_name]

    def add_install(self, project_name, target=None):
        install_step = None
        managed_name = project_name.split(os.sep)[-1]
        install_name = InstallStep.genid(managed_name)
        if install_name in self.vertices:
            # We already decided to install this project, nothing more to add.
            return self.vertices[install_name]

        # We do not know the target at this point so we can't build a fully
        # qualified setup_name and index into *vertices* directly. Since we
        # are trying to install projects through the local package manager,
        # it is doubtful we should either know or care about the target.
        # That's a primary reason why target got somewhat slightly overloaded.
        # We used runtime="python" instead of target="python" in an earlier
        # design.
        setup_name = SetupStep.genid(project_name, target)
        if project_name in self.projects:
            project = self.projects[project_name]
            dist = CONTEXT.host()
            if dist not in project.packages:
                dist = ALIAS_DISTRIBS.get(dist, dist)
            if dist in project.packages:
                filenames = []
                flavor = project.packages[dist]
                for remote_path in flavor.update.fetches:
                    filenames += [CONTEXT.local_dir(remote_path)]
                install_step = create_package_file(project_name, filenames)
                update_s = self.add_update(project_name, flavor.update)
                if update_s:
                    install_step.prerequisites += [update_s]
            elif project.patch:
                # build and install from source
                flavor = project.patch
                prereqs = [] # XXX used to contain setup of prerequisites.
                update_s = self.add_update(
                    project_name, project.patch.update)
                if update_s:
                    prereqs += [update_s]
                install_step = self.add_config_make(
                    TargetStep(0, project_name, target),
                    flavor.configure, flavor.make, prereqs)
        else:
            # XXX Previously we picked the local package manager
            # before patched sources without checking if it is available.
            # Of course it created problems, yet we want to check existance
            # as late as possible so there was no way to decide
            # at this point.
            install_step = create_managed(managed_name, target=target)
        if not install_step:
            # Remove special case install_step is None; replace it with
            # a placeholder instance that will throw an exception
            # when the *run* method is called.
            install_step = InstallStep(project_name, target=target)
        if install_step:
            if setup_name in self.vertices:
                # We collected all bins/libs/includes in a SetupStep.
                # They need to be transfered to the InstallStep.
                setup_step = self.vertices[setup_name]
                install_step.add_prerequisites(setup_step)
            self.vertices[install_name] = install_step
            self.connect_to(setup_name, install_step)
        return install_step

    def add_setup(self, target, deps):
        """
        Add a step that will check all required prerequisites are present.
        """
        targets = []
        for dep in deps:
            target_name = dep.target
            if not dep.target:
                target_name = target
            cap = SetupStep.genid(dep.name)
            if cap in self.custom_steps:
                setup_class = self.custom_steps[cap]
            else:
                setup_class = SetupStep
            setup = setup_class(dep.name, dep.files,
                versions=dep.versions, target=target_name)
            if not setup.name in self.vertices:
                self.vertices[setup.name] = setup
            else:
                self.vertices[setup.name].add_prerequisites(setup)
                # Add prerequisites test not already present in install step.
                managed_name = dep.name.split(os.sep)[-1]
                install_name = InstallStep.genid(managed_name)
                if install_name in self.vertices:
                    self.vertices[install_name].add_prerequisites(setup)
            targets += [self.vertices[setup.name]]
        return targets

    def add_update(self, project_name, update, update_rep=True):
        update_name = UpdateStep.genid(project_name)
        if update_name in self.vertices:
            return self.vertices[update_name]
        update_s = None
        fetches = {}
        if update.fetches:
            # We could unconditionally add all source tarball since
            # the *fetch* function will perform a *find_cache* before
            # downloading missing files. Unfortunately this would
            # interfere with *pub_configure* which checks there are
            # no missing prerequisites whithout fetching anything.
            fetches = find_cache(CONTEXT, update.fetches)
        rep = None
        if update_rep or not os.path.isdir(CONTEXT.src_dir(project_name)):
            rep = update.rep
        if update.rep or fetches:
            update_s = UpdateStep(project_name, rep, fetches)
            self.vertices[update_s.name] = update_s
        return update_s

    def contextual_targets(self, variant):
        raise Error("DependencyGenerator should not be instantiated directly")

    def end_parse(self):
        further = False
        next_active_prerequisites = {}
        for prereq_name in self.active_prerequisites:
            # Each edge is a triplet source: (color, depth, variant)
            # Gather next active Edges.
            color = self.active_prerequisites[prereq_name][0]
            depth = self.active_prerequisites[prereq_name][1]
            variant = self.active_prerequisites[prereq_name][2]
            next_depth = depth + 1
            # The algorithm to select targets depends on the command semantic.
            # The build, make and install commands differ in behavior there
            # in the presence of repository, patch and package tags.
            need_prompt, targets = self.contextual_targets(variant)
            if need_prompt:
                next_active_prerequisites[prereq_name] = (color, depth, variant)
            else:
                for target in targets:
                    further = True
                    target_name = str(target.project)
                    if target_name in next_active_prerequisites:
                        if next_active_prerequisites[target_name][0] > color:
                            # We propagate a color attribute through
                            # the constructed DAG to detect cycles later on.
                            next_active_prerequisites[target_name] = (
                                color, next_depth, target)
                    else:
                        next_active_prerequisites[target_name] = (
                            color, next_depth, target)
                    if not next_depth in self.levels:
                        self.levels[next_depth] = set([])
                    self.levels[next_depth] |= set([target])

        self.active_prerequisites = next_active_prerequisites
        if not further:
            # This is an opportunity to prompt the user.
            # The user's selection will decide, when available, if the project
            # should be installed from a repository, a patch, a binary package
            # or just purely skipped.
            reps = []
            packages = []
            for name in self.active_prerequisites:
                if (not os.path.isdir(CONTEXT.src_dir(name))
                    and self.filters(name)):
                    # If a prerequisite project is not defined as an explicit
                    # package, we will assume the prerequisite name is
                    # enough to install the required tools for the prerequisite.
                    row = [name]
                    if name in self.projects:
                        project = self.as_project(name)
                        if project.installed_version:
                            row += [project.installed_version]
                        if project.repository:
                            reps += [row]
                        if not project.repository:
                            packages += [row]
                    else:
                        packages += [row]
            # Prompt to choose amongst installing from repository
            # patch or package when those tags are available.'''
            reps, packages = select_checkout(reps, packages)
            self.repositories |= set(reps)
            self.packages |= set(packages)
        # Add all these in the include_pats such that we load project
        # information the next time around.
        for name in self.active_prerequisites:
            if not name in self.include_pats:
                self.include_pats |= set([name])

    def more(self):
        '''True if there are more iterations to conduct.'''
        return len(self.active_prerequisites) > 0

    def topological(self):
        '''Returns a topological ordering of projects selected.'''
        ordered = []
        # We first force all install steps using a package manager
        # to be grouped up front by package manager. This way a single
        # command can be executed to install all of them at once.
        next_remains = []
        remains = list(self.vertices.values())
        for priority in (Step.install_native, Step.install_pip,
                         Step.install_gem, Step.install_npm):
            for step in remains:
                if step.priority == priority:
                    ordered += [step]
                else:
                    next_remains += [step]
            remains = next_remains
            next_remains = []
        if False:
            log_info("!!!remains:")
            for step in remains:
                is_vert = ''
                if step.name in self.vertices:
                    is_vert = '*'
                log_info("!!!\t%s %s %s"
                         % (step.name, str(is_vert),
                            str([pre.name for pre in step.prerequisites])))
        loop_cnt = 0
        next_remains = []
        while remains:
            loop_cnt = loop_cnt + 1
            for step in remains:
                ready = True
                min_insert_point = 0
                for prereq in step.prerequisites:
                    index = 0
                    found = False
                    for ordered_step in ordered:
                        index = index + 1
                        if prereq.name == ordered_step.name:
                            found = True
                            break
                    if not found:
                        ready = False
                        break
                    elif index > min_insert_point:
                        min_insert_point = index
                if ready:
                    insert_point = len(ordered)
                    for ordered_step in reversed(ordered[min_insert_point:]):
                        if ordered_step.priority < step.priority:
                            break
                        if(hasattr(ordered_step, 'target')
                           and hasattr(step, 'target')
                           and str(ordered_step.target) > str(step.target)):
                            break
                        insert_point = insert_point - 1
                    ordered.insert(insert_point, step)
                else:
                    next_remains += [step]
            if len(remains) <= len(next_remains):
                raise CircleError([vert.name for vert in next_remains])
            remains = next_remains
            next_remains = []
        if False:
            log_info("!!! => ordered:")
            for ordered_step in ordered:
                log_info("%s -> %s" % (ordered_step.name,
                    [step.name for step in ordered_step.prerequisites]))
        return ordered


class BuildGenerator(DependencyGenerator):
    '''Forces selection of installing from repository when that tag
    is available in a project.'''

    def contextual_targets(self, variant):
        """
        At this point we want to add all prerequisites which are either
        a repository or a patch/package for which the dependencies are not
        complete.
        """
        tags = [CONTEXT.host()]
        targets = []
        name = variant.project
        if name in self.projects:
            project = self.as_project(name)
            if project.repository:
                self.repositories |= set([name])
                targets = self.add_setup(variant.target,
                                       project.repository.prerequisites(tags))
                update_s = self.add_update(name, project.repository.update)
                prereqs = targets
                if update_s:
                    prereqs = [update_s] + targets
                self.add_config_make(variant, project.repository.configure,
                    project.repository.make, prereqs)
            else:
                for dist in tags:
                    if dist not in project.packages and dist in ALIAS_DISTRIBS:
                        dist = ALIAS_DISTRIBS[dist]
                    if dist in project.packages:
                        self.packages |= set([name])
                        targets = self.add_setup(variant.target,
                            project.packages[dist].prerequisites(tags))
                        install_step = self.add_install(name, variant.target)
                        # package files won't install without prerequisites already
                        # on the local system.
                        install_step.prerequisites = (targets
                            + install_step.prerequisites)
        else:
            # We leave the native host package manager to deal with this one...
            self.packages |= set([name])
            self.add_install(name, variant.target)
        return (False, targets)


class PubDepsGenerator(BuildGenerator):

    def add_update(self, project_name, update, update_rep=True):
        return None


class MakeGenerator(DependencyGenerator):
    '''Forces selection of installing from repository when that tag
    is available in a project.'''

    def __init__(self, repositories, packages,
                 exclude_pats=None, custom_steps=None):
        super(MakeGenerator, self).__init__(repositories, packages,
            exclude_pats=exclude_pats, custom_steps=custom_steps,
            force_update=True)
        self.stop_make_after_error = True

    def contextual_targets(self, variant):
        dist = CONTEXT.host()
        name = variant.project
        if not name in self.projects:
            self.packages |= set([name])
            self.add_install(name, variant.target)
            return (False, [])

        need_prompt = True
        project = self.as_project(name)
        if os.path.isdir(CONTEXT.src_dir(name)):
            # If there is already a local source directory in *srcTop*, it is
            # also a no brainer - invoke make.
            nb_choices = 1

        else:
            # First, compute how many potential installation tags we have here.
            nb_choices = 0
            if project.repository:
                nb_choices = nb_choices + 1
            if project.patch:
                nb_choices = nb_choices + 1
            if project.packages:
                nb_choices = nb_choices + 1

        targets = []
        tags = [dist]
        if nb_choices == 1:
            # Only one choice is easy. We just have to make sure we won't
            # put the project in two different sets.
            chosen = self.repositories | self.packages
            if project.repository:
                need_prompt = False
                targets = self.add_setup(variant.target,
                                       project.repository.prerequisites(tags))
                update_s = self.add_update(
                    name, project.repository.update, False)
                prereqs = targets
                if update_s:
                    prereqs = [update_s] + targets
                self.add_config_make(variant,
                                   project.repository.configure,
                                   project.repository.make,
                                   prereqs)
                if not name in chosen:
                    self.repositories |= set([name])
            elif project.packages or project.patch:
                need_prompt = False
                targets = self.add_setup(variant.target,
                    project.packages[dist].prerequisites(tags))
                install_step = self.add_install(name, variant.target)
                # package files won't install without prerequisites already
                # on the local system.
                install_step.prerequisites = (targets
                    + install_step.prerequisites)
                if not name in chosen:
                    self.packages |= set([name])

        # At this point there is more than one choice to install the project.
        # When the repository, patch or package tag to follow through has
        # already been decided, let's check if we need to go deeper through
        # the prerequisistes.
        if need_prompt:
            if name in self.repositories:
                need_prompt = False
                targets = self.add_setup(variant.target,
                                       project.repository.prerequisites(tags))
                update_s = self.add_update(
                    name, project.repository.update, False)
                prereqs = targets
                if update_s:
                    prereqs = [update_s] + targets
                self.add_config_make(variant,
                                   project.repository.configure,
                                   project.repository.make,
                                   prereqs)
            elif project.packages or project.patch:
                need_prompt = False
                targets = self.add_setup(variant.target,
                    project.packages[dist].prerequisites(tags))
                install_step = self.add_install(name, variant.target)
                # package files won't install without prerequisites already
                # on the local system.
                install_step.prerequisites = (targets
                    + install_step.prerequisites)
        return (need_prompt, targets)

    def topological(self):
        '''Filter out the roots from the topological ordering in order
        for 'make recurse' to behave as expected (i.e. not compiling roots).'''
        vertices = DependencyGenerator.topological(self)
        results = []
        roots = set([MakeStep.genid(root) for root in self.roots])
        for project in vertices:
            if not project.name in roots:
                results += [project]
        return results


class DerivedSetsGenerator(PdbHandler):
    '''Generate the set of projects which are not dependency
    for any other project.'''

    def __init__(self):
        PdbHandler.__init__(self)
        self.roots = []
        self.nonroots = []

    def project(self, proj):
        for dep_name in proj.prerequisite_names([CONTEXT.host()]):
            if dep_name in self.roots:
                self.roots.remove(dep_name)
            if not dep_name in self.nonroots:
                self.nonroots += [dep_name]
        if (not proj.name in self.nonroots
            and not proj.name in self.roots):
            self.roots += [proj.name]

# =============================================================================
#     Writers are used to save *Project* instances to persistent storage
#     in different formats.
# =============================================================================

class NativeWriter(PdbHandler):
    '''Write *Project* objects as xml formatted text that can be loaded back
    by the script itself.'''
    def __init__(self):
        PdbHandler.__init__(self)


class Variable(object):
    '''Variable that ends up being defined in the workspace make
    fragment and thus in Makefile.'''

    def __init__(self, name, pairs):
        self.name = name
        self.value = None
        self.descr = None
        self.default = None
        if isinstance(pairs, dict):
            for key, val in _iteritems(pairs):
                if key == 'description':
                    self.descr = val
                elif key == 'value':
                    self.value = val
                elif key == 'default':
                    self.default = val
        else:
            self.value = pairs
            self.default = self.value
        self.constrains = {}

    def __str__(self):
        if self.value:
            return str(self.value)
        else:
            return ''

    def constrain(self, variables):
        pass

    def configure(self, context):
        '''Set value to the string entered at the prompt.

        We used to define a *Pathname* base field as a pointer to a *Pathname*
        instance instead of a string to index context.environ[]. That only
        worked the first time (before dws.mk is created) and when the base
        functionality wasn't used later on. As a result we need to pass the
        *context* as a parameter here.'''
        if self.name in os.environ:
            # In case the variable was set in the environment,
            # we do not print its value on the terminal, as a very
            # rudimentary way to avoid leaking sensitive information.
            self.value = os.environ[self.name]
        if self.value != None:
            return False
        log_info("\n%s:" % self.name, context=context)
        log_info(self.descr, context=context)
        if USE_DEFAULT_ANSWER:
            self.value = self.default
        else:
            default_prompt = ""
            if self.default:
                default_prompt = " [" + self.default + "]"
            self.value = prompt("Enter a string %s: " % default_prompt)
        log_info("%s set to %s" % (self.name, str(self.value)),
            context=context)
        return True

class HostPlatform(Variable):

    def __init__(self, name, pairs=None):
        """
        Initialize an HostPlatform variable. *pairs* is a dictionnary.
        """
        Variable.__init__(self, name, pairs)
        self.dist_codename = None

    def configure(self, context):
        '''Set value to the distribution on which the script is running.'''
        if self.value != None:
            return False
        # sysname, nodename, release, version, machine
        sysname, _, _, version, _ = os.uname()
        if sysname == 'Darwin':
            self.value = 'Darwin'
        elif sysname == 'Linux':
            # Let's try to determine the host platform
            for version_path in ['/etc/system-release', '/etc/lsb-release',
                                 '/etc/debian_version', '/proc/version']:
                if os.path.exists(version_path):
                    version = open(version_path)
                    line = version.readline()
                    while line:
                        for dist in APT_DISTRIBS + DNF_DISTRIBS + YUM_DISTRIBS:
                            look = re.match('.*' + dist + '.*', line)
                            if look:
                                self.value = dist
                                if dist == 'Amazon' and '2023' not in line:
                                    self.value = 'AmazonLinux2'
                            look = re.match('.*' + dist.lower() + '.*', line)
                            if look:
                                self.value = dist
                            if not self.dist_codename:
                                look = re.match(
                                    r'DISTRIB_CODENAME=\s*(\S+)', line)
                                if look:
                                    self.dist_codename = look.group(1)
                                elif self.value:
                                    # First time around the loop we will
                                    # match this pattern but not the previous
                                    # one that sets value to 'Fedora'.
                                    look = re.match(r'.*release (\d+)', line)
                                    if look:
                                        self.dist_codename = \
                                            self.value + look.group(1)
                        line = version.readline()
                    version.close()
                    if self.value:
                        break
        return True


class Pathname(Variable):

    def __init__(self, name, pairs):
        Variable.__init__(self, name, pairs)
        self.base = None
        if 'base' in pairs:
            self.base = pairs['base']

    def configure(self, context):
        """
        Generate an interactive prompt to enter a workspace variable
        value and returns True if the variable value as been set.
        """
        if self.value != None:
            return False
        # compute the default leaf directory from the variable name
        leaf_dir = self.name
        for last in range(0, len(self.name)):
            if self.name[last] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                leaf_dir = self.name[:last]
                break
        dirname = self
        base_value = None
        off_base_chosen = False
        default = self.default
        # We buffer the text and delay writing to log because we can get
        # here to find out where the log resides!
        if self.name == 'logDir':
            global LOGGER_BUFFERING_COUNT
            LOGGER_BUFFERING_COUNT = LOGGER_BUFFERING_COUNT + 1
        log_info("\n%s:\n%s" % (self.name, self.descr), context=context)
        if (not default
            or (not ((':' in default) or default.startswith(os.sep)))):
            # If there are no default values or the default is not
            # an absolute pathname.
            if self.base:
                base_value = str(context.environ[self.base])
                if default != None:
                    # Because '' will evaluates to False
                    show_default = '*' + self.base + '*/' + default
                else:
                    show_default = '*' + self.base + '*/' + leaf_dir
                if not base_value:
                    directly = 'Enter *' + self.name + '* directly ?'
                    offbase = 'Enter *' + self.base + '*, *' + self.name \
                                 + '* will defaults to ' + show_default  \
                                 + ' ?'
                    selection = select_one(
                        '%s is based on *%s* by default. Would you like to ... '
                        % (self.name, self.base),
                        [[offbase], [directly]], False)
                    if selection == offbase:
                        off_base_chosen = True
                        if isinstance(context.environ[self.base], Pathname):
                            context.environ[self.base].configure(context)
                        base_value = str(context.environ[self.base])
            else:
                base_value = os.getcwd()
            if default != None:
                # Because '' will evaluates to False
                default = os.path.join(base_value, default)
            else:
                default = os.path.join(base_value, leaf_dir)
        if not default:
            default = os.getcwd()

        dirname = default
        if off_base_chosen:
            base_value = str(context.environ[self.base])
            if self.default:
                dirname = os.path.join(base_value, self.default)
            else:
                dirname = os.path.join(base_value, leaf_dir)
        else:
            if not USE_DEFAULT_ANSWER:
                dirname = prompt("Enter a pathname [%s]: " % default)
            if dirname == '':
                dirname = default
        if not ':' in dirname:
            dirname = os.path.normpath(os.path.abspath(dirname))
        self.value = dirname
        if not ':' in dirname:
            if not os.path.exists(self.value):
                log_info("%s does not exist." % self.value, context=context)
                # We should not assume the pathname is a directory,
                # hence we do not issue a os.makedirs(self.value)
        # Now it should be safe to write to the logfile.
        if self.name == 'logDir':
            LOGGER_BUFFERING_COUNT = LOGGER_BUFFERING_COUNT - 1
        log_info("%s set to %s" % (self.name, self.value), context=context)
        return True


class Metainfo(Variable):

    def __init__(self, name, pairs):
        Variable.__init__(self, name, pairs)


class Multiple(Variable):

    def __init__(self, name, pairs):
        if pairs and isinstance(pairs, str):
            pairs = pairs.split(' ')
        Variable.__init__(self, name, pairs)
        self.choices = {}
        if 'choices' in pairs:
            self.choices = pairs['choices']

    def __str__(self):
        return ' '.join(self.value)

    def configure(self, context):
        '''Generate an interactive prompt to enter a workspace variable
        *var* value and returns True if the variable value as been set.'''
        # There is no point to propose a choice already constraint by other
        # variables values.
        choices = []
        for key, descr in _iteritems(self.choices):
            if not key in self.value:
                choices += [[key, descr]]
        if len(choices) == 0:
            return False
        descr = self.descr
        if self.value:
            descr += " (constrained: " + ", ".join(self.value) + ")"
        self.value = select_multiple(descr, choices)
        log_info("%s set to %s" % (self.name, ', '.join(self.value)),
            context=context)
        self.choices = []
        return True

    def constrain(self, variables):
        if not self.value:
            self.value = []
        for var in variables:
            if isinstance(variables[var], Variable) and variables[var].value:
                if isinstance(variables[var].value, list):
                    for val in variables[var].value:
                        if (val in variables[var].constrains
                            and self.name in variables[var].constrains[val]):
                            self.value += \
                                variables[var].constrains[val][self.name]
                else:
                    val = variables[var].value
                    if (val in variables[var].constrains
                        and self.name in variables[var].constrains[val]):
                        self.value += variables[var].constrains[val][self.name]

class Single(Variable):

    def __init__(self, name, pairs):
        Variable.__init__(self, name, pairs)
        self.choices = None
        if 'choices' in pairs:
            self.choices = []
            for key, descr in _iteritems(pairs['choices']):
                self.choices += [[key, descr]]

    def configure(self, context):
        '''Generate an interactive prompt to enter a workspace variable
        *var* value and returns True if the variable value as been set.'''
        if self.value:
            return False
        self.value = select_one(self.descr, self.choices)
        log_info("%s set to%s" % (self.name, self.value), context=context)
        return True

    def constrain(self, variables):
        for var in variables:
            if isinstance(variables[var], Variable) and variables[var].value:
                if isinstance(variables[var].value, list):
                    for val in variables[var].value:
                        if (val in variables[var].constrains
                            and self.name in variables[var].constrains[val]):
                            self.value = \
                                variables[var].constrains[val][self.name]
                else:
                    val = variables[var].value
                    if (val in variables[var].constrains
                        and self.name in variables[var].constrains[val]):
                        self.value = variables[var].constrains[val][self.name]


class Dependency(object):

    def __init__(self, name, pairs):
        self.versions = {'includes': [], 'excludes': []}
        self.target = None
        self.files = {}
        self.name = name
        for key, val in _iteritems(pairs):
            if key == 'excludes':
                self.versions['excludes'] = [val]
            elif key == 'includes':
                self.versions['includes'] = [val]
            elif key == 'target':
                # The index file loader will have generated fully-qualified
                # names to avoid key collisions when a project depends on both
                # proj and target/proj. We need to revert the name back to
                # the actual project name here.
                self.target = val
                self.name = os.sep.join(self.name.split(os.sep)[1:])
            else:
                if isinstance(val, list):
                    self.files[key] = []
                    for filename in val:
                        self.files[key] += [(filename, None)]
                else:
                    self.files[key] = [(val, None)]

    def populate(self, build_deps):
        '''*build_deps* is a dictionary.'''
        if self.name in build_deps:
            deps = build_deps[self.name].files
            for dep in deps:
                if dep in self.files:
                    files = []
                    for look_pat, look_path in self.files[dep]:
                        found = False
                        if not look_path:
                            for pat, path in deps[dep]:
                                if pat == look_pat:
                                    files += [(look_pat, path)]
                                    found = True
                                    break
                        if not found:
                            files += [(look_pat, look_path)]
                    self.files[dep] = files

    def prerequisites(self, tags):
        return [self]


class Alternates(Dependency):
    '''Provides a set of dependencies where one of them is enough
    to fullfil the prerequisite condition. This is used to allow
    differences in packaging between distributions.'''

    def __init__(self, name, pairs):
        Dependency.__init__(self, name, pairs)
        self.by_tags = {}
        for key, val in _iteritems(pairs):
            self.by_tags[key] = []
            for dep_key, dep_val in _iteritems(val):
                self.by_tags[key] += [Dependency(dep_key, dep_val)]

    def __str__(self):
        return 'alternates: ' + str(self.by_tags)

    def populate(self, build_deps=None):
        '''XXX write doc. *build_deps* is a dictionary.'''
        for tag in self.by_tags:
            for dep in self.by_tags[tag]:
                dep.populate(build_deps)

    def prerequisites(self, tags):
        prereqs = []
        for tag in tags:
            deps = self.by_tags.get(tag, [])
            if not deps:
                alias = ALIAS_DISTRIBS.get(tag)
                if alias:
                    deps = self.by_tags.get(alias, [])
            for dep in deps:
                prereqs += dep.prerequisites(tags)
        return prereqs


class Maintainer(object):
    '''Information about the maintainer of a project.'''

    def __init__(self, fullname, email):
        self.fullname = fullname
        self.email = email

    def __str__(self):
        return self.fullname + ' <' + self.email + '>'


class Step(object):
    '''Step in the build DAG.'''

    configure = 1
    install_native = 2
    install_gem = 3
    install_npm = 4
    install_pip = 5
    install = 6
    update = 8
    setup = 9
    make = 10

    def __init__(self, priority, project_name):
        self.project = project_name
        self.prerequisites = []
        self.priority = priority
        self.name = self.__class__.genid(project_name)
        self.updated = False

    def __str__(self):
        return self.name

    def qualified_project_name(self, target_name=None):
        name = self.project
        if target_name:
            name = os.path.join(target_name, self.project)
        return name

    @classmethod
    def genid(cls, project_name, target_name=None):
        name = project_name.replace(os.sep, '_').replace('-', '_')
        if target_name:
            name = target_name + '_' + name
        if issubclass(cls, ConfigureStep):
            name = 'configure_' + name
        elif issubclass(cls, InstallStep):
            name = 'install_' + name
        elif issubclass(cls, UpdateStep):
            name = 'update_' + name
        elif issubclass(cls, SetupStep):
            name = name + 'Setup'
        else:
            name = name
        return name

    @property
    def title(self):
        """
        Returns a title that can later be parsed to report status on building
        the associated project.
        """
        # project is a name (unicode) here.
        return "%s:%s" % (self.project, self.__class__.__name__[:-4].lower())


class TargetStep(Step):

    def __init__(self, prefix, project_name, target=None):
        self.target = target
        super(TargetStep, self).__init__(prefix, project_name)
        self.name = self.__class__.genid(project_name, target)

    @property
    def title(self):
        generic_title = super(TargetStep, self).title
        if self.target:
            return "%s:%s" % (self.target, generic_title)
        return generic_title


class ConfigureStep(TargetStep):
    '''The *configure* step in the development cycle initializes variables
    that drive the make step such as compiler flags, where files are installed,
    etc.'''

    def __init__(self, project_name, envvars, target=None):
        super(ConfigureStep, self).__init__(
            Step.configure, project_name, target)
        self.envvars = envvars

    def associate(self, target):
        return ConfigureStep(self.project, self.envvars, target)

    def run(self, context):
        self.updated = config_var(context, self.envvars)


class SetupStep(TargetStep):
    '''The *setup* step in the development cycle installs third-party
    prerequisites. This steps gathers all the <dep> statements referring
    to a specific prerequisite.'''

    def __init__(self, project_name, files, versions=None, target=None):
        """
        files is a dictionnary.

        We keep a reference to the project because we want to decide
        to add native installer/made package/patch right after run.
        """
        super(SetupStep, self).__init__(Step.setup, project_name, target)
        if not versions:
            versions = {'includes': [], 'excludes': []}
        self.managed = {project_name: {
            'files': files,
            'includes': versions.get('includes', []),
            'excludes': versions.get('excludes', [])}}
        self.updated = False
        self.incompletes = None

    def add_prerequisites(self, setup):
        """
        We only add prerequisites from *dep* which are not already present
        in *self*. This is important because *find_prerequisites* will
        initialize tuples (name_pat, absolute_path).
        """
        for dep_name, dep_items in _iteritems(setup.managed):
            if dep_name in self.managed:
                for dirname in dep_items['files']:
                    if not dirname in self.managed[dep_name]['files']:
                        self.managed[dep_name]['files'].update({
                            dirname: dep_items['files'][dirname]})
                    else:
                        for prereq_1 in dep_items['files'][dirname]:
                            found = False
                            for prereq_2 in \
                                self.managed[dep_name]['files'][dirname]:
                                if prereq_2[0] == prereq_1[0]:
                                    found = True
                                    break
                            if not found:
                                self.managed[dep_name]['files'][dirname] \
                                    += [prereq_1]
                self.managed[dep_name]['excludes'] += dep_items['excludes']
                self.managed[dep_name]['includes'] += dep_items['includes']
            else:
                self.managed.update({dep_name: dep_items})

    def run(self, context):
        self.incompletes = []
        for dep_name, dep_items in _iteritems(self.managed):
            versions = {'includes': dep_items['includes'],
                'excludes': dep_items['excludes']}
            self.managed[dep_name]['files'], complete = find_prerequisites(
                dep_items['files'], versions, self.target)
            if complete:
                self.managed[dep_name]['files'], complete = link_prerequisites(
                    dep_items['files'], versions, self.target)
            else:
                self.incompletes += [dep_name]
        self.updated = True
        return len(self.incompletes) == 0


class InstallStep(SetupStep):
    """
    Base class to install prerequisites through package managers, either
    native (apt-get, dnf) or language specific (pip, gem, nodejs).

    ``InstallStep`` derives from ``SetupStep`` such that we are able
    to check prerequisites and create a list of incomplete packages
    to actually install through the native package manager. (see: ``run``)
    This works in concert with the ``DependencyGenerator.add_install`` method.
    """
    def __init__(self, project_name, alt_names=None,
                 versions=None, target=None):
        super(InstallStep, self).__init__(project_name, {},
            versions=versions, target=target)
        if alt_names:
            self.alt_names = {project_name: alt_names}
        else:
            self.alt_names = {}
        self.priority = Step.install

    def insert(self, install_step):
        self.add_prerequisites(install_step)
        self.alt_names.update(install_step.alt_names)

    def get_installs(self):
        if self.incompletes is not None:
            packages = self.incompletes
        else:
            packages = list(self.managed.keys())
        installs = []
        for install_name in packages:
            installs += self.alt_names.get(install_name, [install_name])
        return installs

    def run(self, context):
        super(InstallStep, self).run(context)
        self.updated = False
        installs = self.get_installs()
        if len(installs) > 0:
            self.install(installs, context)
            self.updated = True

    def install_commands(self, managed, context):
        raise Error("Does not know how to install '%s' on %s for %s"
                    % (managed, context.host(), self.name))

    def install(self, managed, context):
        log_info("(PATH=%s) cwd=%s" % (os.getenv('PATH'), os.getcwd()))
        for cmdline, admin, noexecute in self.install_commands(
                managed, context):
            shell_command(cmdline, admin=admin, noexecute=noexecute)

    def info(self):
        raise Error(
            "Does not know how to search package manager for '%s' on %s for %s"
            % (str(self.managed), CONTEXT.host(), self.name))


class AptInstallStep(InstallStep):
    ''' Install a prerequisite to a project through apt (Debian, Ubuntu).'''

    def __init__(self, project_name, alt_names=None,
                 versions=None, target=None):
        super(AptInstallStep, self).__init__(project_name, alt_names=alt_names,
            versions=versions, target=target)
        self.priority = Step.install_native

    @staticmethod
    def install_commands(managed, context):
        # Add DEBIAN_FRONTEND=noninteractive such that interactive
        # configuration of packages do not pop up in the middle
        # of installation. We are going to update the configuration
        # in /etc afterwards anyway.
        # Emit only one shell command so that we can find out what the script
        # tried to do when we did not get priviledge access.
        admin = True
        return [(['sh', '-c', '"/usr/bin/apt-get update'\
' && DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get -y install %s"'
                       % ' '.join(managed)], admin, context.nonative)]

    def info(self):
        info = []
        unmanaged = []
        try:
            # apt-cache showpkg will return 0 even when the package cannot
            # be found.
            cmdline = ['apt-cache', 'showpkg'] + self.managed
            manager_output = subprocess.check_output(' '.join(cmdline),
                shell=True, stderr=subprocess.STDOUT).decode(DEFAULT_ENCODING)
            found = False
            for line in manager_output.splitlines():
                if re.match('^Package:', line):
                    # Apparently we are not able to get error messages
                    # from stderr here ...
                    found = True
            if not found:
                unmanaged = self.managed
            else:
                info = self.managed
        except subprocess.CalledProcessError:
            unmanaged = self.managed
        return info, unmanaged


class DarwinInstallStep(InstallStep):
    ''' Install a prerequisite to a project through pkg (Darwin, OSX).'''

    def __init__(self, project_name, alt_names=None,
                 versions=None, target=None):
        super(DarwinInstallStep, self).__init__(project_name,
            alt_names=alt_names, versions=versions, target=target)
        self.priority = Step.install

    @staticmethod
    def install_commands(managed, context):
        """
        Mount *image*, a pathnme to a .dmg file and use the Apple installer
        to install the *pkg*, a .pkg package onto the platform through the Apple
        installer.
        """
        admin = False
        if len(managed) > 0:
            target = context.value('darwinTargetVolume')
            if target != 'CurrentUserHomeDirectory':
                message = 'ATTENTION: You need administrator privileges '\
                  + 'on the local machine to execute the following cmmand\n'
                log_info(message, context=context)
                admin = True
        cmds = []
        noexecute = False
        for filename in managed:
            volume = None
            if filename.endswith('.dmg'):
                base, ext = os.path.splitext(filename)
                volume = os.path.join('/Volumes', os.path.basename(base))
                cmdline = ['hdiutil', 'attach', filename]
                cmds += [(cmdline, False, noexecute)]
                shell_command(cmdline)
            pkg = filename
            if not filename.endswith('.pkg'):
                pkgs = find_files(volume, r'\.pkg')
                if len(pkgs) != 1:
                    raise RuntimeError(
                        'ambiguous: not exactly one .pkg to install')
                pkg = pkgs[0]
            cmdline = ['installer', '-pkg', os.path.join(volume, pkg),
                          '-target "' + target + '"']
            cmds += [(cmdline, admin, context.nonative)]
            if filename.endswith('.dmg'):
                cmdline = ['hdiutil', 'detach', volume]
                cmds += [(cmdline, False, noexecute)]
                shell_command(cmdline)
        return cmds


class DpkgInstallStep(InstallStep):
    ''' Install a prerequisite to a project through dpkg (Debian, Ubuntu).'''

    def __init__(self, project_name, alt_names=None,
                 versions=None, target=None):
        filenames = []
        for filename in alt_names:
            if filename.endswith('.deb'):
                filenames += [filename]
        super(DpkgInstallStep, self).__init__(project_name,
            alt_names=filenames, versions=versions, target=target)
        self.priority = Step.install

    @staticmethod
    def install_commands(managed, context):
        if managed:
            admin = True
            noexecute = context.nonative
            return [(['dpkg', '-i', ' '.join(managed)], admin, noexecute)]
        return []


class GemInstallStep(InstallStep):
    """
    Install a prerequisite to a project through gem (Ruby).
    """
    def __init__(self, project_name, alt_names=None,
                 versions=None, target=None):
        super(GemInstallStep, self).__init__(project_name,
            alt_names=alt_names, versions=versions, target=target)
        self.priority = Step.install_gem

    def collect(self, context):
        """Collect prerequisites from Gemfile"""
        sys.stdout.write('''XXX collect from Gemfile NotYetImplemented!\n''')

    def install_commands(self, managed, context):
        packages = []
        for dep_name in managed:
            include_versions = self.managed[dep_name].get('includes', [])
            if include_versions:
                packages += ['%s:%s' % (dep_name, include_versions[0])]
            else:
                packages += [dep_name]
        admin = False
        noexecute = False
        site_packages = os.path.join(context.value('shareDir'), 'gems')
        if (os.path.exists(site_packages) and
            os.stat(site_packages).st_uid != os.getuid()):
            admin = True
            noexecute = context.nonative
        if packages:
            return [([find_gem(context), 'install'] + packages + [
                '--install-dir', site_packages], admin, noexecute)]
        return []

    def info(self):
        info = []
        unmanaged = []
        try:
            # XXX There are no pip info command, search is the closest we get.
            # Pip search might match other packages and thus returns zero
            # inadvertently but it is the closest we get so far.
            shell_command([find_gem(CONTEXT), 'search'] + self.managed)
            info = self.managed
        except Error:
            unmanaged = self.managed
        return info, unmanaged


class MacPortInstallStep(InstallStep):
    ''' Install a prerequisite to a project through Macports.'''

    def __init__(self, project_name, alt_names=None,
                 versions=None, target=None):
        super(MacPortInstallStep, self).__init__(project_name,
            alt_names=alt_names, versions=versions, target=target)
        self.priority = Step.install_native

    @staticmethod
    def install_commands(managed, context):
        if managed:
            admin = True
            noexecute = context.nonative
            return [(['/opt/local/bin/port', 'install'] + managed,
                admin, noexecute)]
        return []

    def info(self):
        info = []
        unmanaged = []
        try:
            shell_command(['port', 'info'] + self.managed)
            info = self.managed
        except Error:
            unmanaged = self.managed
        return info, unmanaged


class NpmInstallStep(InstallStep):
    """
    Install a prerequisite to a project through npm (Node.js manager).
    """
    def __init__(self, project_name, alt_names=None,
                 versions=None, target=None):
        super(NpmInstallStep, self).__init__(project_name,
            alt_names=alt_names, versions=versions, target=target)
        self.priority = Step.install_npm

    @staticmethod
    def _manager(context):
        # nodejs is not available as a package on Fedora 17 or rather,
        # it was until the repo site went down.
        find_npm(context)
        return os.path.join(context.value('buildTop'), 'bin', 'npm')

    def install_commands(self, managed, context):
        packages = []
        for dep_name in managed:
            include_versions = self.managed[dep_name].get('includes', [])
            if include_versions:
                packages += ['%s@%s' % (dep_name, include_versions[0])]
            else:
                packages += [dep_name]
        if packages:
            admin = False
            noexecute = False
            return [([self._manager(context), 'install', '-g',
                '--scripts-prepend-node-path', 'true',
                '--cache', os.path.join(context.value('buildTop'), '.npm'),
                '--tmp', os.path.join(context.value('buildTop'), 'tmp'),
                '--prefix', context.value('installTop')] + packages,
                admin, noexecute)]
        return []

    def info(self):
        info = []
        unmanaged = []
        try:
            shell_command([self._manager(CONTEXT), 'search'] + self.managed)
            info = self.managed
        except Error:
            unmanaged = self.managed
        return info, unmanaged


class PipInstallStep(InstallStep):
    """
    Install a prerequisite to a project through pip.
    """
    def __init__(self, project_name, alt_names=None,
                 versions=None, target=None):
        super(PipInstallStep, self).__init__(project_name,
            alt_names=alt_names, versions=versions, target=target)
        self.priority = Step.install_pip

    def collect(self, context):
        """Collect prerequisites from requirements.txt"""
        filepath = context.src_dir(
            os.path.join(self.project, 'requirements.txt'))
        with open(filepath) as file_obj:
            for line in file_obj.readlines():
                look = re.match(r'([\w\-_]+)((>=|==)(\S+))?', line)
                if look:
                    prerequisite = look.group(1)
                    sys.stdout.write('''<dep name="%s">
    <lib>.*/(%s)/__init__.py</lib>
</dep>
''' % (prerequisite, prerequisite))

    def install_commands(self, managed, context):
        packages = []
        for dep_name in managed:
            include_versions = self.managed[dep_name].get('includes', [])
            if include_versions:
                packages += ['%s==%s' % (dep_name, include_versions[0])]
            else:
                packages += [dep_name]
        # In most cases, when installing through pip, we should be running
        # under virtualenv.
        pip = find_pip(context)
        version = None
        site_packages = None
        pip_version = subprocess.check_output(
            [pip, '-V']).decode(DEFAULT_ENCODING)
        look = re.match(r'pip ([0-9\.b]+) from (\S+)', pip_version)
        if look:
            version = [int(val) for val in look.group(1).split('.')]
            site_packages = look.group(2)
        else:
            raise Error("cannot extract site-packages from '%s'" % pip_version)
        admin = False
        noexecute = False
        if os.stat(site_packages).st_uid != os.getuid():
            admin = True
            noexecute = context.nonative
        commands = []
        if version and version[0] < 20:
            commands += [([pip, 'install', '--upgrade', 'pip'],
                admin, noexecute)]
        if packages:
            commands += [([pip, '--log-file', os.path.join(
                context.value('buildTop'), 'pip.log'),
                '--cache-dir', context.obj_dir('.cache/pip'),
                'install'] + packages, admin, noexecute)]
        return commands

    def info(self):
        info = []
        unmanaged = []
        try:
            # XXX There are no pip info command, search is the closest we get.
            # Pip search might match other packages and thus returns zero
            # inadvertently but it is the closest we get so far.
            shell_command([find_pip(CONTEXT), 'search'] + self.managed)
            info = self.managed
        except Error:
            unmanaged = self.managed
        return info, unmanaged


class RpmInstallStep(InstallStep):
    """
    Install a prerequisite to a project through rpm (Redhat-based).
    """
    def __init__(self, project_name, alt_names=None,
                 versions=None, target=None):
        filenames = []
        for filename in alt_names:
            if filename.endswith('.rpm'):
                filenames += [filename]
        super(RpmInstallStep, self).__init__(project_name,
            alt_names=filenames, versions=versions, target=target)
        self.priority = Step.install

    @staticmethod
    def install_commands(managed, context):
        if managed:
            admin = True
            noexecute = context.nonative
            # --nodeps because rpm looks stupid and can't figure out that
            # the vcd package provides the libvcd.so required by the executable.
            return [(['rpm', '-i', '--force'] + managed + ['--nodeps'],
                admin, noexecute)]
            # XXX `yum localinstall` will also install native dependencies,
            # necessary for google-chrome-stable.
            # return [(['yum', 'localinstall'] + managed, admin, noexecute)]
        return []


class DnfInstallStep(InstallStep):
    ''' Install a prerequisite to a project through dnf (Redhat-based).'''

    def __init__(self, project_name, alt_names=None,
                 versions=None, target=None):
        super(DnfInstallStep, self).__init__(project_name, alt_names=alt_names,
            versions=versions, target=target)
        self.priority = Step.install_native

    @staticmethod
    def install_commands(managed, context):
        if managed:
            admin = True
            noexecute = context.nonative
            return [
                (['dnf', '-y', 'update'], admin, noexecute),
                (['dnf', '-y', 'install'] + managed, admin, noexecute)]
        return []

    def install(self, managed, context):
        if managed:
            update_cmd, install_cmd = self.install_commands(managed, context)
            log_info("update, then run: %s" % ' '.join(install_cmd[0]),
                context=context)
            shell_command(update_cmd[0],
                admin=update_cmd[1], noexecute=update_cmd[2])
            filtered = shell_command(install_cmd[0],
                admin=install_cmd[1], noexecute=install_cmd[2],
                pat='No package (.*) available')
            if filtered:
                look = re.match('No package (.*) available', filtered[0])
                if look:
                    unmanaged = look.group(1).split(' ')
                    if unmanaged:
                        raise Error("dnf cannot install " + ' '.join(unmanaged))

    def info(self):
        info = []
        unmanaged = []
        try:
            filtered = shell_command(['dnf', 'info'] + self.managed,
                pat=r'Name\s*:\s*(\S+)')
            if filtered:
                info = self.managed
            else:
                unmanaged = self.managed
        except Error:
            unmanaged = self.managed
        return info, unmanaged


class YumInstallStep(InstallStep):
    ''' Install a prerequisite to a project through yum (Redhat-based).'''

    def __init__(self, project_name, alt_names=None,
                 versions=None, target=None):
        super(YumInstallStep, self).__init__(project_name, alt_names=alt_names,
            versions=versions, target=target)
        self.priority = Step.install_native

    @staticmethod
    def install_commands(managed, context):
        if managed:
            admin = True
            noexecute = context.nonative
            return [
                (['yum', '-y', 'update'], admin, noexecute),
                (['yum', '-y', 'install'] + managed, admin, noexecute)]
        return []

    def install(self, managed, context):
        if managed:
            # XXX Might not be the best place to do this,
            # yet CentOS does not include basic tools such as fail2ban.
            if context.host() == 'CentOS' and not os.path.exists(
                '/etc/yum.repos.d/epel.repo'):
                shell_command(['rpm', '-Uvh',
'https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm'],
                admin=True, noexecute=context.nonative)
            update_cmd, install_cmd = self.install_commands(managed, context)
            log_info("update, then run: %s" % ' '.join(install_cmd[0]),
                context=context)
            shell_command(update_cmd[0],
                admin=update_cmd[1], noexecute=update_cmd[2])
            filtered = shell_command(install_cmd[0],
                admin=install_cmd[1], noexecute=install_cmd[2],
                pat='No package (.*) available')
            if filtered:
                look = re.match('No package (.*) available', filtered[0])
                if look:
                    unmanaged = look.group(1).split(' ')
                    if unmanaged:
                        raise Error("yum cannot install " + ' '.join(unmanaged))

    def info(self):
        info = []
        unmanaged = []
        try:
            filtered = shell_command(['yum', 'info'] + self.managed,
                pat=r'Name\s*:\s*(\S+)')
            if filtered:
                info = self.managed
            else:
                unmanaged = self.managed
        except Error:
            unmanaged = self.managed
        return info, unmanaged


class BuildStep(TargetStep):
    '''Build a project running make, executing a script, etc.'''

    def __init__(self, project_name, target=None, force_update=True):
        TargetStep.__init__(self, Step.make, project_name, target)
        self.force_update = force_update

    def _should_run(self):
        updated_prerequisites = False
        for prereq in self.prerequisites:
            updated_prerequisites |= prereq.updated
        return self.force_update or updated_prerequisites


class MakeStep(BuildStep):
    '''The *make* step in the development cycle builds executable binaries,
    libraries and other files necessary to install the project.'''

    def associate(self, target):
        return MakeStep(self.project, target)

    def run(self, context):
        if self._should_run():
            # We include the configfile (i.e. variable=value) before
            # the project Makefile for convenience. Adding a statement
            # include $(shell dws context) at the top of the Makefile
            # is still a good idea to permit "make" from the command line.
            # Otherwise it just duplicates setting some variables.
            context = localize_context(context, self.project, self.target)
            makefile = context.src_dir(os.path.join(self.project, 'Makefile'))
            if os.path.isfile(makefile):
                cmdline = ['make',
                           '-f', context.config_filename,
                           '-f', makefile]
                # If we do not set PATH to *bin_build_dir*:*binDir*:${PATH}
                # and the install directory is not in PATH, then we cannot
                # build a package for drop because 'make dist' depends
                # on executables installed in *binDir* (dws, dbldpkg, ...)
                # that are not linked into *binBuildDir* at the time
                # 'cd drop ; make dist' is run. Note that it is not an issue
                # for other projects since those can be explicitely depending
                # on drop as a prerequisite.
                # XXX We should only have to include binBuildDir is PATH
                # but that fails because of "/usr/bin/env python" statements
                # and other little tools like hostname, date, etc.
                shell_command(cmdline + context.targets + context.overrides,
                    search_path=[context.bin_build_dir()]
                              + context.search_path('bin'),
                    node_path=["%s/node_modules"  % context.value('libDir')]
                              + os.getenv('NODE_PATH', "").split(':'))
            self.updated = True


class ShellStep(BuildStep):
    '''Run a shell script to *make* a step in the development cycle.'''

    def __init__(self, project_name, script, target=None):
        BuildStep.__init__(self, project_name, target)
        self.script = script

    def associate(self, target):
        return ShellStep(self.project, self.script, target)

    def run(self, context):
        if self._should_run() and self.script:
            context = localize_context(context, self.project, self.target)
            script = tempfile.NamedTemporaryFile(mode='w+t', delete=False)
            script.write('#!/bin/sh\n\n')
            script.write('. ' + context.config_filename + '\n\n')
            script.write(self.script)
            script.close()
            shell_command(['sh', '-x', '-e', script.name],
                search_path=[context.bin_build_dir()]
                          + context.search_path('bin'),
                node_path=["%s/node_modules"  % context.value('libDir')]
                          + os.getenv('NODE_PATH', "").split(':'))
            os.remove(script.name)
            self.updated = True


class UpdateStep(Step):
    '''The *update* step in the development cycle fetches files and source
    repositories from remote server onto the local system.'''

    updated_sources = {}

    def __init__(self, project_name, rep, fetches):
        Step.__init__(self, Step.update, project_name)
        self.rep = rep
        self.fetches = fetches
        self.updated = False

    def run(self, context):
        if self.rep:
#            try:
            self.updated = self.rep.update(self.project, context)
            if self.updated:
                UpdateStep.updated_sources[self.project] = self.rep.rev
#            except:
#                raise Error('cannot update repository or apply patch for %s\n'
#                            % str(self.project))
        try:
            # We cannot fetch resources before a clone of the repo otherwise
            # git will complain. We though have to fetch resources before
            # we try to apply any patches as those might be resources.
            fetch(context, self.fetches)
        except IOError:
            raise Error("unable to fetch " + str(self.fetches))
        if self.rep:
            self.rep.apply_patches(self.project, context)


class Repository(object):
    '''All prerequisites information to install a project
    from a source control system.'''

    dirPats = r'(\.git|\.svn|CVS)'

    def __init__(self, sync, rev):
        self.type = None
        self.url = sync
        self.rev = rev

    def __str__(self):
        result = '\t\tsync repository from ' + self.url + '\n'
        if self.rev:
            result = result + '\t\t\tat revision' + str(self.rev) + '\n'
        else:
            result = result + '\t\t\tat head\n'
        return result

    @staticmethod
    def apply_patches(name, context):
        if os.path.isdir(context.patch_dir(name)):
            patches = []
            for pathname in os.listdir(context.patch_dir(name)):
                if pathname.endswith('.patch'):
                    patches += [pathname]
            if patches:
                log_info("######## patching %s..." % name, context=context)
                prev = os.getcwd()
                os.chdir(context.src_dir(name))
                shell_command(
                    ['patch', '< ' + os.path.join(context.patch_dir(name),
                                                  '*.patch')])
                os.chdir(prev)

    @staticmethod
    def associate(pathname):
        '''This methods returns a boiler plate *Repository* that does
        nothing in case an empty sync url is specified. This is different
        from an absent sync field which would use rsync as a "Repository".
        '''
        rev = None
        if pathname:
            repos = {'.git': GitRepository,
                     '.svn': SvnRepository}
            sync = pathname
            look = search_repo_pat(pathname)
            if look:
                sync = look.group(1)
                rev = look.group(4)
            path_list = sync.split(os.sep)
            for i in range(0, len(path_list)):
                for ext, repo_class in _iteritems(repos):
                    if path_list[i].endswith(ext):
                        if path_list[i] == ext:
                            i = i - 1
                        return repo_class(os.sep.join(path_list[:i + 1]), rev)
            # We will guess, assuming the repository is on the local system
            for ext, repo_class in _iteritems(repos):
                if os.path.isdir(os.path.join(pathname, ext)):
                    return repo_class(pathname, rev)
            return RsyncRepository(pathname, rev)
        return Repository("", rev)

    def update(self, name, context, force=False):
        return False


class GitRepository(Repository):
    '''All prerequisites information to install a project
    from a git source control repository.'''

    def apply_patches(self, name, context):
        '''Apply patches that can be found in the *obj_dir* for the project.'''
        prev = os.getcwd()
        if os.path.isdir(context.patch_dir(name)):
            patches = []
            for pathname in os.listdir(context.patch_dir(name)):
                if pathname.endswith('.patch'):
                    patches += [pathname]
            if patches:
                log_info("######## patching %s..." % name, context=context)
                os.chdir(context.src_dir(name))
                shell_command([find_git(context), 'am', '-3', '-k',
                    os.path.join(context.patch_dir(name), '*.patch')])
        os.chdir(prev)

    @staticmethod
    def push(pathname):
        prev = os.getcwd()
        os.chdir(pathname)
        shell_command([find_git(CONTEXT), 'push'])
        os.chdir(prev)

    @staticmethod
    def tarball(name, version='HEAD'):
        local = CONTEXT.src_dir(name)
        gitexe = find_git(CONTEXT)
        cwd = os.getcwd()
        os.chdir(local)
        if version == 'HEAD':
            shell_command([gitexe, 'rev-parse', version])
        prefix = name + '-' + version
        output_name = os.path.join(cwd, prefix + '.tar.bz2')
        shell_command([gitexe, 'archive', '--prefix', prefix + os.sep,
              '-o', output_name, 'HEAD'])
        os.chdir(cwd)

    def update(self, name, context, force=False):
        # If the path to the remote repository is not absolute,
        # derive it from *remoteTop*. Binding any sooner will
        # trigger a potentially unnecessary prompt for remote_cache_path.
        if not ':' in self.url and context:
            self.url = context.remote_src_path(self.url)
        if not name:
            url_parts = _urlparse(self.url)
            normalized_url = _urlunparse((url_parts.scheme, url_parts.netloc,
                os.path.normpath(url_parts.path), url_parts.params,
                url_parts.query, url_parts.fragment))
            prefix = context.value('remoteSrcTop')
            if not prefix.endswith(':') and not prefix.endswith(os.sep):
                prefix = prefix + os.sep
            if not normalized_url.startswith(prefix):
                # The url is not inside `remoteSrcTop`,
                # let's try `remoteSiteTop`.
                log_info("warning: '%s' outside remoteSrcTop '%s'" % (
                    normalized_url, prefix))
                prefix = context.value('remoteSiteTop')
                if not prefix.endswith(':') and not prefix.endswith(os.sep):
                    prefix = prefix + os.sep
            name = normalized_url.replace(prefix, '')
        if name.endswith('.git'):
            name = name[:-4]
        local = context.src_dir(name)
        updated = False
        cwd = os.getcwd()
        git_executable = find_git(context)
        if not os.path.exists(os.path.join(local, '.git')):
            try:
                shell_command([git_executable, 'clone', self.url, local])
            except Error:
                # This might be a repo outside the remoteSrcTop. We thus
                # try remoteSiteTop.
                self.url = os.path.join(
                    context.value('remoteSiteTop'), name + '.git')
                shell_command([git_executable, 'clone', self.url, local])
            updated = True
        else:
            os.chdir(local)
            # Make sure we are not on a detached HEAD.
            shell_command([git_executable, 'checkout', 'master'])
            # 'pull' does fetch and rebase all in one.
            cmdline = ' '.join([git_executable, 'pull'])
            log_info(cmdline, context=context)
            cmd = subprocess.Popen(cmdline,
                                   shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
            line = cmd.stdout.readline().decode(DEFAULT_ENCODING)
            while line:
                log_info(line.strip(), context=context)
                look = re.match(r'^[Uu]pdating', line)
                if look:
                    updated = True
                line = cmd.stdout.readline().decode(DEFAULT_ENCODING)
            cmd.wait()
            if cmd.returncode != 0:
                # It is ok to get an error in case we are running
                # this on the server machine.
                pass
        if self.rev:
            cof = '-m'
            if force:
                cof = '-f'
            cmd = [git_executable, 'checkout', cof]
            cmd += [self.rev]
            os.chdir(local)
            shell_command(cmd)
        # Print HEAD
        if updated:
            # Just the commit: cmd = [git_executable, 'rev-parse', 'HEAD']
            cmd = [git_executable, 'log', '-1', '--pretty=oneline']
            os.chdir(local)
            logline = subprocess.check_output(cmd).decode(DEFAULT_ENCODING)
            log_info(logline, context=context)
            self.rev = logline.split(' ')[0]
        os.chdir(cwd)
        return updated


class SvnRepository(Repository):
    '''All prerequisites information to install a project
    from a svn source control repository.'''

    def __init__(self, sync, rev):
        Repository.__init__(self, sync, rev)

    def update(self, name, context, force=False):
        # If the path to the remote repository is not absolute,
        # derive it from *remoteTop*. Binding any sooner will
        # trigger a potentially unnecessary prompt for remote_cache_path.
        if not ':' in self.url and context:
            self.url = context.remote_src_path(self.url)
        local = context.src_dir(name)
        if not os.path.exists(os.path.join(local, '.svn')):
            shell_command(['svn', 'co', self.url, local])
        else:
            cwd = os.getcwd()
            os.chdir(local)
            shell_command(['svn', 'update'])
            os.chdir(cwd)
        # \todo figure out how any updates is signaled by svn.
        return True


class RsyncRepository(Repository):
    '''All prerequisites information to install a project
    from a remote directory.'''

    def __init__(self, sync, rev):
        Repository.__init__(self, sync, rev)

    def update(self, name, context, force=False):
        # If the path to the remote repository is not absolute,
        # derive it from *remoteTop*. Binding any sooner will
        # trigger a potentially unnecessary prompt for remote_cache_path.
        if not ':' in self.url and not self.url.startswith(os.sep) and context:
            self.url = context.remote_src_path(self.url)
        fetch(context, {self.url: ''}, force=True)
        return True

class InstallFlavor(object):
    '''All information necessary to install a project on the local system.'''

    def __init__(self, name, pairs):
        rep = None
        fetches = {}
        variables = {}
        self.deps = {}
        self.make = None
        for key, val in _iteritems(pairs):
            if isinstance(val, Variable):
                variables[key] = val
                # XXX Hack? We add the variable in the context here
                # because it might be needed by the setup step even though
                # no configure step has run.
                if CONTEXT and not key in CONTEXT.environ:
                    CONTEXT.environ[key] = val
            elif key == 'sync':
                rep = Repository.associate(val)
            elif key == 'shell':
                self.make = ShellStep(name, val)
            elif key == 'fetch':
                if isinstance(val, list):
                    blocks = val
                else:
                    blocks = [val]
                for blk in blocks:
                    file_url = blk['url']
                    blk.pop('url')
                    fetches[file_url] = blk
            elif key == 'alternates':
                self.deps[key] = Alternates(key, val)
            else:
                self.deps[key] = Dependency(key, val)
        self.update = UpdateStep(name, rep, fetches)
        self.configure = ConfigureStep(name, variables, None)
        if not self.make:
            self.make = MakeStep(name)

    def __str__(self):
        result = ''
        if self.update.fetches:
            result = result + '\t\tfetch archives\n'
            for archive in self.update.fetches:
                result = result + '\t\t\t' + archive + '\n'
        if self.deps:
            result = result + '\t\tdependencies from local system\n'
            for dep in self.deps:
                result = result + '\t\t\t' + str(dep) + '\n'
        if self.configure.envvars:
            result = result + '\t\tenvironment variables\n'
            for var in self.configure.envvars:
                result = result + '\t\t\t' + str(var) + '\n'
        return result

    def fetches(self):
        return self.update.fetches

    def prerequisites(self, tags):
        prereqs = []
        for _, dep in _iteritems(self.deps):
            prereqs += dep.prerequisites(tags)
        return prereqs

    def prerequisite_names(self, tags):
        '''same as *prerequisites* except only returns the names
        of the prerequisite projects.'''
        names = []
        for _, dep in _iteritems(self.deps):
            names += [prereq.name for prereq in dep.prerequisites(tags)]
        return names

    def vars(self):
        return self.configure.envvars


class Project(object):
    '''Definition of a project with its prerequisites.'''

    def __init__(self, name, pairs):
        self.name = name
        self.title = None
        self.descr = None
        # *packages* maps a set of tags to *Package* instances. A *Package*
        # contains dependencies to install a project from a binary distribution.
        # Default update.rep is relative to *remoteSrcTop*. We initialize
        # to a relative path instead of an absolute path here such that it
        # does not trigger a prompt for *remoteSrcTop* until we actually
        # do the repository pull.
        self.packages = {}
        self.patch = None
        self.repository = None
        self.installed_version = None
        for key, val in _iteritems(pairs):
            if key == 'title':
                self.title = val
            elif key == 'version':
                self.version = val
            elif key == 'description':
                self.descr = val
            elif key == 'maintainer':
                self.maintainer = Maintainer(val['personname'], val['email'])
            elif key == 'patch':
                self.patch = InstallFlavor(name, val)
                if not self.patch.update.rep:
                    self.patch.update.rep = Repository.associate(name+'.git')
            elif key == 'repository':
                self.repository = InstallFlavor(name, val)
                if not self.repository.update.rep:
                    self.repository.update.rep = Repository.associate(
                        name + '.git')
            else:
                self.packages[key] = InstallFlavor(name, val)

    def __str__(self):
        result = 'project ' + self.name + '\n' \
            + '\t' + str(self.title) + '\n' \
            + '\tfound version ' + str(self.installed_version) \
            + ' installed locally\n'
        if self.packages:
            result = result + '\tpackages\n'
            for package_name in self.packages:
                result = result + '\t[' + package_name + ']\n'
                result = result + str(self.packages[package_name]) + '\n'
        if self.patch:
            result = result + '\tpatch\n' + str(self.patch) + '\n'
        if self.repository:
            result = result + '\trepository\n' + str(self.repository) + '\n'
        return result

    def prerequisites(self, tags):
        '''returns a set of *Dependency* instances for the project based
        on the provided tags. It enables choosing between alternate
        prerequisites set based on the local machine operating system, etc.'''
        prereqs = []
        if self.repository:
            prereqs += self.repository.prerequisites(tags)
        if self.patch:
            prereqs += self.patch.prerequisites(tags)
        for tag in self.packages:
            if tag in tags:
                prereqs += self.packages[tag].prerequisites(tags)
        return prereqs

    def prerequisite_names(self, tags):
        '''same as *prerequisites* except only returns the names
        of the prerequisite projects.'''
        names = []
        for prereq in self.prerequisites(tags):
            names += [prereq.name]
        return names


class YAMLikeParser(object):
    """
    Parser for YAML-like files used by the ``dws`` script. Bare minimum
    support for a subset of YAML. Nothing fancy.
    """
    def __init__(self, context):
        self.context = context
        self.handler = None
        # stack used to reconstruct the tree.
        self.nodes = []
        self.text = ""

    def parse(self, source, handler):
        """
        This is the public interface for one pass through the database
        that generates callbacks on the handler interface.
        """
        self.handler = handler
        if source.strip().find('\n') >= 0:
            input_file = StringIO(source)
        else:
            input_file = open(source)
        for line in input_file.readlines():
            look = re.match(
        r'(?P<indent>\s*)(?P<bullet>-\s*)?(?P<key>\S+)\s*:\s*(?P<value>\S.*)?',
                line)
            if look:
                key = look.group('key')
                value = look.group('value')
                indent_length = len(look.group('indent'))
                if (self.nodes and
                    indent_length < self.nodes[len(self.nodes)-1]['indent']):
                    while (self.nodes and
                      indent_length < self.nodes[len(self.nodes)-1]['indent']):
                        child = self.nodes.pop()
                        parent = self.nodes[len(self.nodes)-1]['container']
                        if isinstance(parent, dict):
                            parent.update(child)
                        elif isinstance(parent, list):
                            parent += [child]
                        else:
                            raise ValueError()
                if (not self.nodes or
                    indent_length > self.nodes[len(self.nodes)-1]['indent']):
                    if look.group('bullet'):
                        self.nodes += [{
                            'indent': indent_length, 'container': []}]
                    if key and value:
                        self.nodes += [{
                            'indent': indent_length, 'container': {key: value}}]
                else:
                    assert (indent_length
                        == self.nodes[len(self.nodes)-1]['indent'])
                    parent = self.nodes[len(self.nodes)-1]['container']
                    if isinstance(parent, dict):
                        parent.update({key: value})
                    elif isinstance(parent, list):
                        assert look.group('bullet')
                        parent += [{key: value}]
                    else:
                        raise ValueError()
        input_file.close()


class XMLDbParser(xml.sax.ContentHandler):
    '''Parse a project index database stored as an XML file on disc
    and generate callbacks on a PdbHandler. The handler will update
    its state based on the callback sequence.'''

    # Global Constants for the database parser
    tagDb = 'projects'
    tagProject = 'project'
    tagPattern = '.*<' + tagProject + r'\s+name="(.*)"'
    trailerTxt = '</' + tagDb + '>'
    # For dbldpkg
    tagPackage = 'package'
    tagTag = 'tag'
    tagFetch = 'fetch'
    tagHash = 'sha1'

    def __init__(self, context):
        xml.sax.ContentHandler.__init__(self)
        self.context = context
        self.handler = None
        # stack used to reconstruct the tree.
        self.nodes = []
        self.text = ""

    def startElement(self, name, attrs):
        '''Start populating an element.'''
        self.text = ""
        key = name
        elems = {}
        for attr in attrs.keys(): # attrs is a instance of AttributesImpl
            if attr == 'name':
                # \todo have to conserve name if just for fetches.
                # key = Step.genid(Step, attrs['name'], target)
                if 'target' in attrs:
                    target = attrs['target']
                    key = os.path.join(target, attrs['name'])
                else:
                    key = attrs['name']
            else:
                elems[attr] = attrs[attr]
        self.nodes += [(name, {key:elems})]

    def characters(self, characters):
        self.text += characters

    def endElement(self, name):
        '''Once the element is fully populated, call back the simplified
           interface on the handler.'''
        node_name, pairs = self.nodes.pop()
        self.text = self.text.strip()
        if self.text:
            aggregate = self.text
            self.text = ""
        else:
            aggregate = {}
        while node_name != name:
            # We are keeping the structure as simple as possible,
            # only introducing lists when there are more than one element.
            for key, _ in _iteritems(pairs):
                if not key in aggregate:
                    aggregate[key] = pairs[key]
                elif isinstance(aggregate[key], list):
                    if isinstance(pairs[key], list):
                        aggregate[key] += pairs[key]
                    else:
                        aggregate[key] += [pairs[key]]
                else:
                    if isinstance(pairs[key], list):
                        aggregate[key] = [aggregate[key]] + pairs[key]
                    else:
                        aggregate[key] = [aggregate[key], pairs[key]]
            node_name, pairs = self.nodes.pop()
        key = list(pairs.keys())[0]
        cap = name.capitalize()
        if cap in ['Metainfo', 'Multiple', 'Pathname', 'Single', 'Variable']:
            aggregate = getattr(sys.modules[__name__], cap)(key, aggregate)
        if isinstance(aggregate, dict):
            pairs[key].update(aggregate)
        else:
            pairs[key] = aggregate
        if name == 'project':
            self.handler.project(Project(key, pairs[key]))
        elif name == 'projects':
            self.handler.end_parse()
        self.nodes += [(name, pairs)]


    def parse(self, source, handler):
        '''This is the public interface for one pass through the database
           that generates callbacks on the handler interface.'''
        self.handler = handler
        parser = xml.sax.make_parser()
        parser.setFeature(xml.sax.handler.feature_namespaces, 0)
        parser.setContentHandler(self)
        if source.startswith('<?xml'):
            parser.parse(StringIO(source))
        else:
            parser.parse(source)

    # The following methods are used to merge multiple databases together.

    def copy(self, db_next, db_prev, remove_project_end_tag=False):
        '''Copy lines in the db_prev file until hitting the definition
        of a package and return the name of the package.'''
        name = None
        line = db_prev.readline()
        while line:
            look = re.match(self.tagPattern, line)
            if look != None:
                name = look.group(1)
                break
            write_line = True
            look = re.match('.*' + self.trailerTxt, line)
            if look:
                write_line = False
            if remove_project_end_tag:
                look = re.match('.*</' + self.tagProject + '>', line)
                if look:
                    write_line = False
            if write_line:
                db_next.write(line)
            line = db_prev.readline()
        return name


    def next(self, db_prev):
        '''Skip lines in the db_prev file until hitting the definition
        of a package and return the name of the package.'''
        name = None
        line = db_prev.readline()
        while line:
            look = re.match(self.tagPattern, line)
            if look != None:
                name = look.group(1)
                break
            line = db_prev.readline()
        return name

    def start_project(self, db_next, name):
        db_next.write('  <' + self.tagProject + ' name="' + name + '">\n')

    def trailer(self, db_next):
        '''XML files need a finish tag. We make sure to remove it while
           processing Upd and Prev then add it back before closing
           the final file.'''
        db_next.write(self.trailerTxt)


def basenames(pathnames):
    '''return the basename of all pathnames in a list.'''
    bases = []
    for pathname in pathnames:
        bases += [os.path.basename(pathname)]
    return bases

def search_repo_pat(sync_path):
    '''returns a RegexMatch if *sync_path* refers to a repository url/path.'''
    return re.search(r'(\S*%s)(@(\S+))?$' % Repository.dirPats, sync_path)

def filter_rep_ext(name):
    '''Filters the repository type indication from a pathname.'''
    localname = name
    remote_path_list = name.split(os.sep)
    for i in range(len(remote_path_list) - 1, -1, -1):
        look = search_repo_pat(remote_path_list[i])
        if look:
            _, rep_ext = os.path.splitext(look.group(1))
            if remote_path_list[i] == rep_ext:
                localname = os.sep.join(remote_path_list[:i] + \
                                        remote_path_list[i+1:])
            else:
                localname = os.sep.join(remote_path_list[:i] + \
                    [remote_path_list[i][:-len(rep_ext)]] + \
                    remote_path_list[i+1:])
            break
    return localname

def mark(filename, suffix):
    base, ext = os.path.splitext(filename)
    return base + '-' + suffix + ext


def stamp(date=datetime.datetime.now()):
    return str(date.year) \
            + ('_%02d' % (date.month)) \
            + ('_%02d' % (date.day)) \
            + ('-%02d' % (date.hour))


def stampfile(filename):
    global CONTEXT
    if not CONTEXT:
        # This code here is very special. dstamp.py relies on some dws
        # functions all of them do not rely on a context except
        # this special case here.
        CONTEXT = Context()
        CONTEXT.locate()
    if 'buildstamp' not in CONTEXT.environ:
        CONTEXT.environ['buildstamp'] = stamp(datetime.datetime.now())
        CONTEXT.save()
    return mark(os.path.basename(filename), CONTEXT.value('buildstamp'))


def config_var(context, variables):
    '''Look up the workspace configuration file the workspace make fragment
    for definition of variables *variables*, instances of classes derived from
    Variable (ex. Pathname, Single).
    If those do not exist, prompt the user for input.'''
    found = False
    for key, val in _iteritems(variables):
        # apply constrains where necessary
        val.constrain(context.environ)
        if not key in context.environ:
            # If we do not add variable to the context, they won't
            # be saved in the workspace make fragment
            context.environ[key] = val
            found |= val.configure(context)
    if found:
        context.save()
    return found


def create_index_pathname(db_index_pathname, db_pathnames):
    '''create a global dependency database (i.e. project index file) out of
    a set local dependency index files.'''
    parser = XMLDbParser(CONTEXT)
    dirname = os.path.dirname(db_index_pathname)
    if not os.path.isdir(dirname):
        os.makedirs(dirname)
    db_next = sort_build_conf_list(db_pathnames, parser)
    db_index = open(db_index_pathname, 'wb')
    db_next.seek(0)
    shutil.copyfileobj(db_next, db_index)
    db_next.close()
    db_index.close()


def found_bin_suffix(candidate, variant=None):
    if candidate is None:
        return 'no'
    numbers = bin_version_candidates(candidate, variant=variant)
    if numbers:
        return str(numbers[0])
    return 'yes'


def cwd_projects(reps, recurse=False):
    '''returns a list of projects based on the current directory
    and/or a list passed as argument.'''
    if len(reps) == 0:
        # We try to derive project names from the current directory whever
        # it is a subdirectory of buildTop or srcTop.
        cwd = os.path.realpath(os.getcwd())
        build_top = os.path.realpath(CONTEXT.value('buildTop'))
        src_top = os.path.realpath(CONTEXT.value('srcTop'))
        project_name = None
        src_dir = src_top
        src_prefix = os.path.commonprefix([cwd, src_top])
        build_prefix = os.path.commonprefix([cwd, build_top])
        if src_prefix == src_top:
            src_dir = cwd
            project_name = src_dir[len(src_top) + 1:]
        elif build_prefix == build_top:
            src_dir = cwd.replace(build_top, src_top)
            project_name = src_dir[len(src_top) + 1:]
        if project_name:
            reps = [project_name]
        else:
            for repdir in find_files(src_dir, Repository.dirPats):
                reps += [os.path.dirname(
                        repdir.replace(src_top + os.sep, ''))]
    if recurse:
        raise NotImplementedError()
    return reps


def find_bin(names, search_path, build_top, versions=None, variant=None):
    '''Search for a list of binaries that can be executed from $PATH.

       *names* is a list of (pattern,absolute_path) pairs where the absolutePat
       can be None and in which case pattern will be used to search
       for an executable. *versions['excludes']* is a list of versions
       that are concidered false positive and need to be excluded, usually
       as a result of incompatibilities.

       This function returns a list of populated (pattern,absolute_path)
       and a version number. The version number is retrieved
       through a command line flag. --version and -V are tried out.

       This function differs from findInclude() and find_lib() in its
       search algorithm. find_bin() strictly behave like $PATH and
       always returns the FIRST executable reachable from $PATH regardless
       of version number, unless the version is excluded, in which case
       the result is the same as if the executable hadn't been found.

       Implementation Note:

       *names* and *excludes* are two lists instead of a dictionary
       indexed by executale name for two reasons:
       1. Most times find_bin() is called with *names* of executables
       from the same project. It is cumbersome to specify exclusion
       per executable instead of per-project.
       2. The prototype of find_bin() needs to match the ones of
       findInclude() and find_lib().

       Implementation Note: Since the boostrap relies on finding rsync,
       it is possible we invoke this function with log == None hence
       the tests for it.
    '''
    version = None
    if versions and 'excludes' in versions:
        excludes = versions['excludes']
    else:
        excludes = []
    results = []
    droots = search_path
    complete = True
    for name_pat, absolute_path in names:
        if absolute_path is not None and os.path.exists(absolute_path):
            # absolute paths only occur when the search has already been
            # executed and completed successfuly.
            results.append((name_pat, absolute_path))
            continue
        link_name, suffix = link_build_name(name_pat, 'bin', variant)
        linked_path = os.path.realpath(link_name)
        if variant:
            log_interactive("%s/" % variant)
        log_interactive("%s... " % name_pat)
        candidate = None
        if (os.path.islink(link_name) and
            os.path.exists(linked_path)):
            # If we already have a symbolic link that points to a valid
            # file in the binBuildDir, we will assume it is the one to use
            # in order to cut off re-computing things that hardly change.
            candidate = linked_path
            results.append((name_pat, candidate))
            log_info(found_bin_suffix(candidate, variant=variant))
            continue
        if name_pat.endswith('.app'):
            binpath = os.path.join('/Applications', name_pat)
            if os.path.isdir(binpath):
                candidate = binpath
                log_info("yes")
        else:
            for path in droots:
                for binname in find_first_files(path, name_pat):
                    binpath = os.path.join(path, binname)
                    if (os.path.isfile(binpath)
                        and os.access(binpath, os.X_OK)):
                        # We found an executable with the appropriate name,
                        # let's find out if we can retrieve a version number.
                        numbers = bin_version_candidates(binpath, variant)
                        # At this point *numbers* contains a list that can
                        # interpreted as versions. Hopefully, there is only
                        # one candidate.
                        if len(numbers) == 1:
                            excluded = False
                            if excludes:
                                candidate_version = numbers[0]
                                for exclude in list(excludes):
                                    if isinstance(exclude, tuple):
                                        if ((not exclude[0]
                                         or version_compare(exclude[0],
                                            candidate_version) <= 0)
                                         and (not exclude[1]
                                         or version_compare(candidate_version,
                                                            exclude[1]) < 0)):
                                            excluded = True
                                            break
                                    else:
                                        if version_compare(candidate_version,
                                                           exclude) == 0:
                                            excluded = True
                                            break
                            if not excluded:
                                candidate = binpath
                                version = numbers[0]
                                log_info(str(version))
                                break
                            else:
                                log_info("excluded (%s)" % str(numbers[0]))
                        else:
                            candidate = binpath
                            log_info("yes")
                            break
                if candidate is not None:
                    break
        results.append((name_pat, candidate))
        if candidate is None:
            log_info("no")
            complete = False
    return results, version, complete


def find_cache(context, names):
    '''Search for the presence of files in the cache directory. *names*
    is a dictionnary of file names used as key and the associated checksum.'''
    results = {}
    for pathname in names:
        name = os.path.basename(_urlparse(pathname).path)
        log_interactive("%s..." % name)
        local_name = context.local_dir(pathname)
        if os.path.isfile(local_name):
            # It is required for fetching asset directories within a source
            # repo on update that directories are always rsync'ed.
            if isinstance(names[pathname], dict):
                if 'sha1' in names[pathname]:
                    expected = names[pathname]['sha1']
                    with open(local_name, 'rb') as local_file:
                        sha1sum = hashlib.sha1(local_file.read()).hexdigest()
                    if sha1sum == expected:
                        # checksum are matching
                        log_info("matched (sha1)", context=context)
                    else:
                        log_info("corrupted? (sha1)", context=context)
                else:
                    log_info("yes", context=context)
            else:
                log_info("yes", context=context)
        elif os.path.isdir(local_name):
            # We cannot assume existing directories are up-to-date otherwise
            # we will not download recent resources in htdocs/.
            # If we always rsync directories in an environment though,
            # we might end-up raising an invalid error, for example, when
            # building a Docker container when the credentials to the data
            # where not copied inside the container.
            if NO_FETCH:
                log_info("yes", context=context)
            else:
                log_info("yes (update anyway)", context=context)
                results[pathname] = names[pathname]
        else:
            if NO_FETCH:
                log_info("no (but won't fetch)", context=context)
            else:
                log_info("no", context=context)
                results[pathname] = names[pathname]
    return results


def find_files(base, name_pat, recurse=True):
    """
    Search the directory tree rooted at *base* for files matching *name_pat*
    and returns a list of absolute pathnames to those files.
    """
    result = []
    try:
        if os.path.exists(base):
            for name in os.listdir(base):
                path = os.path.join(base, name)
                look = re.match('.*' + name_pat + '$', path)
                if look:
                    result += [path]
                elif recurse and os.path.isdir(path):
                    result += find_files(path, name_pat)
    except OSError:
        # In case permission to execute os.listdir is denied.
        pass
    return sorted(result, reverse=True)


def find_first_files(base, name_pat, subdir=''):
    '''Search the directory tree rooted at *base* for files matching pattern
    *name_pat* and returns a list of relative pathnames to those files
    from *base*.
    If .*/ is part of pattern, base is searched recursively in breadth search
    order until at least one result is found.'''
    try:
        subdirs = []
        results = []
        pat_num_sub_dirs = len(name_pat.split(os.sep))
        sub_num_sub_dirs = len(subdir.split(os.sep))
        candidate_dir = os.path.join(base, subdir)
        if os.path.exists(candidate_dir):
            for filename in os.listdir(candidate_dir):
                relative = os.path.join(subdir, filename)
                path = os.path.join(base, relative)
                regex = name_pat_regex(name_pat)
                look = regex.match(relative)
                if look != None:
                    results += [relative]
                elif (((('.*' + os.sep) in name_pat)
                       or (sub_num_sub_dirs < pat_num_sub_dirs))
                      and os.path.isdir(path)):
                    # When we see .*/, it means we are looking for a pattern
                    # that can be matched by files in subdirectories
                    # of the base.
                    subdirs += [relative]
        if len(results) == 0:
            for subdir in subdirs:
                results += find_first_files(base, name_pat, subdir)
    except OSError:
        # Permission to a subdirectory might be denied.
        pass
    return sorted(results, reverse=True)


def find_data(dirname, names,
              search_path, build_top, versions=None, variant=None):
    '''Search for a list of extra files that can be found from $PATH
       where bin was replaced by *dir*.'''
    results = []
    droots = search_path
    complete = True
    if versions and 'excludes' in versions:
        excludes = versions['excludes']
    else:
        excludes = []
    if variant:
        build_dir = os.path.join(build_top, variant, dirname)
    else:
        build_dir = os.path.join(build_top, dirname)
    for name_pat, absolute_path in names:
        if absolute_path != None and os.path.exists(absolute_path):
            # absolute paths only occur when the search has already been
            # executed and completed successfuly.
            results.append((name_pat, absolute_path))
            continue
        link_name, suffix = link_build_name(name_pat, dirname, variant)
        if os.path.islink(link_name):
            # If we already have a symbolic link in the dataBuildDir,
            # we will assume it is the one to use in order to cut off
            # recomputing of things that hardly change.
            # XXX Be careful if suffix starts with '/'
            results.append((name_pat,
                            os.path.realpath(os.path.join(link_name, suffix))))
            continue

        if variant:
            log_interactive("%s/" % variant)
        log_interactive("%s... " % name_pat)
        link_num = 0
        if name_pat.startswith('.*' + os.sep):
            link_num = len(name_pat.split(os.sep)) - 2
        found = False
        # The structure of share/ directories is not as standard as others
        # and requires a recursive search for prerequisites. As a result,
        # it might take a lot of time to update unmodified links.
        # We thus first check links in build_dir are still valid.
        full_names = find_files(build_dir, name_pat)
        if len(full_names) > 0:
            try:
                os.stat(full_names[0])
                log_info("yes")
                results.append((name_pat, full_names[0]))
                found = True
            except IOError:
                pass
        if not found:
            for base in droots:
                full_names = find_files(base, name_pat)
                if len(full_names) > 0:
                    log_info("yes")
                    tokens = full_names[0].split(os.sep)
                    linked = os.sep.join(tokens[:len(tokens) - link_num])
                    # DEPRECATED: results.append((name_pat, linked))
                    results.append((name_pat, full_names[0]))
                    found = True
                    break
        if not found:
            log_info("no")
            results.append((name_pat, None))
            complete = False
    return results, None, complete


def find_etc(names, search_path, build_top, versions=None, variant=None):
    return find_data('etc', names, search_path, build_top, versions)

def find_include(names, search_path, build_top, versions=None, variant=None):
    '''Search for a list of headers that can be found from $PATH
       where bin was replaced by include.

     *names* is a list of (pattern,absolute_path) pairs where the absolutePat
     can be None and in which case pattern will be used to search
     for a header filename patterns. *excludes* is a list
    of versions that are concidered false positive and need to be
    excluded, usually as a result of incompatibilities.

    This function returns a populated list of (pattern,absolute_path)  pairs
    and a version number if available.

    This function differs from find_bin() and find_lib() in its search
    algorithm. find_include() might generate a breadth search based
    out of a derived root of $PATH. It opens found header files
    and look for a "#define.*VERSION" pattern in order to deduce
    a version number.'''
    results = []
    version = None
    if versions and 'excludes' in versions:
        excludes = versions['excludes']
    else:
        excludes = []
    complete = True
    prefix = ''
    include_sys_dirs = search_path
    for name_pat, absolute_path in names:
        if absolute_path != None and os.path.exists(absolute_path):
            # absolute paths only occur when the search has already been
            # executed and completed successfuly.
            results.append((name_pat, absolute_path))
            continue
        link_name, suffix = link_build_name(name_pat, 'include', variant)
        if os.path.islink(link_name):
            # If we already have a symbolic link in the binBuildDir,
            # we will assume it is the one to use in order to cut off
            # recomputing of things that hardly change.
            # XXX Be careful if suffix starts with '/'
            results.append(
                (name_pat, os.path.realpath(os.path.join(link_name, suffix))))
            continue
        if variant:
            log_interactive("%s/" % variant)
        log_interactive("%s... " % name_pat)
        found = False
        for include_sys_dir in include_sys_dirs:
            includes = []
            for header in find_first_files(include_sys_dir,
                                         name_pat.replace(prefix, '')):
                # Open the header file and search for all defines
                # that end in VERSION.
                numbers = []
                # First parse the pathname for a version number...
                parts = os.path.dirname(header).split(os.sep)
                parts.reverse()
                for part in parts:
                    for ver in version_candidates(part):
                        if not ver in numbers:
                            numbers += [ver]
                # Second open the file and search for a version identifier...
                header = os.path.join(include_sys_dir, header)
                with open(header) as header_file:
                    line = header_file.readline()
                    while line:
                        look = re.match(r'\s*#define.*VERSION\s+(\S+)', line)
                        if look != None:
                            for ver in version_candidates(look.group(1)):
                                if not ver in numbers:
                                    numbers += [ver]
                        line = header_file.readline()
                # At this point *numbers* contains a list that can
                # interpreted as versions. Hopefully, there is only
                # one candidate.
                if len(numbers) >= 1:
                    # With more than one version number, we assume the first
                    # one found is the most relevent and use it regardless.
                    # This is different from previously assumption that more
                    # than one number was an error in the version detection
                    # algorithm. As it turns out, boost packages sources
                    # in a -1_41_0.tar.gz file while version.hpp says 1_41.
                    excluded = False
                    if excludes:
                        for exclude in list(excludes):
                            if ((not exclude[0]
                                 or version_compare(
                                        exclude[0], numbers[0]) <= 0)
                                and (not exclude[1]
                                     or version_compare(
                                        numbers[0], exclude[1]) < 0)):
                                excluded = True
                                break
                    if not excluded:
                        index = 0
                        for include in includes:
                            if ((not include[1])
                                or version_compare(include[1], numbers[0]) < 0):
                                break
                            index = index + 1
                        includes.insert(index, (header, numbers[0]))
                else:
                    # If we find no version number, we append the header
                    # at the end of the list with 'None' for version.
                    includes.append((header, None))
            if includes:
                if includes[0][1]:
                    version = includes[0][1]
                    log_info(version)
                else:
                    log_info("yes")
                results.append((name_pat, includes[0][0]))
                name_pat_parts = name_pat.split(os.sep)
                include_file_parts = includes[0][0].split(os.sep)
                while (name_pat_parts and name_pat_parts[len(name_pat_parts)-1]
                       == include_file_parts[len(include_file_parts)-1]):
                    name_pat_part = name_pat_parts.pop()
                    include_file_part = include_file_parts.pop()
                prefix = os.sep.join(name_pat_parts)
                if prefix:
                    prefix = prefix + os.sep
                    include_sys_dirs = [os.sep.join(include_file_parts)]
                else:
                    include_sys_dirs = [os.path.dirname(includes[0][0])]
                found = True
                break
        if not found:
            log_info("no")
            results.append((name_pat, None))
            complete = False
    return results, version, complete


def found_lib_suffix(candidate, pat):
    if candidate is None:
        return "no"
    look = re.match(r'.*%s(.+)' % pat, candidate)
    if look:
        suffix = look.group(1)
        return suffix
    return "yes (no suffix?)"


def find_lib(names, search_path, build_top, versions=None, variant=None):
    '''Search for a list of libraries that can be found from $PATH
       where bin was replaced by lib.

    *names* is a list of (pattern,absolute_path) pairs where the absolutePat
    can be None and in which case pattern will be used to search
    for library names with neither a 'lib' prefix
    nor a '.a', '.so', etc. suffix. *excludes* is a list
    of versions that are concidered false positive and need to be
    excluded, usually as a result of incompatibilities.

    This function returns a populated list of (pattern,absolute_path)  pairs
    and a version number if available.

    This function differs from find_bin() and find_include() in its
    search algorithm. find_lib() might generate a breadth search based
    out of a derived root of $PATH. It uses the full library name
    in order to deduce a version number if possible.'''
    results = []
    version = None
    if versions and 'excludes' in versions:
        excludes = versions['excludes']
    else:
        excludes = []
    complete = True
    # We used to look for lib suffixes '-version' and '_version'. Unfortunately
    # it picked up libldap_r.so when we were looking for libldap.so. Looking
    # through /usr/lib on Ubuntu does not show any libraries ending with
    # a '_version' suffix so we will remove it from the regular expression.
    suffix = '(-.+)?(\\' + lib_static_suffix() \
        + '|\\' + lib_dyn_suffix() + r'((\.\d+)*))'
    if not variant and CONTEXT.host() in APT_DISTRIBS:
        # Ubuntu 12.04+: host libraries are not always installed
        # in /usr/lib. Sometimes they end-up in /usr/lib/x86_64-linux-gnu
        # like libgmp.so for example.
        droots = []
        for path in search_path:
            droots += [path, os.path.join(path, 'x86_64-linux-gnu')]
    else:
        droots = search_path
    for name_pat, absolute_path in names:
        if absolute_path != None and os.path.exists(absolute_path):
            # absolute paths only occur when the search has already been
            # executed and completed successfuly.
            results.append((name_pat, absolute_path))
            continue
        lib_base_pat = lib_prefix() + name_pat
        if '.*' in name_pat:
            # Dealing with a regular expression already
            lib_priority_suffix = ''
            link_pats = [name_pat]
        elif lib_base_pat.endswith('.so'):
            # local override to select dynamic library.
            lib_base_pat = lib_base_pat[:-3]
            lib_priority_suffix = lib_dyn_suffix()
            link_pats = [lib_base_pat + '.so',
                         lib_base_pat + lib_static_suffix()]
        elif STATIC_LIB_FIRST:
            lib_priority_suffix = lib_static_suffix()
            link_pats = [lib_base_pat + lib_static_suffix(),
                         lib_base_pat + '.so']
        else:
            lib_priority_suffix = lib_dyn_suffix()
            link_pats = [lib_base_pat + '.so',
                         lib_base_pat + lib_static_suffix()]
        candidate = None
        for link_pat in link_pats:
            link_name, link_suffix = link_build_name(link_pat, 'lib', variant)
            if os.path.islink(link_name):
                # If we already have a symbolic link in the libBuildDir,
                # we will assume it is the one to use in order to cut off
                # recomputing of things that hardly change.
                candidate = os.path.realpath(
                    os.path.join(link_name, link_suffix))
                results.append((name_pat, candidate))
                break
        if variant:
            log_interactive("%s/" % variant)
        log_interactive("%s..." % name_pat)
        if candidate is not None:
            log_info(found_lib_suffix(candidate, pat=lib_base_pat))
            continue
        for lib_sys_dir in droots:
            libs = []
            if '.*' in name_pat:
                # We were already given a regular expression.
                # If we are not dealing with a honest to god library, let's
                # just use the pattern we were given. This is because, python,
                # ruby, etc. also put their stuff in libDir.
                # ex patterns for things also in libDir:
                #     - ruby/.*/json.rb
                #     - cgi-bin/awstats.pl
                #     - .*/registration/__init__.py
                lib_pat = name_pat
            else:
                lib_pat = lib_base_pat + suffix
            for libname in find_first_files(lib_sys_dir, lib_pat):
                numbers = version_candidates(libname)
                absolute_path = os.path.join(lib_sys_dir, libname)
                absolute_path_base = os.path.dirname(absolute_path)
                absolute_path_parts = os.path.basename(absolute_path).split('.')
                if len(absolute_path_parts) > 1:
                    absolute_path_ext = ".%s" % absolute_path_parts[1]
                else:
                    absolute_path_ext = ""
                if len(numbers) == 1:
                    excluded = False
                    if excludes:
                        candidate_version = numbers[0]
                        for exclude in list(excludes):
                            if isinstance(exclude, tuple):
                                if ((not exclude[0]
                                 or version_compare(exclude[0],
                                    candidate_version) <= 0)
                                 and (not exclude[1]
                                 or version_compare(candidate_version,
                                                    exclude[1]) < 0)):
                                    excluded = True
                                    break
                            else:
                                if version_compare(candidate_version,
                                                   exclude) == 0:
                                    excluded = True
                                    break
                    if not excluded:
                        # Insert candidate into a sorted list. First to last,
                        # higher version number, dynamic libraries.
                        index = 0
                        for lib in libs:
                            lib_path_base = os.path.dirname(lib[0])
                            if ((not lib[1])
                                or version_compare(lib[1], numbers[0]) < 0):
                                break
                            elif (absolute_path_base == lib_path_base
                                and absolute_path_ext == lib_priority_suffix):
                                break
                            index = index + 1
                        libs.insert(index, (absolute_path, numbers[0]))
                else:
                    # Insert candidate into a sorted list. First to last,
                    # higher version number, shortest name, dynamic libraries.
                    index = 0
                    for lib in libs:
                        lib_path_base = os.path.dirname(lib[0])
                        if lib[1]:
                            pass
                        elif absolute_path_base == lib_path_base:
                            if absolute_path_ext == lib_priority_suffix:
                                break
                        elif lib_path_base.startswith(absolute_path_base):
                            break
                        index = index + 1
                    libs.insert(index, (absolute_path, None))
            if libs:
                candidate = libs[0][0]
                version = libs[0][1]
                break
        results.append((name_pat, candidate))
        log_info(found_lib_suffix(candidate, pat=lib_base_pat))
        if candidate is None:
            complete = False
    return results, version, complete


def find_prerequisites(deps, versions=None, variant=None):
    '''Find a set of executables, headers, libraries, etc. on a local machine.

    *deps* is a dictionary where each key associates an install directory
    (bin, include, lib, etc.) to a pair (pattern,absolute_path) as required
    by *find_bin*(), *find_lib*(), *find_include*(), etc.

    *excludes* contains a list of excluded version ranges because they are
    concidered false positive, usually as a result of incompatibilities.

    This function will try to find the latest version of each file which
    was not excluded.

    This function will return a dictionnary matching *deps* where each found
    file will be replaced by an absolute pathname and each file not found
    will not be present. This function returns True if all files in *deps*
    can be fulfilled and returns False if any file cannot be found.'''
    version = None
    installed = {}
    complete = True
    for dep in deps:
        # Make sure the extras do not get filtered out.
        if not dep in INSTALL_DIRS:
            installed[dep] = deps[dep]
    for dirname in INSTALL_DIRS:
        # The search order "bin, include, lib, etc" will determine
        # how excluded versions apply.
        if dirname in deps:
            command = 'find_' + dirname
            # First time ever *find* is called, libDir will surely not defined
            # in the workspace make fragment and thus we will trigger
            # interactive input from the user.
            # We want to make sure the output of the interactive session does
            # not mangle the search for a library so we preemptively trigger
            # an interactive session.
            # deprecated: done in search_path. context.value(dir + 'Dir')
            installed[dirname], installed_version, installed_complete = \
                getattr(sys.modules[__name__], command)(deps[dirname],
                    CONTEXT.search_path(dirname, variant),
                    CONTEXT.value('buildTop'),
                    versions, variant)
            # Once we have selected a version out of the installed
            # local system, we lock it down and only search for
            # that specific version.
            if not version and installed_version:
                version = installed_version
                versions = {'excludes':
                    [(None, version), (version_incr(version), None)]}
            if not installed_complete:
                complete = False
    return installed, complete


def find_libexec(names, search_path, build_top, versions=None, variant=None):
    '''find files specificed in names inside the libexec/ directory.
    *excludes* is a list of version to exclude from the set of matches.'''
    return find_data(
        'libexec', names, search_path, build_top, versions, variant)


def find_share(names, search_path, build_top, versions=None, variant=None):
    '''find files specificed in names inside the share/ directory.
    *excludes* is a list of version to exclude from the set of matches.'''
    return find_data('share', names, search_path, build_top, versions, variant)


def find_boot_bin(name_pat, package=None, context=None, dbindex=None):
    '''This script needs a few tools to be installed to bootstrap itself,
    most noticeably the initial source control tool used to checkout
    the projects dependencies index file.'''
    if not context:
        global CONTEXT
        if not CONTEXT:
            CONTEXT = Context()
            CONTEXT.locate()
        context = CONTEXT
    name, _ = regex_as_name(name_pat)
    executable = os.path.join(context.bin_build_dir(), name)
    if not os.path.exists(executable):
        # We do not use *validate_controls* here because dws in not
        # a project in *srcTop* and does not exist on the remote machine.
        # We use find_bin() and link_context() directly also because it looks
        # weird when the script prompts for installing a non-existent dws
        # project before looking for the rsync prerequisite.
        if not package:
            package = name
        if not dbindex:
            dbindex = IndexProjects(context,
                          '''<?xml version="1.0" ?>
<projects>
  <project name="find-boot-bin">
    <package>
      <dep name="%s">
        <bin>%s</bin>
      </dep>
    </package>
  </project>
</projects>
''' % (package, name_pat))
        executables, version, complete = find_bin([[name_pat, None]],
            context.search_path('bin'), context.value('buildTop'))
        if len(executables) == 0 or not executables[0][1]:
            validate_controls(
                BuildGenerator(
                    ['find-boot-bin'], [], force_update=True), dbindex)
            executables, version, complete = find_bin([[name_pat, None]],
                context.search_path('bin'), context.value('buildTop'))
        name, absolute_path = executables.pop()
        link_pat_path(name, absolute_path, 'bin')
        executable = os.path.join(context.bin_build_dir(), name)
    return executable


def find_gem(context):
    gem_package = None
    if context.host() in APT_DISTRIBS:
        gem_package = 'rubygems'
    find_boot_bin('(gem).*', package=gem_package, context=context)
    return os.path.join(context.value('buildTop'), 'bin', 'gem')


def find_git(context):
    executable = os.path.join(context.bin_build_dir(), 'git')
    if not os.path.lexists(executable):
        dbindex = IndexProjects(context, """<?xml version="1.0" ?>
<projects>
  <project name="dws">
    <repository>
      <dep name="git">
        <bin>git</bin>
        <share>(git-core)/templates</share>
      </dep>
    </repository>
  </project>
</projects>
""")
        executables, _, complete = find_bin([('git', None)],
            context.search_path('bin'), context.value('buildTop'))
        if len(executables) == 0 or not executables[0][1]:
            validate_controls(
                BuildGenerator(['dws'], [], force_update=True), dbindex)
            executables, version, complete = find_bin([('git', None)],
                context.search_path('bin'), context.value('buildTop'))
        name, absolute_path = executables.pop()
        link_pat_path('git', absolute_path, 'bin')
        executable = os.path.join(context.bin_build_dir(), name)
    return executable


def find_npm(context):
    try:
        node_package = 'nodejs'
        find_boot_bin('(node).*', package=node_package, context=context)
        npm_package = 'npm'
        find_boot_bin('(npm).*', package=npm_package, context=context)
    except Exception:
        # At this point major distributions have nodejs/npm packaged.
        # We keep this code as a fallback.
        log_info("warning: couldn't find node or npm as a native package,"\
            " install from nvm...")
        version = '6.16.0'
        build_npm = os.path.join(context.value('buildTop'), 'bin', 'npm')
        if not os.path.lexists(build_npm):
            dbindex = IndexProjects(context, """<?xml version="1.0" ?>
    <projects>
      <project name="nvm">
        <repository>
          <sync>https://github.com/creationix/nvm.git</sync>
          <shell>
    export NVM_DIR=${buildTop}
    . ${srcTop}/nvm/nvm.sh
    nvm install %s
          </shell>
        </repository>
      </project>
    </projects>
    """ % version)
            executables, _, complete = find_bin(
                [('node', None), ('npm', None)],
                context.search_path('bin'), context.value('buildTop'))
            if len(executables) == 0 or not executables[0][1]:
                validate_controls(
                    BuildGenerator(['nvm'], [], force_update=True), dbindex)
                prev = os.getcwd()
                os.chdir(context.value('binDir'))
                node = os.path.join(context.value('binDir'), 'node')
                if not os.path.exists(node):
                    os.symlink('%s/v%s/bin/node' % (
                        context.value('buildTop'), version), 'node')
                npm = os.path.join(context.value('binDir'), 'npm')
                if not os.path.exists(npm):
                    os.symlink('%s/v%s/bin/npm' % (
                        context.value('buildTop'), version), 'npm')
                os.chdir(prev)
                executables, _, complete = find_bin(
                    [('node', None), ('npm', None)],
                    context.search_path('bin'), context.value('buildTop'))
            for name, absolute_path in executables:
                link_pat_path(name, absolute_path, 'bin')
    return os.path.join(context.bin_build_dir(), 'npm')


def find_pip(context):
    pip_package = None
    if context.host() in DNF_DISTRIBS + YUM_DISTRIBS:
        pip_package = 'python-pip'
    find_boot_bin('(pip).*', package=pip_package, context=context)
    return os.path.join(context.bin_build_dir(), 'pip')


def find_rsync(host, context=None, relative=True, admin=False,
              username=None, key=None):
    '''Check if rsync is present and install it through the package
    manager if it is not. rsync is a little special since it is used
    directly by this script and the script is not always installed
    through a project.'''
    rsync = find_boot_bin('rsync', context=context)

    # We are accessing the remote machine through a mounted
    # drive or through ssh.
    prefix = ""
    if username:
        prefix = prefix + username + '@'
    # -a is equivalent to -rlptgoD, we are only interested in -r (recursive),
    # -p (permissions), -t (times)
    cmdline = [rsync, '-qrptuz']
    if relative:
        cmdline = [rsync, '-qrptuzR']
    if host:
        # We are accessing the remote machine through ssh
        prefix = prefix + host + ':'
        ssh = '--rsh="ssh -q'
        if admin:
            ssh = ssh + ' -t'
        if key:
            ssh = ssh + ' -i ' + str(key)
        ssh = ssh + '"'
        cmdline += [ssh]
    if admin and username != 'root':
        cmdline += ['--rsync-path', 'sudo /usr/bin/rsync']
    else:
        cmdline += ['--rsync-path', '/usr/bin/rsync']
    return cmdline, prefix


def find_virtualenv(context, version=3):
    if version >= 3:
        return [sys.executable, '-m', 'venv']
    virtual_package = 'python-virtualenv'
    find_boot_bin(r"(virtualenv)(-%d\.\d)?" % version,
        package=virtual_package, context=context)
    return [os.path.join(context.bin_build_dir(), 'virtualenv')]


def name_pat_regex(name_pat):
    # Many C++ tools contain ++ in their name which might trip
    # the regular expression parser.
    # We must postpend the '$' sign to the regular expression
    # otherwise "makeconv" and "makeinfo" will be picked up by
    # a match for the "make" executable.
    pat = name_pat.replace('++', r'\+\+')
    if not pat.startswith('.*'):
        # If we don't add the separator here we will end-up with unrelated
        # links to automake, pkmake, etc. when we are looking for "make".
        pat = r'^' + pat + r'$|.*' + os.sep + pat
    return re.compile(pat + '$')


def ordered_prerequisites(dgen, dbindex, graph=False):
    """
    Returns the dependencies in topological order, globbed by type,
    for a set of projects.
    """
    dbindex.validate()

    # Add deep dependencies
    vertices = dbindex.closure(dgen)
    if graph:
        gph_filename = os.path.splitext(CONTEXT.logname())[0] + '.dot'
        gph_file = open(gph_filename, 'w')
        gph_file.write("digraph structural {\n")
        for vertex in vertices:
            for project in vertex.prerequisites:
                gph_file.write(
                    "\t%s -> %s;\n" % (vertex.name, project.name))
        gph_file.write("}\n")
        gph_file.close()
    globbed = []
    while len(vertices) > 0:
        first = vertices.pop(0)
        glob = [first]
        while len(vertices) > 0:
            vertex = vertices.pop(0)
            if(vertex.__class__ != first.__class__
               or (hasattr(vertex, 'target') and hasattr(first, 'target')
                   and vertex.target != first.target)):
                vertices.insert(0, vertex)
                break
            if 'insert' in dir(first):
                first.insert(vertex)
            else:
                glob += [vertex]
        globbed += glob
    return globbed


def fetch(context, filenames,
          force=False, admin=False, relative=True):
    '''download *filenames*, typically a list of distribution packages,
    from the remote server into *cacheDir*. See the upload function
    for uploading files to the remote server.
    When the files to fetch require sudo permissions on the remote
    machine, set *admin* to true.
    '''
    if filenames and len(filenames) > 0:
        # Expand filenames to absolute urls
        remote_site_top = context.value('remoteSiteTop')
        uri = _urlparse(remote_site_top)
        hostname = uri.netloc
        if not uri.netloc:
            # If there is no protocol specified, the hostname
            # will be in uri.scheme (That seems like a bug in urlparse).
            hostname = uri.scheme
        pathnames = {}
        for name in filenames:
            # Absolute path to access a file on the remote machine.
            remote_path = ''
            if name:
                if name.startswith('http') or ':' in name:
                    remote_path = name
                elif ':' in remote_site_top:
                    remote_path = remote_site_top + name
                elif name.startswith('/'):
                    remote_path = name
                else:
                    remote_path = os.path.join(remote_site_top, name)
            pathnames[remote_path] = filenames[name]

        # Check the local cache
        if force:
            downloads = pathnames
        else:
            downloads = find_cache(context, pathnames)
            for filename in downloads:
                local_filename = context.local_dir(filename)
                dirname = os.path.dirname(local_filename)
                if not os.path.exists(dirname):
                    os.makedirs(dirname)

        # Split fetches by protocol
        https = []
        sshs = []
        for package in downloads:
            # Splits between files downloaded through http and ssh.
            if package.startswith('http'):
                https += [package]
            else:
                sshs += [package]
        # fetch https
        for remotename in https:
            localname = context.local_dir(remotename)
            if not os.path.exists(os.path.dirname(localname)):
                os.makedirs(os.path.dirname(localname))
            log_info("fetching %s..." % remotename, context=context)
            with urlopen(Request(remotename)) as remote:
                with open(localname, 'wb') as local:
                    local.write(remote.read())
        # fetch sshs
        if len(sshs) > 0:
            local_sources = []
            remote_sources = {}
            for ssh in sshs:
                parts = ssh.split(':')
                if len(parts) == 2:
                    host = parts[0]
                    path = parts[1]
                    if not host in remote_sources:
                        remote_sources[host] = [path]
                    else:
                        remote_sources[host] += [path]
                else:
                    local_sources += parts
            if local_sources:
                cmdline, prefix = find_rsync(
                    "", context=context, relative=relative, admin=admin)
                shell_command(cmdline + ["'" + ' '.join(local_sources) + "'",
                                    context.value('siteTop')])
            for hostname, paths in _iteritems(remote_sources):
                if hostname and admin:
                    shell_command(['stty -echo;', 'ssh', hostname,
                              'sudo', '-v', '; stty echo'])
                cmdline, prefix = find_rsync(
                    hostname, context=context, relative=relative, admin=admin)
                shell_command(cmdline + ["'" + prefix + ' '.join(paths) + "'",
                                    context.value('siteTop')])


def create_managed(project_name, versions=None, target=None):
    '''Create a step that will install *project_name* through the local
    package manager.
    If the target is pure python, we will try pip before native package
    manager because we prefer to install in the virtualenv. We solely rely
    on the native package manager for python with C bindings.'''
    install_step = None
    if target and target.startswith('python'):
        install_step = PipInstallStep(
            project_name, versions=versions, target=target)
    elif target and target.startswith('gems'):
        install_step = GemInstallStep(
            project_name, versions=versions, target=target)
    elif target and target.startswith('nodejs'):
        install_step = NpmInstallStep(
            project_name, versions=versions, target=target)
    elif CONTEXT.host() in APT_DISTRIBS:
        install_step = AptInstallStep(project_name, target=target)
    elif CONTEXT.host() in PORT_DISTRIBS:
        install_step = MacPortInstallStep(project_name, target=target)
    elif CONTEXT.host() in DNF_DISTRIBS:
        install_step = DnfInstallStep(project_name, target=target)
    elif CONTEXT.host() in YUM_DISTRIBS:
        install_step = YumInstallStep(project_name, target=target)
    else:
        install_step = None
    return install_step


def create_package_file(project_name, filenames):
    if CONTEXT.host() in APT_DISTRIBS:
        install_step = DpkgInstallStep(project_name, alt_names=filenames)
    elif CONTEXT.host() in PORT_DISTRIBS:
        install_step = DarwinInstallStep(project_name, alt_names=filenames)
    elif CONTEXT.host() in DNF_DISTRIBS + YUM_DISTRIBS:
        install_step = RpmInstallStep(project_name, alt_names=filenames)
    else:
        install_step = None
    return install_step


def elapsed_duration(start, finish):
    '''Returns elapsed time between start and finish'''
    duration = finish - start
    # XXX until most system move to python 2.7, we compute
    # the number of seconds ourselves. +1 insures we run for
    # at least a second.
    return datetime.timedelta(seconds=((duration.microseconds
                                        + (duration.seconds
                                           + duration.days * 24 * 3600)
                                        * 10**6) / 10**6) + 1)

def install(packages, dbindex):
    '''install a pre-built (also pre-fetched) package.
    '''
    projects = []
    local_files = []
    package_files = None
    for name in packages:
        if os.path.isfile(name):
            local_files += [name]
        else:
            projects += [name]
    if local_files:
        package_files = create_package_file(local_files[0], local_files)

    if projects:
        handler = Unserializer(projects)
        dbindex.parse(handler)

        managed = []
        for name in projects:
            # *name* is definitely handled by the local system package manager
            # whenever there is no associated project.
            if name in handler.projects:
                project = handler.as_project(name)
                dist = CONTEXT.host()
                if dist not in project.packages:
                    dist = ALIAS_DISTRIBS.get(dist, dist)
                package = project.packages.get(dist)
                if package:
                    package_files.insert(create_package_file(name,
                                                          package.fetches()))
                else:
                    managed += [name]
            else:
                managed += [name]

        if managed:
            step = create_managed(managed[0])
            for package in managed[1:]:
                step.insert(create_managed(package))
            step.run(CONTEXT)

    if package_files:
        package_files.run(CONTEXT)


def help_book(help_string):
    '''Print a text string help message as formatted docbook.'''

    first_term = True
    first_section = True
    lines = help_string.getvalue().split('\n')
    while lines:
        line = lines.pop(0)
        if line.strip().startswith('Usage'):
            look = re.match(r'Usage: (\S+)', line.strip())
            cmdname = look.group(1)
            # /usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd
            # dtd/docbook-xml/docbookx.dtd
            sys.stdout.write("""<?xml version="1.0"?>
<refentry xmlns="http://docbook.org/ns/docbook"
         xmlns:xlink="http://www.w3.org/1999/xlink"
         xml:id=\"""" + cmdname + """">
<info>
<author>
<personname>Sebastien Mirolo &lt;smirolo@djaodjin.com&gt;</personname>
</author>
</info>
<refmeta>
<refentrytitle>""" + cmdname + """</refentrytitle>
<manvolnum>1</manvolnum>
<refmiscinfo class="manual">User Commands</refmiscinfo>
<refmiscinfo class="source">drop</refmiscinfo>
<refmiscinfo class="version">""" + str(__version__) + """</refmiscinfo>
</refmeta>
<refnamediv>
<refname>""" + cmdname + """</refname>
<refpurpose>inter-project dependencies tool</refpurpose>
</refnamediv>
<refsynopsisdiv>
<cmdsynopsis>
<command>""" + cmdname + """</command>
<arg choice="opt">
  <option>options</option>
</arg>
<arg>command</arg>
</cmdsynopsis>
</refsynopsisdiv>
""")
        elif (line.strip().startswith('Version')
            or re.match(r'\S+ version', line.strip())):
            pass
        elif line.strip().endswith(':'):
            if not first_term:
                sys.stdout.write("</para>\n")
                sys.stdout.write("</listitem>\n")
                sys.stdout.write("</varlistentry>\n")
            if not first_section:
                sys.stdout.write("</variablelist>\n")
                sys.stdout.write("</refsection>\n")
            first_section = False
            sys.stdout.write("<refsection>\n")
            sys.stdout.write('<title>' + line.strip() + '</title>\n')
            sys.stdout.write("<variablelist>")
            first_term = True
        elif len(line) > 0 and (re.search("[a-z]", line[0])
                                or line.startswith("  -")):
            stmt = line.strip().split(' ')
            if not first_term:
                sys.stdout.write("</para>\n")
                sys.stdout.write("</listitem>\n")
                sys.stdout.write("</varlistentry>\n")
            first_term = False
            for word in stmt[1:]:
                if word:
                    break
            if line.startswith("  -h,"):
                # Hack because "show" does not start
                # with uppercase.
                sys.stdout.write("<varlistentry>\n<term>" + ' '.join(stmt[0:2])
                                 + "</term>\n")
                word = 'S'
                stmt = stmt[1:]
            elif not re.search("[A-Z]", word[0]):
                sys.stdout.write("<varlistentry>\n<term>" + line + "</term>\n")
            else:
                if not stmt[0].startswith('-'):
                    sys.stdout.write("<varlistentry xml:id=\"dws." \
                                         + stmt[0] + "\">\n")
                else:
                    sys.stdout.write("<varlistentry>\n")
                sys.stdout.write("<term>" + stmt[0] + "</term>\n")
            sys.stdout.write("<listitem>\n")
            sys.stdout.write("<para>\n")
            if re.search("[A-Z]", word[0]):
                sys.stdout.write(' '.join(stmt[1:]) + '\n')
        else:
            sys.stdout.write(line + '\n')
    if not first_term:
        sys.stdout.write("</para>\n")
        sys.stdout.write("</listitem>\n")
        sys.stdout.write("</varlistentry>\n")
    if not first_section:
        sys.stdout.write("</variablelist>\n")
        sys.stdout.write("</refsection>\n")
    sys.stdout.write("</refentry>\n")


def lib_prefix():
    '''Returns the prefix for library names.'''
    lib_prefixes = {
        'Cygwin': ''
        }
    if CONTEXT.host() in lib_prefixes:
        return lib_prefixes[CONTEXT.host()]
    return 'lib'


def lib_static_suffix():
    '''Returns the suffix for static library names.'''
    lib_static_suffixes = {
        }
    if CONTEXT.host() in lib_static_suffixes:
        return lib_static_suffixes[CONTEXT.host()]
    return '.a'


def lib_dyn_suffix():
    '''Returns the suffix for dynamic library names.'''
    lib_dyn_suffixes = {
        'Cygwin': '.dll',
        'Darwin': '.dylib'
        }
    if CONTEXT.host() in lib_dyn_suffixes:
        return lib_dyn_suffixes[CONTEXT.host()]
    return '.so'


def link_prerequisites(files, versions=None, target=None):
    '''All projects which are dependencies but are not part of *srcTop*
    are not under development in the current workspace. Links to
    the required executables, headers, libraries, etc. will be added to
    the install directories such that projects in *srcTop* can build.
    *excludes* is a list of versions to exclude.'''
    # First, we will check if find_prerequisites needs to be rerun.
    # It is the case if the link in [bin|include|lib|...]Dir does
    # not exist and the pathname for it in build_deps is not
    # an absolute path.
    complete = True
    for dirname in INSTALL_DIRS:
        if dirname in files:
            for name_pat, absolute_path in files[dirname]:
                complete &= link_pat_path(name_pat, absolute_path,
                                        dirname, target)
    if not complete:
        files, complete = find_prerequisites(files, versions, target)
        if complete:
            for dirname in INSTALL_DIRS:
                if dirname in files:
                    for name_pat, absolute_path in files[dirname]:
                        complete &= link_pat_path(
                            name_pat, absolute_path, dirname, target)
    return files, complete


def link_context(path, link_name):
    """
    Links a *path* into the workspace as *link_name*.
    """
    if not path:
        log_error('There is no target for link ' + link_name + '\n')
        return
    if os.path.realpath(path) == os.path.realpath(link_name):
        return
    if not os.path.exists(os.path.dirname(link_name)):
        os.makedirs(os.path.dirname(link_name))
    # In the following two 'if' statements, we are very careful
    # to only remove/update symlinks and leave other files
    # present in [bin|lib|...]Dir 'as is'.
    if os.path.islink(link_name):
        os.remove(link_name)
    if not os.path.exists(link_name) and os.path.exists(path):
        os.symlink(path, link_name)

def regex_as_name(name_pat):
    """
    Extract the normalized name used for creating links in *buildTop*.
    """
    suffix = ''
    regex = name_pat_regex(name_pat)
    if regex.groups == 0:
        name = name_pat.replace('\\', '')
        parts = name.split(os.sep)
        if parts:
            name = parts[len(parts) - 1]
    else:
        look = re.search(r'\(([^\)]+)\)', name_pat)
        name = look.group(1)
        if '|' in name:
            name = name.split('|')[0]
        # XXX +1 ')', +2 '/'
        suffix = name_pat[look.end(1) + 1:]
    return name, suffix

def link_build_name(name_pat, subdir, target=None):
    # We normalize the library link name such as to make use of the default
    # definitions of .LIBPATTERNS and search paths in make. It also avoids
    # having to prefix and suffix library names in Makefile with complex
    # variable substitution logic.
    name, suffix = regex_as_name(name_pat)
    subpath = subdir
    if target:
        subpath = os.path.join(target, subdir)
    link_build = os.path.join(CONTEXT.value('buildTop'), subpath, name)
    return link_build, suffix


def link_pat_path(name_pat, absolute_path, subdir, target=None):
    """
    Creates a link to *absolute_path* in the build directory with a name
    derived from *name_pat*.
    """
    link_path = absolute_path
    subpath = subdir
    if target:
        subpath = os.path.join(target, subdir)
    link_name = None
    clean_pat = name_pat.replace('.*', '')
    if not name_pat.startswith('.*'):
        ext = ''
        if absolute_path:
            _, ext = os.path.splitext(absolute_path)
        if clean_pat.endswith('.a') or clean_pat.endswith('.so'):
            # static/dynamic was explicitly specified. We override ``ext``
            # because it could have been previously computed as ``.so.X``.
            clean_pat, ext = os.path.splitext(clean_pat)
        if ext in ['.a', lib_static_suffix()]:
            link_name = CONTEXT.obj_dir(
                os.path.join(subpath, 'lib%s.a' % clean_pat))
        elif ext in ['.so', lib_dyn_suffix()]:
            link_name = CONTEXT.obj_dir(os.path.join(
                subpath, 'lib%s.so' % clean_pat))
    if link_name is None:
        link_name, suffix = link_build_name(clean_pat, subdir, target)
        if absolute_path and suffix and absolute_path.endswith(suffix):
            if os.path.isdir(absolute_path[:-len(suffix)]):
                # Interestingly absolute_path[:-0] returns an empty string.
                link_path = absolute_path[:-len(suffix)]
    # create links. at this point link_path and link_name are absolute.
    complete = True
    if link_path:
        if not os.path.exists(link_name):
            link_context(link_path, link_name)
    elif not os.path.isfile(link_name):
        complete = False
    return complete


def localize_context(context, name, target):
    '''Create the environment in *buildTop* necessary to make a project
    from source.'''
    if target:
        local_context = Context()
        local_context.environ['buildTop'] \
            = os.path.join(context.value('buildTop'), target)
        local_context.config_filename \
            = os.path.join(local_context.value('buildTop'), context.config_name)
        if os.path.exists(local_context.config_filename):
            local_context.locate(local_context.config_filename)
        else:
            local_context.environ['srcTop'] = context.value('srcTop')
            local_context.environ['siteTop'] = context.value('siteTop')
            local_context.environ['installTop'].default \
                = os.path.join(context.value('installTop'), target)
            local_context.save()
    else:
        local_context = context

    obj_dir = context.obj_dir(name)
    if obj_dir != os.getcwd():
        if not os.path.exists(obj_dir):
            os.makedirs(obj_dir)
        os.chdir(obj_dir)

    # prefix.mk and suffix.mk expects these variables to be defined
    # in the workspace make fragment. If they are not you might get
    # some strange errors where a g++ command-line appears with
    # -I <nothing> or -L <nothing> for example.
    # This code was moved to be executed right before the issue
    # of a "make" subprocess in order to let the project index file
    # a change to override defaults for installTop, etc.
    for dir_name in ['include', 'lib', 'bin', 'etc', 'share']:
        name = local_context.value(dir_name + 'Dir')

    return local_context


def runuser():
    return getpass.getuser()


def merge_unique(left, right):
    '''Merge a list of additions into a previously existing list.
    Or: adds elements in *right* to the end of *left* if they were not
    already present in *left*.'''
    for item in right:
        if not item in left:
            left += [item]
    return left


def merge_build_conf(db_prev, db_upd, parser):
    '''Merge an updated project dependency database into an existing
       project dependency database. The existing database has been
       augmented by user-supplied information such as "use source
       controlled repository", "skip version X dependency", etc. Hence
       we do a merge instead of a complete replace.'''
    if db_prev is None:
        return db_upd
    elif db_upd is None:
        return db_prev
    else:
        # We try to keep user-supplied information in the prev
        # database whenever possible.
        # Both databases supply packages in alphabetical order,
        # so the merge can be done in a single pass.
        db_next = tempfile.TemporaryFile()
        proj_prev = parser.copy(db_next, db_prev)
        proj_upd = parser.next(db_upd)
        while proj_prev != None and proj_upd != None:
            if proj_prev < proj_upd:
                parser.start_project(db_next, proj_prev)
                proj_prev = parser.copy(db_next, db_prev)
            elif proj_prev > proj_upd:
                parser.start_project(db_next, proj_upd)
                proj_upd = parser.copy(db_next, db_upd)
            elif proj_prev == proj_upd:
                # when names are equals, we need to import user-supplied
                # information as appropriate. For now, there are only one
                # user supplied-information, the install mode for the package.
                # Package name is a unique key so we can increment
                # both iterators.
                parser.start_project(db_next, proj_upd)
                #installMode, version = parser.installMode(proj_prev)
                #parser.setInstallMode(db_next,installMode,version)
                # It is critical this line appears after we set the installMode
                # because it guarentees that the install mode will always be
                # the first line after the package tag.
                proj_upd = parser.copy(db_next, db_upd, True)
                proj_prev = parser.copy(db_next, db_prev)
        while proj_prev != None:
            parser.start_project(db_next, proj_prev)
            proj_prev = parser.copy(db_next, db_prev)
        while proj_upd != None:
            parser.start_project(db_next, proj_upd)
            proj_upd = parser.copy(db_next, db_upd)
        parser.trailer(db_next)
        return db_next


def upload(filenames, remote_cache_path=None):
    '''upload *filenames*, typically a list of result logs,
    to the remote server. See the fetch function for downloading
    files from the remote server.
    '''
    if not remote_cache_path:
        remote_cache_path = CONTEXT.remote_dir(CONTEXT.log_path(''))
    cmdline, _ = find_rsync(
        CONTEXT.remote_host(), context=CONTEXT, relative=True)
    up_cmdline = cmdline + [' '.join(filenames), remote_cache_path]
    shell_command(up_cmdline)

def createmail(subject, filenames=None):
    '''Returns an e-mail with *filenames* as attachments.
    '''
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = CONTEXT.value('dwsEmail')
    msg.preamble = 'The contents of %s' % ', '.join(filenames)

    for filename in list(filenames):
        with open(filename, 'rb') as filep:
            content = MIMEText(filep.read())
            content.add_header('Content-Disposition', 'attachment',
                               filename=os.path.basename(filename))
        msg.attach(content)
    return msg.as_string()


def sendmail(msgtext, dests):
    '''Send a formatted email *msgtext* through the default smtp server.'''
    if len(dests) > 0:
        if CONTEXT.value('smtpHost') == 'localhost':
            try:
                session = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                session.connect(
                    CONTEXT.value('smtpHost'), CONTEXT.value('smtpPort'))
                session.shutdown(2)
            except socket.error:
                # Can't connect to that port on local host, we will thus assume
                # we are accessing the smtp server through a ssh tunnel.
                ssh_tunnels(CONTEXT.tunnel_point,
                    [CONTEXT.value('smtpPort')[:-1]])

        import smtplib
        # Send the message via our own SMTP server, but don't include the
        # envelope header.
        session = smtplib.SMTP(
            CONTEXT.value('smtpHost'), CONTEXT.value('smtpPort'))
        session.set_debuglevel(1)
        session.ehlo()
        session.starttls()
        session.ehlo()
        session.login(
            CONTEXT.value('dwsSmtpLogin'), CONTEXT.value('dwsSmtpPasswd'))
        session.sendmail(CONTEXT.value('dwsEmail'), dests,
                   'To:' + ', '.join(dests) + '\r\n' + msgtext)
        session.close()


def search_back_to_root(filename, root=os.sep):
    '''Search recursively from the current directory to the *root*
    of the directory hierarchy for a specified *filename*.
    This function returns the relative path from *filename* to pwd
    and the absolute path to *filename* if found.'''
    cur_dir = os.getcwd()
    dirname = '.'
    while (not os.path.samefile(cur_dir, root)
           and not os.path.isfile(os.path.join(cur_dir, filename))):
        if dirname == '.':
            dirname = os.path.basename(cur_dir)
        else:
            dirname = os.path.join(os.path.basename(cur_dir), dirname)
        cur_dir = os.path.dirname(cur_dir)
    if not os.path.isfile(os.path.join(cur_dir, filename)):
        raise IOError(1, "cannot find file", filename)
    return dirname, os.path.join(cur_dir, filename)


def shell_command(execute, admin=False, search_path=None, node_path=None,
    pat=None, noexecute=False, nolog=None):
    '''Execute a shell command and throws an exception when the command fails.
    sudo is used when *admin* is True.
    the text output is filtered and returned when pat exists.
    '''
    filtered_output = []
    env = os.environ.copy()
    if admin and not (USER or GROUP):
        if False:
            # \todo cannot do this simple check because of a shell variable
            # setup before call to apt-get.
            if not execute.startswith('/'):
                raise Error("admin command without a fully quaified path: "
                    + execute)
        # ex: su username -c 'sudo port install icu'
        cmdline = ['/usr/bin/sudo']
        if USE_DEFAULT_ANSWER:
            # Error out if sudo prompts for a password because this should
            # never happen in non-interactive mode.
            if ASK_PASS:
                # XXX Workaround while sudo is broken
                # http://groups.google.com/group/comp.lang.python/\
                # browse_thread/thread/4c2bb14c12d31c29
                env['SUDO_ASKPASS'] = ASK_PASS
                cmdline = cmdline + ['-A']
            else:
                cmdline += ['-n']
        if isinstance(admin, string_types):
            cmdline += ['-u', admin]
        cmdline += execute
    else:
        cmdline = execute
    if search_path:
        env['PATH'] = ':'.join(search_path)
    if node_path:
        env['NODE_PATH'] = ':'.join(node_path)
    log_cmdline = ""
    for cmdline_item in cmdline:
        if log_cmdline:
            log_cmdline += " "
        if ' ' in cmdline_item:
            log_cmdline += '"%s"' % cmdline_item
        else:
            log_cmdline += cmdline_item
    if not (noexecute or DO_NOT_EXECUTE):
        log_info(log_cmdline, nolog=nolog)
    else:
        log_info("(noexecute) %s" % log_cmdline, nolog=nolog)
    if not (noexecute or DO_NOT_EXECUTE):
        prev_euid = None
        prev_egid = None
        if admin and USER:
            prev_euid = os.geteuid()
            os.seteuid(USER)
        if admin and GROUP:
            prev_egid = os.getegid()
            os.setegid(GROUP)
        cmd = subprocess.Popen(log_cmdline,
                               shell=True,
                               env=env,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,
                               close_fds=True)
        line = cmd.stdout.readline()
        if not isinstance(line, string_types):
            line = line.decode(DEFAULT_ENCODING)
        while line:
            if pat and re.match(pat, line):
                filtered_output += [line]
            log_info(line[:-1], nolog=nolog)
            line = cmd.stdout.readline()
            if not isinstance(line, string_types):
                line = line.decode(DEFAULT_ENCODING)
        cmd.wait()
        if prev_euid:
            os.seteuid(prev_euid)
        if prev_egid:
            os.setegid(prev_egid)
        if cmd.returncode != 0:
            raise Error("unable to complete: %s\n%s\n"
                % (log_cmdline, '\n'.join(filtered_output)), cmd.returncode)
    return filtered_output


def sort_build_conf_list(db_pathnames, parser):
    '''Sort/Merge projects defined in a list of files, *db_pathnames*.
    *parser* is the parser used to read the projects files in.'''
    db_prev = None
    db_upd = None
    if len(db_pathnames) == 0:
        return None
    elif len(db_pathnames) == 1:
        db_prev = open(db_pathnames[0], 'rb')
        return db_prev
    elif len(db_pathnames) == 2:
        db_prev = open(db_pathnames[0], 'rb')
        db_upd = open(db_pathnames[1], 'rb')
    else:
        db_prev = sort_build_conf_list(
            db_pathnames[:len(db_pathnames) / 2], parser)
        db_upd = sort_build_conf_list(
            db_pathnames[len(db_pathnames) / 2:], parser)
    db_next = merge_build_conf(db_prev, db_upd, parser)
    db_next.seek(0)
    db_prev.close()
    db_upd.close()
    return db_next

def ssh_tunnels(hostname, ports):
    '''Create ssh tunnels from localhost to a remote host when they don't
    already exist.'''
    if len(ports) > 0:
        cmdline = ['ps', 'xwww']
        connections = []
        for line in subprocess.check_output(' '.join(cmdline), shell=True,
                stderr=subprocess.STDOUT).decode(DEFAULT_ENCODING).splitlines():
            look = re.match('ssh', line)
            if look:
                connections += [line]
        tunnels = []
        for port in ports:
            found = False
            tunnel = port + '0:localhost:' + port
            for connection in connections:
                look = re.match(tunnel, connection)
                if look:
                    found = True
                    break
            if not found:
                tunnels += ['-L', tunnel]
        if len(tunnels) > 0:
            err = os.system(' '.join(['ssh', '-fN'] + tunnels + [hostname]))
            if err:
                raise Error("attempt to create ssh tunnels to "
                            + hostname + " failed.")


def validate_controls(dgen, dbindex, graph=False,
    priorities=[Step.configure, Step.install_native,
                Step.install_gem, Step.install_npm,
                Step.install_pip, Step.install,
                Step.update, Step.setup,
                Step.make]):
    '''Checkout source code files, install packages such that
    the projects specified in *repositories* can be built.
    *dbindex* is the project index that contains the dependency
    information to use. If None, the global index fetched from
    the remote machine will be used.

    This function returns a topologicaly sorted list of projects
    in *srcTop* and an associated dictionary of Project instances.
    By iterating through the list, it is possible to 'make'
    each prerequisite project in order.'''
    global ERRORS

    glob = ordered_prerequisites(dgen, dbindex, graph=graph)

    # \todo "make recurse" should update only projects which are missing
    # from *srcTop* and leave other projects in whatever state they are in.
    # This is different from "build" which should update all projects.
    for vertex in glob:
        if vertex.priority in priorities:
            errcode = 0
            elapsed = 0
            prev_cwd = os.getcwd()
            log_header(vertex.title)
            start = datetime.datetime.now()
            try:
                vertex.run(CONTEXT)
                finish = datetime.datetime.now()
                elapsed = elapsed_duration(start, finish)
            except Error as err:
                if True:
                    import traceback
                    traceback.print_exc()
                errcode = err.code
                ERRORS += [str(vertex)]
                if dgen.stop_make_after_error:
                    finish = datetime.datetime.now()
                    elapsed = elapsed_duration(start, finish)
                    log_footer(vertex.title, elapsed, errcode)
                    raise err
                else:
                    log_error(str(err))
            log_footer(vertex.title, elapsed, errcode)
            os.chdir(prev_cwd)

    nb_updated_projects = len(UpdateStep.updated_sources)
    if nb_updated_projects > 0:
        log_info("%d updated project(s)." % nb_updated_projects)
    else:
        log_info("all project(s) are up-to-date.")
    return nb_updated_projects


def version_candidates(line):
    '''Extract patterns from *line* that could be interpreted as a
    version numbers. That is every pattern that is a set of digits
    separated by dots and/or underscores.'''
    part = line
    candidates = []
    while part != '':
        # numbers should be full, i.e. including '.'
        look = re.match(r'[^0-9]*([0-9].*)', part)
        if look:
            part = look.group(1)
            look = re.match(r'[^0-9]*([0-9]+([_\.][0-9]+)+)+(.*)', part)
            if look:
                candidates += [look.group(1)]
                part = look.group(2)
            else:
                while (len(part) > 0
                       and part[0] in ['0', '1', '2', '3', '4', '5',
                                       '6', '7', '8', '9']):
                    part = part[1:]
        else:
            part = ''
    return candidates


def bin_version_candidates(binpath, variant=None):
    if variant is not None:
        # When looking for a specific *variant*, we do not
        # try to execute executables as they are surely
        # not meant to be run on the native system.
        return []
    numbers = []
    # We run the help flag before --version, -V
    # because bzip2 would wait on stdin for data
    # otherwise.
    for flag in ['--help', '--version', '-V']:
        numbers = []
        cmdline = [binpath, flag]
        try:
            output = subprocess.check_output(
                cmdline, stderr=subprocess.STDOUT).decode(DEFAULT_ENCODING)
            for line in output.splitlines():
                numbers += version_candidates(line)
        except subprocess.CalledProcessError:
            # When the command returns with an error
            # code, we assume we passed an incorrect
            # flag to retrieve the version number.
            numbers = []
        if len(numbers) > 0:
            break
    return numbers


def python_version(context):
    """
    Returns a name as typically expected for prefixes to site-packages.
    """
    dirname = context.bin_build_dir()
    link_name = os.path.join(dirname, 'python')
    if not os.path.exists(link_name):
        prev = os.getcwd()
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        os.chdir(dirname)
        os.symlink(os.path.relpath(sys.executable), 'python')
        os.chdir(prev)
    numbers = bin_version_candidates(link_name)
    version = '.'.join(numbers[0].split('.')[:2])
    return "python%s" % str(version)


def version_compare(left, right):
    '''Compare version numbers

    This function returns -1 if a *left* is less than *right*, 0 if *left
    is equal to *right* and 1 if *left* is greater than *right*.
    It is suitable as a custom comparaison function for sorted().'''
    left_remain = left.replace('_', '.').split('.')
    right_remain = right.replace('_', '.').split('.')
    while len(left_remain) > 0 and len(right_remain) > 0:
        left_num = left_remain.pop(0)
        right_num = right_remain.pop(0)
        if left_num < right_num:
            return -1
        elif left_num > right_num:
            return 1
    if len(left_remain) < len(right_remain):
        return -1
    elif len(left_remain) > len(right_remain):
        return 1
    return 0


def version_incr(ver_num):
    '''returns the version number with the smallest increment
    that is greater than *v*.'''
    return ver_num + '.1'

def build_subcommands_parser(parser, module):
    '''Returns a parser for the subcommands defined in the *module*
    (i.e. commands starting with a 'pub_' prefix).'''
    mdefs = module.__dict__
    keys = list(mdefs.keys())
    keys.sort()
    subparsers = parser.add_subparsers(help='sub-command help')
    for command in keys:
        if command.startswith('pub_'):
            func = module.__dict__[command]
            parser = subparsers.add_parser(command[4:], help=func.__doc__)
            parser.set_defaults(func=func)
            argspec = inspect.getargspec(func)
            flags = len(argspec.args)
            if argspec.defaults:
                flags = len(argspec.args) - len(argspec.defaults)
            if flags >= 1:
                for arg in argspec.args[:flags - 1]:
                    parser.add_argument(arg)
                parser.add_argument(argspec.args[flags - 1], nargs='*')
            short_opts = set([])
            for idx, arg in enumerate(argspec.args[flags:]):
                arg = arg.replace('_', '-')
                short_opt = arg[0]
                if not (arg.startswith('no') or (short_opt in short_opts)):
                    opts = ['-%s' % short_opt, '--%s' % arg]
                else:
                    opts = ['--%s' % arg]
                short_opts |= set([short_opt])
                if isinstance(argspec.defaults[idx], list):
                    parser.add_argument(*opts, action='append')
                elif isinstance(argspec.defaults[idx], dict):
                    parser.add_argument(*opts, type=json.loads)
                elif argspec.defaults[idx] is False:
                    parser.add_argument(*opts, action='store_true')
                elif argspec.defaults[idx] is not None:
                    parser.add_argument(*opts, default=argspec.defaults[idx])
                else:
                    parser.add_argument(*opts)


def filter_subcommand_args(func, options):
    '''Filter out all options which are not part of the function *func*
    prototype and returns a set that can be used as kwargs for calling func.'''
    kwargs = {}
    argspec = inspect.getargspec(func)
    for arg in argspec.args:
        if arg in options:
            kwargs.update({arg: getattr(options, arg)})
    return kwargs


def integrate(srcdir, pchdir, verbose=True):
    '''Replaces files in srcdir with links to files in pchdir
    for all files that match in the directory hierarchy.'''
    for name in os.listdir(pchdir):
        srcname = os.path.join(srcdir, name)
        pchname = os.path.join(pchdir, name)
        if (os.path.isdir(pchname)
            and not re.match(Repository.dirPats, os.path.basename(name))):
            integrate(srcname, pchname, verbose)
        else:
            if not name.endswith('~'):
                if not os.path.islink(srcname):
                    if verbose:
                        # Use sys.stdout and not log as the integrate command
                        # will mostly be emitted from a Makefile and thus
                        # trigger a "recursive" call to dws. We thus do not
                        # want nor need to open a new log file.
                        sys.stdout.write(srcname + '... patched\n')
                    # Change directory such that relative paths are computed
                    # correctly.
                    prev = os.getcwd()
                    dirname = os.path.dirname(srcname)
                    basename = os.path.basename(srcname)
                    if not os.path.isdir(dirname):
                        os.makedirs(dirname)
                    os.chdir(dirname)
                    if os.path.exists(basename):
                        shutil.move(basename, basename + '~')
                    os.symlink(os.path.relpath(pchname), basename)
                    os.chdir(prev)


def wait_until_ssh_up(hostname,
                      login=None, keyfile=None, port=None, timeout=120):
    '''wait until an ssh connection can be established to *hostname*
    or the attempt timed out after *timeout* seconds.'''
    is_up = False
    waited = 0
    cmdline = ['ssh',
               '-v',
               '-o', 'ConnectTimeout 30',
               '-o', 'BatchMode yes',
               '-o', 'StrictHostKeyChecking no']
    if port:
        cmdline += ['-p', str(port)]
    if keyfile:
        cmdline += ['-i', keyfile]
    ssh_connect = hostname
    if login:
        ssh_connect = login + '@' + hostname
    cmdline += [ssh_connect, 'echo']
    while (not is_up) and (waited <= timeout):
        try:
            subprocess.check_call(cmdline)
            is_up = True
        except subprocess.CalledProcessError:
            waited = waited + 30
            sys.stdout.write("waiting 30 more seconds (" \
                                 + str(waited) + " so far)...\n")
    if waited > timeout:
        raise Error("ssh connection attempt to " + hostname + " timed out.")


def log_init(context=None):
    if context is None:
        context = CONTEXT
    global LOGGER
    if not LOGGER:
        if os.path.exists(context.logname()):
            # We would rather not append to the previous logfile
            # but rather create a new one.
            os.remove(context.logname())
        logging.config.dictConfig({
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'simple': {
                'format': '%(message)s',
                'datefmt': '%d/%b/%Y:%H:%M:%S %z'
            },
        },
        'handlers': {
            'logfile':{
                'level': 'INFO',
                'class':'logging.handlers.WatchedFileHandler',
                'filename': context.logname(),
                'formatter': 'simple'
            },
            'logbuild':{
                'level': 'INFO',
                'class':'logging.handlers.WatchedFileHandler',
                'filename': context.logbuildname(),
                'formatter': 'simple'
            },
         },
        'loggers': {
            __name__: {
                'handlers': ['logfile'],
                'level': 'INFO',
                'propagate': True,
            },
            'build': {
                'handlers': ['logbuild'],
                'level': 'INFO',
                'propagate': True,
            }
        },
        })
    LOGGER = logging.getLogger(__name__)


def log_footer(prefix, elapsed=datetime.timedelta(), errcode=0):
    '''Write a footer into the log file.'''
    if not NO_LOG:
        if not LOGGER:
            log_init()
        if errcode > 0:
            LOGGER.info('%s: error after %s (%d)'
                        % (prefix, elapsed, errcode))
        else:
            LOGGER.info('%s: completed in %s' % (prefix, elapsed))


def log_header(message, *args, **kwargs):
    '''Write a header into the log file'''
    sys.stdout.write('######## ' + message + '...\n')
    if not NO_LOG:
        if not LOGGER:
            log_init()
        LOGGER.info('######## ' + message + '...')


def log_error(message, *args, **kwargs):
    '''Write an error message onto stdout and into the log file'''
    sys.stderr.write('error: ' + message)
    if not NO_LOG:
        if not LOGGER:
            log_init()
        LOGGER.error(message, *args, **kwargs)

def log_interactive(message):
    '''Write a message that should absolutely end up on the screen
    even when no newline is present at the end of the message.'''
    if PY3:
        sys.stdout.write(message)
    else:
        sys.stdout.write(message.encode(DEFAULT_ENCODING))
    sys.stdout.flush()
    if not NO_LOG:
        global LOGGER_BUFFER
        if not LOGGER_BUFFER:
            LOGGER_BUFFER = StringIO()
        LOGGER_BUFFER.write(message)


def log_info(message, context=None, nolog=None, *args, **kwargs):
    '''Write a info message onto stdout and into the log file'''
    message_line = "%s\n" % message
    if PY3:
        sys.stdout.write(message_line)
    else:
        sys.stdout.write(message_line.encode(DEFAULT_ENCODING))
    if nolog is None:
        nolog = NO_LOG
    if not nolog:
        global LOGGER_BUFFER
        if LOGGER_BUFFERING_COUNT > 0:
            if not LOGGER_BUFFER:
                LOGGER_BUFFER = StringIO()
            LOGGER_BUFFER.write((message_line % args) % kwargs)
        else:
            if not LOGGER:
                log_init(context=context)
            if LOGGER_BUFFER:
                LOGGER_BUFFER.write((message_line % args) % kwargs)
                for line in LOGGER_BUFFER.getvalue().splitlines():
                    LOGGER.info(line)
                LOGGER_BUFFER = None
            else:
                LOGGER.info(message, *args, **kwargs)


def pub_build(args, graph=False, clean=False,
              novirtualenv=False, nonative=False, python2=False):
    '''remoteIndex [ siteTop [ buildTop ] ]
    This command executes a complete build cycle:
      - (optional) delete all files in *siteTop*,
         *buildTop* and *installTop*.
      - fetch the build dependency file *remoteIndex*
      - setup third-party prerequisites through
        the appropriate package manager.
      - update a local source tree from remote
        repositories
      - (optional) apply local patches
      - configure required environment variables
      - make libraries, executables and tests.
      - (optional) send a report email.
    As such, this command is most useful as part
    of a cron job on build servers. Thus it is designed
    to run to completion with no human interaction.
    To be really useful in an automatic build system,
    authentication to the remote server (if required)
    should also be setup to run with no human
    interaction.
    ex: dws build http://hostname/everything.git
    --graph        Generate a .dot graph of the dependencies
    --clean        Backup *siteTop* and remove all subdirectories
                   before executing a build command.
    --novirtualenv Install pure python packages in
                   the system paths.
    --nonative     Do not attempt to install native packages
                   (otherwise sudo permissions are required)
    '''
    global USE_DEFAULT_ANSWER
    USE_DEFAULT_ANSWER = True
    CONTEXT.from_remote_index(args[0], nonative=nonative)
    # When CONTEXT.logDir is called before pub_build, the siteTop
    # will be set already.
    site_top = str(CONTEXT.environ['siteTop'])
    if not site_top:
        if len(args) > 1:
            site_top = os.path.abspath(args[1])
        else:
            site_top = os.path.join(os.getcwd(), CONTEXT.base('remoteIndex'))
        CONTEXT.environ['siteTop'].value = site_top
    if clean:
        # We don't want to remove the log we just created
        # so we buffer until it is safe to flush.
        global LOGGER_BUFFERING_COUNT
        LOGGER_BUFFERING_COUNT = LOGGER_BUFFERING_COUNT + 1
    build_top = str(CONTEXT.environ['buildTop'])
    if not build_top:
        if len(args) > 2:
            build_top = args[2]
        else:
            # Can't call *configure* before *locate*, otherwise config_filename
            # is set to be inside the buildTop on the first save.
            build_top = os.path.join(site_top, 'build')
        CONTEXT.environ['buildTop'].value = build_top
    prevcwd = os.getcwd()
    if not os.path.exists(build_top):
        os.makedirs(build_top)
    os.chdir(build_top)
    CONTEXT.locate(CONTEXT_FILENAME)
    if not str(CONTEXT.environ['installTop']):
        CONTEXT.environ['installTop'].configure(CONTEXT)
    install_top = str(CONTEXT.environ['installTop'])
    if clean:
        # First we backup everything in siteTop, buildTop and installTop
        # as we are about to remove those directories - just in case.
        tardirs = []
        for path in [site_top, build_top, install_top]:
            if os.path.isdir(path):
                tardirs += [path]
        if len(tardirs) > 0:
            prefix = os.path.commonprefix(tardirs)
            pkgbase = '%s-%s' % (os.path.basename(site_top), stamp())
            if os.path.samefile(prefix, site_top):
                # optimize common case: *buildTop* and *installTop* are within
                # *siteTop*. We cd into the parent directory to create the tar
                # in order to avoid 'Removing leading /' messages. Those do
                # not display the same on Darwin and Ubuntu, creating false
                # positive regressions between both systems.
                shell_command(create_tarball(pkgbase, site_top))
            else:
                shell_command(create_tarball(pkgbase, site_top, tardirs))
        os.chdir(prevcwd)
        for dirpath in [build_top, install_top]:
            # we only remove build_top and installTop. Can neither be too
            # prudent.
            if os.path.isdir(dirpath):
                # Test directory exists, in case it is a subdirectory
                # of another one we already removed.
                sys.stdout.write('removing ' + dirpath + '...\n')
                shutil.rmtree(dirpath)
        if not os.path.exists(build_top):
            os.makedirs(build_top)
        os.chdir(build_top)
        LOGGER_BUFFERING_COUNT = LOGGER_BUFFERING_COUNT - 1

    global NO_VIRTUALENV
    NO_VIRTUALENV = novirtualenv
    pip_executable = os.path.join(install_top, 'bin', 'pip')
    if not novirtualenv and not os.path.isfile(pip_executable):
        shell_command(find_virtualenv(CONTEXT, 2 if python2 else 3) + [
            '--system-site-packages', site_top])
        link_pat_path(
            'python', os.path.join(CONTEXT.value('binDir'), 'python'), 'bin')
        # Force upgrade of setuptools otherwise html5lib install complains.
        shell_command([pip_executable,
            '--log-file', os.path.join(CONTEXT.value('buildTop'), 'pip.log'),
            '--cache-dir', CONTEXT.obj_dir('.cache/pip'),
            'install', 'setuptools', '--upgrade'])

    rgen = DerivedSetsGenerator()
    # If we do not force the update of the index file, the dependency
    # graph might not reflect the latest changes in the repository server.
    INDEX.validate(True)
    INDEX.parse(rgen)
    # note that *EXCLUDE_PATS* and *CUSTOM_STEPS* are global.
    dgen = BuildGenerator(
        rgen.roots, [], exclude_pats=EXCLUDE_PATS, custom_steps=CUSTOM_STEPS)
    CONTEXT.targets = ['install']
    # Set the buildstamp that will be use by all "install" commands.
    if 'buildstamp' not in CONTEXT.environ:
        CONTEXT.environ['buildstamp'] = '-'.join([socket.gethostname(),
                                            stamp(datetime.datetime.now())])
    CONTEXT.save()
    validate_controls(dgen, INDEX, graph=graph)
    # Once we have built the repository, let's report the results.
    # We stamp the logfile such that it gets a unique name.
    logstamp = stampfile(CONTEXT.logname())
    if not os.path.exists(os.path.dirname(CONTEXT.log_path(logstamp))):
        os.makedirs(os.path.dirname(CONTEXT.log_path(logstamp)))
    if LOGGER:
        for handler in LOGGER.handlers:
            handler.flush()
    shell_command(['install', '-m', '644', CONTEXT.logname(),
                  CONTEXT.log_path(logstamp)])
    logging.getLogger('build').info(
        'build %s', str(UpdateStep.updated_sources))
    look = re.match(r'.*((-.+)?-\d\d\d\d_\d\d_\d\d-\d\d\.log)', logstamp)
    global LOG_PAT
    LOG_PAT = look.group(1)
    if len(ERRORS) > 0:
        raise Error("Found errors while making " + ' '.join(ERRORS))
    if CUSTOM_STEPS is not None:
        return [setup for setup in dgen.topological()
            if setup.__class__ in list(CUSTOM_STEPS.values())]
    return []


def pub_collect(args, output=None):
    '''[ project ... ]
    Consolidate local dependencies information
    into a global dependency database. Copy all
    distribution packages built into a platform
    distribution directory.
    (example: dws --exclude test collect)
    '''
    # Collect cannot log or it will prompt for index file.
    roots = []
    if len(args) > 0:
        for dir_name in args:
            roots += [os.path.join(CONTEXT.value('srcTop'), dir_name)]
    else:
        roots = [CONTEXT.value('srcTop')]
    # Name of the output index file generated by collect commands.
    collected_index = output
    if not collected_index:
        collected_index = CONTEXT.db_pathname()
    else:
        collected_index = os.path.abspath(collected_index)

    # Create the distribution directory, i.e. where packages are stored.
    package_dir = CONTEXT.local_dir('./resources/' + CONTEXT.host())
    if not os.path.exists(package_dir):
        os.makedirs(package_dir)
    src_package_dir = CONTEXT.local_dir('./resources/srcs')
    if not os.path.exists(src_package_dir):
        os.makedirs(src_package_dir)

    # Create the project index file
    # and copy the packages in the distribution directory.
    extensions = {'Darwin': (r'\.dsx', r'\.dmg'),
                  'CentOS': (r'\.spec', r'\.rpm'),
                  'Fedora': (r'\.spec', r'\.rpm'),
                  'Debian': (r'\.dsc', r'\.deb'),
                  'Ubuntu': (r'\.dsc', r'\.deb')}
    # collect index files and packages
    indices = []
    for root in roots:
        pre_exclude_indices = find_files(root, CONTEXT.indexName)
        for index in pre_exclude_indices:
            # We exclude any project index files that has been determined
            # to be irrelevent to the collection being built.
            found = False
            if index == collected_index:
                found = True
            else:
                for exclude_pat in EXCLUDE_PATS:
                    if re.match('.*' + exclude_pat + '.*', index):
                        found = True
                        break
            if not found:
                indices += [index]

    pkg_indices = []
    cpy_src_packages = None
    copy_bin_packages = None
    if str(CONTEXT.environ['buildTop']):
        # If there are no build directory, then don't bother to look
        # for built packages and avoid prompty for an unncessary value
        # for buildTop.
        for index in indices:
            buildr = os.path.dirname(index.replace(CONTEXT.value('buildTop'),
                                                   CONTEXT.value('srcTop')))
            src_packages = find_files(buildr, '.tar.bz2')
            if len(src_packages) > 0:
                cmdline, prefix = find_rsync(
                    CONTEXT.remote_host(), context=CONTEXT)
                cpy_src_packages = cmdline + [
                    ' '.join(src_packages), src_package_dir]
            if CONTEXT.host() in extensions:
                ext = extensions[CONTEXT.host()]
                pkg_indices += find_files(buildr, ext[0])
                bin_packages = find_files(buildr, ext[1])
                if len(bin_packages) > 0:
                    cmdline, prefix = find_rsync(
                        CONTEXT.remote_host(), context=CONTEXT)
                    copy_bin_packages = cmdline + [' '.join(bin_packages),
                                                  package_dir]

    # Create the index and checks it is valid according to the schema.
    create_index_pathname(collected_index, indices + pkg_indices)
    shell_command(['xmllint', '--noout', '--schema ',
                  CONTEXT.derived_helper('index.xsd'), collected_index])
    # We should only copy the index file after we created it.
    if copy_bin_packages:
        shell_command(copy_bin_packages)
    if cpy_src_packages:
        shell_command(cpy_src_packages)


def pub_configure(args):
    '''Locate direct dependencies of a project on
    the local machine and create the appropriate
    symbolic links such that the project can be made
    later on.
    '''
    dbindex = IndexProjects(CONTEXT, CONTEXT.src_dir(
        os.path.join(CONTEXT.cwd_project(), CONTEXT.indexName)))
    project_name = CONTEXT.cwd_project()
    dgen = MakeGenerator([project_name], [])
    dbindex.parse(dgen)
    prerequisites = set([])
    for vertex in dgen.vertices:
        if vertex.endswith('Setup'):
            setup = dgen.vertices[vertex]
            if not setup.run(CONTEXT):
                prerequisites |= set([str(setup.project)])
        elif vertex.startswith('update_'):
            update = dgen.vertices[vertex]
            if len(update.fetches) > 0:
                for miss in update.fetches:
                    prerequisites |= set([miss])
    if len(prerequisites) > 0:
        raise MissingError(project_name, prerequisites)


def pub_context(args):
    '''[ file ]
    Prints the absolute pathname to a *file*.
    If the file cannot be found from the current
    directory up to the workspace root, i.e where
    the .mk fragment is located (usually *buildTop*,
    it assumes the file is in *shareDir* alongside
    other make helpers.
    '''
    pathname = CONTEXT.config_filename
    if len(args) >= 1:
        try:
            _, pathname = search_back_to_root(args[0],
                   os.path.dirname(CONTEXT.config_filename))
        except IOError:
            pathname = CONTEXT.derived_helper(args[0])
    sys.stdout.write(pathname)


def pub_deps(args, native=False):
    """
    Prints the statement used to install native and language packaged
    prerequisites.
    --native   Display only the prerequisites installed through
               the native package manager.
    """
    top = os.path.realpath(os.getcwd())
    if ((str(CONTEXT.environ['buildTop'])
         and top.startswith(os.path.realpath(CONTEXT.value('buildTop')))
         and top != os.path.realpath(CONTEXT.value('buildTop')))
        or (str(CONTEXT.environ['srcTop'])
            and top.startswith(os.path.realpath(CONTEXT.value('srcTop')))
            and top != os.path.realpath(CONTEXT.value('srcTop')))):
        roots = [CONTEXT.cwd_project()]
    else:
        # make from the top directory makes every project in the index file.
        rgen = DerivedSetsGenerator()
        INDEX.parse(rgen)
        roots = rgen.roots
    dgen = PubDepsGenerator(roots, [], exclude_pats=EXCLUDE_PATS)
    builds = []
    for step in ordered_prerequisites(dgen, INDEX):
        if isinstance(step, InstallStep):
            if not native or step.priority == Step.install_native:
                cmds = step.install_commands(step.get_installs(), CONTEXT)
                for cmd, admin, noexecute in cmds:
                    sys.stdout.write("%s\n" % ' '.join(cmd))
        elif isinstance(step, BuildStep):
            builds += [step.qualified_project_name()]
    if not native:
        sys.stdout.write("build: %s\n" % ' '.join(builds))


def pub_dockerfile(args):
    """dockerfile_template
    Create a Dockerfile in *siteTop* from a template file and the workspace
    context.
    """
    if len(args) < 1:
        raise Error("usage: dws dockerfile *dockerfile_template_path*")
    dockerfile_template_path = args[0]
    with open(dockerfile_template_path) as dockerfile_template_file:
        dockerfile_template = dockerfile_template_file.readlines()
    look = re.match(r'FROM (\S+):.*', dockerfile_template[0])
    if look:
        CONTEXT.environ['distHost'] = look.group(1).capitalize()
    rgen = DerivedSetsGenerator()
    INDEX.parse(rgen)
    dgen = PubDepsGenerator(rgen.roots, [], exclude_pats=EXCLUDE_PATS)
    native_prerequisites = ""
    app_name = rgen.roots[0]
    for step in ordered_prerequisites(dgen, INDEX):
        if isinstance(step, InstallStep):
            if step.priority == Step.install_native:
                cmds = step.install_commands(step.get_installs(), CONTEXT)
                sep = ""
                for cmd, _, _ in cmds:
                    native_prerequisites += "%s%s" % (sep, ' '.join(cmd))
                    sep = "\nRUN "
    sys.stdout.write(''.join(dockerfile_template) % {
        'native_prerequisites': native_prerequisites,
        'app_name': app_name,
        'site_top': '/var/www/%s' % app_name,
        'bin_dir': '/var/www/%s/bin' % app_name,
        'lib_dir': '/var/www/%s/lib' % app_name,
        'src_top': '/var/www/%s/reps' % app_name,
        'share_dir': '/var/www/%s/share' % app_name,
        'etc_dir': '/var/www/%s/etc' % app_name
    })


def pub_export(args):
    '''rootpath
    Exports the project index file in a format
    compatible with Jenkins. [experimental]
    '''
    rootpath = args[0]
    top = os.path.realpath(os.getcwd())
    if (top == os.path.realpath(CONTEXT.value('buildTop'))
        or top == os.path.realpath(CONTEXT.value('srcTop'))):
        rgen = DerivedSetsGenerator()
        INDEX.parse(rgen)
        roots = rgen.roots
    else:
        roots = [CONTEXT.cwd_project()]
    handler = Unserializer(roots)
    if os.path.isfile(CONTEXT.db_pathname()):
        INDEX.parse(handler)
    for name in roots:
        jobdir = os.path.join(rootpath, name)
        if not os.path.exists(jobdir):
            os.makedirs(os.path.join(jobdir, 'builds'))
            os.makedirs(os.path.join(jobdir, 'workspace'))
            with open(os.path.join(jobdir, 'nextBuildNumber'), 'w') as \
                    next_build_number:
                next_build_number.write('0\n')
        project = handler.projects[name]
        rep = project.repository.update.rep
        config = open(os.path.join(jobdir, 'config.xml'), 'w')
        config.write('''<?xml version='1.0' encoding='UTF-8'?>
<project>
  <actions/>
  <description>''' + project.descr + '''</description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <scm class="hudson.plugins.git.GitSCM">
    <configVersion>2</configVersion>
    <userRemoteConfigs>
      <hudson.plugins.git.UserRemoteConfig>
        <name>origin</name>
        <refspec>+refs/heads/*:refs/remotes/origin/*</refspec>
        <url>''' + rep.url + '''</url>
      </hudson.plugins.git.UserRemoteConfig>
    </userRemoteConfigs>
    <branches>
      <hudson.plugins.git.BranchSpec>
        <name>**</name>
      </hudson.plugins.git.BranchSpec>
    </branches>
    <recursiveSubmodules>false</recursiveSubmodules>
    <doGenerateSubmoduleConfigurations>false</doGenerateSubmoduleConfigurations>
    <authorOrCommitter>false</authorOrCommitter>
    <clean>false</clean>
    <wipeOutWorkspace>false</wipeOutWorkspace>
    <pruneBranches>false</pruneBranches>
    <remotePoll>false</remotePoll>
    <buildChooser class="hudson.plugins.git.util.DefaultBuildChooser"/>
    <gitTool>Default</gitTool>
    <submoduleCfg class="list"/>
    <relativeTargetDir>''' + os.path.join('reps', name)+ '''</relativeTargetDir>
    <excludedRegions></excludedRegions>
    <excludedUsers></excludedUsers>
    <gitConfigName></gitConfigName>
    <gitConfigEmail></gitConfigEmail>
    <skipTag>false</skipTag>
    <scmName></scmName>
  </scm>
  <canRoam>true</canRoam>
  <disabled>false</disabled>
  <blockBuildWhenDownstreamBuilding>true</blockBuildWhenDownstreamBuilding>
  <blockBuildWhenUpstreamBuilding>false</blockBuildWhenUpstreamBuilding>
  <triggers class="vector">
    <hudson.triggers.SCMTrigger>
      <spec></spec>
    </hudson.triggers.SCMTrigger>
  </triggers>
  <concurrentBuild>false</concurrentBuild>
  <builders>
    <hudson.tasks.Shell>
      <command>
cd ''' + os.path.join('build', name) + '''
dws configure
dws make
      </command>
    </hudson.tasks.Shell>
  </builders>
  <publishers />
  <buildWrappers/>
</project>
''')
        config.close()


def pub_find(args):
    '''bin|lib filename ...
    Search through a set of directories derived
    from PATH for *filename*.
    '''
    dir_name = args[0]
    command = 'find_' + dir_name
    searches = []
    for arg in args[1:]:
        searches += [(arg, None)]
    installed, _, complete = \
        getattr(sys.modules[__name__], command)(
        searches, CONTEXT.search_path(dir_name), CONTEXT.value('buildTop'))
    if len(installed) != len(searches):
        sys.exit(1)


def pub_init(args):
    '''    Prompt for variables which have not been
    initialized in the workspace make fragment.
    (This will fetch the project index).
    '''
    config_var(CONTEXT, CONTEXT.environ)
    INDEX.validate()


def pub_install(args):
    ''' [ binPackage | project ... ]
     Install a package *binPackage* on the local system
     or a binary package associated to *project*
     through either a *package* or *patch* node in the
     index database or through the local package
     manager.
    '''
    INDEX.validate()
    install(args, INDEX)


def pub_integrate(args):
    '''[ srcPackage ... ]
    Integrate a patch into a source package
    '''
    while len(args) > 0:
        srcdir = unpack(args.pop(0))
        pchdir = CONTEXT.src_dir(os.path.join(CONTEXT.cwd_project(),
                                             srcdir + '-patch'))
        integrate(srcdir, pchdir)


class FilteredList(PdbHandler):
    '''Print a list binary package files specified in an index file.'''
    # Note: This code is used by dservices.

    def __init__(self):
        PdbHandler.__init__(self)
        self.first_time = True
        self.fetches = []

    def project(self, proj_obj):
        host = CONTEXT.host()
        if host in proj_obj.packages and proj_obj.packages[host]:
            if len(proj_obj.packages[host].update.fetches) > 0:
                for file_to_fetch in proj_obj.packages[host].update.fetches:
                    self.fetches += [file_to_fetch]


class ListPdbHandler(PdbHandler):
    '''List project available in the workspace.'''

    def __init__(self):
        PdbHandler.__init__(self)
        self.first_time = True

    def project(self, proj):
        if self.first_time:
            sys.stdout.write('HEAD                                     name\n')
            self.first_time = False
        if os.path.exists(CONTEXT.src_dir(proj.name)):
            prev = os.getcwd()
            os.chdir(CONTEXT.src_dir(proj.name))
            cmdline = ' '.join(['git', 'rev-parse', 'HEAD'])
            lines = subprocess.check_output(cmdline, shell=True,
                stderr=subprocess.STDOUT).decode(DEFAULT_ENCODING).splitlines()
            sys.stdout.write(' '.join(lines).strip() + ' ')
            os.chdir(prev)
        sys.stdout.write(proj.name + '\n')


def pub_list(args):
    '''    List available projects
    '''
    INDEX.parse(ListPdbHandler())


def pub_make(args, graph=False):
    """    Make projects. `make recurse` will build
    all dependencies required before a project
    can be itself built.
    `make recurse` will install prerequisites available
    through package managers as needed but won't update
    source repositories nor download asset files.
    For a full-blown update/compile look at the `build`
    command.
    """
    # \todo That should not be required:
    # context.environ['siteTop'].default = os.path.dirname(os.path.dirname(
    #    os.path.realpath(os.getcwd())))
    CONTEXT.targets = []
    recurse = False
    top = os.path.realpath(os.getcwd())
    if (top == os.path.realpath(CONTEXT.value('buildTop'))
        or top == os.path.realpath(CONTEXT.value('srcTop'))):
        # make from the top directory makes every project in the index file.
        rgen = DerivedSetsGenerator()
        INDEX.parse(rgen)
        roots = rgen.roots
        recurse = True
    else:
        roots = [CONTEXT.cwd_project()]
    for opt in args:
        if opt == 'recurse':
            CONTEXT.targets += ['install']
            recurse = True
            global NO_FETCH
            NO_FETCH = True
        elif re.match(r'\S+=.*', opt):
            CONTEXT.overrides += [opt]
        else:
            CONTEXT.targets += [opt]
    if recurse:
        # note that *EXCLUDE_PATS* is global.
        validate_controls(
            MakeGenerator(roots, [], EXCLUDE_PATS), INDEX, graph=graph)
    else:
        handler = Unserializer(roots)
        if os.path.isfile(CONTEXT.db_pathname()):
            INDEX.parse(handler)

        for name in roots:
            make = None
            src_dir = CONTEXT.src_dir(name)
            if os.path.exists(src_dir):
                if name in handler.projects:
                    rep = handler.as_project(name).repository
                    if not rep:
                        rep = handler.as_project(name).patch
                    make = rep.make
                else:
                    # No luck we do not have any more information than
                    # the directory name. Let's do with that.
                    make = MakeStep(name)
                if make:
                    make.run(CONTEXT)
    if len(ERRORS) > 0:
        raise Error("Found errors while making " + ' '.join(ERRORS))


def pub_patch(args):
    '''    Generate patches vs. the last pull from a remote
    repository, optionally send it to a list
    of receipients.
    '''
    reps = args
    recurse = False
    if 'recurse' in args:
        recurse = True
        reps.remove('recurse')
    reps = cwd_projects(reps, recurse)
    prev = os.getcwd()
    for rep in reps:
        patches = []
        log_info("######## generating patch for project %s" % rep)
        os.chdir(CONTEXT.src_dir(rep))
        patch_dir = CONTEXT.patch_dir(rep)
        if not os.path.exists(patch_dir):
            os.makedirs(patch_dir)
        cmdline = ['git', 'format-patch', '-o', patch_dir, 'origin']
        for line in subprocess.check_output(' '.join(cmdline), shell=True,
                stderr=subprocess.STDOUT).decode(DEFAULT_ENCODING).splitlines():
            patches += [line.strip()]
            sys.stdout.write(line)
        for patch in patches:
            with open(patch) as msgfile:
                msg = msgfile.readlines()
                msg = ''.join(msg[1:])
            sendmail(msg, MAILTO)
    os.chdir(prev)


def pub_push(args):
    '''    Push commits to projects checked out
    in the workspace.
    '''
    reps = args
    recurse = False
    if 'recurse' in args:
        recurse = True
        reps.remove('recurse')
    reps = cwd_projects(reps, recurse)
    for rep in reps:
        sys.stdout.write('######## pushing project ' + str(rep) + '\n')
        src_dir = CONTEXT.src_dir(rep)
        svc = Repository.associate(src_dir)
        svc.push(src_dir)


def pub_status(args, recurse=False):
    '''    Show status of projects checked out
    in the workspace with regards to commits.
    '''
    reps = cwd_projects(args, recurse)

    cmdline = 'git status'
    prev = os.getcwd()
    for rep in reps:
        os.chdir(CONTEXT.src_dir(rep))
        try:
            output = subprocess.check_output(cmdline, shell=True,
                stderr=subprocess.STDOUT).decode(DEFAULT_ENCODING)
            untracked = False
            for line in output.splitlines():
                look = re.match(r'#?\s*([a-z]+):\s+(\S+)', line)
                if look:
                    sys.stdout.write(' '.join([
                                look.group(1).capitalize()[0],
                                rep, look.group(2)]) + '\n')
                elif re.match(r'#?\s*Untracked files:', line):
                    untracked = True
                elif untracked:
                    look = re.match(r'#?\s+([A-Za-z0-9_\-/]+)', line)
                    if look:
                        sys.stdout.write(
                            ' '.join(['?', rep, look.group(1)]) + '\n')
        except subprocess.CalledProcessError:
            # It is ok. git will return error code 1 when no changes
            # are to be committed.
            pass
    os.chdir(prev)


def pub_update(args):
    '''[ project ... ]
    Update projects that have a *repository* or *patch*
    node in the index database and are also present in
    the workspace by pulling changes from the remote
    server. "update recurse" will recursively update all
    dependencies for *project*.
    If a project only contains a *package* node in
    the index database, the local system will be
    modified only if the version provided is greater
    than the version currently installed.
    '''
    reps = args
    recurse = False
    if 'recurse' in args:
        recurse = True
        reps.remove('recurse')
    INDEX.validate(True)
    reps = cwd_projects(reps)
    if recurse:
        # note that *EXCLUDE_PATS* is global.
        dgen = MakeGenerator(reps, [], EXCLUDE_PATS)
        validate_controls(dgen, INDEX)
    else:
        global ERRORS
        handler = Unserializer(reps)
        INDEX.parse(handler)
        for name in reps:
            # The project is present in *srcTop*, so we will update the source
            # code from a repository.
            update = None
            if not name in handler.projects:
                # We found a directory that contains source control information
                # but which is not in the interdependencies index file.
                src_dir = CONTEXT.src_dir(name)
                if os.path.exists(src_dir):
                    update = UpdateStep(
                        name, Repository.associate(src_dir), None)
            else:
                update = handler.as_project(name).repository.update
                if not update:
                    update = handler.as_project(name).patch.update
            if update:
                # Not every project is made a first-class citizen. If there are
                # no rep structure for a project, it must depend on a project
                # that does in order to have a source repled repository.
                # This is a simple way to specify inter-related projects
                # with complex dependency set and barely any code.
                # \todo We do not propagate force= here to avoid messing up
                #       the local checkouts on pubUpdate()
                try:
                    log_header(update.title)
                    update.run(CONTEXT)
                    log_footer(update.title)
                except Error as err:
                    log_info("warning: cannot update repository from %s"
                        % str(update.rep.url))
                    log_footer(update.title, errcode=err.code)
            else:
                ERRORS += [name]
        if len(ERRORS) > 0:
            raise Error("%s is/are not project(s) under source control."
                        % ' '.join(ERRORS))
        nb_updated_projects = len(UpdateStep.updated_sources)
        if nb_updated_projects > 0:
            log_info("%d updated project(s)." % nb_updated_projects)
        else:
            log_info("all project(s) are up-to-date.")


def pub_upstream(args):
    '''[ srcPackage ... ]
    Generate a patch to submit to upstream
    maintainer out of a source package and
    a -patch subdirectory in a project src_dir.
    '''
    while len(args) > 0:
        pkgfilename = args.pop(0)
        srcdir = unpack(pkgfilename)
        orgdir = srcdir + '.orig'
        if os.path.exists(orgdir):
            shutil.rmtree(orgdir, ignore_errors=True)
        shutil.move(srcdir, orgdir)
        srcdir = unpack(pkgfilename)
        pchdir = CONTEXT.src_dir(os.path.join(CONTEXT.cwd_project(),
                                             srcdir + '-patch'))
        integrate(srcdir, pchdir)
        # In the common case, no variables will be added to the workspace
        # make fragment when the upstream command is run. Hence sys.stdout
        # will only display the patched information. This is important to be
        # able to execute:
        #   dws upstream > patch
        cmdline = ['diff', '-ruNa', orgdir, srcdir]
        subprocess.call(' '.join(cmdline), shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def select_checkout(rep_candidates, package_candidates):
    '''Interactive prompt for a selection of projects to checkout.
    *rep_candidates* contains a list of rows describing projects available
    for selection. This function will return a list of projects to checkout
    from a source repository and a list of projects to install through
    a package manager.'''
    reps = []
    if len(rep_candidates) > 0:
        reps = select_multiple(
'''The following dependencies need to be present on your system.
You have now the choice to install them from a source repository. You will
later have the choice to install them from either a patch, a binary package
or not at all.''',
        rep_candidates)
    # Filters out the dependencies which the user has decided to install
    # from a repository.
    packages = []
    for row in package_candidates:
        if not row[0] in reps:
            packages += [row]
    packages = select_install(packages)
    return reps, packages


def select_install(package_candidates):
    '''Interactive prompt for a selection of projects to install
    as binary packages. *package_candidates* contains a list of rows
    describing projects available for selection. This function will
    return a list of projects to install through a package manager. '''
    packages = []
    if len(package_candidates) > 0:
        packages = select_multiple(
    '''The following dependencies need to be present on your system.
You have now the choice to install them from a binary package. You can skip
this step if you know those dependencies will be resolved correctly later on.
''', package_candidates)
    return packages


def select_one(description, choices, sort=True):
    '''Prompt an interactive list of choices and returns the element selected
    by the user. *description* is a text that explains the reason for the
    prompt. *choices* is a list of elements to choose from. Each element is
    in itself a list. Only the first value of each element is of significance
    and returned by this function. The other values are only use as textual
    context to help the user make an informed choice.'''
    choice = None
    if sort:
        # We should not sort 'Enter ...' choices for pathnames else we will
        # end-up selecting unexpected pathnames by default.
        choices.sort()
    while True:
        show_multiple(description, choices)
        if USE_DEFAULT_ANSWER:
            selection = "1"
        else:
            selection = prompt("Enter a single number [1]: ")
            if selection == "":
                selection = "1"
        try:
            choice = int(selection)
            if choice >= 1 and choice <= len(choices):
                choice = choices[choice - 1][0]
                break
        except TypeError:
            choice = None
        except ValueError:
            choice = None
    return choice


def select_multiple(description, selects):
    '''Prompt an interactive list of choices and returns elements selected
    by the user. *description* is a text that explains the reason for the
    prompt. *choices* is a list of elements to choose from. Each element is
    in itself a list. Only the first value of each element is of significance
    and returned by this function. The other values are only use as textual
    context to help the user make an informed choice.'''
    result = []
    done = False
    selects.sort()
    choices = [['all']] + selects
    while len(choices) > 1 and not done:
        show_multiple(description, choices)
        log_info("%d) done", len(choices) + 1)
        if USE_DEFAULT_ANSWER:
            selection = "1"
        else:
            selection = prompt(
                "Enter a list of numbers separated by spaces [1]: ")
            if len(selection) == 0:
                selection = "1"
        # parse the answer for valid inputs
        selection = selection.split(' ')
        for sel in selection:
            try:
                choice = int(sel)
            except TypeError:
                choice = 0
            except ValueError:
                choice = 0
            if choice > 1 and choice <= len(choices):
                result += [choices[choice - 1][0]]
            elif choice == 1:
                result = []
                for choice_value in choices[1:]:
                    result += [choice_value[0]]
                done = True
            elif choice == len(choices) + 1:
                done = True
        # remove selected items from list of choices
        remains = []
        for row in choices:
            if not row[0] in result:
                remains += [row]
        choices = remains
    return result


def select_yes_no(description):
    '''Prompt for a yes/no answer.'''
    if USE_DEFAULT_ANSWER:
        return True
    yes_no = prompt("%s [Y/n]? " % description)
    if yes_no == '' or yes_no == 'Y' or yes_no == 'y':
        return True
    return False


def show_multiple(description, choices):
    '''Returns a list of choices on the user interface as a string.
    We do this instead of printing directly because this function
    is called to configure CONTEXT variables, including *logDir*.'''
    # Compute display layout
    widths = []
    displayed = []
    for item, row in enumerate(choices, start=1):
        line = []
        for col_index, column in enumerate([str(item) + ')'] + row):
            col = column
            if isinstance(col, dict):
                if 'description' in column:
                    col = column['description'] # { description: ... }
                else:
                    col = ""
            line += [col]
            if len(widths) <= col_index:
                widths += [2]
            widths[col_index] = max(widths[col_index], len(col) + 2)
        displayed += [line]
    # Ask user to review selection
    log_info("%s" % description)
    for project in displayed:
        for col_index, col in enumerate(project):
            log_info(col.ljust(widths[col_index]))


def create_tarball(pkgbase, site_top, inputs=None):
    """
    Create a package.
    """
    if not inputs:
        inputs = [os.path.basename(site_top)]
    if os.path.exists('/usr/bin/bzip2'):
        pkgflag = 'j'
        tarname = pkgbase + '.tar.bz2'
    else:
        pkgflag = 'z'
        tarname = pkgbase + '.tar.gz'
    return ['cd', os.path.dirname(site_top),
            '&&', 'tar', pkgflag + 'cf', tarname] + inputs


def unpack(pkgfilename):
    '''unpack a tar[.gz|.bz2] source distribution package.'''
    if pkgfilename.endswith('.bz2'):
        pkgflag = 'j'
    elif pkgfilename.endswith('.gz'):
        pkgflag = 'z'
    shell_command(['tar', pkgflag + 'xf', pkgfilename])
    return os.path.basename(os.path.splitext(
               os.path.splitext(pkgfilename)[0])[0])


def main(args):
    '''Main Entry Point'''

    exit_code = 0
    start_timestamp = datetime.datetime.now()
    try:
        import __main__
        import argparse

        global CONTEXT
        CONTEXT = Context()
        keys = list(CONTEXT.environ.keys())
        keys.sort()
        epilog = 'Variables defined in the workspace make fragment (' \
            + CONTEXT.config_name + '):\n'
        for varname in keys:
            var = CONTEXT.environ[varname]
            if var.descr:
                epilog += ('  ' + var.name).ljust(23, ' ') + var.descr + '\n'

        parser = argparse.ArgumentParser(
            usage='%(prog)s [options] command\n\nVersion\n  %(prog)s version '
            + str(__version__),
            formatter_class=argparse.RawTextHelpFormatter, epilog=epilog)
        parser.add_argument('--version', action='version',
                            version='%(prog)s ' + str(__version__))
        parser.add_argument('--context', dest='context', action='store',
            help='Set the path to the context file instead of deriving it'\
' from the current directory.')
        parser.add_argument('--default', dest='default', action='store_true',
            help='Use default answer for every interactive prompt.')
        parser.add_argument('-D', dest='defines', action='append', default=[],
            help='Add a (key,value) definition to use in templates.')
        parser.add_argument('--exclude', dest='exclude_pats', action='append',
            help='The specified command will not be applied to projects'\
' matching the name pattern.')
        parser.add_argument('--nolog', dest='nolog', action='store_true',
            help='Do not generate output in the log file')
        parser.add_argument('--nofetch', dest='nofetch', action='store_true',
            help='Do not fetch asset files (i.e. outside source control)')
        parser.add_argument('--patch', dest='patchTop', action='store',
            help='Set *patchTop* the root where local patches can be found.')
        parser.add_argument('--prefix', dest='installTop', action='store',
            help='Set the root for installed bin, include, lib, etc. ')
        parser.add_argument('--mailto', dest='mailto', action='append',
            help='Add an email address to send log reports to')
        parser.add_argument('--rsyncto', dest='rsyncto', action='append',
            help='Upload log files to remote host')
        parser.add_argument('-u', '--user', dest='user', action='store',
            help='Run as user')
        parser.add_argument('-g', '--group', dest='group', action='store',
            help='Run as group')
        build_subcommands_parser(parser, __main__)

        if len(args) <= 1:
            parser.print_help()
            return 1

        if args[1] == 'help-book':
            # Print help in docbook format.
            # We need the parser here so we can't create a pub_ function
            # for this command.
            help_str = StringIO()
            parser.print_help(help_str)
            help_book(help_str)
            return 0

        options = parser.parse_args(args[1:])

        if options.user or options.group:
            import pwd
            if options.user:
                global USER
                USER = os.getuid()
                os.seteuid(pwd.getpwnam(options.user).pw_uid)
            if options.group:
                global GROUP
                GROUP = os.getgid()
                os.setegid(pwd.getpwnam(options.user).pw_gid)

        # Find the build information
        global USE_DEFAULT_ANSWER
        USE_DEFAULT_ANSWER = options.default
        global NO_FETCH, NO_LOG
        NO_FETCH = options.nofetch
        NO_LOG = options.nolog
        if options.exclude_pats:
            global EXCLUDE_PATS
            EXCLUDE_PATS = options.exclude_pats
        if options.context:
            global CONTEXT_FILENAME
            CONTEXT_FILENAME = options.context

        if not options.func in [pub_build]:
            # The *build* command is special in that it does not rely
            # on locating a pre-existing context file.
            try:
                CONTEXT.locate(CONTEXT_FILENAME)
            except IOError:
                pass
            except:
                raise
        if options.installTop:
            CONTEXT.environ['installTop'] = os.path.abspath(options.installTop)
        if options.patchTop:
            CONTEXT.environ['patchTop'] = os.path.abspath(options.patchTop)

        for define in options.defines:
            key, value = define.split('=')
            CONTEXT.environ[key] = value

        global INDEX
        INDEX = IndexProjects(CONTEXT)
        # Filter out options with are not part of the function prototype.
        func_args = filter_subcommand_args(options.func, options)
        options.func(**func_args)

    except Error as err:
        log_error(str(err))
        exit_code = err.code

    if options.mailto and len(options.mailto) > 0 and LOG_PAT:
        logs = find_files(CONTEXT.log_path(''), LOG_PAT)
        log_info("forwarding logs %s..." % ' '.join(logs))
        sendmail(createmail('build report', logs), options.mailto)
    if options.rsyncto and len(options.rsyncto) > 0 and LOG_PAT:
        log_dir = CONTEXT.log_path('')
        logs = find_files(log_dir, LOG_PAT)
        log_info("uploading logs %s..." % ' '.join(logs))
        logs = [log.replace(log_dir, log_dir + './') for log in logs]
        for remote_path in options.rsyncto:
            upload(logs, remote_path)

    return exit_code


if __name__ == '__main__':
    sys.exit(main(sys.argv))
