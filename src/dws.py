#!/usr/bin/env python
#
# Copyright (c) 2009-2010, Fortylines LLC
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of fortylines nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY Fortylines LLC ''AS IS'' AND ANY
#   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL Fortylines LLC BE LIABLE FOR ANY
#   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# This script implements workspace management.
#
# The workspace manager script is used to setup a local machine
# with third-party prerequisites and source code under revision
# control such that it is possible to execute a development cycle
# (edit/build/run) on a local machine.
#
# Primary Author(s): Sebastien Mirolo <smirolo@fortylines.com>

__version__ = None

import datetime, hashlib, re, os, optparse, shutil
import socket, subprocess, sys, tempfile, urllib2, urlparse
import xml.dom.minidom, xml.sax
import cStringIO

modself = sys.modules[__name__]

# Object that implements logging into an XML formatted file 
# what gets printed on sys.stdout.
log = None
# When True, the log object is not used and output is only
# done on sys.stdout.
nolog = False
# When True, all commands invoked through shellCommand() are printed
# but not executed.
doNotExecute = False
# *uploadResults* is false by default such that everyone can download and build
# the source repository locally but only users with an account can upload to
# to the forum server.
uploadResults = False
# When True, the script runs in batch mode and assumes the default answer
# for every question where it would have prompted the user for an answer.
useDefaultAnswer = False
# When processing a project dependency index file, all project names matching 
# one of the *excludePats* will be considered non-existant.
excludePats = []


class Error(Exception):
    '''This type of exception is used to identify "expected" 
    error condition and will lead to a useful message. 
    Other exceptions are not caught when *__main__* executes,
    and an internal stack trace will be displayed. Exceptions
    which are not *Error*s are concidered bugs in the workspace 
    management script.'''
    def __init__(self, msg='unknow error', code=1, projectName=None):
        self.code = code
        self.msg = msg
        self.projectName = projectName

    def __str__(self):
        if self.projectName:
            return ':'.join([self.projectName,str(self.code),' error']) \
                + ' ' + self.msg + '\n'
        return 'error: ' + self.msg + ' (error ' + str(self.code) + ')\n' 


class CircleError(Error):
    '''Thrown when a circle has been detected while doing
    a topological traversal of a graph.'''
    def __init__(self,source,target):
        Error.__init__(self,msg="circle exception while traversing edge from " \
                           + str(source) + " to " + str(target))


class MissingError(Error):
    '''This error is thrown whenever a project has missing prerequisites.'''
    def __init__(self, projectName, prerequisites):
        Error.__init__(self,'The following prerequisistes are missing: ' \
                           + ' '.join(prerequisites),2,projectName)


class Context:
    '''The workspace configuration file contains environment variables used
    to update, build and package projects. The environment variables are roots
    of the general dependency graph as most other routines depend at the least 
    on srcTop and buildTop.'''

    configName = 'dws.mk'
    indexName = 'dws.xml'

    def __init__(self):
        siteTop = Pathname('siteTop',
                          'Root of the tree where the website is generated and thus where *remoteSiteTop* is cached on the local system',
                          default=os.getcwd())
        remoteSiteTop = Pathname('remoteSiteTop',
             'Root of the remote tree that holds the published website (ex: url:/var/cache).',
                  default='')
        installTop = Pathname('installTop',
                    'Root of the tree for installed bin/, include/, lib/, ...',
                          siteTop,default='')
        # We use installTop (previously siteTop), such that a command like
        # "dws build remoteIndexFile *siteTop*" run from a local build 
        # directory creates intermediate and installed files there while
        # checking out the sources under siteTop. 
        # It might just be my preference...
        # \todo we cannot have a dependency siteTop -> installTop -> buildTop
        #       right now because the user prompt logic is not recursive :(.
        buildTop = Pathname('buildTop',
                    'Root of the tree where intermediate files are created.',
                            siteTop,default='build')
        self.srcTop = Pathname('srcTop',
             'Root of the tree where the source code under revision control lives on the local machine.',siteTop,default='reps')
        self.environ = { 'buildTop': buildTop, 
                         'srcTop' : self.srcTop,
                         'makeHelperDir': Pathname('makeHelperDir',
            'Directory to the helper files used in Makefiles (prefix.mk, etc.)',
             default=os.path.normpath(os.path.join(os.path.dirname(sys.argv[0]),
                                                 '..','share','dws'))),
                         'binDir': Pathname('binDir',
             'Root of the tree where executables are installed',
                                            installTop),
                         'installTop': installTop,
                         'includeDir': Pathname('includeDir',
             'Root of the tree where include files are installed',
                                                installTop),
                         'libDir': Pathname('libDir',
             'Root of the tree where libraries are installed',
                                            installTop),
                         'etcDir': Pathname('etcDir',
             'Root of the tree where extra files are installed',
                                            installTop,'etc'),
                         'shareDir': Pathname('shareDir',
             'Directory where the shared files are installed.',
                                            installTop,'share'),
                         'duplicateDir': Pathname('duplicateDir',
             'Directory where important directory trees on the remote machine are duplicated.',
                                            installTop,'duplicate'),
                         'siteTop': siteTop,
                         'logDir': Pathname('logDir',
             'Directory where the generated log files are created',
                                          siteTop,'log'),
                         'indexFile': Pathname('indexFile',
             'Index file with projects dependencies information',
                                          siteTop,
              os.path.join('resources',os.path.basename(sys.argv[0]) + '.xml')),
                         'remoteSiteTop': remoteSiteTop,
                         'remoteIndexFile': Pathname('remoteIndexFile',
             'Index file with projects dependencies information stored on the remote server',
                                          remoteSiteTop,
              os.path.join('resources',os.path.basename(sys.argv[0]) + '.xml')),
                         'remoteSrcTop': Pathname('remoteSrcTop',
             'Root of the tree on the remote machine where repositories are located',
                                          remoteSiteTop,'reps'),
                        'darwinTargetVolume': SingleChoice('darwinTargetVolume',
                                                           None,
              descr='Destination of installed packages on a Darwin local machine. Installing on the "LocalSystem" requires administrator privileges.',
              choices=[ ['LocalSystem', 
                         'install packages on the system root for all users'],
                        ['CurrentUserHomeDirectory', 
                         'install packages for the current user only'] ]),
                         'distHost': HostPlatform('distHost') }

        self.buildTopRelativeCwd = None

    def binBuildDir(self):
        return os.path.join(self.value('buildTop'),'bin')

    def includeBuildDir(self):
        return os.path.join(self.value('buildTop'),'include')

    def libBuildDir(self):
        return os.path.join(self.value('buildTop'),'lib')

    def shareBuildDir(self):
        return os.path.join(self.value('buildTop'),'share')

    def cachePath(self,name=None):
        '''Absolute path to a file in the local system cache
        directory hierarchy.'''
        resourcesDir = os.path.join(self.value('siteTop'),'resources')
        if name:
            relative = name.find('.' + os.sep)
            if relative > 0:
                return os.path.join(resourcesDir,name[relative + 2:])
            return os.path.join(resourcesDir,name)
        return resourcesDir

    def derivedHelper(self,name):
        '''Absolute path to a file which is part of drop helper files
        located in the share/dws subdirectory. The absolute directory
        name to share/dws is derived from the path of the script
        being executed as such: dirname(sys.argv[0])/../share/dws.'''
        return os.path.join(self.value('makeHelperDir'),name)

    def hostCachePath(self,name):
        '''Absolute path to a file in the local system cache for host 
        specific packages.'''
        return os.path.join(self.value('siteTop'),host(),name)

    def logPath(self,name):
        '''Absolute path to a file in the local system log
        directory hierarchy.'''
        return os.path.join(self.value('logDir'),name)

    def remoteCachePath(self,name=None):
        '''Absolute path to access a file on the remote machine.'''
        if name:
            return os.path.join(self.value('remoteSiteTop'),'resources',name)
        return os.path.join(self.value('remoteSiteTop'),'resources')

    def remoteSrcPath(self,name):
        '''Absolute path to access a repository on the remote machine.''' 
        return os.path.join(self.value('remoteSrcTop'),name)        

    def cwdProject(self):
        '''Returns a project name derived out of the current directory.'''
        if not self.buildTopRelativeCwd:
            self.environ['buildTop'].default = os.path.dirname(os.getcwd())
            writetext('no workspace configuration file could be ' \
               + 'found from ' + os.getcwd() \
               + ' all the way up to /. A new one, called ' + self.configName\
               + ', will be created in *buildTop* after that path is set.\n')
            self.configFilename = os.path.join(self.value('buildTop'),
                                               self.configName)
            self.save()
            self.locate()
        #print "!!! os.getcwd()=" + str(os.getcwd())
        #print "!!! buildTop=" + self.value('buildTop')
        #print "!!! srcTop=" + self.value('srcTop')
        if os.path.realpath(os.getcwd()).startswith(
            os.path.realpath(self.value('buildTop'))):
                top = os.path.realpath(self.value('buildTop'))
        elif os.path.realpath(os.getcwd()).startswith(
            os.path.realpath(self.value('srcTop'))):
                top = os.path.realpath(self.value('srcTop'))            
        prefix = os.path.commonprefix([top,os.getcwd()])
        return os.getcwd()[len(prefix) + 1:]
        # return self.buildTopRelativeCwd

    def dbPathname(self,remote=False):
        '''Absolute pathname to the project index file.'''
        if remote:
            return self.value('remoteIndexFile')
        else:            
            if not str(self.environ['indexFile']):                
                default = str(self.environ['remoteIndexFile'])
                if default:
                    self.environ['indexFile'].default \
                        = default.replace(context.value('remoteSiteTop'),
                                          context.value('siteTop'))
            return self.value('indexFile')

    def host(self):
        '''Returns the distribution on which the script is running.'''
        return self.value('distHost')

    def localDir(self,remotename):
        pos = remotename.find('./')
        if pos > 0:
            localname = os.path.join(context.value('siteTop'),
                                     remotename[pos + 2:])
        else:
            localname = remotename.replace(context.value('remoteSiteTop'),
                                           context.value('siteTop'))
        if localname.endswith('.git'):
            localname = localname[:-4]
        return localname

    def locate(self):
        '''Locate the workspace configuration file and derive the project
        name out of its location.'''
        try:
            self.buildTopRelativeCwd, self.configFilename \
                = searchBackToRoot(self.configName)
        except IOError, e:
            self.buildTopRelativeCwd = None
            self.configFilename = os.path.join(self.environ['buildTop'].default,
                                              self.configName)
            if not os.path.isfile(self.configFilename):
                raise e
        if self.buildTopRelativeCwd == '.':
            self.buildTopRelativeCwd = os.path.basename(os.getcwd())
            # \todo is this code still relevent?
            look = re.match('([^-]+)-.*',self.buildTopRelativeCwd)
            if look:
                # Change of project name in *indexName* on "make dist-src".
                # self.buildTopRelativeCwd = look.group(1)
                None
        # -- Read the environment variables set in the config file.
        siteTopFound = False
        configFile = open(self.configFilename)
        line = configFile.readline()
        while line != '':
            look = re.match('(\S+)\s*=\s*(\S+)',line)
            if look != None:
                if look.group(1) == 'siteTop':
                    siteTopFound = True
                if not look.group(1) in self.environ:
                    self.environ[look.group(1)] = look.group(2)
                else:
                    self.environ[look.group(1)].value = look.group(2)
            line = configFile.readline()
        if not siteTopFound:
            # By default we set *siteTop* to be the directory
            # where the configuration file was found since basic paths
            # such as *buildTop* and *srcTop* defaults are based on it.
            self.environ['siteTop'].value = os.path.dirname(self.configFilename)
        configFile.close()

    def logname(self):
        '''Name of the XML tagged log file where sys.stdout is captured.''' 
        filename = os.path.basename(self.dbPathname())
        filename = os.path.splitext(filename)[0] + '.log'
        filename = self.logPath(filename)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        return filename

    def objDir(self,name):
        return os.path.join(self.value('buildTop'),name)

    def remoteSite(self,indexPath):
        '''We need to set the remoteIndex to a realpath when we are dealing
        with a local file else links could end-up generating a different prefix
        than remoteSiteTop for remoteIndex.'''
        remoteIndex = indexPath
        if not ':' in remoteIndex:
            remoteIndex = os.path.realpath(remoteIndex)
        context.environ['remoteIndexFile'].value = remoteIndex
        remoteCachePath = os.path.dirname(indexPath)
        if not ':' in remoteCachePath:
            remoteCachePath = os.path.realpath(remoteCachePath)
        if remoteCachePath.endswith('resources'):
            context.environ['remoteSiteTop'].default \
                = os.path.dirname(remoteCachePath)
        else:
            context.environ['remoteSiteTop'].default = remoteCachePath

    def save(self):
        '''Write the config back to a file.'''
        try:
            configFile = open(self.configFilename,'w')
        except:
            self.configFilename = self.objDir(self.configName)
            if not os.path.exists(os.path.dirname(self.configFilename)):
                os.makedirs(os.path.dirname(self.configFilename))
            configFile = open(self.configFilename,'w')
        keys = sorted(self.environ.keys())
        configFile.write('# configuration for development workspace\n\n')
        for key in keys:
            val = self.environ[key]
            if len(str(val)) > 0:
                configFile.write(key + '=' + str(val) + '\n')
        configFile.close()

    def searchPath(self):
        return [ self.binBuildDir(), self.value('binDir') ] \
            + os.environ['PATH'].split(':')

    def srcDir(self,name):
        return os.path.join(self.value('srcTop'),name)

    def value(self,name):
        '''returns the value of the workspace variable *name*. If the variable
        has no value yet, a prompt is displayed for it.'''
        if not name in self.environ:
            raise Error("Trying to read unknown variable " + name + ".")
        if (isinstance(self.environ[name],Variable) 
            and self.environ[name].configure()):
            self.save()
        # recursively resolve any variables that might appear 
        # in the variable value. We do this here and not while loading
        # the context because those names can have been defined later.
        value = str(self.environ[name])
        look = re.match('(.*)\${(\S+)}(.*)',value)
        while look:
            indirect = ''
            if look.group(2) in self.environ:
                indirect = self.value(look.group(2))
            elif look.group(2) in os.environ:
                indirect = os.environ[look.group(2)]
            value = look.group(1) + indirect + look.group(3)
            look = re.match('(.*)\${(\S+)}(.*)',value)        
        return value

# Formats help for script commands. The necessity for this class 
# can be understood by the following posts on the internet:
# - http://groups.google.com/group/comp.lang.python/browse_thread/thread/6df6e6b541a15bc2/09f28e26af0699b1
# - http://www.alexonlinux.com/pythons-optparse-for-human-beings
#
# \todo The argparse (http://code.google.com/p/argparse/) might be part
#       of the standard python library and address the issue at some point.
class CommandsFormatter(optparse.IndentedHelpFormatter):
  def format_epilog(self, description):
    import textwrap
    result = ""
    if description: 
        descWidth = self.width - self.current_indent
        bits = description.split('\n')
        formattedBits = [
          textwrap.fill(bit,
            descWidth,
            initial_indent="",
            subsequent_indent="                       ")
          for bit in bits]
        result = result + "\n".join(formattedBits) + "\n"
    return result         


class IndexProjects:
    '''Index file containing the graph dependency for all projects.'''

    def __init__(self, context, source = None):
        self.context = context
        self.parser = xmlDbParser(context)
        self.source = source
 
    def closure(self, dgen):
        '''Find out all dependencies from a root set of projects as defined 
        by the dependency generator *dgen*.'''
        while dgen.more():
            self.parse(dgen)
        vars = []
        reps, packages, fetches = dgen.topological()
        projs = reps + packages
        projs.reverse()
        for projName in projs:
            if projName in dgen.projects:
                if projName in dgen.repositories:
                    vars += dgen.projects[projName].repository.vars
                elif projName in dgen.patches:
                    vars += dgen.projects[projName].patch.vars
                elif projName in dgen.packages:
                    distHost = context.value('distHost')                
                    vars += dgen.projects[projName].packages[distHost].vars
        # Configure environment variables required by a project 
        # and that need to be present in the workspace make fragment
        configVar(vars)
        return reps, packages, fetches
        
    def parse(self, dgen):
        '''Parse the project index and generates callbacks to *dgen*'''
        self.validate()        
        self.parser.parse(self.source,dgen)

    def validate(self,force=False):
        '''Create the project index file if it does not exist
        either by fetching it from a remote server or collecting
        projects indices locally.'''
        if not self.source:
            self.source = self.context.dbPathname()
        if not self.source.startswith('<?xml'):
            # The source is an actual string, thus we do not fetch any file.
            if not os.path.exists(self.source) or force:
                selection = ''
                if not force:
                    # index or copy.
                    selection = selectOne('The project index file could not '
                                    + 'be found at ' + self.source \
                                    + '. It can be regenerated through one ' \
                                    + 'of the two following method:',
                                    [ [ 'fetching', 'from remote server' ],
                                      [ 'indexing', 
                                        'local projects in the workspace' ] ],
                                          False)
                if selection == 'indexing':
                    pubCollect([])
                elif selection == 'fetching' or force:
                    if not os.path.exists(os.path.dirname(self.source)):
                        os.makedirs(os.path.dirname(self.source))
                    fetch({self.context.value('remoteIndexFile'): None},
                          os.path.dirname(self.source),True)                
            if not os.path.exists(self.source):
                raise Error(self.source + ' does not exist.')


class LogFile:
    '''Logging into an XML formatted file of sys.stdout and sys.stderr
    output while the script runs.'''

    def __init__(self,logfilename,nolog):
        self.nolog = nolog
        if not self.nolog:
            self.logfile = open(logfilename,'w')
            self.logfile.write('<?xml version="1.0" ?>\n')
            self.logfile.write('<book>\n')

    def close(self):
        if not self.nolog:
            self.logfile.write('</book>\n')
            self.logfile.close()        

    def error(self,text):
        if not text.startswith('error'):
            text = 'error: ' + text 
        sys.stdout.flush()
        self.logfile.flush()
        sys.stderr.write(text)
        if not self.nolog:
            self.logfile.write(text)

    def footer(self,status,errcode=0):
        if not self.nolog:
            self.logfile.write('<status')
            if errcode > 0:
                self.logfile.write(' error="' + str(errcode) + '"')
            self.logfile.write('>' + status + '</status>\n')
            self.logfile.write('</section>\n')

    def header(self, text):
        sys.stdout.write('### make ' + text + '...\n')
        if not self.nolog:
            self.logfile.write('<section id="' + text + '">\n')

    def flush(self):
        sys.stdout.flush()
        if not self.nolog:
            self.logfile.flush()

    def write(self, text):
        sys.stdout.write(text)
        if not self.nolog:
            self.logfile.write(text)


class PdbHandler:
    '''Callback interface for a project index as generated by an *xmlDbParser*.
       The generic handler does not do anything. It is the responsability of
       implementing classes to filter callback events they care about.'''
    def __init__(self):
        None

    def endParse(self):
        None

    def project(self, project):
        None


class Unserializer(PdbHandler):
    '''Builds *Project* instances for every project that matches *includePats*
    and not *excludePats*. See *filters*() for implementation.'''

    def __init__(self, includePats=[], excludePats=[]):
        PdbHandler.__init__(self)
        self.includePats = set(includePats)
        self.excludePats = set(excludePats)
        self.projects = {}

    def asProject(self, name):
        if not name in self.projects:
            raise Error("unable to find " + name + "in the index file.",
                        projectName=name) 
        return self.projects[name]

    def filters(self, projectName):
        for inc in self.includePats:
            inc = inc.replace('+','\+')
            if re.match(inc,projectName):
                for exc in self.excludePats:
                    if re.match(exc.replace('+','\+'),projectName):
                        return False
                return True
        return False

    def project(self, p):        
        '''Callback for the parser.'''
        if (not p.name in self.projects) and self.filters(p.name):
            self.projects[p.name] = p


class DependencyGenerator(Unserializer):
    '''*DependencyGenerator* implements a breath-first search of the project
    dependencies index with a specific twist.
    At each iteration, if all prerequisites for a project can be found 
    on the local system, the dependency edge is cut from the next iteration.
    Missing prerequisite executables, headers and libraries require 
    the installation of prerequisite projects as stated by the *missings*
    list of edges. The user will be prompt for *candidates*() and through
    the options available will choose to install prerequisites through
    compiling them out of a source controlled repository or a binary 
    distribution package.
    *DependencyGenerator.endParse*() is at the heart of the workspace
    bootstrapping and other "recurse" features.
    '''

    def __init__(self, repositories, patches, packages, excludePats = []):
        '''*repositories* and *patches* will be installed from compiling
        a source controlled repository while *packages* will be installed
        from a binary distribution package. 
        *excludePats* is a list of projects which should be removed from 
        the final topological order.'''
        Unserializer.__init__(self, packages + patches + repositories,
                              excludePats)
        self.packages = set(packages)
        self.patches = set(patches)
        self.repositories = set(repositories)
        # Project which either fullfil all prerequisites or that have been 
        # explicitely excluded from installation by the user will be added 
        # to *excludePats*.

        # This contains a list of list of edges. When levels is traversed last 
        # to first and each edge's source vertex is outputed, it displays 
        # a topological ordering of the selected projects.
        # In other words, levels holds each recursing of a breadth-first search
        # algorithm through the graph of projects from the roots.
        # We store edges in each level rather than simply the source vertex 
        # such that we can detect cycles. That is when an edge would be 
        # traversed again.
        # *missings* contains a list of dependency edges (source,target) where
        # prerequisites required by source and installed by target cannot be 
        # fullfiled with the current configuration of the local machine.
        self.missings = []
        for p in self.includePats:
            self.missings += [ [ None, p ] ]
        self.levels = [ [] ]            
        self.buildDeps = {}
        self.extraSyncs = []
        self.extraFetches = {}

    def candidates(self):
        '''Returns a triple (repositories, patches, packages) where each element
        is a list of rows, each row describes a missing prerequisite project. 
        When a missing project can be installed from either a repository, 
        a patch or a package, it will be described in each element 
        of the triplet as appropriate.'''
        repositories = []
        patches = []
        packages = []
        targets = set([])
        for miss in self.missings:
            targets |= set([ miss[1] ])
        for name in targets:      
            if (not os.path.isdir(context.srcDir(name))
                and self.filters(name)):
                # If a prerequisite project is not defined as an explicit
                # package, we will assume the prerequisite name is
                # enough to install the required tools for the prerequisite.
                row = [ name ]
                if name in self.projects:                
                    if self.projects[name].installedVersion:
                        row += [ self.projects[name].installedVersion ]
                    if self.projects[name].repository:
                        repositories += [ row ]
                    if self.projects[name].patch:
                        patches += [ row ]
                    if not (self.projects[name].repository 
                            or self.projects[name].patch):
                        packages += [ row ]
                else:
                    packages += [ row ]
        return repositories, patches, packages
 
    def endParse(self):
        # !!! Debugging Prints !!!
        # print "* endParse:"
        # print "     includes: " + str(self.includePats) 
        # print "     excludes: " + str(self.excludePats) 
        # print "     levels:   " + str(self.levels)
        # print "     missings: " + str(self.missings)

        # This is an opportunity to prompt for missing dependencies.
        reps, patches, packages = self.candidates()
        reps, patches, packages = selectCheckout(reps,patches,packages)
        # The user's selection will decide, when available, if the project
        # should be installed from a repository, a patch, a binary package
        # or just purely skipped. 
        self.repositories |= set(reps)
        self.patches |= set(patches)
        self.packages |= set(packages)

        # We now know what to do with the missing dependency edges, 
        # so let's add the ones we have to track. 
        for newEdge in self.missings:
            if (newEdge[1] in self.repositories 
                or newEdge[1] in self.patches
                or newEdge[1] in self.packages):
                if newEdge[1] in self.projects:
                    # If the prerequisite is not a project, it will be 
                    # installed by the distribution's package manager 
                    # on the local machine and we do not track 
                    # its prerequisites explicitely. We leave
                    # this work to the distribution package manager.
                    self.levels[0] += [ newEdge ]
            else:
                self.excludePats |= set([ newEdge[1] ])
        locals = []
        fetches = {}
        syncs = []
        tags = [ context.host() ]
        for edge in self.levels[0]:
            target = edge[1]
            if (target in self.repositories
                and not self.projects[target].repository):
                # Miscategorized, it is actually a patch.
                self.repositories -= set([target])
                self.patches |= set([target])
            if target in self.repositories:
                syncs += [ target ]
                locals += self.projects[target].repository.prerequisites(tags)
                for f in self.projects[target].repository.fetches:
                    fetches[f] = self.projects[target].repository.fetches[f]
            elif target in self.patches:
                syncs += [ target ]
                locals += self.projects[target].patch.prerequisites(tags)
                for f in self.projects[target].patch.fetches:
                    fetches[f] = self.projects[target].patch.fetches[f]
            elif target in self.packages:
                distHost = context.value('distHost')                
                locals += self.projects[target].packages[distHost].prerequisites(tags)
                for f in self.projects[target].packages[distHost].fetches:
                    fetches[f] = self.projects[target].packages[distHost].fetches[f]
        # Find all executables, libraries, etc. that are already 
        # installed on the local system.
        aggDeps = self.buildDeps
        for local in locals:
            if local.name in aggDeps:
                for key in local.files:
                    if key in aggDeps[local.name].files:
                       for filePat, filePath in local.files[key]:
                           found = False
                           for prevPat, prevPath \
                                   in aggDeps[local.name].files[key]:
                               if filePat == prevPat:
                                   # This prerequisite as a pattern has already
                                   # been searched before so let's not search
                                   # for it on the local system again.
                                   found = True
                                   break
                           if not found:
                               aggDeps[local.name].files[key] \
                                   += [ (filePat, filePath) ]
                    else:
                        aggDeps[local.name].files[key] = local.files[key]
                for exclude in local.excludes:
                    if not exclude in aggDeps[local.name].excludes:
                        aggDeps[local.name].excludes += [ exclude ]
            else:
                aggDeps[local.name] = Dependency(local.name,local.files,
                                                 local.excludes,local.target)
        newLevel = []
        self.missings = []
        for name in aggDeps:
            files, complete \
                = findPrerequisites(aggDeps[name].files,
                                    aggDeps[name].excludes,
                                    aggDeps[name].target)
            self.buildDeps[name] = Dependency(name,files,
                                              aggDeps[name].excludes,
                                              aggDeps[name].target)
            for edge in self.levels[0]:
                source = edge[1]
                if (source in self.projects
                    and name in self.projects[source].prerequisiteNames(tags)):
                    if os.path.isdir(context.srcDir(name)):
                        # Here we will force add the dependencies when 
                        # a repository is locally checked out such that 
                        # a "make recurse" rebuilds every prerequisite 
                        # projects locally checked out.
                        newLevel += [ [ source, name ] ]
                        self.repositories |= set([ name ])
                        self.includePats |= set([ name ])
                    elif complete:
                        # All bin. lib, etc. prerequisites have been found
                        # so we do not look further down the dependency graph.
                        self.excludePats |= set([ name ])
                    else:
                        # Can't find something, we will prompt the user
                        # for installation from appropriate options.
                        self.missings += [ [ source, name ] ]
                        self.includePats |= set([ name ])

        # Check for the presence of a local checkout of required source
        # control repositories. If it is present, we'll do a recursive make.
        for name in syncs:
            if not os.path.isdir(context.srcDir(name)):
                self.extraSyncs += [ name ]
        # Check that the extra files required (such as .tar.bz2 source
        # distribution) are in the local cache.
        found, version = findCache(fetches)
        for source in fetches:
            if not context.cachePath(source) in found:
                self.extraFetches[source] = fetches[source]
        # Update project prerequisites that can be satisfied
        for p in self.projects:
            self.projects[ p ].populate(self.buildDeps)

        roots = []
        level = []
        for newEdge in newLevel:
            found = False
            for edge in level:
                if (edge[0] == newEdge[0] and edge[1] == newEdge[1]):
                    found = True
                    break
            if not found:
                level += [ newEdge ]
                if not newEdge[1] in roots:
                    # Insert each vertex once. 
                    roots += [ newEdge[1] ]
        # If an edge's source is matching a vertex added 
        # to the next level, obviously, it was too "late"
        # in the topological order.
        newLevel = []
        for edge in level:
            found = False
            for vertex in roots:
                if edge[0] == vertex:
                    found = True
                    break
            if not found:
                newLevel += [ edge ] 
        self.levels.insert(0,newLevel)

        # Going one step further in the breadth-first recursion introduces 
        # a new level.
        if None:
            # \todo cannot detect cycles like this...
            print "levels:"
            print self.levels
            for newEdge in self.levels[0]:
                # We first walk the tree of previously recorded edges to find out 
                # if we detected a cycle.
                if len(self.levels) > 1:
                    for level in self.levels[1:]:
                        for edge in level:
                            if edge[0] == newEdge[0] and edge[1] == newEdge[1]:
                                raise CircleError(edge[0],edge[1])

    def more(self):
        '''True if there are more iterations of the breath-first 
        search to conduct.'''
        return len(self.levels[0]) > 0 or len(self.missings) > 0

    def topological(self):
        '''Returns a topological ordering of projects selected.'''
        sorted = []
        for level in self.levels:
            for edge in level:
                if not edge[1] in sorted:
                    sorted += [ edge[1] ] 
        results = []
        for name in sorted:
            found = False
            for excludePat in self.excludePats:
                if re.match(excludePat.replace('+','\+'),name):
                    found = True
                    break
            if not found:
                results += [ name ]
        packages = []
        for p in self.packages:
            if self.filters(p):
                packages += [ p ]
        return results, packages, self.extraFetches


class DerivedSetsGenerator(PdbHandler):
    '''Generate the set of projects which are not dependency 
    for any other project.'''
   
    def __init__(self):
        self.roots = []
        self.nonroots = []

    def project(self, p):
        for depName in p.prerequisiteNames([ context.host() ]):
            if depName in self.roots:
                self.roots.remove(depName)
            if not depName in self.nonroots:
                self.nonroots += [ depName ]
        if (not p.name in self.nonroots 
            and not p.name in self.roots):
            self.roots += [ p.name ]


class Variable:
    '''Variable that ends up being defined in the workspace make fragment and thus in Makefile.'''

    def __init__(self,name,value=None,descr=None):
        self.name = name
        self.value = value
        self.descr = descr
        self.default = None
        if descr:
            self.descr = descr.strip()
        self.constrains = {}

    def __str__(self):
        if self.value:
            return str(self.value)
        else:
            return ''

    def constrain(self,vars):
        None

    def configure(self):
        '''Set value to the string entered at the prompt.'''
        if self.value != None:
            return False
        writetext('\n' + self.name + ':\n')
        writetext(self.descr + '\n')
        if useDefaultAnswer:
            self.value = self.default
        else:
            defaultPrompt = ""
            if self.default:
                defaultPrompt = " [" + self.default + "]"
            self.value = prompt("Enter a string" + defaultPrompt + ": ")
        writetext(self.name + ' set to ' + self.value +'\n')
        return True

class HostPlatform(Variable):

    def __init__(self,name,descr=None):
        Variable.__init__(self,name,None,descr)
        self.distCodename = None

    def configure(self):
        '''Set value to the distribution on which the script is running.'''
        if self.value != None:
            return False
        # The following code was changed when upgrading from python 2.5 
        # to 2.6. Since most distribution come with 2.6 installed, it does
        # not seem important at this point to figure out the root cause
        # and keep a backward compatible implementation.
        #   hostname = socket.gethostbyaddr(socket.gethostname())
        #   hostname = hostname[0]
        hostname = socket.gethostname()
        sysname, nodename, release, version, machine = os.uname()
        if sysname == 'Darwin':
            self.value = 'Darwin'
        elif sysname == 'Linux':
            for versionPath in [ '/proc/version', '/etc/apt/sources.list' ]: 
                # If we can't determine the host platform for /proc/version,
                # let's try to guess from the package manager installed.
                if os.path.exists(versionPath):
                    version = open(versionPath)
                    line = version.readline()
                    while line != '':
                        for d in [ 'Ubuntu', 'ubuntu', 'fedora' ]:
                            look = re.match('.*' + d + '.*',line)
                            if look:
                                self.value = d
                                break
                        if self.value:
                            break
                        line = version.readline()
                    version.close()
                    if self.value:
                        break                    
            if self.value:
                self.value = self.value.capitalize()
            if self.value == 'Ubuntu':                
                if os.path.isfile('/etc/lsb-release'):
                    release = open('/etc/lsb-release')
                    line = release.readline()
                    while line:
                        look = re.match('DISTRIB_CODENAME=\s*(\S+)',line)
                        if look:
                            self.distCodename = look.group(1)
                            break
                        line = release.readline()
                    release.close()
        return True


class Pathname(Variable):
    
    def __init__(self,name,descr=None,base=None,default=None):
        Variable.__init__(self,name,None,descr)
        self.base = base
        self.default = default

    def configure(self):
        '''Generate an interactive prompt to enter a workspace variable 
        *var* value and returns True if the variable value as been set.'''
        if self.value != None:
            return False
        writetext('\n' + self.name + ':\n' + self.descr + '\n')
        # compute the default leaf directory from the variable name 
        leafDir = self.name
        for last in range(0,len(self.name)):
            if self.name[last] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                leafDir = self.name[:last]
                break
        dir = self
        default = self.default
        if (not default 
            or (not (':' in default) or default.startswith(os.sep))):
            # If there are no default values or the default is not
            # an absolute pathname.
            if self.base:
                if default:
                    showDefault = '*' + self.base.name + '*/' + default
                else:
                    showDefault = '*' + self.base.name + '*/' + leafDir
                if not self.base.value:
                    directly = 'Enter *' + self.name + '* directly ?'
                    offbase = 'Enter *' + self.base.name + '*, *' + self.name \
                                 + '* will defaults to ' + showDefault  \
                                 + ' ?'
                    selection = selectOne(self.name + ' is based on *' \
                                              + self.base.name \
                        + '* by default. Would you like to ... ',
                              [ [ offbase  ],
                                [ directly ] ],
                                          False)
                    if selection == offbase:
                        dir = self.base
                        default = dir.default
                else:
                    if default:
                        default = os.path.join(self.base.value,default)
                    else:
                        default = os.path.join(self.base.value,leafDir)
            elif default:
                default = os.path.join(os.getcwd(),default)
        if not default:
            default = os.getcwd()

        if useDefaultAnswer:
            dirname = default
        else:
            dirname = prompt("Enter a pathname [" + default + "]: ")
        if dirname == '':
            dirname = default
        if not ':' in dirname:
            dirname = os.path.normpath(os.path.abspath(dirname))
        dir.value = dirname
        if dir != self:
            if self.default:
                self.value = os.path.join(self.base.value,self.default)
            else:
                self.value = os.path.join(self.base.value,leafDir)
        if not ':' in dirname:
            if not os.path.exists(self.value):
                writetext(self.value + ' does not exist.\n')
                # We should not assume the pathname is a directory 
                # (i.e. remoteIndex).
                if None:
                    os.makedirs(self.value)
        writetext(self.name + ' set to ' + self.value +'\n')
        return True


class MultipleChoice(Variable):

    def __init__(self,name,value,descr=None,choices=[]):
        if value and isinstance(value,str):
            value = value.split(' ')
        Variable.__init__(self,name,value,descr)
        self.choices = choices

    def __str__(self):
        return ' '.join(self.value)

    def configure(self):
        '''Generate an interactive prompt to enter a workspace variable 
        *var* value and returns True if the variable value as been set.'''
        # There is no point to propose a choice already constraint by other
        # variables values.
        choices = []
        for choice in self.choices:
            if not choice[0] in self.value:
                choices += [ choice ]
        if len(choices) == 0:
            return False
        descr = self.descr
        if len(self.value) > 0:
            descr +=  " (constrained: " + ", ".join(self.value) + ")"
        self.value += selectMultiple(descr,choices)
        writetext(self.name + ' set to ' + ', '.join(self.value) +'\n')
        self.choices = []
        return True

    def constrain(self,vars):
        if not self.value:
            self.value = []
        for var in vars:
            if isinstance(vars[var],Variable) and vars[var].value:
                if isinstance(vars[var].value,list):
                    for val in vars[var].value:
                        if (val in vars[var].constrains
                            and self.name in vars[var].constrains[val]):
                            self.value += vars[var].constrains[val][self.name]
                else:
                    val = vars[var].value 
                    if (val in vars[var].constrains 
                        and self.name in vars[var].constrains[val]):
                        self.value += vars[var].constrains[val][self.name]

class SingleChoice(Variable):

    def __init__(self,name,value,descr=None,choices=[]):
        Variable.__init__(self,name,value,descr)
        self.choices = choices

    def configure(self):
        '''Generate an interactive prompt to enter a workspace variable 
        *var* value and returns True if the variable value as been set.'''
        if self.value:
            return False
        self.value = selectOne(self.descr,self.choices)
        writetext(self.name + ' set to ' + self.value +'\n')
        return True

    def constrain(self,vars):
        for var in vars:
            if isinstance(vars[var],Variable) and vars[var].value:
                if isinstance(vars[var].value,list):
                    for val in vars[var].value:
                        if (val in vars[var].constrains
                            and self.name in vars[var].constrains[val]):
                            self.value = vars[var].constrains[val][self.name]
                else:
                    val = vars[var].value 
                    if (val in vars[var].constrains 
                        and self.name in vars[var].constrains[val]):
                        self.value = vars[var].constrains[val][self.name]

class Dependency:
    '''A dependency of a project on another project 
    as defined by the <dep> tag in the project index.'''

    def __init__(self, name, files, excludes=[], target=None):
        self.name = name
        self.files = files
        self.excludes = excludes
        self.target = target

    def __str__(self):
        result = self.name + ': ' + str(self.files)
        if len(self.excludes) > 0:
            result = result + ', excludes:' + str(self.excludes)
        if self.target:
            result = result + ', target:' + str(self.target)
        return result

    def populate(self, buildDeps = {}):
        if self.name in buildDeps:
            deps = buildDeps[self.name].files
            for d in deps:
                if d in self.files:
                    files = []
                    for lookPat, lookPath in self.files[d]:
                        found = False
                        if not lookPath:
                            for pat, path in deps[d]:
                                if pat == lookPat:
                                    files += [ (lookPat, path) ]
                                    found = True
                                    break
                        if not found:
                            files += [ (lookPat, lookPath) ]
                    self.files[d] = files

    def prerequisites(self,tags):
        return [ self ]    


class Alternates(Dependency):
    '''Provides a set of dependencies where one of them is enough
    to fullfil the prerequisite condition. This is used to allow 
    differences in packaging between distributions.'''

    def __init__(self):
        self.byTags = {}

    def __str__(self):
        return 'alternates: ' + str(self.byTags)

    def populate(self, buildDeps = {}):
        for tag in self.byTags:
            for dep in self.byTags[tag]:
                dep.populate(buildDeps)

    def prerequisites(self, tags):
        prereqs = []
        for tag in tags:
            if tag in self.byTags:
                for dep in self.byTags[tag]:
                    prereqs += dep.prerequisites(tags)
        return prereqs


class Maintainer:
    '''Information about the maintainer of a project.'''

    def __init__(self, fullname, email):
        self.fullname = fullname
        self.email = email

class Configure:
    '''All prerequisites information to check in order to install a project. 
    This is the base class for *Package* and *Repository*.'''

    def __init__(self, fetches, locals, vars):
        self.fetches = fetches
        self.vars = vars
        self.locals = locals

    def __str__(self):
        result = ''
        if len(self.fetches) > 0:
            result = result + '\t\tfetch archives\n'
            for archive in self.fetches:
                result = result + '\t\t\t' + archive + '\n'
        if len(self.locals) > 0:
            result = result + '\t\tdependencies from local system\n'
            for dep in self.locals:
                result = result + '\t\t\t' + str(dep) + '\n'
        if len(self.vars) > 0:
            result = result + '\t\tenvironment variables\n'
            for var in self.vars:
                result = result + '\t\t\t' + str(var) + '\n'
        return result

    def populate(self, buildDeps = {}):
        for local in self.locals:
            local.populate(buildDeps)

    def prerequisites(self, tags):
        prereqs = []
        for local in self.locals:
            prereqs += local.prerequisites(tags)
        return prereqs

    def prerequisiteNames(self, tags):
        '''same as *prerequisites* except only returns the names 
        of the prerequisite projects.'''
        names = []
        for local in self.locals:
            for prereq in local.prerequisites(tags):
                names += [ prereq.name ]
        return names


class Package(Configure):
    '''All prerequisites information to install a project from a package.'''

    def __init__(self, fetches, locals, vars):
        Configure.__init__(self,fetches,locals,vars)


class Repository(Configure):
    '''All prerequisites information to install a project 
    from a source control system.''' 

    def __init__(self, sync, fetches, locals, vars):
        Configure.__init__(self,fetches,locals,vars)
        self.type = None
        self.sync = sync
        self.fetches = fetches
        self.vars = vars
        self.locals = locals

    def __str__(self):
        result = '\t\tsync repository from ' + self.sync + '\n'
        result = result + Configure.__str__(self) 
        return result        

    def update(self,name,context,force=False):
        raise Error("unknown source control system for " + self.sync)


class GitRepository(Repository):
    '''All prerequisites information to install a project 
    from a git source control repository.'''

    def __init__(self, sync, fetches, locals, vars):
        Repository.__init__(self,sync,fetches,locals,vars)
 
    def update(self,name,context,force=False):
        # If the path to the remote repository is not absolute,
        # derive it from *remoteTop*. Binding any sooner will 
        # trigger a potentially unnecessary prompt for remoteCachePath.
        if not ':' in self.sync and context:
            self.sync = context.remoteSrcPath(self.sync)
        local = context.srcDir(name)
        if not os.path.exists(os.path.join(local,'.git')):
            shellCommand(['git', 'clone', self.sync, local])
        else:
            cwd = os.getcwd()
            os.chdir(local)
            try:
                shellCommand(['git', 'pull'])
            except:
                # It is ok to get an error in case we are running
                # this on the server machine.
                None
            cof = '-m'
            if force:
                cof = '-f'
            shellCommand(['git', 'checkout', cof])
            os.chdir(cwd)

 
class SvnRepository(Repository):
    '''All prerequisites information to install a project 
    from a svn source control repository.'''

    def __init__(self, sync, fetches, locals, vars):
        Repository.__init__(self,sync,fetches,locals,vars)
 
    def update(self,name,context,force=False):
        # If the path to the remote repository is not absolute,
        # derive it from *remoteTop*. Binding any sooner will 
        # trigger a potentially unnecessary prompt for remoteCachePath.
        if not ':' in self.sync and context:
            self.sync = context.remoteSrcPath(self.sync)
        local = context.srcDir(name)
        if not os.path.exists(os.path.join(local,'.svn')):
            shellCommand(['svn', 'co', self.sync, local])
        else:
            cwd = os.getcwd()
            os.chdir(local)
            shellCommand(['svn', 'update'])
            os.chdir(cwd)


class Project:
    '''Definition of a project with its prerequisites.'''

    def __init__(self, name):
        self.name = name
        self.title = None
        self.descr = None
        self.maintainer = None
        self.complete = False
        # *packages* maps a set of tags to *Package* instances. A *Package*
        # contains dependencies to install a project from a binary distribution.
        self.packages = {}
        self.patch = None
        self.repository = None
        self.installedVersion = None

    def __str__(self):
        result = 'project ' + self.name + '\n' \
            + '\t' + str(self.title) + '\n' \
            + '\tfound version ' + str(self.installedVersion) \
            + ' installed locally\n' \
            + '\tcomplete: ' + str(self.complete) + '\n'
        if len(self.packages) > 0:
            result = result + '\tpackages\n'
            for p in self.packages:
                result = result + '\t[' + p + ']\n'
                result = result + str(self.packages[p]) + '\n'
        if self.patch:
            result = result + '\tpatch\n' + str(self.patch) + '\n'
        if self.repository:
            result = result + '\trepository\n' + str(self.repository) + '\n'
        return result

    def populate(self, buildDeps = {}):
        if self.repository:
            self.repository.populate(buildDeps)
        if self.patch:
            self.patch.populate(buildDeps)
        for p in self.packages:
            self.packages[p].populate(buildDeps)

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

    def prerequisiteNames(self, tags):
        '''same as *prerequisites* except only returns the names 
        of the prerequisite projects.'''
        names = []
        for prereq in self.prerequisites(tags):
            names += [ prereq.name ]
        return names


class xmlDbParser(xml.sax.ContentHandler):
    '''Parse a project index database stored as an XML file on disc 
    and generate callbacks on a PdbHandler. The handler will update 
    its state based on the callback sequence.'''

    # Global Constants for the database parser
    tagAlternate = 'alternate'
    tagAlternates = 'alternates'
    tagTag = 'tag'
    tagBase = 'base'
    tagDb = 'projects'
    tagDefault = 'default'
    tagConstrain = 'constrain'
    tagDepend = 'dep'
    tagDescription = 'description'
    tagFetch = 'fetch'
    tagHash = 'sha1'
    tagMaintainer = 'maintainer'
    tagMultiple = 'multiple'
    tagPackage = 'package'
    tagPatch = 'patch'
    tagPathname = 'pathname'
    tagProject = 'project'
    tagRepository = 'repository'
    tagSingle = 'single'
    tagSync = 'sync'
    tagTitle = 'title'
    tagValue = 'value'
    tagVariable = 'variable'
    tagPattern = '.*<' + tagProject + '\s+name="(.*)"'
    trailerTxt = '</projects>'

    def __init__(self, context, build=True):
        self.build = build
        self.context = context
        self.handler = None
        self.choice = None
        self.constrain = None
 
    def startElement(self, name, attrs):
        '''Start populating an element.'''
        self.text = ''
        if name == self.tagAlternate:
            self.tagIndices += [ len(self.tags) ]
            self.locIndices += [ len(self.locals) ]
        elif name == self.tagAlternates:
            self.locals += [ Alternates() ]
            self.tagIndices += [ len(self.tags) ]
            self.locIndices += [ len(self.locals) ]
        elif name == self.tagConstrain:
            self.constrain = attrs['name']
            self.constrainValues = []
        elif name == self.tagFetch:
            self.filename = attrs['name']
        elif name == self.tagProject:
            self.var = None
            self.project = Project(attrs['name'])
        elif name == self.tagMaintainer:
            self.project.maintainer = Maintainer(attrs['name'],attrs['email'])
        elif name in [ self.tagPackage, self.tagPatch, self.tagRepository ]: 
            # We manage an explicit stack of local dependencies 
            # in order to build alternates.
            self.tagIndices = []
            self.locIndices = []  
            self.tags = []
            self.fetches = {}
            self.locals = []
            self.vars = []
            self.sync = None
        elif name == self.tagDepend:
            self.depName = attrs['name']
            self.deps = {}
            self.excludes = []
            self.target = None
            if 'target' in attrs:
                self.target = attrs['target']
        elif name == self.tagMultiple:
            self.constrain = None
            choiceValue = None
            if attrs['name'] in self.context.environ:
                choiceValue = str(self.context.environ[attrs['name']])
            self.var = MultipleChoice(attrs['name'],choiceValue,None,[])
        elif name == self.tagPathname:
            self.constrain = None
            if attrs['name'] in self.context.environ:
                if isinstance(self.context.environ[attrs['name']],Pathname):
                    self.var = self.context.environ[attrs['name']]
                else:
                    self.var = Pathname(attrs['name'])
                    self.var.value = str(self.context.environ[attrs['name']])
            else:
                self.var = Pathname(attrs['name'])
        elif name == self.tagSingle:
            self.constrain = None
            # We have to specify [] explicitely here else self.var.choices
            # is aliased to the default parameter and self.var.choices 
            # are duplicated when the xml is parsed multiple times.
            choiceValue = None
            if attrs['name'] in self.context.environ:
                choiceValue = str(self.context.environ[attrs['name']])
            self.var = SingleChoice(attrs['name'],choiceValue,None,[])
        elif name == self.tagVariable:
            self.constrain = None
            choiceValue = None
            if attrs['name'] in self.context.environ:
                choiceValue = str(self.context.environ[attrs['name']])
            self.var = Variable(attrs['name'])
            self.var.value = choiceValue
        elif name == self.tagValue:
            if not self.constrain:
                self.choice = [ attrs['name'] ]
        elif name in [ 'bin', 'include', 'lib', 'etc', 'share' ]:
            if 'excludes' in attrs:
                self.excludes += attrs['excludes'].split(',')
 
    def characters(self, ch):
        self.text += ch

    def createRepositoryObject(self):
        if self.sync.endswith('.git'):
            return GitRepository(self.sync,self.fetches,
                                 self.locals,self.vars)
        elif re.match('.*svn.*',self.sync):
            return SvnRepository(self.sync,self.fetches,
                                 self.locals,self.vars)
        return Repository(self.sync,self.fetches,
                          self.locals,self.vars)


    def endElement(self, name):
        '''Once the element is fully populated, call back the simplified
           interface on the handler.'''
        if name == self.tagDb:
            self.handler.endParse()
        elif name == self.tagAlternate:
            depFirst = self.locIndices.pop()
            tagFirst = self.tagIndices.pop()
            alternateSet = self.locals[depFirst:]
            alternates = self.locals[depFirst - 1]
            if len(self.tags[tagFirst:]) == 0:
                alternates.byTags['any'] = alternateSet
            for tag in self.tags[tagFirst:]:
                alternates.byTags[tag] = alternateSet
            self.tags = self.tags[:tagFirst]
            self.locals = self.locals[:depFirst]
        elif name == self.tagAlternates:
            depFirst = self.locIndices.pop()
            tagFirst = self.tagIndices.pop()
            self.tags = self.tags[:tagFirst]
        elif name == self.tagBase:
            if isinstance(self.var,Pathname):
                self.var.base = self.context.environ[self.text.strip()]
        elif name == self.tagConstrain:
            if not self.choice[0] in self.var.constrains:
                self.var.constrains[self.choice[0]] = {}
            self.var.constrains[self.choice[0]][self.constrain] \
                = self.constrainValues
            self.constrain = None
        elif name == self.tagDefault:
            if isinstance(self.var,Variable):
                self.var.default = self.text.strip()
        elif name == self.tagTag:
            self.tags += [ self.text ]
        elif name == self.tagPackage:
            package = Package(self.fetches,self.locals,self.vars)
            if len(self.tags) == 0:
                self.tags += [ 'any' ]
            for tag in self.tags:
                self.project.packages[tag] = package
        elif name == self.tagPatch:
            if not self.sync:
                self.sync = os.path.join(self.project.name,'.git')            
            self.project.patch = self.createRepositoryObject()
        elif name == self.tagRepository:
            if not self.sync:
                self.sync = os.path.join(self.project.name,'.git')
            self.project.repository = self.createRepositoryObject()
        elif name == self.tagDepend:
            self.locals += [ Dependency(self.depName,self.deps,
                                        self.excludes,self.target) ]
        elif name == self.tagDescription:
            if self.choice:
                self.choice += [ self.text.strip() ]
            elif self.var:
                self.var.descr = self.text.strip()
            else:
                # The project description is used to make the dist target.
                self.project.descr = self.text.strip()
        elif name == self.tagTitle:
            self.project.title = self.text.strip()
        elif name == self.tagProject:
            self.handler.project(self.project)
        elif name == self.tagHash:
            self.fetches[ self.filename ] = self.text.strip()
        elif name in [ self.tagMultiple, self.tagPathname, self.tagSingle,
                       self.tagVariable ]:
            self.vars += [ self.var ]            
            self.var = None
        elif name == self.tagFetch:
            self.filename = None
        elif name == self.tagSync:
            self.sync = self.text
        elif name == self.tagValue:
            if self.constrain:
                self.constrainValues += [ self.text.strip() ]
            else:
                self.var.choices += [ self.choice ]
                self.choice = None
        elif name in [ 'bin', 'include', 'lib', 'etc', 'share' ]:
            if not name in self.deps:
                self.deps[name] = []
            self.deps[name] += [ (self.text,None) ]

    def parse(self, source, handler):
        '''This is the public interface for one pass through the database
           that generates callbacks on the handler interface.'''
        self.handler = handler
        parser = xml.sax.make_parser()
        parser.setFeature(xml.sax.handler.feature_namespaces, 0)
        parser.setContentHandler(self)
        if source.startswith('<?xml'):
            parser.parse(cStringIO.StringIO(source))
        else:
            parser.parse(source)

    # The following methods are used to merge multiple databases together.

    def copy(self, dbNext, dbPrev, removeProjectEndTag=False):
        '''Copy lines in the dbPrev file until hitting the definition
        of a package and return the name of the package.'''
        name = None
        line = dbPrev.readline()
        while line != '':
            look = re.match(self.tagPattern,line)
            if look != None:
                name = look.group(1)
                break
            writeLine = True
            look = re.match('.*' + self.trailerTxt,line)
            if look:
                writeLine = False
            if removeProjectEndTag:
                look = re.match('.*</' + self.tagProject + '>',line)
                if look:
                    writeLine = False
            if writeLine:
                dbNext.write(line)
            line = dbPrev.readline()
        return name


    def next(self, dbPrev):
        '''Skip lines in the dbPrev file until hitting the definition
        of a package and return the name of the package.'''
        name = None
        line = dbPrev.readline()
        while line != '':
            look = re.match(self.tagPattern,line)
            if look != None:
                name = look.group(1)
                break
            line = dbPrev.readline()
        return name

    def startProject(self, dbNext, name):
        dbNext.write('  <' + self.tagProject + ' name="' + name + '">\n')
        None

    def trailer(self, dbNext):  
        '''XML files need a finish tag. We make sure to remove it while
           processing Upd and Prev then add it back before closing 
           the final file.'''
        dbNext.write(self.trailerTxt)

def basenames(pathnames):
    '''return the basename of all pathnames in a list.'''
    bases = []
    for p in pathnames:
        bases += [ os.path.basename(p) ]
    return bases

def mark(filename,suffix):    
    base, ext = os.path.splitext(filename)
    return base + '-' + suffix + ext

def stamp(filename,date=datetime.datetime.now()):
    base, ext = os.path.splitext(filename)
    return base + '-' + str(date.year) \
               + ('_%02d' % (date.month)) \
               + ('_%02d' % (date.day)) \
               + ('-%02d' % (date.hour)) + ext

def stampfile(filename):
    return stamp(mark(os.path.basename(filename),
                      socket.gethostname()))


def createIndexPathname(dbIndexPathname,dbPathnames):
    '''create a global dependency database (i.e. project index file) out of
    a set local dependency index files.'''
    parser = xmlDbParser(context)
    dir = os.path.dirname(dbIndexPathname)
    if not os.path.isdir(dir):
        os.makedirs(dir)
    dbNext = sortBuildConfList(dbPathnames,parser)
    dbIndex = open(dbIndexPathname,'wb')
    dbNext.seek(0)
    shutil.copyfileobj(dbNext,dbIndex)
    dbNext.close()
    dbIndex.close()


def derivedRoots(name,target=None):
    '''Derives a list of directory names based on the PATH 
    environment variable, *name* and a *target* triplet.'''
    # We want the actual value of *name*Dir and not one derived
    # from binDir so we do not use context.searchPath() here.
    dirs = []
    subpath = name
    if target:
        subpath = os.path.join(target,name)
    for p in os.environ['PATH'].split(':'):
        dir = os.path.join(os.path.dirname(p),subpath)
        if os.path.isdir(dir):
            dirs += [ dir ]
    return [ context.value(name + 'Dir') ] + dirs


def findBin(names,excludes=[],target=None):
    '''Search for a list of binaries that can be executed from $PATH.

       *names* is a list of (pattern,absolutePath) pairs where the absolutePat
       can be None and in which case pattern will be used to search 
       for an executable. *excludes* is a list of versions that are concidered 
       false positive and need to be excluded, usually as a result 
       of incompatibilities.

       This function returns a list of populated (pattern,absolutePath) 
       and a version number. The version number is retrieved 
       through a command line flag. --version and -V are tried out.

       This function differs from findInclude() and findLib() in its
       search algorithm. findBin() strictly behave like $PATH and
       always returns the FIRST executable reachable from $PATH regardless 
       of version number, unless the version is excluded, in which case
       the result is the same as if the executable hadn't been found.

       Implementation Note:

       *names* and *excludes* are two lists instead of a dictionary
       indexed by executale name for two reasons:
       1. Most times findBin() is called with *names* of executables 
       from the same project. It is cumbersome to specify exclusion 
       per executable instead of per-project.
       2. The prototype of findBin() needs to match the ones of 
       findInclude() and findLib().

       Implementation Note: Since the boostrap relies on finding rsync, 
       it is possible we invoke this function with log == None hence
       the tests for it.
    '''
    results = []
    version = None
    for namePat, absolutePath in names:
        if absolutePath:
            # absolute paths only occur when the search has already been
            # executed and completed successfuly.
            results.append((namePat, absolutePath))
            continue
        # First time ever *findBin* is called, binBuildDir will surely not 
        # defined in the workspace make fragment and thus we will trigger interactive input from 
        # the user. We want to make sure the output of the interactive session 
        # does not mangle the search for an executable so we preemptively 
        # trigger an interactive session.
        context.binBuildDir()
        writetext(namePat + '... ')
        found = False
        if namePat.endswith('.app'):
            bin = os.path.join('/Applications',namePat)
            if os.path.isdir(bin):
                found = True
                writetext('yes\n')
                results.append((namePat, bin))
        else:
            for p in context.searchPath():
                bin = os.path.realpath(os.path.join(p,namePat))
                if (os.path.isfile(bin) 
                    and os.access(bin, os.X_OK)):
                    # We found an executable with the appropriate name,
                    # let's find out if we can retrieve a version number.
                    for flag in [ '--version', '-V' ]:
                        numbers = []
                        cmdline = [ bin, flag ]
                        cmd = subprocess.Popen(cmdline,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.STDOUT)
                        line = cmd.stdout.readline()
                        while line != '':
                            numbers += versionCandidates(line)
                            line = cmd.stdout.readline()
                        cmd.wait()
                        if cmd.returncode != 0:
                            # When the command returns with an error code,
                            # we assume we passed an incorrect flag to retrieve
                            # the version number.
                            numbers = []
                        if len(numbers) > 0:
                            break
                    # At this point *numbers* contains a list that can
                    # interpreted as versions. Hopefully, there is only
                    # one candidate.
                    if len(numbers) == 1:
                        excluded = False
                        for exclude in excludes:
                            if ((not exclude[0] 
                                 or versionCompare(exclude[0],numbers[0]) <= 0)
                                and (not exclude[1] 
                                 or versionCompare(numbers[0],exclude[1]) < 0)):
                                excluded = True
                                break
                        if not excluded:
                            version = numbers[0]
                            writetext(str(version) + '\n')
                            results.append((namePat, bin))
                        else:
                            writetext('excluded (' + str(numbers[0]) + ')\n')
                    else:
                        writetext('yes\n')
                        results.append((namePat, bin))
                    found = True
                    break
        if not found:
            writetext('no\n')
    return results, version


def findCache(names):
    '''Search for the presence of files in the cache directory. *names* 
    is a dictionnary of file names used as key and the associated checksum.'''
    results = []
    version = None
    for pathname in names:
        name = os.path.basename(urlparse.urlparse(pathname).path)
        writetext(name + "... ")
        log.flush()
        fullName = context.localDir(pathname)
        if os.path.exists(fullName):
            if names[name]:
                f = open(fullName,'rb')
                sum = hashlib.sha1(f.read()).hexdigest()
                f.close()
                if sum == names[name]:
                    # checksum are matching
                    writetext("cached\n")
                    results += [ fullName ]
                else:
                    writetext("corrupted?\n")
            else:
                writetext("yes\n")
        else:
            writetext("no\n")
    return results, version


def findFiles(base,namePat):
    '''Search the directory tree rooted at *base* for files matching *namePat*
       and returns a list of absolute pathnames to those files.'''
    result = []
    try:
        if os.path.exists(base):
            for p in os.listdir(base):
                path = os.path.join(base,p)
                look = re.match('.*' + namePat + '$',path)
                if look:
                    result += [ path ]
                elif os.path.isdir(path):
                    result += findFiles(path,namePat)
    except OSError:
        # In case permission to execute os.listdir is denied.
        None
    return result


def findFirstFiles(base,namePat,subdir=''):
    '''Search the directory tree rooted at *base* for files matching pattern
    *namePat* and returns a list of relative pathnames to those files 
    from *base*.
    If .*/ is part of pattern, base is searched recursively in breadth search 
    order until at least one result is found.'''
    try:
        subdirs = []
        results = []
        patNumSubDirs = len(namePat.split(os.sep))
        subNumSubDirs = len(subdir.split(os.sep))
        if os.path.exists(os.path.join(base,subdir)):
            for p in os.listdir(os.path.join(base,subdir)):
                relative = os.path.join(subdir,p)
                path = os.path.join(base,relative)
                look = re.match(namePat + '$',relative)
                if look != None:
                    results += [ relative ]
                elif (((('.*' + os.sep) in namePat) 
                       or (subNumSubDirs < patNumSubDirs))
                      and os.path.isdir(path)):
                    # When we see .*/, it means we are looking for a pattern 
                    # that can be matched by files in subdirectories 
                    # of the base.
                    subdirs += [ relative ]
        if len(results) == 0:
            for subdir in subdirs:
                results += findFirstFiles(base,namePat,subdir)
    except OSError, e:
        # Permission to a subdirectory might be denied.
        None
    return results


def findData(dir,names,excludes=[],target=None):
    '''Search for a list of extra files that can be found from $PATH
       where bin was replaced by *dir*.'''
    results = []
    for namePat, absolutePath in names:
        if absolutePath:
            # absolute paths only occur when the search has already been
            # executed and completed successfuly.
            results.append((namePat, absolutePath))
            continue
        writetext(namePat + '... ')
        log.flush()
        linkNum = 0
        if namePat.startswith('.*' + os.sep):
            linkNum = len(namePat.split(os.sep)) - 2
        found = False
        for base in derivedRoots(dir,target):
            fullNames = findFiles(base,namePat)
            if len(fullNames) > 0:
                writetext('yes\n')
                tokens = fullNames[0].split(os.sep)
                linked = os.sep.join(tokens[:len(tokens) - linkNum])
                # DEPRECATED: results.append((namePat,linked))
                results.append((namePat,fullNames[0]))
                found = True
                break
        if not found:
            writetext('no\n')
    return results, None

def findEtc(names,excludes=[],target=None):
    return findData('etc',names,excludes)

def findInclude(names,excludes=[],target=None):
    '''Search for a list of headers that can be found from $PATH
       where bin was replaced by include.

     *names* is a list of (pattern,absolutePath) pairs where the absolutePat
     can be None and in which case pattern will be used to search 
     for a header filename patterns. *excludes* is a list
    of versions that are concidered false positive and need to be 
    excluded, usually as a result of incompatibilities.
    
    This function returns a populated list of (pattern,absolutePath)  pairs
    and a version number if available.

    This function differs from findBin() and findLib() in its search 
    algorithm. findInclude() might generate a breadth search based 
    out of a derived root of $PATH. It opens found header files
    and look for a "#define.*VERSION" pattern in order to deduce
    a version number.'''
    results = []
    version = None
    includeSysDirs = derivedRoots('include',target)
    for namePat, absolutePath in names:
        if absolutePath:
            # absolute paths only occur when the search has already been
            # executed and completed successfuly.
            results.append((namePat, absolutePath))
            continue
        writetext(namePat + '... ')
        log.flush()
        found = False
        for includeSysDir in includeSysDirs:
            includes = []
            for header in findFirstFiles(includeSysDir,namePat):
                # Open the header file and search for all defines
                # that end in VERSION.
                numbers = []
                # First parse the pathname for a version number...
                parts = os.path.dirname(header).split(os.sep)
                parts.reverse()
                for part in parts:
                    for v in versionCandidates(part):
                        if not v in numbers:
                            numbers += [ v ]
                # Second open the file and search for a version identifier...
                header = os.path.join(includeSysDir,header)
                f = open(header,'rt')
                line = f.readline()
                while line != '':
                    look = re.match('\s*#define.*VERSION\s+(\S+)',line)
                    if look != None:
                        for v in versionCandidates(look.group(1)):
                            if not v in numbers:
                                numbers += [ v ]
                    line = f.readline()
                f.close()
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
                    for exclude in excludes:
                        if ((not exclude[0] 
                             or versionCompare(exclude[0],numbers[0]) <= 0)
                            and (not exclude[1] 
                                 or versionCompare(numbers[0],exclude[1]) < 0)):
                            excluded = True
                            break
                    if not excluded:
                        index = 0
                        for include in includes:
                            if ((not include[1]) 
                                or versionCompare(include[1],numbers[0]) < 0):
                                break
                            index = index + 1
                        includes.insert(index,(header,numbers[0]))
                else:
                    # If we find no version number, we append the header 
                    # at the end of the list with 'None' for version.
                    includes.append((header,None))
            if len(includes) > 0:
                if includes[0][1]:
                    version = includes[0][1]
                    writetext(version + '\n')
                else:
                    writetext('yes\n')
                results.append((namePat, includes[0][0]))
                includeSysDirs = [ os.path.dirname(includes[0][0]) ]
                found = True
                break
        if not found:
            writetext('no\n')
    return results, version
    

def findLib(names,excludes=[],target=None):
    '''Search for a list of libraries that can be found from $PATH
       where bin was replaced by lib.

    *names* is a list of (pattern,absolutePath) pairs where the absolutePat
    can be None and in which case pattern will be used to search 
    for library names with neither a 'lib' prefix 
    nor a '.a', '.so', etc. suffix. *excludes* is a list
    of versions that are concidered false positive and need to be 
    excluded, usually as a result of incompatibilities.
    
    This function returns a populated list of (pattern,absolutePath)  pairs
    and a version number if available.
    
    This function differs from findBin() and findInclude() in its
    search algorithm. findLib() might generate a breadth search based 
    out of a derived root of $PATH. It uses the full library name
    in order to deduce a version number if possible.'''
    results = []
    version = None
    suffix = '((-.+)|(_.+))?(\\' + libStaticSuffix() + '|\\' + libDynSuffix() + ')'
    for namePat, absolutePath in names:
        if absolutePath:
            # absolute paths only occur when the search has already been
            # executed and completed successfuly.
            results.append((namePat, absolutePath))
            continue
        # First time ever *findLib* is called, libDir will surely not defined
        # in the workspace make fragment and thus we will trigger interactive input from the user.
        # We want to make sure the output of the interactive session does not
        # mangle the search for a library so we preemptively trigger 
        # an interactive session.
        context.value('libDir')
        writetext(namePat + '... ')
        log.flush()
        found = False
        for libSysDir in derivedRoots('lib',target):
            libs = []
            libPat = libPrefix() + namePat.replace('+','\+') + suffix
            base, ext = os.path.splitext(namePat)
            if len(ext) > 0 and not ext.startswith('.*'):
                libPat = namePat.replace('+','\+')
            for libname in findFirstFiles(libSysDir,libPat):
                numbers = versionCandidates(libname)
                if len(numbers) == 1:
                    excluded = False
                    for exclude in excludes:
                        if ((not exclude[0] 
                             or versionCompare(exclude[0],numbers[0]) <= 0)
                            and (not exclude[1] 
                                 or versionCompare(numbers[0],exclude[1]) < 0)):
                            excluded = True
                            break
                    if not excluded:
                        index = 0
                        for lib in libs:
                            if ((not lib[1]) 
                                or versionCompare(lib[1],numbers[0]) < 0):
                                break
                            index = index + 1
                        libs.insert(index,(os.path.join(libSysDir,libname),
                                           numbers[0]))
                else:
                    libs.append((os.path.join(libSysDir,libname),None))
            if len(libs) > 0:             
                candidate = libs[0][0]
                for lib in libs:
                    if lib[0].endswith(libStaticSuffix()):
                        # Give priority to static libraries
                        candidate = lib[0]
                        if lib[1]:
                            version = lib[1] 
                        break
                    elif lib[1]:
                        # Then libraries with an associated version number
                        version = lib[1] 
                        candidate = lib[0] 
                look = re.match('.*' + libPrefix() + namePat + '(.+)',candidate)
                if look:                        
                    suffix = look.group(1)
                    writetext(suffix + '\n')
                else:
                    writetext('yes (no suffix?)\n')
                results.append((namePat, candidate))
                found = True
                break
        if not found:
            writetext('no\n')
    return results, version


def findPrerequisites(deps, excludes=[],target=None):
    '''Find a set of executables, headers, libraries, etc. on a local machine.
    
    *deps* is a dictionary where each key associates an install directory 
    (bin, include, lib, etc.) to a pair (pattern,absolutePath) as required
    by *findBin*(), *findLib*(), *findInclude*(), etc.

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
    for dir in [ 'bin', 'include', 'lib', 'etc', 'share' ]:
        # The search order "bin, include, lib, etc" will determine 
        # how excluded versions apply.
        if dir in deps:
            command = 'find' + dir.capitalize()   
            installed[dir], installedVersion = \
                modself.__dict__[command](deps[dir],excludes,target)
            # Once we have selected a version out of the installed
            # local system, we lock it down and only search for
            # that specific version.
            if not version and installedVersion:
                version = installedVersion
                excludes = [ (None,version), (versionIncr(version),None) ]
            if len(installed[dir]) != len(deps[dir]):
                complete = False
    return installed, complete


def findShare(names,excludes=[],target=None):
    return findData('share',names,excludes)


def findRSync(remotePath, relative=False, admin=False):
    '''Check if rsync is present and install it through the package
    manager if it is not. rsync is a little special since it is used
    directly by this script and the script is not always installed
    through a project.'''
    rsync = os.path.join(context.binBuildDir(),'rsync')
    if not os.path.exists(rsync):
        # We do not use validateControls() here because dws in not
        # a project in *srcTop* and does not exist on the remote machine. 
        # We use findBin() and linkContext() directly also because it looks
        # weird when the script prompts for installing a non-existent dws 
        # project before looking for the rsync prerequisite.
        dbindex = IndexProjects(context,
                          '''<?xml version="1.0" ?>
<projects>
  <project name="dws">
    <repository>
      <dep name="rsync">
	<bin>rsync</bin>
      </dep>
    </repository>
  </project>
</projects>
''')
        rsyncs, version = findBin([ [ 'rsync', None ] ])        
        if len(rsyncs) == 0 or not rsyncs[0][1]:
            install(['rsync'],{},dbindex)
        name, absolutePath = rsyncs.pop()
        linkPatPath(name, absolutePath,'bin')        

    # Create the rsync command
    uri = urlparse.urlparse(remotePath)
    hostname = uri.netloc
    if not uri.netloc:
        # If there is no protocol specified, the hostname
        # will be in uri.scheme (That seems like a bug in urlparse).
        hostname = uri.scheme
    username = None # \todo find out how urlparse is parsing ssh uris.
    # We are accessing the remote machine through a mounted
    # drive or through ssh.
    prefix = ""
    if username:
        prefix = prefix + username + '@'
    cmdline = [ rsync, '-avuzb' ]
    if relative:
        cmdline = [ rsync, '-avuzbR' ]
    if hostname:
        # We are accessing the remote machine through ssh
        prefix = prefix + hostname + ':'
        cmdline += [ '--rsh=ssh' ]
    if admin:
        cmdline += [ '--rsync-path "sudo rsync"' ]

    return cmdline, prefix


def configVar(vars):
    '''Look up the workspace configuration file the workspace make fragment for definition
    of variables *vars*, instances of classes derived from Variable 
    (ex. Pathname, SingleChoice). 
    If those do not exist, prompt the user for input.'''
    found = False
    for v in vars:
        # apply constrains where necessary
        v.constrain(context.environ)           
        if not v.name in context.environ:
            # If we do not add variable to the context, they won't
            # be saved in the workspace make fragment
            context.environ[v.name] = v 
            found |= v.configure()
    if found:                
        context.save()
    return vars


def fetch(filenames, cacheDir=None, force=False, admin=False, relative=False):
    '''download *filenames*, typically a list of distribution packages, 
    from the remote server into *cacheDir*. See the upload function 
    for uploading files to the remote server.
    When the files to fetch require sudo permissions on the remote
    machine, set *admin* to true.
    '''
    cachePath = cacheDir
    if not cacheDir:
        cachePath = context.cachePath()
    if len(filenames) > 0:
        if force:
            downloads = filenames
        else:
            locals = findCache(filenames)
            downloads = []
            for filename in filenames:
                if not context.cachePath(filename) in locals:
                    dir = os.path.dirname(context.cachePath(filename))
                    if not os.path.exists(dir):
                        os.makedirs(dir)
                    downloads += [ filename ]
        remoteCachePath = context.remoteCachePath()

        # Convert all filenames to absolute urls
        pathnames = []
        for f in downloads:
            if f.startswith('http') or ':' in f:
                pathnames += [ f ]
            elif f.startswith('/'):
                pathnames += [ '/.' + f ]
            else:
                pathnames += [ context.remoteCachePath('./' + f) ]
            
        # Split fetches by protocol
        https = []
        sshs = []
        for p in pathnames:
            # Splits between files downloaded through http and ssh.
            if p.startswith('http'):
                https += [ p ]
            else:
                sshs += [ p ]
        uri = urlparse.urlparse(remoteCachePath)
        hostname = uri.netloc
        if not uri.netloc:
            # If there is no protocol specified, the hostname
            # will be in uri.scheme (That seems like a bug in urlparse).
            hostname = uri.scheme
        # fetch https
        for remotename in https:
                localname = context.localDir(remotename)
                if not os.path.exists(os.path.dirname(localname)):
                    os.makedirs(os.path.dirname(localname))
                writetext('fetching ' + remotename + '...\n')
                remote = urllib2.urlopen(urllib2.Request(remotename))
                local = open(localname,'w')
                local.write(remote.read())
                local.close()
                remote.close()                
        # fetch sshs
        sources = []
        for s in sshs:
            sources += [ s.replace(hostname + ':','') ]
        if len(sources) > 0:
            if admin:
                shellCommand(['stty -echo;', 'ssh', hostname,
                              'sudo', '-v', '; stty echo'])
            cmdline, prefix = findRSync(remoteCachePath,
                                        relative or not cacheDir,admin)
            shellCommand(cmdline + ["'" + prefix + ' '.join(sources) + "'", 
                                    cachePath ])


def install(packages, extraFetches={}, dbindex=None, force=False):
    '''install a pre-built (also pre-fetched) package.
    '''

    projects = []
    for name in packages:
        if os.path.isfile(name):
            installLocalPackage(name)
        else:
            projects += [ name ]

    if len(extraFetches) > 0:
        fetch(extraFetches)

    if len(projects) > 0:
        if not dbindex:
            dbindex = index
        dbindex.validate(force)
        handler = Unserializer(projects)
        dbindex.parse(handler)

        managed = []
        for name in projects:
            # *name* is definitely handled by the local system package manager
            # whenever there is no associated project.
            if name in handler.projects:
                package = handler.asProject(name).packages[context.host()]
                if package:
                    for filename in package.fetches:
                        # The package is not part of the local system package 
                        # manager so it has to have been pre-built.
                        installLocalPackage(context.localDir(filename))
                else:
                    managed += [ name ]
            else:
                managed += [ name ]

        if len(managed) > 0:
            if context.host() == 'Ubuntu':
                # Add DEBIAN_FRONTEND=noninteractive such that interactive
                # configuration of packages do not pop up in the middle 
                # of installation. We are going to update the configuration
                # in /etc afterwards anyway.
                shellCommand(['/usr/bin/apt-get', 'update'], admin=True)
                shellCommand(['DEBIAN_FRONTEND=noninteractive',
                              '/usr/bin/apt-get','-y ',
                              'install'] + projects, admin=True)
            elif context.host() == 'Darwin':
                darwinNames = {
                    # translation of package names. It is simpler than
                    # creating an <alternates> node even if it look more hacky.
                    'libicu-dev': 'icu' }
                darwinPkgs = []
                for p in projects:
                    if p in darwinNames:
                        darwinPkgs += [ darwinNames[p] ]
                    else:
                        darwinPkgs += [ p ]
                shellCommand(['/opt/local/bin/port', 'install' ] \
                                 + darwinPkgs,admin=True)
            elif context.host() == 'Fedora':
                fedoraNames = {
                    'libbz2-dev': 'bzip2-devel',
                    'python-all-dev': 'python-devel',
                    'zlib1g-dev': 'zlib-devel' }
                fedoraPkgs = []
                for p in projects:
                    if p in fedoraNames:
                        fedoraPkgs += [ fedoraNames[p] ]
                    elif p.endswith('-dev'):
                        fedoraPkgs += [ p + 'el' ]
                    else:
                        fedoraPkgs += [ p ]
                shellCommand(['yum', '-y', 'install' ] + fedoraPkgs, admin=True)
            else:
                raise Error("Use of package manager for '" \
                                + context.host() + " not yet implemented.'")


def installDarwinPkg(image,target,pkg=None):
    '''Mount *image*, a pathnme to a .dmg file and use the Apple installer 
    to install the *pkg*, a .pkg package onto the platform through the Apple 
    installer.'''
    base, ext = os.path.splitext(image)
    volume = os.path.join('/Volumes',os.path.basename(base))
    shellCommand(['hdiutil', 'attach', image])
    if target != 'CurrentUserHomeDirectory':
        message = 'ATTENTION: You need administrator privileges on ' \
                + 'the local machine to execute the following cmmand\n'
        writetext(message)
        admin = True
    else:
        admin = False
    if not pkg:
        pkgs = findFiles(volume,'\.pkg')
        if len(pkgs) != 1:
            raise RuntimeError('ambiguous: not exactly one .pkg to install')
        pkg = pkgs[0]
    shellCommand(['installer', '-pkg', os.path.join(volume,pkg),
                  '-target "' + target + '"'], admin)
    shellCommand(['hdiutil', 'detach', volume])


def installLocalPackage(filename):
    '''Install a package from a file on the local system.'''
    if context.host() == 'Darwin':
        installDarwinPkg(filename,context.value('darwinTargetVolume'))
    elif context.host() == 'Ubuntu':
        shellCommand(['dpkg', '-i', filename], admin=True)
    elif context.host() == 'Fedora':
        shellCommand(['rpm', '-i', filename], admin=True)
    else:
        raise Error("Does not know how to install '" \
                        + filename + "' on " + context.host())

def libPrefix():
    '''Returns the prefix for library names.'''
    libPrefixes = {
        'Cygwin': ''
        }
    if context.host() in libPrefixes:
        return libPrefixes[context.host()]
    return 'lib'


def libStaticSuffix():
    '''Returns the suffix for static library names.'''
    libStaticSuffixes = {
        }
    if context.host() in libStaticSuffixes:
        return libStaticSuffixes[context.host()]
    return '.a'


def libDynSuffix():
    '''Returns the suffix for dynamic library names.'''
    libDynSuffixes = {
        'Cygwin': '.dll',
        'Darwin': '.dylib'
        }
    if context.host() in libDynSuffixes:
        return libDynSuffixes[context.host()]
    return '.so'


def linkDependencies(projects, cuts=[]):
    '''All projects which are dependencies but are not part of *srcTop*
    are not under development in the current workspace. Links to 
    the required executables, headers, libraries, etc. will be added to 
    the install directories such that projects in *srcTop* can build.'''
    missings = []
    tags = [ context.host() ]
    for project in projects:
        for prereq in projects[project].prerequisites(tags):
            if not prereq.name in cuts:
                # First, we will check if findPrerequisites needs to be rerun.
                # It is the case if the link in [bin|include|lib|...]Dir does
                # not exist and the pathname for it in buildDeps is not 
                # an absolute path.  
                complete = True
                deps = prereq.files
                for dir in deps:                    
                    for namePat, absolutePath in deps[dir]:
                        complete |= linkPatPath(namePat,absolutePath,
                                                dir,prereq.target)
                if not complete:
                    deps, complete = findPrerequisites(prereq.files,
                                                       prereq.excludes,
                                                       prereq.target)
                if not complete:
                    if not prereq in missings:
                        missings += [ prereq.name ]
                else:
                    for dir in deps:
                        for namePat, absolutePath in deps[dir]:
                            complete |= linkPatPath(namePat,absolutePath,
                                                    dir,prereq.target)
    if len(missings) > 0:
        raise Error("incomplete prerequisites for " + ' '.join(missings),1)


def linkContext(path,linkName):
    '''link a *path* into the workspace.'''
    if not path:
        log.error('There is no target for link ' + linkName + '\n')
        return
    if os.path.realpath(path) == os.path.realpath(linkName):
        return
    if not os.path.exists(os.path.dirname(linkName)):
        os.makedirs(os.path.dirname(linkName))
    # In the following two 'if' statements, we are very careful
    # to only remove/update symlinks and leave other files 
    # present in [bin|lib|...]Dir 'as is'.
    if os.path.islink(linkName):
        os.remove(linkName)
    if not os.path.exists(linkName) and os.path.exists(path):
        os.symlink(path,linkName)

def linkPatPath(namePat, absolutePath, dir, target=None):
    linkPath = absolutePath
    ext = ''
    if absolutePath:
        pathname, ext = os.path.splitext(absolutePath)
    if ext in [ libStaticSuffix(), libDynSuffix() ]:
        linkName = libPrefix() + namePat + ext 
    else:
        # Yeah, looking for g++ might be a little bit of trouble. 
        regex = re.compile(namePat.replace('+','\+') + '$')        
        if regex.groups == 0:
            linkName = namePat
            parts = namePat.split(os.sep)
            if len(parts) > 0:
                linkName = parts[len(parts) - 1]
        else:
            linkName = re.search('\((.+)\)',namePat).group(1)
            if absolutePath:
                look = regex.search(absolutePath)
                parts = absolutePath[look.end(1):].split(os.sep)
                linkPath = absolutePath[:look.end(1)] + parts[0]
    # linkName, linkPath
    subpath = dir
    if target:
        subpath = os.path.join(target,dir)
    linkName = os.path.join(context.value('buildTop'),subpath,linkName)
    # create links
    complete = True
    if linkPath:
        if not os.path.isfile(linkName):
            linkContext(linkPath,linkName)
    else:
        if not os.path.isfile(linkName):
            complete = False
    return complete


def make(names, targets, dbindex=None):
    '''invoke the make utility to build a set of projects.'''
    writetext('### make projects "' + ', '.join(names) \
                  + '" with targets "' + ', '.join(targets) + '"\n')
    distHost = context.value('distHost')
    errcode = 0
    errors = []
    if 'recurse' in targets:
        targets.remove('recurse')
        # Recurse through projects that need to be rebuilt first 
        # If no targets have been specified, the default target is to build
        # projects. Each project in turn has thus to be installed in order
        # to build the next one in the topological chain.
        recursiveTargets = targets
        if len(recursiveTargets) == 0:
            recursiveTargets = [ 'install' ]
        names, projects = validateControls(names,dbindex)
        last = names.pop()
        for name in names:
            errcode = makeProject(name,recursiveTargets,{ name: projects[name]})
            if errcode > 0:
                errors += [ name ]
        # Make current project
        if len(targets) > 0:
            errcode = makeProject(last,targets,{ last: projects[last]})
            if errcode > 0:
                errors += [ last ]
        else:
            linkDependencies({ last: projects[last]})
    else:
        for name in names:
            errcode = makeProject(name,targets)
            if errcode > 0:
                errors += [ name ]
    return errors


def makeProject(name,options,dependencies={}):
    '''Create links for prerequisites when necessary, then issue a make 
    command and log output.'''
    log.header(name)
    # Make sure the variable will be available in Makefiles.
    context.value('makeHelperDir')
    makefile = context.srcDir(os.path.join(name,'Makefile'))
    objDir = context.objDir(name)
    if objDir != os.getcwd():
        if not os.path.exists(objDir):
            os.makedirs(objDir)
        os.chdir(objDir)
    errcode = 0
    targets = []
    overrides = []
    for opt in options:
        if re.match('\S+=.*',opt):
            overrides += [ opt ]
        else:
            targets += [ opt ]
    # If we do not set PATH to *binBuildDir*:*binDir*:${PATH}
    # and the install directory is not in PATH, then we cannot
    # build a package for drop because 'make dist' depends
    # on executables installed in *binDir* (dws, buildpkg, ...)
    # that are not linked into *binBuildDir* at the time 
    # 'cd drop ; make dist' is run. Note that it is not an issue
    # for other projects since those can be explicitely depending
    # on drop as a prerequisite.
    cmdline = ['export PATH=' + ':'.join(context.searchPath()) + ' ;',
               'make', '-f', makefile]
    start = datetime.datetime.now()
    try:        
        if len(dependencies) > 0:
            # Dependencies which are concidered to be packages have files 
            # located anywhere on the local system and only links to those
            # files end-up in build{Bin,Lib,etc.}. 
            # Those links cannot be created in validateControls though since
            # we also have "package patches projects", i.e. projects which
            # are only there as temporary workarounds for packages which 
            # will be coming out of the local system package manager at some
            # point in the future.
            linkDependencies(dependencies)
        # prefix.mk and suffix.mk expects these variables to be defined 
        # in the workspace make fragment. If they are not you might get some strange errors where
        # a g++ command-line appears with -I <nothing> or -L <nothing> 
        # for example.
        # This code was moved to be executed right before the issue 
        # of a "make" subprocess in order to let the project index file 
        # a change to override defaults for installTop, etc.
        for dir in [ 'include', 'lib', 'bin', 'etc', 'share' ]:
            name = context.value(dir + 'Dir')
        if len(targets) > 0:
            for target in targets:
                shellCommand(cmdline + [ target ] + overrides)
        else:
            shellCommand(cmdline)
    except Error, e:
        errcode = e.code
        log.error(str(e))
    finish = datetime.datetime.now()
    elapsed = finish - start
    log.footer(str(elapsed),errcode)
    return errcode


def mergeBuildConf(dbPrev,dbUpd,parser):
    '''Merge an updated project dependency database into an existing
       project dependency database. The existing database has been
       augmented by user-supplied information such as "use source
       controlled repository", "skip version X dependency", etc. Hence
       we do a merge instead of a complete replace.'''
    if dbPrev == None:
        return dbUpd
    elif dbUpd == None:
        return dbPrev
    else:
        # We try to keep user-supplied information in the prev
        # database whenever possible.
        # Both databases supply packages in alphabetical order,
        # so the merge can be done in a single pass.
        dbNext = tempfile.TemporaryFile()
        projPrev = parser.copy(dbNext,dbPrev)
        projUpd = parser.next(dbUpd)
        while projPrev != None and projUpd != None:
            if projPrev < projUpd:
                parser.startProject(dbNext,projPrev)
                projPrev = parser.copy(dbNext,dbPrev)
            elif projPrev > projUpd:
                parser.startProject(dbNext,projUpd)
                projUpd = parser.copy(dbNext,dbUpd)
            elif projPrev == projUpd:
                # when names are equals, we need to import user-supplied
                # information as appropriate. For now, there are only one
                # user supplied-information, the install mode for the package.
                # Package name is a unique key so we can increment
                # both iterators.
                parser.startProject(dbNext,projUpd)
                #installMode, version = parser.installMode(projPrev)
                #parser.setInstallMode(dbNext,installMode,version)
                # It is critical this line appears after we set the installMode
                # because it guarentees that the install mode will always be
                # the first line after the package tag.
                projUpd = parser.copy(dbNext,dbUpd,True)
                projPrev = parser.copy(dbNext,dbPrev)
        while projPrev != None:
            parser.startProject(dbNext,projPrev)
            projPrev = parser.copy(dbNext,dbPrev)
        while projUpd != None:
            parser.startProject(dbNext,projUpd)
            projUpd = parser.copy(dbNext,dbUpd)
        parser.trailer(dbNext)
        return dbNext


def upload(filenames, cacheDir=None):
    '''upload *filenames*, typically a list of result logs, 
    to the remote server. See the fetch function for downloading
    files from the remote server.
    '''
    cmdline, prefix = findRSync(remoteCachePath,not cacheDir)
    upCmdline = cmdline + [ '././' + ' ././'.join(sshs), remoteCachePath ]
    prev = os.getcwd()
    os.chdir(cachePath)
    shellCommand(upCmdline)
    os.chdir(prev)


def searchBackToRoot(filename,root=os.sep):
    '''Search recursively from the current directory to the *root*
    of the directory hierarchy for a specified *filename*.
    This function returns the relative path from *filename* to pwd
    and the absolute path to *filename* if found.'''
    d = os.getcwd()
    dirname = '.'
    while (not os.path.samefile(d,root) 
           and not os.path.isfile(os.path.join(d,filename))):
        if dirname == '.':
            dirname = os.path.basename(d)
        else:
            dirname = os.path.join(os.path.basename(d),dirname)
        d = os.path.dirname(d)
    if not os.path.isfile(os.path.join(d,filename)):
        raise IOError(1,"cannot find file",filename)
    return dirname, os.path.join(d,filename)


def shellCommand(commandLine, admin=False):
    '''Execute a shell command and throws an exception when the command fails'''
    if admin:
        if None:
            # \todo cannot do this simple check because of a shell variable
            # setup before call to apt-get.
            if not commandLine.startswith('/'):
                raise Error("admin command without a fully quaified path: " \
                                + commandLine)
        # ex: su username -c 'sudo port install icu'        
        cmdline = [ '/usr/bin/sudo' ] + commandLine
    else:
        cmdline = commandLine
    if log:
        log.logfile.write('<command><![CDATA[' + ' '.join(cmdline) + ']]></command>\n')
    sys.stdout.write(' '.join(cmdline) + '\n')
    if not doNotExecute:
        if log:
            log.logfile.write('<output><![CDATA[\n')
        cmd = subprocess.Popen(' '.join(cmdline),shell=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
        line = cmd.stdout.readline()
        while line != '':
            writetext(line)
            line = cmd.stdout.readline()
        cmd.wait()
        if log:
            log.logfile.write(']]></output>\n')
        if cmd.returncode != 0:
            raise Error("unable to complete: " + ' '.join(cmdline),
                        cmd.returncode)


def sortBuildConfList(dbPathnames,parser):
    '''Sort/Merge projects defined in a list of files, *dbPathnames*.
    *parser* is the parser used to read the projects files in.'''
    dbPrev = None
    dbUpd = None
    if len(dbPathnames) == 0:
        return None
    elif len(dbPathnames) == 1:
        dbPrev = open(dbPathnames[0])
        return dbPrev
    elif len(dbPathnames) == 2:
        dbPrev = open(dbPathnames[0])
        dbUpd = open(dbPathnames[1])
    else:
        dbPrev = sortBuildConfList(dbPathnames[:len(dbPathnames) / 2],parser)
        dbUpd = sortBuildConfList(dbPathnames[len(dbPathnames) / 2:],parser)
    dbNext = mergeBuildConf(dbPrev,dbUpd,parser)
    dbNext.seek(0)
    dbPrev.close()
    dbUpd.close()
    return dbNext


def validateControls(repositories, dbindex=None, force=False):
    '''Checkout source code files, install packages such that 
    the projects specified in *repositories* can be built.
    *dbindex* is the project index that contains the dependency 
    information to use. If None, the global index fetched from
    the remote machine will be used.

    This function returns a topologicaly sorted list of projects
    in *srcTop* and an associated dictionary of Project instances. 
    By iterating through the list, it is possible to 'make' 
    each prerequisite project in order.'''
    if not dbindex:
        dbindex = index
    dbindex.validate(force)
    # note that *excludePats* is global.
    dgen = DependencyGenerator(repositories,[],[],excludePats) 

    # Add deep dependencies
    reps, packages, fetches = dbindex.closure(dgen)

    # Checkout missing source controlled projects
    # and install missing packages.
    install(packages,fetches,dbindex)
    if force:
        # Force update all projects under revision control
        update(reps,fetches,dbindex,force)
    else:
        # Update only projects which are missing from *srcTop*
        # and leave other projects in whatever state they are in.
        update(dgen.extraSyncs,fetches,dbindex,force)
    return reps, dgen.projects


def versionCandidates(line):
    '''Extract patterns from *line* that could be interpreted as a 
    version numbers. That is every pattern that is a set of digits
    separated by dots and/or underscores.'''
    part = line
    candidates = []
    while part != '':
        # numbers should be full, i.e. including '.'
        look = re.match('[^0-9]*([0-9].*)',part)
        if look:
            part = look.group(1)
            look = re.match('[^0-9]*([0-9]+([_\.][0-9]+)+)+(.*)',part)
            if look:
                candidates += [ look.group(1) ]
                part = look.group(2)
            else:
                while (len(part) > 0
                       and part[0] in ['0', '1', '2', '3', '4', '5', 
                                       '6', '7', '8', '9' ]):
                    part = part[1:]
        else:
            part = ''
    return candidates


def versionCompare(left,right):
    '''Compare version numbers

    This function returns -1 if a *left* is less than *right*, 0 if *left 
    is equal to *right* and 1 if *left* is greater than *right*.
    It is suitable as a custom comparaison function for sorted().'''
    leftRemain = left.replace('_','.').split('.')
    rightRemain = right.replace('_','.').split('.')
    while len(leftRemain) > 0 and len(rightRemain) > 0:
        leftNum = leftRemain.pop(0)
        rightNum = rightRemain.pop(0)
        if leftNum < rightNum:
            return -1
        elif leftNum > rightNum:
            return 1
    if len(leftRemain) < len(rightRemain):
        return -1
    elif len(leftRemain) > len(rightRemain):
        return 1
    return 0


def versionIncr(v):
    '''returns the version number with the smallest increment 
    that is greater than *v*.'''
    return v + '.1'


def integrate(srcdir, pchdir, verbose=True):
    for name in os.listdir(pchdir):
        srcname = os.path.join(srcdir,name)
        pchname = os.path.join(pchdir,name)
        if os.path.isdir(pchname):
            if not os.path.basename(name) in [ 'CVS', '.git']:
                integrate(srcname,pchname,verbose)
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
                        shutil.move(basename,basename + '~')
                    os.symlink(os.path.relpath(pchname),basename)
                    os.chdir(prev)


def update(reps, extraFetches={}, dbindex = None, force=False):
    '''Update a list of *reps* within the workspace. The update will either 
    sync with a source rep repository if the project is present in *srcTop*
    or will install a new binary package through the local package manager.
    *extraFetches* is a list of extra files to fetch from the remote machine,
    usually a list of compressed source tar files.'''
    if not dbindex:
        dbindex = index
    dbindex.validate(force)
    handler = Unserializer(reps)
    dbindex.parse(handler)

    if len(extraFetches) > 0:
        fetch(extraFetches)

    # If an error occurs, at least save previously configured variables.
    context.save()
    for name in reps:
        # The project is present in *srcTop*, so we will update the source 
        # code from a repository. 
        rep = handler.asProject(name).repository
        if not rep:
            rep = handler.asProject(name).patch
        if rep:
            # Not every project is made a first-class citizen. If there are 
            # no rep structure for a project, it must depend on a project
            # that does in order to have a source repled repository.
            # This is a simple way to specify inter-related projects 
            # with complex dependency set and barely any code. 
            writetext('######## updating project ' + name + '...\n')
            # \todo We do not propagate force= here to avoid messing up
            #       the local checkouts on pubUpdate()
            rep.update(name,context)
        else:
            writetext('warning: ' + name + ' is not a project under source control. It is most likely a psuedo-project and will be updated through an "update recurse" command.\n')


def writetext(message):
    if log:
        log.write(message)
        log.flush()
    else:
        sys.stdout.write(message)
        sys.stdout.flush()


def prompt(message):
    '''If the script is run through a ssh command, the message would not
    appear if passed directly in raw_input.'''
    writetext(message)
    return raw_input("")

            
def pubBuild(args):
    '''build              [remoteIndexFile [localTop]]
                        This bootstrap command will download an index 
                        database file from *remoteTop* and starts issuing
                        make for every project listed in it with targets 
                        'install' and 'dist'. 
                        This command is meant to be used as part of cron
                        jobs on build servers and thus designed to run 
                        to completion with no human interaction. As such, 
                        in order to be really useful in an automatic build 
                        system, authentication to the remote server should 
                        also be setup to run with no human interaction.
    '''
    if len(args) > 0:
        context.remoteSite(args[0])
    if len(args) > 1:
        context.environ['siteTop'].value = os.path.realpath(args[1])
    global useDefaultAnswer
    useDefaultAnswer = True
    global log
    log = LogFile(context.logname(),nolog)
    rgen = DerivedSetsGenerator()
    index.parse(rgen)
    errors = make(rgen.roots,[ 'recurse', 'install', 'dist' ])
    log.close()
    log = None
    # Once we have built the repository, let's report the results
    # back to the remote server. We stamp the logfile such that
    # it gets a unique name before uploading it.
    logstamp = stampfile(context.logname())
    if not os.path.exists(os.path.dirname(context.logPath(logstamp))):
        os.makedirs(os.path.dirname(context.logPath(logstamp)))
    shellCommand(['install', '-m', '644', context.logname(),
                  context.logPath(logstamp)])
    if uploadResults:
        upload([ logstamp ])
    if len(errors) > 0:
        raise Error("Found errors while making " + ' '.join(errors))


def pubCollect(args):
    '''collect                Consolidate local dependencies information 
                       into a global dependency database. Copy all 
                       distribution packages built into a platform 
                       distribution directory.
                       (example: dws --exclude test collect)
    '''

    # Collect cannot log or it will prompt for index file.
    # global log 
    # log = LogFile(context.logname(),nolog)

    # Create the distribution directory, i.e. where packages are stored.
    packageDir = context.cachePath(context.host())
    if not os.path.exists(packageDir):
        os.makedirs(packageDir)
    srcPackageDir = context.cachePath('srcs')
    if not os.path.exists(srcPackageDir):
        os.makedirs(srcPackageDir)

    # Create the project index file
    # and copy the packages in the distribution directory.
    extensions = { 'Darwin': ('\.dsx', '\.dmg'),
                   'Fedora': ('\.spec', '\.rpm'),
                   'Ubuntu': ('\.dsc', '\.deb')
                 }
    # collect index files and packages
    copySrcPackages = None
    copyBinPackages = None
    preExcludeIndices = []
    if str(context.environ['buildTop']):
        # If there are no build directory, then don't bother to look
        # for built packages and avoid prompty for an unncessary value
        # for buildTop.
        srcPackages = findFiles(context.value('buildTop'),'.tar.bz2')
        if len(srcPackages) > 0:
            cmdline, prefix = findRSync(srcPackageDir)
            copySrcPackages = cmdline + [ ' '.join(srcPackages),
                                          srcPackageDir]
        if context.host() in extensions:
            ext = extensions[context.host()]
            preExcludeIndices = findFiles(context.value('buildTop'),ext[0])
            binPackages = findFiles(context.value('buildTop'),ext[1])
            if len(binPackages) > 0:
                cmdline, prefix = findRSync(packageDir)
                copyBinPackages = cmdline + [ ' '.join(binPackages),
                                              packageDir ]

    preExcludeIndices += findFiles(context.value('srcTop'),context.indexName)
    # We exclude any project index files that has been determined 
    # to be irrelevent to the collection being built.
    indices = []
    for index in preExcludeIndices:
        found = False
        for excludePat in excludePats:
            if re.match('.*' + excludePat + '.*',index):
                found = True
                break
        if not found:
            indices += [ index ]
    # Create the index and checks it is valid according to the schema. 
    createIndexPathname(context.dbPathname(),indices)
    shellCommand(['xmllint', '--noout', '--schema ',
                  context.derivedHelper('index.xsd'),
                  context.dbPathname()])
    # We should only copy the index file after we created it.
    if copyBinPackages:
        shellCommand(copyBinPackages)
    if copySrcPackages:
        shellCommand(copySrcPackages)


def pubConfigure(args):
    '''configure              Configure the local machine with direct 
                       dependencies of a project such that the project 
                       can be built later on.
    '''
    global log 
    log = LogFile(context.logname(),nolog)
    projectName = context.cwdProject()
    dgen = DependencyGenerator([ projectName ],[],[])
    dbindex = IndexProjects(context,
                            context.srcDir(os.path.join(context.cwdProject(),
                                                        context.indexName)))
    dbindex.parse(dgen)
    if len(dgen.missings) > 0 or len(dgen.extraFetches) > 0:
        # This is an opportunity to prompt for missing dependencies.
        # After installing both, source controlled and packaged
        # projects, the checked-out projects will be added to 
        # the dependency graph while the packaged projects will
        # be added to the *cut* list.
        prerequisites = set([])
        for miss in dgen.missings:
            prerequisites |= set([ miss[1] ])
        for miss in dgen.extraFetches:
            prerequisites |= set([ miss ])            
        raise MissingError(projectName,prerequisites)
    else:
        linkDependencies({ projectName: dgen.projects[projectName]})


def pubContext(args):
    '''context                Prints the absolute pathname to a file.
                       If the filename cannot be found from the current 
                       directory up to the workspace root (i.e where the workspace make fragment 
                       is located), it assumes the file is in *etcDir*.
    '''
    pathname = context.configFilename
    if len(args) >= 1:
        try:
            dir, pathname = searchBackToRoot(args[0],
                   os.path.dirname(context.configFilename))
        except IOError:
            pathname = context.derivedHelper(args[0])
    sys.stdout.write(pathname)


def pubCreate(args):
    '''create               projectName
                       Create a new directory and initial it as a project
                       repository.
    '''
    prev = os.getcwd()
    projName = args[0]
    projDir = os.path.join(context.value('srcTop'),projName)
    if os.path.exists(projDir):
        raise Error(projDir + ' already exists')
    os.makedirs(projDir)
    os.chdir(projDir)
    shellCommand(['git', 'init'])
    hookSample = os.path.join('.git','hooks','post-update.sample')
    hook = os.path.join('.git','hooks','post-update')
    if os.path.isfile(hookSample):
        shutil.move(hookSample,hook)
    if os.path.isfile(hook):
        shellCommand(['chmod', '755', hook])
    config = open( os.path.join('.git','config'))
    lines = config.readlines()
    config.close()
    foundReceive = -1
    foundDenyCurrentBranch = -1
    for i in range(0,len(lines)):
        if re.match('[receive]',lines[i]):            
            foundReceive = i
        elif re.match('\s*denyCurrentBranch = (\S+)',lines[i]):
            foundDenyCurrentBranch = i
    config = open(os.path.join('.git','config'),'w')
    if foundReceive >= 0:
       if foundDenyCurrentBranch >= 0:
           config.write(''.join(lines[0:foundDenyCurrentBranch]))
           config.write('\tdenyCurrentBranch = ignore\n')
           config.write(''.join(lines[foundDenyCurrentBranch + 1:]))
       else:
           config.write(''.join(lines[0:foundDenyCurrentBranch]))
           config.write('\tdenyCurrentBranch = ignore\n')
           config.write(''.join(lines[foundDenyCurrentBranch:]))
    else:
        config.write(''.join(lines))
        config.write('[receive]\n')
        config.write('\tdenyCurrentBranch = ignore\n')
    config.close()
    index = open(os.path.join(context.indexName),'w')
    index.write('''<?xml version="1.0" ?>
<projects>
  <project name="''' + projName + '''">
    <title></title>
    <description></description>
    <maintainer name="" email="" />
    <repository>
    </repository>
  </project>
</projects>
''')
    index.close()
    shellCommand(['git', 'add', '.'])
    shellCommand(['git', 'commit', '-m', "'initial index (template)'"])


def pubDuplicate(args):
    '''duplicate              Duplicate pathnames from the remote machine into
                       *duplicateDir* on the local machine. 
    ''' 
    remoteCachePath = context.value('remoteSiteTop')
    uri = urlparse.urlparse(remoteCachePath)
    hostname = uri.netloc
    if not uri.netloc:
        # If there is no protocol specified, the hostname
        # will be in uri.scheme (That seems like a bug in urlparse).
        hostname = uri.scheme
    pathnames = [ uri.path, '/var/www', '/var/log', 
                  '/var/lib/awstats', '/var/lib/mailman' ]
    duplicateDir = context.value('duplicateDir')
    if hostname:
        duplicateDir = os.path.join(duplicateDir,hostname)
    if not os.path.exists(duplicateDir):
        os.makedirs(duplicateDir)
    fetch(pathnames,duplicateDir,force=True,admin=True,relative=True)


def pubFind(args):
    '''find               bin|lib filename ...
                       Search through a set of directories derived from PATH
                       for *filename*.
    ''' 
    global log 
    log = LogFile(context.logname(),True)
    dir = args[0]
    command = 'find' + dir.capitalize()
    searches = []
    for arg in args[1:]:
        searches += [ (arg,None) ]
    installed, installedVersion = \
        modself.__dict__[command](searches)
    if len(installed) != len(searches):
        sys.exit(1)


def pubInit(args):
    '''init                   Prompt for variables which have not been 
                       initialized in the workspace make fragment. Fetch the project index.
    '''
    configVar(context.environ.values())
    index.validate()


def pubInstall(args):
    '''install                Install a package on the local system.
    '''
    install(args)


def pubIntegrate(args):
    '''integrate          [ srcPackage ... ]
                       Integrate a patch into a source package
    '''
    while len(args) > 0:
        srcdir = unpack(args.pop(0))
        pchdir = context.srcDir(os.path.join(context.cwdProject(),
                                             srcdir + '-patch'))
        integrate(srcdir,pchdir)


class ListPdbHandler(PdbHandler):

    def project(self, p):
        sys.stdout.write(str(p))


def pubList(args):
    '''list                   List available projects
    '''
    index.parse(ListPdbHandler())


def pubMake(args):
    '''make                   Make projects. "make recurse" will build 
                       all dependencies required before a project 
                       can be itself built.
    '''
    global log 
    context.environ['siteTop'].default = os.path.dirname(os.path.dirname(
        os.path.realpath(os.getcwd())))
    log = LogFile(context.logname(),nolog)
    repositories = [ context.cwdProject() ]
    errors = make(repositories,args)
    if len(errors) > 0:
        raise Error("Found errors while making " + ' '.join(errors))


def pubStatus(args):
    '''status                 Show status of projects checked out 
                       in the workspace with regards to commits.
    '''
    global log 
    log = LogFile(context.logname(),nolog)
    reps = args
    recurse = False
    if 'recurse' in args:
        recurse = True
        reps.remove('recurse')
    if len(reps) == 0:
        # We try to derive project names from the current directory whever 
        # it is a subdirectory of buildTop or srcTop.
        cwd = os.path.realpath(os.getcwd())
        buildTop = os.path.realpath(context.value('buildTop'))
        srcTop = os.path.realpath(context.value('srcTop'))
        srcDir = srcTop
        srcPrefix = os.path.commonprefix([ cwd,srcTop ])
        buildPrefix = os.path.commonprefix([ cwd, buildTop ])
        if srcPrefix == srcTop:
            srcDir = cwd
        elif buildPrefix == buildTop:
            srcDir = cwd.replace(buildTop,srcTop)
        if os.path.exists(srcDir):
            for repdir in findFiles(srcDir,'\.git'):
                reps += [ os.path.dirname(repdir.replace(srcTop + os.sep,'')) ]
        else:
            reps = [ context.cwdProject() ]
    if recurse:
        raise NotYetImplemented()
    else:
        cmdline = 'git status'
        prev = os.getcwd()
        for r in reps:            
            os.chdir(context.srcDir(r))
            try:                
                cmd = subprocess.Popen(cmdline,shell=True,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT)
                line = cmd.stdout.readline()
                untracked = False
                while line != '':
                    look = re.match('#\s+([a-z]+):\s+(\S+)',line)
                    if look:
                        sys.stdout.write(' '.join([
                                    look.group(1).capitalize()[0],
                                    r, look.group(2)]) + '\n')
                    elif re.match('# Untracked files:',line):
                        untracked = True
                    elif untracked:
                        look = re.match('#	(\S+)',line)
                        if look:
                            sys.stdout.write(' '.join(['?', r,
                                                       look.group(1)]) + '\n')
                    line = cmd.stdout.readline()
                cmd.wait()
                if cmd.returncode != 0:
                    raise Error("unable to complete: " + cmdline,
                                cmd.returncode)
            except Error, e:
                # It is ok. git will return error code 1 when no changes
                # are to be committed.
                None
        os.chdir(prev)


def pubUpdate(args):
    '''update                 [ projectName ... ]
                            Update projects installed in the workspace
    '''
    global log 
    log = LogFile(context.logname(),nolog)
    reps = args
    recurse = False
    if 'recurse' in args:
        recurse = True
        reps.remove('recurse')
    if len(reps) == 0:
        # We try to derive project names from the current directory whever 
        # it is a subdirectory of buildTop or srcTop.
        cwd = os.path.realpath(os.getcwd())
        buildTop = os.path.realpath(context.value('buildTop'))
        srcTop = os.path.realpath(context.value('srcTop'))
        projectName = None
        srcDir = srcTop
        srcPrefix = os.path.commonprefix([ cwd,srcTop ])
        buildPrefix = os.path.commonprefix([ cwd, buildTop ])
        if srcPrefix == srcTop:
            srcDir = cwd
            projectName = srcDir[len(srcTop) + 1:]
        elif buildPrefix == buildTop:
            srcDir = cwd.replace(buildTop,srcTop)
            projectName = srcDir[len(srcTop) + 1:]
        if projectName:
            reps = [ projectName ]
        else:
            for repdir in findFiles(srcDir,'\.git'):
                reps += [ os.path.dirname(repdir.replace(srcTop + os.sep,'')) ]
    if recurse:
        names, projects = validateControls(reps,force=True)
    else:
        update(reps,force=True)
    

def pubUpstream(args):
    '''upstream          [ srcPackage ... ]
                       Generate a patch to submit to upstream 
                       maintainer out of a source package and 
                       a -patch subdirectory in a project srcDir.
    '''
    while len(args) > 0:
        pkgfilename = args.pop(0)
        srcdir = unpack(pkgfilename)
        orgdir = srcdir + '.orig'
        if os.path.exists(orgdir):
            os.removedirs(orgdir)        
        shutil.move(srcdir,orgdir)
        srcdir = unpack(pkgfilename)
        pchdir = context.srcDir(os.path.join(context.cwdProject(),
                                             srcdir + '-patch'))
        integrate(srcdir,pchdir)
        # In the common case, no variables will be added to the workspace make fragment when 
        # the upstream command is run. Hence sys.stdout will only display
        # the patched information. This is important to be able to execute:
        #   dws upstream > patch
        cmdline = 'diff -ruNa ' + orgdir + ' ' + srcdir
        p = subprocess.Popen(cmdline, shell=True,
                             stdout=subprocess.PIPE, close_fds=True)
        line = p.stdout.readline()
        while line != '':
            # log might not defined at this point. 
            sys.stdout.write(line)
            line = p.stdout.readline()
        p.poll()


def selectCheckout(repCandidates, patchCandidates, packageCandidates=[]):
    '''Interactive prompt for a selection of projects to checkout.
    *repCandidates* contains a list of rows describing projects available
    for selection. This function will return a list of projects to checkout
    from a source repository and a list of projects to install through 
    a package manager.'''
    reps = []
    if len(repCandidates) > 0:
        reps = selectMultiple(
'''The following dependencies need to be present on your system. 
You have now the choice to install them from a source repository. You will later
have  the choice to install them from either a patch, a binary package or not at all.''',
        repCandidates)
    # Filters out the dependencies which the user has decided to install
    # from a repository.
    patches = []
    for row in patchCandidates:
        if not row[0] in reps:
            patches += [ row ]
    if len(patches) > 0:
        patches = selectMultiple(
'''The following dependencies need to be present on your system. 
You have now the choice to install them from a patch from a known source distribution. You will later have the choice to install them from binary package or not at all.''',
        patches)
    # Filters out the dependencies which the user has decided to install
    # from a repository.
    packages = []
    for row in packageCandidates:
        if not row[0] in reps + patches:
            packages += [ row ]
    packages = selectInstall(packages)
    return reps, patches, packages


def selectInstall(packageCandidates):
    '''Interactive prompt for a selection of projects to install 
    as binary packages. *packageCandidates* contains a list of rows 
    describing projects available for selection. This function will 
    return a list of projects to install through a package manager. '''
    packages = []
    if len(packageCandidates) > 0:
        packages = selectMultiple(
    '''The following dependencies need to be present on your system. 
You have now the choice to install them from a binary package. You can skip
this step if you know those dependencies will be resolved correctly later on.
''',packageCandidates)
    return packages


def selectOne(description, choices, sort=True):
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
        showMultiple(description,choices)
        if useDefaultAnswer:
            selection = "1"
        else:
            selection = prompt("Enter a single number [1]: ")
            if selection == "":
                selection = "1"
        try:
            choice = int(selection)
            if choice >= 1 and choice <= len(choices):
                return choices[choice - 1][0]
        except TypeError:
            choice = None
        except ValueError:  
            choice = None
    return choice


def selectMultiple(description,selects):
    '''Prompt an interactive list of choices and returns elements selected
    by the user. *description* is a text that explains the reason for the 
    prompt. *choices* is a list of elements to choose from. Each element is 
    in itself a list. Only the first value of each element is of significance
    and returned by this function. The other values are only use as textual
    context to help the user make an informed choice.'''
    result = []
    done = False
    selects.sort()
    choices = [ [ 'all' ] ] + selects
    while len(choices) > 1 and not done:
        showMultiple(description,choices)
        writetext(str(len(choices) + 1) + ')  done\n')
        if useDefaultAnswer:
            selection = "1"
        else:
            selection = prompt("Enter a list of numbers separated by spaces [1]: ")
            if len(selection) == 0:
                selection = "1"
        # parse the answer for valid inputs
        selection = selection.split(' ')
        for s in selection:
            try:
                choice = int(s)
            except TypeError:
                choice = 0
            except ValueError:  
                choice = 0
            if choice > 1 and choice <= len(choices):
                result += [ choices[choice - 1][0] ]
            elif choice == 1:
                result = []
                for c in choices[1:]:
                    result += [ c[0] ] 
                done = True
            elif choice == len(choices) + 1:
                done = True
        # remove selected items from list of choices
        remains = []
        for row in choices:
            if not row[0] in result:
                remains += [ row ]
        choices = remains
    return result


def selectYesNo(description):
    '''Prompt for a yes/no answer.'''
    if useDefaultAnswer:
        return True
    yesNo = prompt(description + " [Y/n]? ")
    if yesNo == '' or yesNo == 'Y' or yesNo == 'y':
        return True
    return False


def showMultiple(description,choices):
    '''Display a list of choices on the user interface.'''
    # Compute display layout
    item = 1
    widths = []
    displayed = []
    for row in choices:
        c = 0
        row = [ str(item) + ')' ] + row
        displayed += [ row ]
        item = item + 1
        for col in row:
            if len(widths) <= c:
                widths += [ 2 ]
            widths[c] = max(widths[c],len(col) + 2)
            c = c + 1
    # Ask user to review selection
    writetext(description + '\n')
    for project in displayed:
        c = 0
        for col in project:
            writetext(col.ljust(widths[c]))
            c = c + 1
        writetext('\n')


def unpack(pkgfilename):
    '''unpack a tar[.gz|.bz2] source distribution package.'''
    if pkgfilename.endswith('.bz2'):
        d = 'j'
    elif pkgfilename.endswith('.gz'):
        d = 'z'
    shellCommand(['tar', d + 'xf', pkgfilename])    
    return os.path.basename(os.path.splitext(
               os.path.splitext(pkgfilename)[0])[0])


# Main Entry Point
if __name__ == '__main__':

    try:
        import __main__
	import optparse

        context = Context()
        epilog= '\nCommands:\n'
        d = __main__.__dict__
        keys = d.keys()
        keys.sort()
        for command in keys:
            if command.startswith('pub'):
                epilog += __main__.__dict__[command].__doc__ + '\n'
        keys = context.environ.keys()
        keys.sort()
        epilog += 'Variables defined in the workspace make fragment (' \
            + Context.configName + '):\n'
        for varname in keys:
            var = context.environ[varname]
            if var.descr:
                epilog += var.name.ljust(23,' ') + var.descr + '\n\n'

	parser = optparse.OptionParser(\
            usage='%prog [options] command\n\nVersion\n  %prog version ' \
                + str(__version__),
            formatter=CommandsFormatter(),
            epilog=epilog)
	parser.add_option('--default', dest='default', action='store_true',
	    help='Use default answer for every interactive prompt.')
	parser.add_option('--exclude', dest='excludePats', action='append',
	    help='The specified command will not be applied to projects matching the name pattern.')
	parser.add_option('--help-book', dest='helpBook', action='store_true',
	    help='Print help in docbook format')
	parser.add_option('--nolog', dest='nolog', action='store_true',
	    help='Do not generate output in the log file')
	parser.add_option('--prefix', dest='installTop', action='append',
	    help='Set the root for installed bin, include, lib, etc. ')
	parser.add_option('--upload', dest='uploadResults', action='store_true',
	    help='Upload log files to the server after building the repository')
	parser.add_option('--version', dest='version', action='store_true',
	    help='Print version information')
        
	options, args = parser.parse_args()
	if options.version:
            sys.stdout.write(sys.argv[0] + ' version ' + str(__version__) \
                                 + '\n')
            sys.exit(0)
        if options.helpBook:
            help = cStringIO.StringIO()
            parser.print_help(help)
            sys.stdout.write("""<?xml version="1.0"?>
<refentry xmlns="http://docbook.org/ns/docbook" 
         xmlns:xlink="http://www.w3.org/1999/xlink"
         xml:id="dws.book">
<refmeta>
<refentrytitle>dws</refentrytitle>
</refmeta>
<refnamediv>
<refname>dws</refname>
<refpurpose>inter-project dependencies tool</refpurpose>
</refnamediv>
<refsynopsisdiv>
<cmdsynopsis>
<command>dws</command>
<arg choice="opt">
  <option>options</option>
</arg>
<arg>command</arg>
</cmdsynopsis>
</refsynopsisdiv>
""")
            firstTerm = True
            firstSection = True
            lines = help.getvalue().split('\n')
            while len(lines) > 0:                
                line = lines.pop(0)
                if (line.strip().startswith('Usage')
                    or line.strip().startswith('Version')
                    or line.strip().startswith('dws version')):
                    None
                elif line.strip().endswith(':'):
                    if not firstTerm:
                        sys.stdout.write("</para>\n")
                        sys.stdout.write("</listitem>\n")
                        sys.stdout.write("</varlistentry>\n")
                    if not firstSection:
                        sys.stdout.write("</variablelist>\n")
                        sys.stdout.write("</refsection>\n")
                    firstSection = False
                    sys.stdout.write("<refsection>\n")
                    sys.stdout.write('<title>' + line.strip() + '</title>\n')
                    sys.stdout.write("<variablelist>")
                    firstTerm = True
                elif len(line) > 0 and (re.search("[a-z]",line[0]) 
                                        or line.startswith("  -")):
                    s = line.strip().split(' ')
                    if not firstTerm:
                        sys.stdout.write("</para>\n")
                        sys.stdout.write("</listitem>\n")
                        sys.stdout.write("</varlistentry>\n")
                    firstTerm = False                    
                    for w in s[1:]:
                        if len(w) > 0:
                            break
                    sys.stdout.write("<varlistentry>\n")
                    if line.startswith("  -h,"):
                        # Hack because "show" does not start
                        # with uppercase.
                        sys.stdout.write("<term>" + ' '.join(s[0:2])
                                         + "</term>\n")
                        w = 'S'
                        s = s[1:]
                    elif not re.search("[A-Z]",w[0]):
                        sys.stdout.write("<term>" + line + "</term>\n")
                    else:
                        if not s[0].startswith('-'):
                            sys.stdout.write("<term xml:id=\"" + s[0] + "\">\n")
                        else:
                            sys.stdout.write("<term>\n")
                        sys.stdout.write(s[0] + "</term>\n")
                    sys.stdout.write("<listitem>\n")
                    sys.stdout.write("<para>\n")
                    if not re.search("[A-Z]",w[0]):
                        None
                    else:
                        sys.stdout.write(' '.join(s[1:]) + '\n')
                else:
                    sys.stdout.write(line + '\n')
            if not firstTerm:
                sys.stdout.write("</para>\n")
                sys.stdout.write("</listitem>\n")
                sys.stdout.write("</varlistentry>\n")
            if not firstSection:
                sys.stdout.write("</variablelist>\n")
                sys.stdout.write("</refsection>\n")
            sys.stdout.write("</refentry>\n")
            sys.exit(0)
        if options.installTop:
            context.environ['installTop'].value = options.installTop

        useDefaultAnswer = options.default
        uploadResults = options.uploadResults
        nolog = options.nolog
        if options.excludePats:
            excludePats = options.excludePats

        if len(args) < 1:
            parser.print_help()
            sys.exit(1)

        # Find the build information
        arg = args.pop(0)
        try:
            context.locate()
        except IOError:
            None
        except:
            raise

        index = IndexProjects(context)
        command = 'pub' + arg.capitalize()
        if command in __main__.__dict__:
            __main__.__dict__[command](args)
        else:
            raise Error(sys.argv[0] + ' ' + arg + ' does not exist.\n')

    except Error, err:
        writetext(str(err))
        sys.exit(err.code)

    if log:
        log.close()
