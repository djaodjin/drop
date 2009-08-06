#!/usr/bin/env python
#
# Copyright (c) 2009, Sebastien Mirolo
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of codespin nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.

#   THIS SOFTWARE IS PROVIDED BY Sebastien Mirolo ''AS IS'' AND ANY
#   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL Sebastien Mirolo BE LIABLE FOR ANY
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

import hashlib
import re, os, optparse, shutil
import socket, subprocess, sys, tempfile
import xml.dom.minidom, xml.sax

log = None
useDefaultAnswer = False

class Error(Exception):
    '''This type of exception is used to identify "expected" 
    error condition and will lead to a useful message. 
    Other exceptions are not caught when *__main__* executes,
    and an internal stack trace will be displayed. Exceptions
    which are not *Error*s are concidered bugs in the workspace 
    management script.'''
    def __init__(self,msg="error",code=1):
        self.code = code
        self.msg = msg

    def __str__(self):
        return 'error ' + str(self.code) + ':' + self.msg


class Context:
    '''The workspace configuration file contains environment variables used
    to update, build and package projects. The environment variables are roots
    of the dependency graph as most other routines depend at the least 
    on srcTop and buildTop.'''

    configName = 'ws.mk'

    def __init__(self):
        self.cacheTop = Pathname('cacheTop',
                          'Root of the tree where cached packages are fetched',
                          default=os.path.dirname(os.path.dirname(os.getcwd())))
        self.remoteCacheTop = Pathname('remoteCacheTop',
             'Root of the remote tree where packages are located',
                  default='codespin.is-a-geek.com:/var/codespin')
        self.environ = { 'buildTop': Pathname('buildTop',
             'Root of the tree where intermediate files are created.',
                                              self.cacheTop,default='build'), 
                         'srcTop' : Pathname('srcTop',
             'Root of the tree where the source code under revision control lives on the local machine.',self.cacheTop,default='reps'),
                         'binDir': Pathname('binDir',
             'Root of the tree where executables are installed',
                                            self.cacheTop),
                         'includeDir': Pathname('includeDir',
             'Root of the tree where include files are installed',
                                                self.cacheTop),
                         'libDir': Pathname('libDir',
             'Root of the tree where libraries are installed',
                                            self.cacheTop),
                         'etcDir': Pathname('etcDir',
             'Root of the tree where extra files are installed',
                                            self.cacheTop,'etc/dws'),
                         'cacheTop': self.cacheTop,
                         'remoteCacheTop': self.remoteCacheTop,
                         'remoteSrcTop': Pathname('remoteSrcTop',
             'Root the remote tree where repositories are located',
                                          self.remoteCacheTop,'reps'),
                        'darwinTargetVolume': SingleChoice('darwinTargetVolume',
              'Destination of installed packages on a Darwin local machine. Installing on the "LocalSystem" requires administrator privileges.',
              choices=[ ['LocalSystem', 
                         'install packages on the system root for all users'],
                        ['CurrentUserHomeDirectory', 
                         'install packages for the current user only'] ]) }

        self.buildTopRelativeCwd = None
        try:
            self.locate()
            # -- Read the environment variables set in the config file.
            configFile = open(self.configFilename)
            line = configFile.readline()
            while line != '':
                look = re.match('(\S+)\s*=\s*(\S+)',line)
                if look != None:
                    if not look.group(1) in self.environ:
                        self.environ[look.group(1)] = Pathname(look.group(1),
                                                               'no description')
                    self.environ[look.group(1)].value = look.group(2)
                line = configFile.readline()
            configFile.close()        
        except IOError:
            None
        except:
            raise


    def cachePath(self,name):
        '''Absolute path to a file in the cached packages 
        directory hierarchy.'''
        return os.path.join(self.value('cacheTop'),name)


    def remoteCachePath(self,name):
        '''Absolute path to access a cached file on the remote machine.''' 
        return os.path.join(self.value('remoteCacheTop'),name)

    def remoteSrcPath(self,name):
        '''Absolute path to access a repository file on the remote machine.''' 
        return os.path.join(self.value('remoteSrcTop'),name)        

    def cwdProject(self):
        '''Returns a project name based on the current directory.'''
        if not self.buildTopRelativeCwd:
            self.environ['buildTop'].default = os.path.dirname(os.getcwd())
            log.write('no workspace configuration file could be ' \
               + 'found from ' + os.getcwd() \
               + ' all the way up to /. A new one, called ' + self.configName\
               + ', will be created in *buildTop* after that path is set.\n')
            self.configFilename = os.path.join(self.value('buildTop'),
                                               self.configName)
            self.save()
            self.locate()
        return self.buildTopRelativeCwd


    def dbPathname(self,remote=False):
        '''Absolute pathname to the project index file.'''
        if remote:
            return self.remoteCachePath('db.xml')
        return os.path.join(self.value('etcDir'),'db.xml')


    def host(self):
        '''Returns the distribution on which the script is running.'''
        dist = None
        hostname = socket.gethostbyaddr(socket.gethostname())
        hostname = hostname[0]
        sysname, nodename, release, version, machine = os.uname()
        if sysname == 'Darwin':
            dist = 'Darwin'
        elif sysname == 'Linux':
            version = open('/proc/version')
            line = version.readline()
            while line != '':
                for d in [ 'Ubuntu', 'fedora' ]:
                    look = re.match('.*' + d + '.*',line)
                    if look:
                        dist = d
                        break
                if dist:
                    break
                line = version.readline()
            version.close()
            if dist:
                dist = dist.capitalize()
        return dist


    def linkPath(self,paths,installName):
        '''Link a set of files in paths into the installName directory.'''
        for path in paths:
            install = None
            if installName == 'libDir':
                libname, libext = os.path.splitext(os.path.basename(path))
                libname = libname.split('-')[0]
                libname = libname + libext
                install = os.path.join(self.value(installName),
                                       libname)
            elif installName == 'includeDir':
                dirname, header = os.path.split(path)
                if dirname != 'include':
                    install = os.path.join(self.value(installName),
                                           os.path.basename(dirname))
                    path = os.path.dirname(path)
            if not install:
                install = os.path.join(self.value(installName),
                                       os.path.basename(path))
            if not os.path.exists(os.path.dirname(install)):
                os.makedirs(os.path.dirname(install))
            if os.path.islink(install):
                os.remove(install)
            if os.path.exists(path):
                os.symlink(path,install)

    def locate(self):
        '''Locate the workspace configuration file and derive the project
        name out of its location.'''
        self.buildTopRelativeCwd, self.configFilename \
            = searchBackToRoot(self.configName)
        if self.buildTopRelativeCwd == '.':
            self.buildTopRelativeCwd = os.path.basename(os.getcwd())
            look = re.match('([^-]+)-.*',self.buildTopRelativeCwd)
            if look:
                self.buildTopRelativeCwd = look.group(1)

    def logname(self):
        filename = os.path.join(self.value('etcDir'),'dws.log')
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        return filename

    def objDir(self,name):
        return os.path.join(self.value('buildTop'),name)

        
    def save(self):
        '''Write the config back to a file.'''
        try:
            configFile = open(self.configFilename,'w')
        except:
            self.configFilename = self.objDir(self.configName)
            configFile = open(self.configFilename,'w')
        keys = sorted(self.environ.keys())
        configFile.write('# configuration for development workspace\n\n')
        for key in keys:
            if self.environ[key].value:
                configFile.write(key + '=' + self.environ[key].value + '\n')
        configFile.close()


    def srcDir(self,name):
        return os.path.join(self.value('srcTop'),name)


    def value(self,name):
        '''returns the value of the workspace variable *name*. If the variable
        has no value yet, a prompt is displayed for it.'''
        if not name in self.environ:
            raise Error("Trying to read unknown variable " + name + ".\n")
        if not self.environ[name].value:
            if selectVariable(self.environ[name]):
                self.save()
        return self.environ[name].value


class IndexProjects:
    '''Index file containing the graph dependency for all projects.'''

    def __init__(self, context, filename = None):
        self.context = context
        self.parser = xmlDbParser(context)
        self.filename = filename

 
    def closure(self, dgen):
        '''Find out all dependencies from a root set of projects as defined 
        by the dependency generator *dgen*.'''
        while len(dgen.vertices) > 0:
            self.parse(dgen)
            dgen.nextLevel()
        return dgen.topological()
        

    def parse(self, dgen):
        '''Parse the project index and generates callbacks to *dgen*'''
        self.validate()
        self.parser.parse(self.filename,dgen)


    def validate(self,force=False):
        '''Create the project index file if it does not exist
        either by fetching it from a remote server or collecting
        projects indices locally.'''
        if not self.filename:
            self.filename = self.context.dbPathname()
        if self.filename == self.context.dbPathname():
            if not os.path.exists(self.filename) and not force:
                # index or copy.
                selection = selectOne('The project index file could not '
                                      + 'be found at ' + self.filename \
                                          + '. It can be regenerated through one ' \
                                          + 'of the two following method:',
                                      [ [ 'fetching', 'from remote server' ],
                                        [ 'indexing', 
                                          'local projects in the workspace' ] ])
                if selection == 'fetching':
                    force = True
                if selection == 'indexing':
                    pubCollect([])
            if force:
                fetch([os.path.join(self.context.host(),
                                    os.path.basename(self.filename))],
                      context.value('etcDir'))
        elif not os.path.exists(self.filename):
            raise Error(filename + ' does not exist.')


class LogFile:
    
    def __init__(self,logfilename):
        self.logfile = open(logfilename,'w')
        self.logfile.write('<?xml version="1.0" ?>\n')
        self.logfile.write('<book>\n')

    def close(self):
        self.logfile.write('</book>\n')
        self.logfile.close()        

    def error(self,text):
        sys.stderr.write(text)
        self.logfile.write(text)

    def footer(self):
        self.logfile.write('</section>\n')

    def header(self, text):
        sys.stdout.write(text + '...\n')
        self.logfile.write('<section id="' + text + '">\n')

    def flush(self):
        sys.stdout.flush()
        self.logfile.flush()

    def write(self, text):
        sys.stdout.write(text)
        self.logfile.write(text)
        

class PdbHandler:
    '''Callback interface for a project index as generated by a PdbParser.
       The generic handler does not do anything. It is the responsability of
       implementing classes to filter callback events they care about.'''
    def __init__(self):
        None

    def startProject(self, name):
        None

    def dependency(self, name, deps, excludes=[]):
        None

    def description(self, text):
        None
    
    def endProject(self):
        None

    def control(self, type, url):
        None

    def package(self, filename, sha1):
        None

    def sources(self, name, patched):
        None

    def version(self, text):
        '''This can only be added from package'''
        None


class DependencyGenerator(PdbHandler):
    '''Aggregate dependencies for a set of projects'''

    def __init__(self, projects):
        # None if we don't record dependencies for a project and the name 
        # of the project otherwise.
        self.source = None
        # This contains a list of list of edges. When levels is traversed last 
        # to first and each edge's source vertex is printed, it displays 
        # a topological ordering of the selected projects.
        # In other words, levels holds each recursing of a breadth-first search
        # algorithm through the graph of projects from the roots.
        # We store edges in each level rather than simply the source vertex 
        # such that we can detect cycles. That is when an edge would be 
        # traversed again.
        roots = []
        self.projects = projects
        for p in projects:
            roots += [ [ None, p ] ]
        self.levels = [ roots ]
        self.vertices = projects
        # *cuts* is a list of Project(). Each instance contains resolution
        # for links on the local machine.
        self.cuts = []
        # *missings* contains a list of dependencies which cannot be fullfiled
        # with the current configuration of the local machine.
        # *prerequisites* contains a list a missing projects, which is to say
        # projects which are targets of *missings* dependencies.
        self.missings = []
        self.prerequisites = {}
        self.nextLevel()

    def candidates(self):
        '''Returns a list of rows where each row contains expanded information
        for each missing project.'''
        results = []
        for name in self.prerequisites:
            row = [ name ]
            if self.prerequisites[name].installedVersion:
                row += [ self.prerequisites[name].installedVersion ]
            results += [ row ]
        return results
 
    def dependency(self, name, deps, excludes=[]):
        if self.source:
            if self.addDep(name,deps,excludes):
                self.levels[0] += [ [ self.source, name ] ]
            else:
                cut = self.addCut(name,deps,excludes)
                if cut.complete:
                    self.cuts += [ cut ]
                else:
                    self.prerequisites[name] = Project(name)
                    self.prerequisites[name].deps = deps
                    self.prerequisites[name].excludes = excludes
                    self.missings += [ [ self.source, name ] ]

    def linkPackageDeps(self):
        '''All projects which are dependencies but are not part of *srcTop*
        are not under development in the current workspace. Links to the required
        executables, headers, libraries, etc. will be added to the install
        directories such that projects in *srcTop* can build.'''
        for cut in self.cuts:
            if not cut.complete:        
                cut.deps, cut.complete = findPrerequisites(cut.deps,
                                                           cut.excludes)
            for install in cut.deps:
                context.linkPath(cut.deps[install],install + 'Dir')

    def nextLevel(self, filtered=[]):
        '''Going one step further in the breadth-first recursion introduces 
        a new level. All missing edges whose target is in *filtered* will 
        be added to the dependency graph.
        By definition, all missing projects which are not in *filtered* 
        will be added as cut points. From this time, *cuts* contains 
        *complete*d projects as well as projects that still need to be 
        resolved before links are created.'''
        for newEdge in self.missings:
            if newEdge[1] in filtered:
                self.levels[0] += [ newEdge ]
        self.missings = []
        for package in self.prerequisites:
            if not package in filtered:
                self.cuts += [ self.prerequisites[package] ]
        self.prerequisites = {}
        self.vertices = []
        for newEdge in self.levels[0]:
            # We first walk the tree of previously recorded edges to find out 
            # if we detected a cycle.
            if len(self.levels) > 1:
                for level in self.levels[1:]:
                    for edge in level:
                        if edge[0] == newEdge[0] and edge[1] == newEdge[1]:
                            raise CircleException()
            if not newEdge[1] in self.vertices:
                # insert each vertex only once
                self.vertices += [ newEdge[1] ]
        self.levels.insert(0,[])

    def startProject(self, name):
        self.source = None
        if name in self.vertices:
            self.source = name

    def addDep(self, name, deps, excludes=[]):
        return True

    def topological(self):
        '''Returns a topological ordering of projects selected.'''
        results = []
        for level in self.levels:
            for edge in level:
                if not edge[1] in results:
                    results += [ edge[1] ] 
        return results


class MakeGenerator(DependencyGenerator):
    '''As other dependency generators, *MakeGenerator* is initialized
    with a set of projects. All prerequisite projects necessary to **build** 
    that set which have an associated directory in *srcTop* will be added
    to the *found* list.
    For other prerequisiste projects, the script will search for necessary 
    executables, headers, libraries, etc. on the local machine. If they
    all can be found, the prerequisiste project will be added to 
    the *installed* list, else the prerequisiste project will be added to
    the *missing* list.
    It is the responsability of the owner of the MakeGenerator instance
    to check there are no *missing* prerequisites and act appropriately.
    '''
    
    def __init__(self, projects):
        self.extraFetches = {}
        DependencyGenerator.__init__(self, projects)

    def addDep(self, name, deps, excludes=[]):
        if os.path.isdir(context.srcDir(name)):
            return True
        return False

    def addCut(self, name, deps, excludes=[]):
        result = Project(name)
        result.deps, result.complete = findPrerequisites(deps,excludes)
        return result
    
    def sources(self, name, patched={}):
        if self.source:
            found, version = findCache(patched)
            for source in patched:
                if not context.cachePath(source) in found:
                    self.extraFetches[source] \
                        = os.path.join('srcs',patched[source])


class DerivedSetsGenerator(PdbHandler):
    '''Generate different sets of projects which are of interests 
    to the workspace management algorithms.
    - roots          set of projects which are not dependency 
                     for any other project.
    - repositories   set of projects which are managed under a source 
                     revision control system.
    '''
   
    def __init__(self):
        self.roots = []
        self.nonroots = []
        self.repositories = []
        self.curProjName = None

    def control(self, type, url):
        self.repositories += [ self.curProjName ]

    def dependency(self, name, deps, excludes=[]):
        if name in self.roots:
            self.roots.remove(name)
        if not name in self.nonroots:
            self.nonroots += [ name ]

    def endProject(self):
        self.curProjName = None

    def startProject(self, name):
        self.curProjName = name
        if not name in self.nonroots:
            self.roots += [ name ]


class Variable:
    
    def __init__(self,name,descr=None):
        self.name = name
        self.descr = descr
        self.value = None

class Pathname(Variable):
    
    def __init__(self,name,descr=None,base=None,default=None):
        Variable.__init__(self,name,descr)
        self.base = base
        self.default = default

class SingleChoice(Variable):

    def __init__(self,name,descr=None,choices=[]):
        Variable.__init__(self,name,descr)
        self.choices = choices

class Control:

    def __init__(self, type, url):
        self.type = type
        self.url = url

class Package:

    def __init__(self, filename, sha1):
        self.filename = filename
        self.sha1 = sha1


class Project:
    '''*complete* will be True whenever all necessary executables, headers,
    libraries, etc. have been found on the local machine. At which point.
    *deps* contains such resolution. Otherwise, *deps* contains the 
    required files and *excludes* the excluded versions.'''

    def __init__(self, name):
        self.name = name
        self.deps = {}
        self.description = None
        self.excludes = []
        self.complete = False
        self.control = None
        self.package = None
        self.patched = []
        self.installedVersion = None

class Unserializer(PdbHandler):
    '''Aggregate dependencies for a set of projects only when prerequisites
    can not be found on the system.'''

    def __init__(self, builds=None):
        PdbHandler.__init__(self)
        self.project = None
        self.projects = {}
        self.builds = builds

    def asProject(self, name):
        return self.projects[name]

    def control(self, type, url):
        if self.project:
            self.projects[self.project].control = Control(type,url)

    def description(self, text):
        if self.project:
            self.projects[self.project].description = text

    def package(self, filename, sha1):
        if self.project:
            self.projects[self.project].package = Package(filename,sha1)        

    def startProject(self, name):
        self.project = None
        if (not self.builds) or (name in self.builds):
            self.project = name
            self.projects[name] = Project(name)


class UbuntuIndexWriter(PdbHandler):
    '''As the index file parser generates callback, an instance of this class
    will rewrite the exact same information in a format compatible with apt.'''
    def __init__(self, out):
        self.out = out

    def startProject(self, name):
        self.out.write('Package: ' + name + '\n')

    def dependency(self, name, deps, excludes=[]):
        self.out.write('Depends: ' + ','.join(deps.keys()) + '\n')

    def description(self, text):
        self.out.write('Description:' + text)
    
    def endProject(self):
        self.out.write('\n')

    def control(self, type, url):
        self.out.write('ControlType:' + type + '\n')
        self.out.write('ControlUrl:' + url + '\n')

    def version(self, text):
        self.out.write('Version:' + text)


class xmlDbParser(xml.sax.ContentHandler):
    '''Parse a project database stored as an XML file on disc and generate
       callbacks on a PdbHandler. The handler will update its state
       based on the callback sequence.
       '''

    # Global Constants for the database parser
    tagBuild = 'build'
    tagControl = 'sccs'
    tagDepend = 'xref'
    tagDescription = 'description'
    tagHash = 'sha1'
    tagInstall = 'install'
    tagPackage = 'package'
    tagProject = 'section'
    tagSrc = 'src'
    tagUrl = 'url'
    tagVersion = 'version'
    tagPattern = '.*<' + tagProject + '\s+id="(.*)"'
    trailerTxt = '</book>'

    def __init__(self, context=None, build=True):
        self.build = build
        self.context = context
        self.handler = None
        self.depName = None
        self.deps = { 'bin': [], 'include': [], 'lib': [], 'etc': [] }
        self.src = None
        self.patchedSourcePackages = {}

    def startElement(self, name, attrs):
        '''Start populating an element.'''
        self.text = ''
        if name == self.tagProject:
            self.patchedSourcePackages = {}
            self.filename = None
            self.sha1 = None
            self.src = None
            self.handler.startProject(attrs['id'])
        elif name == self.tagDepend:
            self.depName = attrs['linkend']
            self.deps = { 'bin': [], 'include': [], 'lib': [], 'etc': [] }
            self.excludes = []
        elif name == self.tagInstall:
            if 'version' in attrs:
                self.handler.install(attrs['mode'],attrs['version'])
            else:
                self.handler.install(attrs['mode'])
        elif name == self.tagControl:
            self.url = None
            self.type = attrs['name']
        elif name == self.tagPackage:
            self.filename = attrs['name']
        elif name in [ 'bin', 'include', 'lib', 'etc' ]:
            self.deps[name] += [ attrs['name'] ]
            if 'excludes' in attrs:
                self.excludes += attrs['excludes'].split(',')
        elif name == self.tagSrc:
            self.src = os.path.join('srcs',attrs['name'])
 
    def characters(self, ch):
        self.text += ch

    def endElement(self, name):
        '''Once the element is fully populated, call back the simplified
           interface on the handler.'''
        if name == self.tagControl:
            # If the path to the remote repository is not absolute,
            # derive it from *remoteTop*.
            if not ':' in self.url and self.context:
                self.url = self.context.remoteSrcPath(self.url)
            self.handler.control(self.type, self.url)
        elif name == self.tagDepend:
            self.handler.dependency(self.depName, self.deps,self.excludes)
            self.depName = None
        elif name == self.tagDescription:
            self.handler.description(self.text)
        elif name == self.tagProject:
            self.handler.sources(name,self.patchedSourcePackages)
            if self.filename:
                self.handler.package(self.filename,self.sha1)
            self.handler.endProject()
        elif name == self.tagHash:
            if self.src:
                self.patchedSourcePackages[ self.src ] = self.text.strip()
            else:
                self.sha1 = self.text
        elif name == self.tagSrc:
            self.src = None
        elif name == self.tagUrl:
            self.url = self.text
        elif name == self.tagVersion:
            self.handler.version(self.text)

    def parse(self, pathname, handler):
        '''This is the public interface for one pass through the database
           that generates callbacks on the handler interface.'''
        self.handler = handler
        parser = xml.sax.make_parser()
        parser.setFeature(xml.sax.handler.feature_namespaces, 0)
        parser.setContentHandler(self)
        parser.parse(pathname)

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
        dbNext.write('  <' + self.tagProject + ' id="' + name + '">\n')
        None

    def trailer(self, dbNext):  
        '''XML files need a finish tag. We make sure to remove it while
           processing Upd and Prev then add it back before closing 
           the final file.'''
        dbNext.write(self.trailerTxt)


def createIndexPathname( dbIndexPathname, dbPathnames ):
    '''create a global dependency database (i.e. project index file) out of
    a set local dependency index files.'''
    parser = xmlDbParser()
    dir = os.path.dirname(dbIndexPathname)
    if not os.path.isdir(dir):
        os.makedirs(dir)
    dbNext = sortBuildConfList(dbPathnames,parser)
    dbIndex = open(dbIndexPathname,'wb')
    dbNext.seek(0)
    shutil.copyfileobj(dbNext,dbIndex)
    dbNext.close()
    dbIndex.close()


def derivedRoots(name):
    '''Derives a list of directory names based on the PATH 
    environment variable.'''
    dirs = []
    for p in os.environ['PATH'].split(':'):
        dir = os.path.join(os.path.dirname(p),name)
        if os.path.isdir(dir):
            dirs += [ dir ]
    return dirs


def findBin(names,excludes=[]):
    '''Search for a list of binaries that can be executed from $PATH.

       *names* is a list of exectuable names. *excludes* is a list
       of versions that are concidered false positive and need to be 
       excluded, usually as a result of incompatibilities.

       This function returns a list of absolute paths for the executables
       found and a version number. The version number is retrieved 
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
    '''
    results = []
    version = None
    for name in names:
        log.write(name + '... ')
        log.flush()
        found = False
        for p in os.environ['PATH'].split(':'):
            bin = os.path.join(p,name)
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
                        log.write(str(version) + '\n')
                        results.append(bin)
                    else:
                        log.write('excluded (' + str(numbers[0]) + ')\n')
                else:
                    log.write('yes\n')
                    results.append(bin)
                found = True
                break
        if not found:
            log.write('no\n')
    return results, version


def findCache(names):
    '''Search for the presence of files in the cache directory. *names* 
    is a dictionnary of file names used as key and the associated checksum.'''
    results = []
    version = None
    for name in names:
        log.write(name + "... ")
        log.flush()
        fullName = context.cachePath(name)
        if os.path.exists(fullName):
            if names[name]:
                f = open(fullName,'rb')
                sum = hashlib.sha1(f.read()).hexdigest()
                f.close()
                if sum == names[name]:
                    # checksum are matching
                    log.write("cached\n")
                    results += [ fullName ]
                else:
                    log.write("corrupted?\n")
            else:
                log.write("yes\n")
        else:
            log.write("no\n")
    return results, version


def findFiles(base,namePat):
    '''Search the directory tree rooted at *base* for files matching *namePat*
       and returns a list of absolute pathnames to those files.'''
    result = []
    for p in os.listdir(base):
        path = os.path.join(base,p)
        if os.path.isdir(path):
            result += findFiles(path,namePat)
        else:
            look = re.match('.*' + namePat + '$',path)
            if look:
                result += [ path ]
    return result


def findFirstFiles(base,namePat,subdir=''):
    '''Search the directory tree rooted at *base* for files matching pattern
    *namePat* and returns a list of relative pathnames to those files 
    from *base*.
    If ./ is part of pattern, base is searched recursively in breadth search 
    order until at least one result is found.'''
    subdirs = []
    results = []
    patNumSubDirs = len(namePat.split(os.sep))
    subNumSubDirs = len(subdir.split(os.sep))
    for p in os.listdir(os.path.join(base,subdir)):
        relative = os.path.join(subdir,p)
        path = os.path.join(base,relative)
        look = re.match(namePat.replace('.' + os.sep,'(.*)' + os.sep),relative)
        if look != None:
            results += [ relative ]
        elif (((('.' + os.sep) in namePat) 
               or (subNumSubDirs < patNumSubDirs))
              and os.path.isdir(path)):
            # When we see ./, it means we are looking for a pattern 
            # that can be matched by files in subdirectories of the base. 
            subdirs += [ relative ]
    if len(results) == 0:
        for subdir in subdirs:
            results += findFirstFiles(base,namePat,subdir)
    return results


def findEtc(names,excludes=[]):
    '''Search for a list of extra files that can be found from $PATH
       where bin was replaced by etc.'''
    found = []
    for base in derivedRoots('etc'):
        for name in names:
            found += [ findFiles(base,name) ]
        if len(found) == len(names):
            return found
    return []


def findInclude(names,excludes=[]):
    '''Search for a list of libraries that can be found from $PATH
       where bin was replaced by include.

    *names* is list of header filename patterns. *excludes* is a list
    of versions that are concidered false positive and need to be 
    excluded, usually as a result of incompatibilities.
    
    This function returns a list of absolute pathnames to found headers
    and a version number if available.

    This function differs from findBin() and findLib() in its search 
    algorithm. findInclude() might generate a breadth search based 
    out of a derived root of $PATH. It opens found header files
    and look for a "#define.*VERSION" pattern in order to deduce
    a version number.'''
    results = []
    version = None
    includeSysDirs = derivedRoots('include')
    for name in names:
        log.write(name + '... ')
        log.flush()
        found = False
        for includeSysDir in includeSysDirs:
            includes = []
            for header in findFirstFiles(includeSysDir,name):
                # Open the header file and search for all defines
                # that end in VERSION.
                numbers = []
                header = os.path.join(includeSysDir,header)
                f = open(header,'rt')
                line = f.readline()
                while line != '':
                    look = re.match('\s*#define.*VERSION\s+(\S+)',line)
                    if look != None:
                        numbers += versionCandidates(look.group(1))
                    line = f.readline()
                f.close()
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
                        index = 0
                        for include in includes:
                            if ((not include[1]) 
                                or versionCompare(include[1],numbers[0]) < 0):
                                break
                        includes.insert(index,(header,numbers[0]))
                else:
                    # If we find no version number of find more than one 
                    # version number, we append the header at the end 
                    # of the list with 'None' for version.
                    includes.append((header,None))
            if len(includes) > 0:
                if includes[0][1]:
                    version = includes[0][1]
                    log.write(version + '\n')
                else:
                    log.write('yes\n')
                results.append(includes[0][0])
                includeSysDirs = [ os.path.dirname(includes[0][0]) ]
                found = True
                break
        if not found:
            log.write('no\n')
    return results, version
    

def findLib(names,excludes=[]):
    '''Search for a list of libraries that can be found from $PATH
       where bin was replaced by lib.

    *names* is list of library names with neither a 'lib' prefix 
    nor a '.a', '.so', etc. suffix. *excludes* is a list
    of versions that are concidered false positive and need to be 
    excluded, usually as a result of incompatibilities.
    
    This function returns a list of absolute pathnames to libraries
    found and a version number if available.
    
    This function differs from findBin() and findInclude() in its
    search algorithm. findLib() might generate a breadth search based 
    out of a derived root of $PATH. It uses the full library name
    in order to deduce a version number if possible.'''
    suffix = '.*\.a'                  # Always selects static libraries
    results = []
    version = None
    for name in names:
        log.write(name + '... ')
        log.flush()
        found = False
        for libSysDir in derivedRoots('lib'):
            libs = []
            for libname in findFirstFiles(libSysDir,'lib' + name + suffix):
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
                        libs.insert(index,(os.path.join(libSysDir,libname),
                                           numbers[0]))
                else:
                    libs.append((os.path.join(libSysDir,libname),None))
            if len(libs) > 0:
                if libs[0][1]:
                    version = libs[0][1] 
                    look = re.match('.*lib' + name + '(.+)',libs[0][0])
                    if look:
                        suffix = look.group(1)
                    log.write(suffix + '\n')
                else:
                    log.write('yes\n')
                results.append(libs[0][0])
                found = True
                break
        if not found:
            log.write('no\n')
    return results, version


def findPrerequisites(deps, excludes=[]):
    '''Find a set of executables, headers, libraries, etc. on a local machine.
    
    *deps* is a dictionary where each key associates an install directory 
    (bin, include, lib, etc.) to file names (executable, header, library, 
    etc.). *excludes* contains a list of excluded version ranges.

    This function will try to find the latest version of each file which 
    was not excluded.

    This function will return a dictionnary matching *deps* where each found
    file will be replaced by an absolute pathname and each file not found
    will not be present. This function returns True if all files in *deps* 
    can be fulfilled and returns False if any file cannot be found.'''
    import __main__

    version = None
    installed = {}
    complete = True
    for dir in [ 'bin', 'include', 'lib', 'etc' ]:
        if len(deps[dir]) > 0:
            command = 'find' + dir.capitalize()
            installed[dir], installedVersion = \
                __main__.__dict__[command](deps[dir],excludes)
            # Once we have selected a version out of the installed
            # local system, we lock it down and only search for
            # that specific version.
            if not version and installedVersion:
                version = installedVersion
                excludes = [ (None,version), (versionIncr(version),None) ]
            if len(installed[dir]) != len(deps[dir]):
                complete = False

    return installed, complete


def fetch(filenames, cacheDir=None, force=False):
    '''download file from remote server.'''
    print "fetch: " + ' '.join(filenames)
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
        cmdline = "rsync -avuzb"
        if not cacheDir:
            cacheDir = context.cachePath('')
            cmdline = cmdline + 'R'
        remotePath = context.remoteCachePath('')
        if  remotePath.find(':') > 0:
            remotePath = remotePath[remotePath.find(':') + 1:]
        sources = context.remoteCachePath('') + './' \
                +' ./'.join(downloads).replace(' ',' ' + remotePath + os.sep)
        if context.remoteCachePath('').find(':') > 0:
            cmdline = cmdline + " --rsh=ssh '" \
                + username + "@" + sources + "' " + cacheDir
        else:
            cmdline = cmdline + ' ' + sources + ' ' + cacheDir
        shellCommand(cmdline)


def make(targets, projects):
    '''invoke the make utility to build a set of projects.'''
    recurse = 'recurse' in targets
    if 'recurse' in targets:
        targets.remove('recurse')

    # Find build information
    if recurse:
        projects = validateControls(projects)
        # We will generate a "make install" for all projects which are 
        # a prerequisite. Those Makefiles expects bin, include, lib, etc.
        # to be defined.
        for dir in [ 'bin', 'include', 'lib', 'etc' ]:
            name = context.value(dir + 'Dir')
 
    last = projects.pop()
    try:
        # Recurse through projects that need to be rebuilt first 
        for repository in projects:
            makeProject(repository,['install'])

        # Make current project
        if not recurse or len(targets) > 0:
            makeProject(last,targets)

    except Error, e:
        log.error(str(e))


def makeProject(name,targets):
    '''Issue make command and log output'''
    log.header(name)
    makefile = context.srcDir(os.path.join(name,'Makefile'))
    objDir = context.objDir(name)
    if objDir != os.getcwd():
        if not os.path.exists(objDir):
            os.makedirs(objDir)
        os.chdir(objDir)
    cmdline = 'make -f ' + makefile + ' ' + ' '.join(targets)
    shellCommand(cmdline)
    log.footer()


def makeSrcDirs(names):
    '''For each project name in a list of *names*, make a directory
    in *srcTop*. This function is used to mark projects that
    need to be checked out from a source control repository.'''
    for name in names:
        if not os.path.exists(context.srcDir(name)):
            os.makedirs(context.srcDir(name))


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


def shellCommand(cmdline):
    '''Execute a shell command and throws an exception when the command fails'''
    if log:
        log.write(cmdline + '\n')
        log.flush()
    else:
        sys.stdout.write(cmdline + '\n')
    cmd = subprocess.Popen(cmdline,shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    line = cmd.stdout.readline()
    while line != '':
        if log:
            log.write(line)
        else:
            sys.stdout.write(line)
        line = cmd.stdout.readline()
    cmd.wait()
    if cmd.returncode != 0:
        raise Error("unable to complete: " + cmdline,cmd.returncode)


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


def validateControls(repositories,dbindex=None):
    '''Checkout source code files, install packages and generate 
    links such that the project *repositories* can be built.
    *dbindex* is the project index that contains the dependency 
    information to use. If None, the global index fetched from
    the remote machine will be used.

    This function returns a topologicaly sorted list of projects
    in *srcTop*. By iterating through the list, it is possible
    to 'make' each prerequisite project in order.'''
    if not dbindex:
        dbindex = index
    dbindex.validate()
    dgen = MakeGenerator(repositories)
    missingControls = []
    missingPackages = []

    # Make sure that at least all projects specified as input for
    # make will be present in *srcTop*.
    for project in repositories:
        if not os.path.isdir(context.srcDir(project)):
            os.makedirs(context.srcDir(project))
            missingControls += [ project ]

    # Add deep dependencies
    while len(dgen.vertices) > 0:
        controls = []
        dbindex.parse(dgen)
        if len(dgen.missings) > 0:
            # This is an opportunity to prompt for missing dependencies.
            # After installing both, source controlled and packaged
            # projects, the checked-out projects will be added to 
            # the dependency graph while the packaged projects will
            # be added to the *cut* list.
            controls, packages = selectCheckout(dgen.candidates())
            missingControls += controls
            missingPackages += packages
        dgen.nextLevel(controls)
    # Checkout missing source controlled projects
    # and install missing packages.
    makeSrcDirs(missingControls)
    update(missingControls + missingPackages,dgen.extraFetches,dbindex)
    # Executables, headers and libraries for recently installed 
    # packages need to be fully resolved.
    dgen.linkPackageDeps()
    return dgen.topological()


def versionCandidates(line):
    '''Extract patterns from *line* that could be interpreted as a 
    version numbers. That is every pattern that is a set of digits
    separated by dots and/or underscores.'''
    part = line
    candidates = []
    while part != '':
        # numbers should be full, including '.'
        # look = re.match('[^0-9]*([0-9][0-9_\.]*)+(.*)',part)
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


def upstreamRecurse(srcdir,pchdir):
    for name in os.listdir(pchdir):
        srcname = os.path.join(srcdir,name)
        pchname = os.path.join(pchdir,name)
        if os.path.isdir(name):
            upstreamRecurse(srcname,pchname)
        else:
            if os.path.islink(srcname):
                os.unlink(srcname)
            if os.path.isfile(srcname + '.patched'):
                shutil.copy(srcname + '.patched',srcname)


def integrate(srdir,pchdir):
    for name in os.listdir(pchdir):
        srcname = os.path.join(srcdir,name)
        pchname = os.path.join(pchdir,name)
        if os.path.isdir(name):
            if not name.endswith('CVS'):
                integrate(srcname,pchname)
        else:
            if not name.endswith('~'):
                if not os.path.islink(srcname):
                    if os.path.isfile(srcname):
                        shutil.move(srcname,srcname + '.patched')
                    os.symlink(os.path.relpath(pchname),srcname)


def update(projects, extraFetches={}, dbindex = None, force=False):
    '''Update a list of *projects* within the workspace. The update will either 
    sync with a source control repository if the project is present in *srcTop*
    or will install a new binary package through the local package manager.
    *extraFetches* is a list of extra files to fetch from the remote machine,
    usually a list of compressed source tar files.'''
    if not dbindex:
        dbindex = index
    dbindex.validate(force)
    handler = Unserializer(projects)
    dbindex.parse(handler)
    controls = []
    packages = []
    for name in projects:
        if os.path.exists(context.srcDir(name)):
            controls += [ name ]
        else:
            packages += [ name ]

    for name in controls:
        # The project is present in *srcTop*, so we will update the source 
        # code from a repository. 
        control = handler.asProject(name).control
        if not control:
            raise Error('project exists in *srcTop* but as no control structure.')
        if control.type == 'git':
            if not os.path.exists(os.path.join(context.srcDir(name),'.git')):
                shutil.rmtree(context.srcDir(name))
                cmdline = 'git clone ' + control.url \
                    + ' ' + context.srcDir(name)
                shellCommand(cmdline)
            else:
                cwd = os.getcwd()
                os.chdir(context.srcDir(name))
                cmdline = 'git pull'
                shellCommand(cmdline)
                cmdline = 'git checkout'
                shellCommand(cmdline)
                os.chdir(cwd)
        else:
            raise Error("unknown source control system '"  + control.type + "'")

    # Install executables, includes, libraries, etc. which are necessary 
    # to build the projects in *srcTop* but are not themselves in active 
    # development in the workspace. We will use the local machine official 
    # package manager for this task. If there are no official package manager 
    # for the system, we will provide an ad-hoc solution if possible.
    if context.host() == 'Darwin':
        images = {}
        filenames = []
        for name in packages:
            package = handler.asProject(name).package
            images[ os.path.join(context.host(),package.filename) ] \
                = package.sha1
            filenames += [ package.filename ]
        images.update(extraFetches)
        fetch(images)
        for image in filenames:
            pkg, ext = os.path.splitext(image)
            shellCommand('hdiutil attach ' + context.cachePath(image))
            target = context.value('darwinTargetVolume')
            if target != 'CurrentUserHomeDirectory':
                log.write('ATTENTION: You need sudo access on ' \
                 + 'the local machine to execute the following cmmand\n')
                cmdline = 'sudo '
            else:
                cmdline = ''
            cmdline += 'installer -pkg ' + os.path.join('/Volumes',
                                                        pkg,pkg + '.pkg') \
                + ' -target "' + target + '"'
            shellCommand(cmdline)
            shellCommand('hdiutil detach ' \
                         + os.path.join('/Volumes',pkg))
    else:
        raise Error("Use of package manager for '" \
                    + context.host() + " not yet implemented.'")
                             
            
def upstream(srcdir,pchdir):
    upstreamRecurse(srcdir,pchdir)
    #subprocess.call('diff -ru ' + srcdir + ' ' + pchdir,shell=True)
    p = subprocess.Popen('diff -ru ' + srcdir + ' ' + pchdir, shell=True,
              stdout=subprocess.PIPE, close_fds=True)
    line = p.stdout.readline()
    while line != '':
        look = re.match('Only in ' + srcdir + ':',line)
        if look == None:
            log.write(line)
        line = p.stdout.readline()
    p.poll()
    integrate(srcdir,pchdir)


def pubBuild(args):
    '''build  [remoteTop [localTop]]      
           Download all projects from a remote machine 
           and rebuild everything.
    '''
    print args
    if len(args) > 0:
        context.remoteCacheTop.default = args[0]
    if len(args) > 1:
        context.cacheTop.default = args[1]
    global useDefaultAnswer
    useDefaultAnswer = True
    global log
    log = LogFile(context.logname())
    rgen = DerivedSetsGenerator()
    index.parse(rgen)
    make([ 'recurse', 'check', 'dist', 'install' ],rgen.repositories)
    pubCollect([])


def pubCollect(args):
    '''collect    Consolidate local dependencies information into a glabal
                  dependency database. Copy all distribution packages built
                  into a platform distribution directory.
    '''

    # Create the distribution directory, i.e. where packages are stored.
    remotePackageDir = context.remoteCachePath(context.host())
    if not os.path.exists(remotePackageDir):
        os.makedirs(remotePackageDir)

    # Create the project index file
    extensions = { 'Darwin': '\.dsx' }
    ext = extensions[context.host()]
    indices = findFiles(context.value('buildTop'),ext) \
      + findFiles(context.value('srcTop'),'index.xml')
    createIndexPathname(context.dbPathname(),indices)

    # Copy the packages in the distribution directory.
    extensions = { 'Darwin': '\.dmg', 
                   'Fedora': '\.rpm', 
                   'Ubuntu': '\.deb' }
    ext = extensions[context.host()]
    cmdline = 'rsync ' + context.dbPathname() + ' ' \
                       + ' '.join(findFiles(context.value('buildTop'),ext)) \
                       + ' ' + remotePackageDir
    shellCommand(cmdline)


def pubConfigure(args):
    '''configure     Configure the local machine with direct dependencies
                     of a project such that the project can be built later on.
    '''
    projectName = context.cwdProject()
    validateControls([ projectName ],
                     IndexProjects(context,
                                   context.srcDir(os.path.join(projectName,
                                                               'index.xml'))))


def pubContext(args):
    '''context      Prints the absolute pathname to a file.
                    If the filename cannot be found from the current directory 
                    up to the workspace root (i.e where ws.mk is located), 
                    it assumes the file is in *etcDir*.'''
    pathname = context.configFilename
    if len(args) >= 1:
        try:
            dir, pathname = searchBackToRoot(args[0],
                   os.path.dirname(context.configFilename))
        except IOError:
            pathname = os.path.join(context.value('etcDir'),args[0])
    sys.stdout.write(pathname)


def pubInit(args):
    '''init     Prompt for variables which have not been 
                initialized in ws.mk. Fetch the project index.'''
    found = False
    for d in context.environ.values():
        found |= selectVariable(d)
    if found:
        context.save()
    index.validate()


def pubIntegrate(args):
    '''integrate    Integrate a patch into a source package
    '''
    while len(sys.argv) > 0:
        srcdir = sys.argv.pop(0)
        pchdir = srcdir + '-patch'
        integrate(srcdir,pchdir)


def pubHost(args):
    '''host       host platform used to build the workspace.
                  This will print the distribution name on
                  stdout.'''
    print context.host()


class ListPdbHandler(PdbHandler):

    def startProject(self, name):
        sys.stdout.write(name)

    def description(self, text):
        sys.stdout.write(text)

    def endProject(self):
        sys.stdout.write('\n')


def pubList(args):
    '''list    list available packages
    '''
    parser = xmlDbParser()
    parser.parse(context.dbPathname(),ListPdbHandler())


def pubMake(args):
    '''make    Make projects. "make recurse" will build all dependencies
               required before a project can be itself built.'''
    global log 
    log = LogFile(context.logname())
    repositories = [ context.cwdProject() ]
    make(args,repositories)


def pubUpdate(args):
    '''update    Update projects installed in the workspace
    '''
    if len(args) == 0:
        args = [ context.cwdProject() ]
    update(args,force=True)


def pubUpstream(args):
    '''upstream    Generate a patch to submit to upstream maintainer out of 
                   a source package and a repository
    '''
    while len(sys.argv) > 0:
        srcdir = sys.argv.pop(0)
        pchdir = srcdir + '-patch'
        upstream(srcdir,pchdir)


def selectCheckout(controlCandidates):
    '''Interactive prompt for a selection of projects to checkout.
    *controlCandidates* contains a list of rows describing projects available
    for selection. This function will return a list of projects to checkout
    from a source repository and a list of projects to install through 
    a package manager.'''
    controls = []
    packages = []
    if len(controlCandidates) > 0:
        controls = selectMultiple(
'''The following dependencies need to be present on your system. 
You have now the choice to install them from a source repository. You will later
have  the choice to install them from binary package or not at all.''',
        controlCandidates)

        # Filters out the dependencies that should be installed from a source 
        # repository from the list of candidates to install as binary packages.
        packageCandidates = []
        for row in controlCandidates:
            if not row[0] in controls:
                packageCandidates += [ row ]
        packages = selectInstall(packageCandidates)
    return controls, packages


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


def selectOne(description,choices):
    '''Prompt an interactive list of choices and returns the element selected
    by the user. *description* is a text that explains the reason for the 
    prompt. *choices* is a list of elements to choose from. Each element is 
    in itself a list. Only the first value of each element is of significance
    and returned by this function. The other values are only use as textual
    context to help the user make an informed choice.'''
    choice = None
    while True:
        showMultiple(description,choices)
        if useDefaultAnswer:
            selection = "1"
        else:
            selection = raw_input("Enter a single number [1]: ")
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
    choices = [ [ 'all' ] ] + selects
    while len(choices) > 1 and not done:
        showMultiple(description,choices)
        sys.stdout.write(str(len(choices) + 1) + ')  done\n')
        if useDefaultAnswer:
            selection = "1"
        else:
            selection = raw_input("Enter a list of numbers separated by spaces [1]: ")
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


def selectVariable(d):
    '''Generate an interactive prompt to enter a workspace variable 
    *var* value and returns True if the variable value as been set.'''
    found = False
    if not d.value:
        found = True
        sys.stdout.write('\n' + d.name + ':\n')
        if isinstance(d,Pathname):
            sys.stdout.write(d.descr + '\n')
            # compute the default leaf directory from the variable name 
            leafDir = d.name
            for last in range(0,len(d.name)):
                if d.name[last] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                    leafDir = d.name[:last]
                    break
            dir = d
            default = d.default
            if (not default 
                or (not (':' in default) or default.startswith(os.sep))):
                # If there are no default values or the default is not
                # an absolute pathname.
                if d.base:
                    if default:
                        showDefault = '*' + d.base.name + '*/' + default
                    else:
                        showDefault = '*' + d.base.name + '*/' + leafDir
                    if not d.base.value:
                        directly = 'Enter *' + d.name + '* directly ?'
                        offbase = 'Enter *' + d.base.name + '*, *' + d.name \
                                     + '* will defaults to ' + showDefault + ' ?'
                        selection = selectOne(d.name + ' is based on *' + d.base.name \
                            + '* by default. Would you like to ... ',
                                  [ [ offbase  ],
                                    [ directly ] ])
                        if selection == offbase:
                            dir = d.base
                            default = dir.default
                    else:
                        if default:
                            default = os.path.join(d.base.value,default)
                        else:
                            default = os.path.join(d.base.value,leafDir)
                elif default:
                    default = os.path.join(os.getcwd(),default)
            if not default:
                default = os.getcwd()

            if useDefaultAnswer:
                dirname = default
            else:
                dirname = raw_input("Enter a pathname [" + default + "]: ")
            if dirname == '':
                dirname = default
            if not ':' in dirname:
                dirname = os.path.normpath(os.path.abspath(dirname))
            dir.value = dirname
            if dir != d:
                if d.default:
                    d.value = os.path.join(d.base.value,d.default)
                else:
                    d.value = os.path.join(d.base.value,leafDir)
            if not ':' in dirname:
                if not os.path.exists(d.value):
                    sys.stdout.write(d.value + ' does not exist.\n')
                    os.makedirs(d.value)
        elif isinstance(d,SingleChoice):
            d.value = selectOne(d.descr,d.choices)
    return found


def selectYesNo(description):
    '''Prompt for a yes/no answer.'''
    if useDefaultAnswer:
        return True
    yesNo = raw_input(description + " [Y/n]? ")
    if yesNo == '' or yesNo == 'Y' or yesNo == 'y':
        return True
    return False


def showMultiple(description,choices):
    '''Print a list of choices on the user interface.'''
    # Compute display layout
    item = 1
    widths = []
    printed = []
    for row in choices:
        c = 0
        row = [ str(item) + ')' ] + row
        printed += [ row ]
        item = item + 1
        for col in row:
            if len(widths) <= c:
                widths += [ 2 ]
            widths[c] = max(widths[c],len(col) + 2)
            c = c + 1
    # Ask user to review selection
    sys.stdout.write(description + '\n')
    for project in printed:
        c = 0
        for col in project:
            sys.stdout.write(col.ljust(widths[c]))
            c = c + 1
        sys.stdout.write('\n')


# Main Entry Point
if __name__ == '__main__':
    try:
        import __main__
	import optparse

        epilog= ''
        d = __main__.__dict__
        for command in d.keys():
            if command.startswith('pub'):
                epilog += __main__.__dict__[command].__doc__ + '\n'

	parser = optparse.OptionParser(epilog=epilog)
	parser.add_option('--version', dest='version', action='store_true',
	    help='Print version information')
	parser.add_option('--default', dest='default', action='store_true',
	    help='Use default answer for every interactive prompt.')
        
	options, args = parser.parse_args()
	if options.version:
		print('dws version: ', __version__)
		sys.exit(0)
        useDefaultAnswer = options.default

        # Find the build information
        arg = args.pop(0)
        context = Context()
        index = IndexProjects(context)
        command = 'pub' + arg.capitalize()
        if command in __main__.__dict__:
            __main__.__dict__[command](args)
        else:
            raise Error(sys.argv[0] + ' ' + arg + ' does not exist.\n')

    except Error, err:
        log.error(str(err))
        sys.exit(err.code)

    if log:
        log.close()
