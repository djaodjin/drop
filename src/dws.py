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
# (edit/build/run) on the local machine.
#
# A third-party package can either be a binary package or a source
# package. A source controlled project can either contain full source
# code or only contain a patch into a source package.


# Skip lines in the dbPrev file until hitting the definition
#        of the "install" status for the package or another package
#        definition. 
#        The install mode can be on of 
#          - skipped         The workspace script skips management 
#                            of the package and the user is responsible
#                            for installing the package manually when necessary.
#          - distribution    The workspace script installs the package 
#          (distrib)         through the platform binary package manager.
#          - upstream        The workspace script tries to compile the package 
#          (package)         through an upstream source tarball.
#          - repository      The workspace script updates the package
#          (control)         through a source controlled repository.
#        Along with the install mode, the version of the package when the install
#        tag was created is kept around. This way, the user only gets prompt 
#        about potentially changing the install mode when the package version 
#        is updated compared to the version when the user was prompted about 
#        the install mode.


import re, os, optparse, shutil
import socket, subprocess, sys, tempfile
import xml.dom.minidom, xml.sax

class Error(Exception):

    def __init__(self,msg="error",code=1):
        self.code = code
        self.msg = msg

    def show(self,ostr):
        ostr.write('error: ' + self.msg)

def shellCommand(cmdline):
    '''Execute a shell command and throws an exception when the command fails'''
    sys.stdout.write(cmdline + '\n')
    sys.stdout.flush()
    err = os.system(cmdline)
    if err != 0:
        raise Error("unable to complete: " + cmdline,err)


# Functions that deal with searching installed dependencies
# ---------------------------------------------------------

def derivedRoots(name):
    '''Derives a list of directory names based on the PATH 
    environment variable.'''
    dirs = []
    for p in os.environ['PATH'].split(':'):
        dir = os.path.join(os.path.dirname(p),name)
        if os.path.isdir(dir):
            dirs += [ dir ]
    return dirs


def findBin(names):
    '''Search for a list of binaries that can be executed from $PATH.

       *names* is a list of tuples where the first element is the name
       of the executable and the second element the command line flag
       use to retrieve the version of the executable.

       This function returns a list of tuples where the first element
       is the absolute path of the executable and the second element
       the version number retrieved through the command line flag.
    '''
    bins = []
    for name in names:
        sys.stdout.write(name + '... ')
        sys.stdout.flush()
        found = False
        for p in os.environ['PATH'].split(':'):
            bin = os.path.join(p,name)
            if os.path.isfile(bin):
                sys.stdout.write('yes\n')
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
                    bins += [ (bin,numbers[0]) ]
                    found = True
                    break
                else:
                    raise Error("Cannot guess version number for " + bin)
        if not found:
            sys.stdout.write('no\n')
    return bins


def findFilePat(base,namePat):
    '''Search the directory tree rooted at *base* for files named *name* 
       and returns a list of absolute pathnames to those files.'''
    for p in os.listdir(base):
        path = os.path.join(base,p)
        look = re.match(namePat.replace('.' + os.sep,'(.*)' + os.sep),path)
        if look != None:
            return path
        elif (('.' + os.sep) in namePat) and os.path.isdir(path):
            # When we see ./, it means we are looking for a pattern 
            # that can be matched by files in subdirectories of the base. 
            result = findFilePat(path,namePat)
            if result:
                return result
    return None


def findIncludes(names):
    '''Search for a list of headers that can be found from derived
    roots out of $PATH.

    *names* is list of header filename patterns.'''
    includes = []
    for name in names:
        sys.stdout.write(name + '... ')
        sys.stdout.flush()
        found = False
        for includeSysDir in derivedRoots('include'):
            header = findFilePat(includeSysDir,name)
            if header:
                sys.stdout.write('yes\n')
                # Open the header file and search for all defines
                # that end in VERSION.
                numbers = []
                f = open(header,'rt')
                line = f.readline()
                while line != '':
                    line = f.readline()
                    look = re.match('\s*#define.*VERSION\s+(\S+)',line)
                    if look != None:
                        numbers += versionCandidates(look.group(1))
                f.close()
                # At this point *numbers* contains a list that can
                # interpreted as versions. Hopefully, there is only
                # one candidate.
                if len(numbers) == 0:
                    includes += [ (header,None) ]
                elif len(numbers) == 1:
                    includes += [ (header,numbers[0]) ]
                else:
                    raise Error("Ambiguous version number for " + header \
                                    + ': found ' + ' '.join(numbers))
                found = True
                break
        if not found:
            sys.stdout.write('no\n')
    return includes
    

def findLib(names,version=""):
    '''Search for a list of libraries that can be found from $PATH
       where bin was replaced by lib.

       *names* is list of library names with neither a 'lib' prefix 
       nor a '.a', '.so', etc. suffix.
       *version* is a suffix attached to the library filename used
       when a library is present in multiple instances.'''
    libs = []
    for name in names:
        sys.stdout.write(name + '... ')
        sys.stdout.flush()
        found = False
        for libSysDir in derivedRoots('lib'):
            for libname in os.listdir(libSysDir):
                look = re.match('lib' + name + '.*' + version,libname)
                if look != None:
                    sys.stdout.write('yes\n')
                    libs += [ os.path.join(libSysDir,libname) ]
                    found = True
                    break
            if found:
                break
        if not found:
            sys.stdout.write('no\n')
    return libs


def makeProject(name,targets):
    '''Issue make command and log output'''
    sys.stdout.write('<book id="' + name + '">\n')
    makefile = context.srcDir(os.path.join(name,'Makefile'))
    objDir = context.objDir(name)
    if objDir != os.getcwd():
        if not os.path.exists(objDir):
            os.makedirs(objDir)
        os.chdir(objDir)
    cmdline = 'make -f ' + makefile + ' ' + ' '.join(targets)
    shellCommand(cmdline)
    sys.stdout.write('</book>\n')


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


def versionCandidates(line):
    '''Extract patterns from *line* that could be interpreted as a 
    version number. That is every pattern that is a set of digits
    separated by dots and/or underscores.'''
    part = line
    candidates = []
    while part != '':
        # numbers should be full, including '.'
        # look = re.match('[^0-9]*([0-9][0-9_\.]*)+(.*)',part)
        look = re.match('[^0-9]*([0-9]+([_\.][0-9]+)+)+(.*)',part)
        if look != None:
            candidates += [ look.group(1) ]
            part = look.group(2)
        else:
            part = ''
    return candidates


class Variable:
    
    def __init__(self,name,descr=None,base=None,default=None):
        self.base = base
        self.name = name
        self.descr = descr
        self.default = default
        self.value = None


# Find the environment configuration file, then initialize srcDir and objDir.
# For each project, srcDir points to the top of the project hierarchy where
# version controlled sources can be found and objDir points to the top of
# the project hierarchy where intermediate files are created.
class DropContext:

    configName = 'ws.mk'

    def __init__(self):
        prefix = Variable('prefix',
                          'Root of the tree where executables, include files and libraries are installed',default='/usr/local')
        self.environ = { 'buildTop': Variable('buildTop',
             'Root of the tree where intermediate files are created.'), 
                         'srcTop' : Variable('srcTop',
             'Root of the tree where the source code under revision control lives on the local machine.'),
                         'binDir': Variable('binDir',
             'Root of the tree where executables are installed',
                                            prefix),
                         'includeDir': Variable('includeDir',
             'Root of the tree where include files are installed',
                                                prefix),
                         'libDir': Variable('libDir',
             'Root of the tree where libraries are installed',
                                            prefix),
                         'pkgRepoTop': Variable('pkgRepoTop',
             'Root the tree where the remote packages are located',
                  default='codespin.is-a-geek.com:/var/codespin/reps') }

        try:
            self.cwdProject, self.configFilename = searchBackToRoot(self.configName)
            if self.cwdProject == '.':
                self.cwdProject = os.path.basename(os.getcwd())
            look = re.match('([^-]+)-.*',self.cwdProject)
            if look:
                self.cwdProject = look.group(1)
            # -- Read the environment variables set in the config file.
            configFile = open(self.configFilename)
            line = configFile.readline()
            while line != '':
                look = re.match('(\S+)\s*=\s*(\S+)',line)
                if look != None:
                    if not look.group(1) in self.environ:
                        self.environ[look.group(1)] = Variable(look.group(1),
                                                               'no description')
                    self.environ[look.group(1)].value = look.group(2)
                line = configFile.readline()
            configFile.close()        
        except IOError:
            None
        except:
            raise
            
    def closure(self, dgen, db=None):
        '''Find out all dependencies from a root set of projects as defined 
        by the dependency generator *dgen*.'''
        if not db:
            db = self.dbPathname()
        parser = xmlDbParser()
        while len(dgen.vertices) > 0:
            parser.parse(db,dgen)
            dgen.nextLevel()
        return dgen.topological()

    def dbPathname(self):
        return self.objDir(os.path.join('etc','dws','db.xml'))

    def host(self):
        '''returns the distribution on which the script is running.'''
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


    # Functions that deal with linking installed dependencies
    # ---------------------------------------------------------
    def linkPath(self,paths,installName):
        for path in paths:
            install = None
            if installName == 'libDir':
                libname, libext = os.path.splitext(os.path.basename(path))
                libname = libname.split('-')[0]
                libname = libname + libext
                install = os.path.join(self.environ[installName].value,
                                       libname)
            elif installName == 'includeDir':
                dirname, header = os.path.split(path)
                if dirname != 'include':
                    install = os.path.join(self.environ[installName].value,
                                           os.path.basename(dirname))
                    path = os.path.dirname(path)
            if not install:
                install = os.path.join(self.environ[installName].value,
                                       os.path.basename(path))
            if not os.path.exists(os.path.dirname(install)):
                os.makedirs(os.path.dirname(install))
            if os.path.islink(install):
                os.remove(install)
            if os.path.exists(path):
                os.symlink(path,install)

    def objDir(self,name):
        return os.path.join(self.environ['buildTop'].value,name)

    def remotedb(self,name):
        '''Path based of the local host platform''' 
        return self.remotePath(os.path.join(self.host(),name))

    def remotePath(self,name):
        '''Absolute path to access a file on the remote package repository''' 
        return os.path.join(self.environ['pkgRepoTop'].value,name)
        
    def repositories(self, recurse=False):
        if recurse:
            results = []
            deps = self.closure(DependencyGenerator([ self.cwdProject ]))
            for d in deps:
                if os.path.exists(self.srcDir(d)):
                    results += [ d ]
            return results
        return [ self.cwdProject ]

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
            configFile.write(key + '=' + self.environ[key].value + '\n')
        configFile.close()

    def srcDir(self,name):
        return os.path.join(self.environ['srcTop'].value,name)


class PdbHandler:
    '''Callback interface for a project database as generated by a PdbParser.
       The generic handler does not do anything. It is the responsability of
       implementing classes to filter callback events they care about.'''
    def __init__(self):
        None

    def startProject(self, name):
        None

    def dependency(self, name, bins, includes, libs):
        None

    def description(self, text):
        None

    def install(self, mode, version=None):
        '''This tag only appears in the local workspace to manage
        wether projects are installed from a source control system
        or a binary package.'''
        None
    
    def endProject(self):
        None

    def control(self, type, url):
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
        self.nextLevel()
 
    def dependency(self, name, bins, includes, libs):
        if self.source:
            if self.shouldAddDep(name,bins,includes,libs):
                newEdge = [ self.source, name ]
                # We found a new edge that needs to be recorded. We first walk the tree 
                # of previously recorded edges to find out if we detected a cycle.
                for level in self.levels:
                    for edge in level:
                        if edge[0] == newEdge[0] and edge[1] == newEdge[1]:
                            # found a cycle...
                            raise CircleException()
                self.levels[0] += [ newEdge ]

    def nextLevel(self):
        '''Going one step further in the breadth-first recursion introduces 
        a new level.'''
        self.vertices = []
        for edge in self.levels[0]:
            if not edge[1] in self.vertices:
                # insert each vertex only once
                self.vertices += [ edge[1] ]
        self.levels.insert(0,[])

    def startProject(self, name):
        self.source = None
        if name in self.vertices:
            self.source = name

    def shouldAddDep(self, name, bins, includes, libs):
        return True

    def topological(self):
        '''Returns a topological ordering of projects selected.'''
        results = []
        for level in self.levels:
            for edge in level:
                if not edge[1] in results:
                    results += [ edge[1] ] 
        return results


class xmlDbParser(xml.sax.ContentHandler):
    '''Parse a project database stored as an XML file on disc and generate
       *simplified* callbacks on a PdbHandler. The handler will update its
       states based on the callback sequence.'''

    # Global Constants for the database parser
    tagControl = 'sccs'
    tagDepend = 'xref'
    tagInstall = 'install'
    tagProject = 'section'
    tagVersion = 'version'
    tagDescription = 'description'
    tagUrl = 'url'
    tagPattern = '.*<' + tagProject + '\s+id="(.*)"'
    trailerTxt = '</book>'

    def __init__(self):
        self.handler = None
        self.depName = None
        self.depBins = []
        self.depIncludes = []
        self.depLibs = []

    def startElement(self, name, attrs):
        '''Start populating an element.'''
        self.text = ''
        if name == self.tagProject:
            self.handler.startProject(attrs['id'])
        elif name == self.tagDepend:
            self.depName = attrs['linkend']
            self.depBins = {}
            self.depIncludes = []
            self.depLibs = []
        elif name == self.tagInstall:
            if 'version' in attrs:
                self.handler.install(attrs['mode'],attrs['version'])
            else:
                self.handler.install(attrs['mode'])
        elif name == self.tagControl:
            self.url = None
            self.type = attrs['name']
        elif name == 'include':
            self.depIncludes += [ attrs['name'] ]
        elif name == 'lib':
            self.depLibs += [ attrs['name'] ]
        elif name == 'bin':
            if 'excludes' in attrs:
                self.depBins[ attrs['name'] ] = attrs['excludes'].split(',')
            else:
                self.depBins[ attrs['name'] ] = []

    def characters(self, ch):
        self.text += ch

    def endElement(self, name):
        '''Once the element is fully populated, call back the simplified
           interface on the handler.'''
        if name == self.tagControl:
            self.handler.control(self.type, self.url)
        elif name == self.tagDepend:
            self.handler.dependency(self.depName,self.depBins,
                                    self.depIncludes,self.depLibs)
            self.depName = None
        elif name == self.tagDescription:
            self.handler.description(self.text)
        elif name == self.tagProject:
            self.handler.endProject()
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

    def copy(self, dbNext, dbPrev):
        '''Copy lines in the dbPrev file until hitting the definition
        of a package and return the name of the package.'''
        name = None
        line = dbPrev.readline()
        while line != '':
            look = re.match(self.tagPattern,line)
            if look != None:
                name = look.group(1)
                break
            look = re.match('.*' + self.trailerTxt,line)
            if look == None:
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
            

def findFiles(base,namePat):
    '''Search the directory tree rooted at *base* for files matching *namePat*
       and returns a list of absolute pathnames to those files.'''
    result = []
    for p in os.listdir(base):
        path = os.path.join(base,p)
        if os.path.isdir(path):
            result += findFiles(path,namePat)
        else:
            look = re.match('.*' + namePat,path)
            if look:
                result += [ path ]
    return result


def index(dbPathname):
    '''Consolidate local dependencies information into a glabal
    dependency database.'''
    indices = findFiles(context.environ['buildTop'].value,'index.xml')\
      + findFiles(context.environ['srcTop'].value,'index.xml')
    createIndexPathname(dbPathname,indices)


def createIndexPathname(dbIndexPathname,dbPathnames):
    '''create a global dependency database (i.e. index file) out of
    a set local dependency index files.'''
    dir = os.path.dirname(dbIndexPathname)
    if not os.path.isdir(dir):
        os.makedirs(dir)
    dbNext = sortBuildConfList(dbPathnames)
    dbIndex = open(dbIndexPathname,'wb')
    dbNext.seek(0)
    shutil.copyfileobj(dbNext,dbIndex)
    dbNext.close()
    dbIndex.close()


def sortBuildConfList(dbPathnames):
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
        dbPrev = sortBuildConfList(dbPathnames[:len(dbPathnames) / 2])
        dbUpd = sortBuildConfList(dbPathnames[len(dbPathnames) / 2:])
    dbNext = mergeBuildConf(dbPrev,dbUpd)
    dbNext.seek(0)
    dbPrev.close()
    dbUpd.close()
    return dbNext


def mergeBuildConfPathname(dbPrevPathname,dbUpdPathname):
    if os.path.isfile(dbPrevPathname):
        dbPrev = open(dbPrevPathname)
        dbUpd = open(dbUpdPathname)
        dbNext = mergeBuildConf(dbPrev,dbUpd)
        dbPrev.close()
        dbUpd.close()
        dbPrev = open(dbPrevPathname,'wb')
        dbNext.seek(0)
        shutil.copyfileobj(dbNext,dbPrev)
        dbNext.close()
        dbPrev.close()
    else:
        shutil.copy(dbUpdPathname,dbPrevPathname)


def mergeBuildConf(dbPrev,dbUpd):
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
        parser = xmlDbParser()
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
                projUpd = parser.copy(dbNext,dbUpd)
                projPrev = parser.next(dbPrev)
        while projPrev != None:
            parser.startProject(dbNext,projPrev)
            projPrev = parser.copy(dbNext,dbPrev)
        while projUpd != None:
            parser.startProject(dbNext,projUpd)
            projUpd = parser.copy(dbNext,dbUpd)
        parser.trailer(dbNext)
        return dbNext

class InstallInfo:

    def __init__(self):
        self.version = None
        self.deliver = None
        self.mode = None

class InstallGenerator(DependencyGenerator):
    '''Aggregate dependencies for a set of projects only when prerequisites
    can not be found on the system.'''

    def __init__(self, projects):
        DependencyGenerator.__init__(self, projects)
        self.installs = {}

    def expanded(self, names):
        '''Returns a list of rows where each row contains expanded information
        for each project in *names*. all project that do not have expanded
        information will be filtered out as a side effect of this method.'''
        results = []
        for name in names:
            # Either the name is a root project or should have been seen 
            # at least once by shouldAddDep() in order to be added 
            # to the installs dictionnary.
            if name in self.installs:
                results += [ [ name, self.installs[name] ] ]
        return results

    def shouldAddDep(self, name, bins, includes, libs):
        # Find executables, then filters out versions
        # known to be incompatible.
        version = None
        installedBins = []
        foundBins = findBin(bins.keys())
        for bin in foundBins:
            version = bin[1]
            excluded = False
            excludes = bins[os.path.basename(bin[0])]
            for exclude in excludes:
                if version == exclude:
                    # \todo use comparaison operators.
                    excluded = True
                    break
            if not excluded:
                installedBins += [ bin[0] ]
        if len(installedBins) != len(bins):
            self.installs[name] = InstallInfo()
            self.installs[name].version = version
            return True
        installedIncludes = []
        foundIncludes = findIncludes(includes)
        for header in foundIncludes:
            installedIncludes += [ header[0] ]
            if header[1]:
                version = header[1]
        if len(installedIncludes) != len(includes):
            self.installs[name] = InstallInfo()
            self.installs[name].version = version
            return True
        installedLibs = findLib(libs,version)
        if len(installedLibs) != len(libs):
            self.installs[name] = InstallInfo()
            self.installs[name].version = version
            return True
        context.linkPath(installedBins,'binDir')
        context.linkPath(installedIncludes,'includeDir')
        context.linkPath(installedLibs,'libDir')
        return False

    def version(self, text):
        if self.source:
            self.installs[name].deliver = text


## \todo following is deprecated code?

def selectBuildEnv(context):
    '''This routine updates the build environment 'configure'
    link to resources in buildBin, buildLib, etc. return packages
    that need to be installed.'''
    installPackages = []
    installRepositories = []
    installPackagedSources = []
    for node in context.doc.getElementsByTagName("book"):
        nodeId = node.getAttribute('id')
        sys.stdout.write('<book id="' + nodeId + '">\n')
        # create the build tree structure
        objDir = context.objDir(nodeId)
        if objDir != os.getcwd():
            if not os.path.exists(objDir):
                os.makedirs(objDir)
        os.chdir(objDir)
        # Check that the tools necessary to build the repository
        # are installed on the local platform.
        if node.getAttribute('mode') != "package":
            # Check binary executables (ie. $prefix/bin)
            bins = []
            for bin in node.getElementsByTagName("bin"):
                bins += (bin.getAttribute('name'),
                         bin.getAttribute('version'))
            installedBins = findBin(bins)
            if len(installedBins) != len(bins):
                installPackages += [ nodeId ]
            else:
                context.linkPath(installedBins,'binDir')
            libs = []
            for lib in node.getElementsByTagName("lib"):
                libs += (lib.getAttribute('name'),
                         lib.getAttribute('version'))
            installedLibs = findLib(libs)
            if len(installedLibs) != len(libs):
                installPackages += [ nodeId ]
            else:
                context.linkPath(installedLibs,'libDir')
            # \todo includes and shares.

        else:
            if not os.path.exists(context.srcDir(nodeId)):
                installRepositories += [ nodeId ]
                if node.getAttribute('patch') != "":
                    # This repository is a patch into a third-party package
                    installPackagedSources += [ node.getAttribute('patch') ]
        sys.stdout.write('</book>\n')
    return installPackages, installRepositories, installPackagedSources


## \todo end of code rewritten for closure.

def updatedb():
    init()
    if not os.path.isdir(os.path.dirname(context.dbPathname())):
        os.makedirs(os.path.dirname(context.dbPathname()))
    # download latest index file from package server.
    cmdline = 'rsync ' + context.remotedb('db.xml') \
                       + ' ' + context.dbPathname()
    print cmdline
    shellCommand(cmdline)


# \param db           XML dom structure
# \param dbPathname   (string) filename to write the build configuration into
def writeBuildConf(db,dbPathname):
    tmpFile = open(os.path.basename(dbPathname) +'~','w')
    tmpFile.write(db.toprettyxml())
    tmpFile.close()
    tmpFile = open(os.path.basename(dbPathname) +'~','r')
    dbFile = open(dbPathname,'w')
    for line in tmpFile.readlines():
        if re.match('^\s*$',line) == None:
            dbFile.write(line)
    dbFile.close()
    tmpFile.close()

# Functions that deal with package management
# -------------------------------------------

cacheDir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))),'cache')
# \todo current hack while we put packaged patched sources on a remove server.
packagedSourcesDir = cacheDir

def fetch(location,package):
    if not os.path.isfile(os.path.join(cacheDir,package)):
        p = os.getcwd()
        os.chdir(cacheDir)
        shellCommand("curl --location -O " + location + package)
        os.chdir(p)
    else:
        print package + "... cached"


def packageManagerCommands():
    if 'packageInstall' in context.environ \
           and 'packageDownload' in context.environ:
        return context.environ['packageInstall'], context.environ['packageDownload']
    # Look for a package manager on the system.
    while True:
        paths = []
        for manager in ['fink']:
            paths = findBin(manager)
            if len(paths) == 1:
                break
        if len(paths) == 1:
            manager = paths[0]
            if manager == 'fink':
                packageInstall = manager + ' install '
                packageDownload = manager + ' fetch '
            elif manager == 'apt-get':
                packageInstall = manager + ' install '
                packageDownload = manager + ' --download-only install '
            else:
                raise Error(1,"unknown package manager: " + manager)
            context.environ['packageInstall'] = packageInstall
            context.environ['packageDownload'] = packageDownload
            return packageInstall, packageDownload
        # If we cannot find a package manager, we will try to install
        # one. Prompt the user.
        finkPackage = "fink-0.28.1.tar.gz"
        fetch("http://downloads.sourceforge.net/fink/",finkPackage)
        p = os.getcwd()
        name, ext = os.path.splitext(finkPackage)
        if not os.path.isfile(os.path.join(cacheDir,finkPackage)):
            raise Error(1,finkPackage + " not found in cache")
        if finkPackage.endswith('.tar.gz'):
            name, ext = os.path.splitext(name)
            shellCommand('tar zxf ' + os.path.join(cacheDir,finkPackage))
            os.chdir(name)
            shellCommand('./bootstrap /sw')
            shellCommand('/sw/bin/fink selfupdate')
            os.chdir(p)
            context.linkPath('/sw/bin/fink','binDir')
        else:
            raise Error(1,finkPackage + " not installed properly")
    return None

# download a package using the development platform
# package manager.
def download(packages):
    packageInstall, packageDownload = packageManagerCommands()
    status = shellCommand(packageDownload + ' '.join(packages))
    if status != 0:
        raise Error("download of packages" + ' '.join(packages))


def init():
    '''Interactively ask for variables which have not been initialized 
       in the ws.mk'''
    found = False
    for d in context.environ.values():
        if not d.value:
            found = True
            print '\n' + d.name + ': ' +  d.descr
            # compute the default leaf directory from the variable name 
            leafDir = d.name
            for last in range(0,len(d.name)):
                if d.name[last] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                    leafDir = d.name[:last]
                    break
            dir = d
            default = d.default
            if not default:
                if d.base:
                    default = '*' + d.base.name + '*/' + leafDir
                    if not d.base.value:
                        print d.name + ' is based on *' + d.base.name + '* by default.'
                        print 'Would you like to ... '
                        print '1) Enter *' + d.name + '* directly ?'
                        print '2) Enter *' + d.base.name + '*, *' + d.name \
                            + '* will defaults to ' + default + ' ?'
                        choice = raw_input("Choice [2]: ")
                        if choice == '' or choice == '2':
                            dir = d.base
                            default = dir.default
                    else:
                        default = os.path.join(d.base.value,leafDir)
                else:
                    default = os.getcwd()

            dirname = raw_input("Enter a pathname name for " + dir.name \
                                    + " [" + default + "]: ")
            if dirname == '':
                dirname = default
            if not ':' in dirname:
                dirname = os.path.normpath(os.path.abspath(dirname))
            dir.value = dirname
            if dir != d:
                d.value = os.path.join(d.base.value,leafDir)
            if not ':' in dirname:
                if not os.path.exists(d.value):
                    print d.value + ' does not exist.'
                    yesNo = raw_input("Would you like to create it [Y/n]: ")
                    if yesNo == '' or yesNo == 'Y' or yesNo == 'y':
                        os.makedirs(d.value)
    if found:
        context.save()


def install(packageCandidates):
    '''Interactive selection of project to install as binary packages.'''
    if len(packageCandidates) > 0:
        packages = selectMultiple(
    '''The following dependencies need to be present on your system. 
    You have now the choice to install them from a binary package. You can skip
    this step if you know those dependencies will be resolved correctly later on.
    ''',packageCandidates)
        print "packages: "
        print packages
        return packages
    return []

def updatePackages(packages):
    packageInstall, packageDownload = packageManagerCommands()
    if len(packages) > 0:
        status = shellCommand(packageInstall + ' '.join(packages))
        if status != 0:
            raise Error("installation of packages" + ' '.join(packages))


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


class Control:

    def __init__(self, type, url):
        self.type = type
        self.url = url

class Project:

    def __init__(self):
        self.control = None
        self.package = None

class UpdateHandler(PdbHandler):
    '''Aggregate dependencies for a set of projects only when prerequisites
    can not be found on the system.'''

    def __init__(self, projects):
        PdbHandler.__init__(self)
        self.mode = None
        self.project = None
        self.projects = {}
        for p in projects:
            self.projects[p] = Project()
        self.filtered = projects

    def asProject(self, name):
        return self.projects[name]

    def control(self, type, url):
        if self.project:
            if context.srcDir(self.project):
                self.projects[self.project].control = Control(type, url)

    def startProject(self, name):
        self.project = None
        if name in self.filtered:
            self.project = name


def update(projects):
    '''Update a list of *projects* within the workspace. The update will either 
    sync with a source control repository or install a new binary package based
    on the install mode in the local db.'''
    parser = xmlDbParser()
    handler = UpdateHandler(projects)
    parser.parse(context.dbPathname(),handler)
    for name in projects:
        control = handler.asProject(name).control
        if control:
            if control.type == 'git':
                if not os.path.exists(os.path.join(context.srcDir(name),'.git')):
                    shutil.rmtree(context.srcDir(name))
                    cmdline = 'git clone ' + control.url + ' ' + context.srcDir(name)
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
                raise RuntimeError("unknown source control system '" + control.type + "'")
        elif handler.asProject(name).package:
            print "update package is not yet implemented"
            None
        else:
            raise RuntimeError("unknown install mode for '" + name + "'")
            

def upstream(srcdir,pchdir):
    upstreamRecurse(srcdir,pchdir)
    #subprocess.call('diff -ru ' + srcdir + ' ' + pchdir,shell=True)
    p = subprocess.Popen('diff -ru ' + srcdir + ' ' + pchdir, shell=True,
              stdout=subprocess.PIPE, close_fds=True)
    line = p.stdout.readline()
    while line != '':
        look = re.match('Only in ' + srcdir + ':',line)
        if look == None:
            sys.stdout.write(line)
        line = p.stdout.readline()
    p.poll()
    integrate(srcdir,pchdir)

def pubCo(args):
    '''co    Check out source repositories
    '''
    # Load the latest package index file
    updatedb()

    # Search for the projects to check out and their dependencies
    dgen = InstallGenerator(args)
    controlCandidates = dgen.expanded(context.closure(dgen))

    controls = args + selectMultiple(
'''The following dependencies need to be present on your system. 
You have now the choice to install them from a source repository. You will later
have  the choice to install them from binary package or not at all.''',
        controlCandidates)
    for control in controls:
        if not os.path.exists(context.srcDir(control)):
            os.makedirs(context.srcDir(control))

    # Filters out the dependencies that should be installed from a source 
    # repository from the list of candidates to install as binary packages.
    packageCandidates = []
    for row in controlCandidates:
        if not row[0] in controls:
            packageCandidates += [ row ]
    packages = install(packageCandidates)
    # Checkout projects from a source repository through an update.
    update(controls + packages)


def pubCollect(args):
    '''collect    Generate an index database out of specification files
                  and collect all packages into a directory.
    '''
    index(context.dbPathname())
    distSrcs = findFiles(context.environ['buildTop'].value,'.*\.tar\.bz2')
    distSrcDir = context.remotePath('srcs')
    if not os.path.exists(distSrcDir):
        os.makedirs(distSrcDir)
    cmdline = 'rsync ' + context.dbPathname() \
        + ' ' + os.path.join(distSrcDir,'db.xml')
    shellCommand(cmdline)
    for dist in distSrcs:
        shutil.copy(dist,distSrcDir)


def pubConfigure(args):
    '''configure     Look through the development platform for tools
                     required in order to build a project.'''
    reps = context.repositories()
    print reps
    dgen = InstallGenerator(reps)
    deps = dgen.expanded(context.closure(dgen,'index.xml'))
    if len(deps) > 0:
        showMultiple('error: The following prerequisites are missing.',deps)
        sys.exit(1)


def pubContext(args):
    '''Prints the absolute pathname to the filename specified in *args*.
    If the filename cannot be found from the current directory up to 
    the root (i.e where ws.mk is located), it assumes the file is 
    in *srcTop*/drop/src.'''
    pathname = context.configFilename
    if len(args) >= 1:
        try:
            dir, pathname = searchBackToRoot(args[0],
                   os.path.dirname(context.configFilename))
        except IOError:
            pathname = context.srcDir(os.path.join('drop','src',args[0]))
    print pathname


def pubInit(args):
    '''init     Create a ws.mk config file in the current directory 
                and bootstrap a workspace.
    '''
    init()


def pubInstall(args):
    '''install    Install new packages
    '''
    # Get list from arguments.
    # update()
    dgen = InstallGenerator(args)
    packageCandidates = dgen.expanded(context.closure(dgen))
    packages = install(packageCandidates)

    # Set the install mode in the local db 
    # and install binary packages through an update.
    update(args + packages)


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
        sys.stdout.write(name + '\n')

def pubList(args):
    '''list    list available packages
    '''
    parser = xmlDbParser()
    parser.parse(context.dbPathname(),ListPdbHandler())


def pubMake(args):
    '''make    make projects'''
    recurse = 'recurse' in args
    if 'recurse' in args:
        args.remove('recurse')

    # Find build information
    print '<build>'
    try:
        repositories = context.repositories(recurse)
        last = repositories.pop()
        # Recurse through projects that need to be rebuilt first 
        for repository in repositories:
            makeProject(repository,['install'])

        # Make current project
        if not recurse or len(args) > 0:
            makeProject(last,args)
        print '</build>'

    except Exception, e:
        print e
        print '</build>'


def pubUpdate(args):
        '''update    Update packages and repositories installed in the workspace
        '''
        # Get list from cwd (and/or arguments?)
        print '<build>'
        # Update repositories which are in the current workspace.
        # As a side effect, the build dependency database will also
        # be updated.
        updatedb()

        # 1. Make sure all packages and repositories have been installed
        #    correctly
        installPackages,
        installRepositories,
        installPackagedSources = selectBuildEnv(context)

        # Install all packages
        updatePackages(installPackages)

        # Checkout repositories
        for repository in installRepositories:
            sys.stdout.write('checkout ' + repository + '\n')

        # Install packaged sources where they belong in the workspace.
        fetch(packagedSourcesDir,installPackagedSources)
        for repository in installRepositories:
            node = context.findNodeByName(repository)
            packagedSource = node.getAttribute('patch')
            if packagedSource != '' and not os.path.exists(context.srcDir(repository)):
                # Untar sources in repository
                prevDir = os.getcwd()
                os.chdir(context.srcDir(repository))
                err = subprocess.call('tar zxf ' + os.path.join(cacheDir,packagedSource))
                if err == 0:
                    raise Error(1,"error while intalling packaged sources: " + packagedSource)
                os.chdir(prevDir)

        print '</build>'

def pubUpstream(args):
    '''upstream    Generate a patch to submit to upstream maintainer out of a source package
                   and a repository
    '''
    while len(sys.argv) > 0:
        srcdir = sys.argv.pop(0)
        pchdir = srcdir + '-patch'
        upstream(srcdir,pchdir)


def selectMultiple(description,choices):
    '''Generate an interactive list of choices and returns elements selected
    by the user.'''
    result = []
    done = False
    while len(choices) > 0 and not done:
        showMultiple(description,choices)
        sys.stdout.write(str(len(choices) + 1) + ')  done\n')
        selection = raw_input("Enter a list of numbers separated by spaces: ")
        # parse the answer for valid inputs
        selection = selection.split(' ')
        for s in selection:
            try:
                choice = int(s)
            except TypeError:
                choice = 0
            except ValueError:  
                choice = 0
            if choice >= 1 and choice <= len(choices):
                result += [ choices[choice - 1][0] ]
            elif choice == len(choices) + 1:
                done = True
        # remove selected items from list of choices
        remains = []
        for row in choices:
            if not row[0] in result:
                remains += [ row ]
        choices = remains
    return result


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

	options, args = parser.parse_args()
	if options.version:
		print('dws version: ', __version__)
		sys.exit(0)

        # Find the build information
        arg = args.pop(0)
        context = DropContext()
        command = 'pub' + arg.capitalize()
        if command in __main__.__dict__:
            __main__.__dict__[command](args)

    except Error, err:
        err.show(sys.stderr)
        sys.exit(err.code)
