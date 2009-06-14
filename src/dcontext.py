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

# Common infrastructure for accessing workspace information

import re, os, subprocess, sys
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


def searchBackToRoot(filename,root=os.sep):
    '''Search recursively from the current directory to the *root*
    of the directory hierarchy for a specified *filename*.
    This function returns the relative path from *filename* to pwd
    and the absolute path to *filename* if found.'''
    d = os.getcwd()
    dirname = None 
    while (not os.path.samefile(d,root) 
           and not os.path.isfile(os.path.join(d,filename))):
        if dirname == None:
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

    configName = '.buildrc'

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
                                            prefix) }

        self.cwdProject, self.configFilename = searchBackToRoot(self.configName)
        # -- Read the environment variables set in the config file.
        configFile = open(self.configFilename)
        line = configFile.readline()
        while line != '':
            look = re.match('(\S+)\s*=\s*(\S+)',line)
            if look != None:
                if not look.group(1) in self.environ:
                    self.environ[look.group(1)] = Variable(look.group(1),'no description')
                self.environ[look.group(1)].value = look.group(2)
            line = configFile.readline()
        configFile.close()        

    def closure(self, dgen):
        '''Find out all dependencies from a root set of projects as defined 
        by the dependency generator *dgen*.'''
        parser = xmlDbParser()
        while len(dgen.vertices) > 0:
            parser.parse(self.localDbPathname(),dgen)
            dgen.nextLevel()
        return dgen.topological()

    def dbPathname(self):
        return os.path.join(self.environ['topSrc'].value,
                            'drop','data','db.xml')

    def localDbPathname(self):
        return os.path.join(self.environ['topSrc'].value,
                            'drop','data','local.xml')

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
        configFile = open(self.configFilename,'w')
        keys = self.environ.keys.sort()
        configFile.write('# configuration for development workspace\n\n')
        for key in keys:
            configFile.write(key + '=' + self.environ[key].value + '\n')
        configFile.close()

    def srcDir(self,name):
        return os.path.join(self.environ['topSrc'].value,name)


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


    def installMode(self, dbPrev):
        '''Skip lines in the dbPrev file until hitting the definition
        of the "install" status for the package or another package
        definition. 
        The install mode can be on of 
          - skipped         The workspace script skips management 
                            of the package and the user is responsible
                            for installing the package manually when necessary.
          - distribution    The workspace script installs the package 
          (distrib)         through the platform binary package manager.
          - upstream        The workspace script tries to compile the package 
          (package)         through an upstream source tarball.
          - repository      The workspace script updates the package
          (control)         through a source controlled repository.
        Along with the install mode, the version of the package when the install
        tag was created is kept around. This way, the user only gets prompt 
        about potentially changing the install mode when the package version 
        is updated compared to the version when the user was prompted about 
        the install mode.''' 
        mode = None
        version = None
        line = dbPrev.readline()
        while line != '':
            look = re.match('.*<install mode="(.*)" version="(.*)"',line)
            if look != None:
                mode = look.group(1)
                version = look.group(2)
                break
            look = re.match(self.tagPattern,line)
            if look != None:
                break
            line = dbPrev.readline()
        return mode, version


    def setInstallMode(self, dbNext, installMode, version=None):
        dbNext.write('<install mode="' + installMode + '"')
        if version:
            dbNext.write(' version="' + version + '"')
        dbNext.write('/>\n')

    def startProject(self, dbNext, name):
        dbNext.write('  <' + self.tagProject + ' id="' + name + '">\n')
        None

    def trailer(self, dbNext):  
        '''XML files need a finish tag. We make sure to remove it while
           processing Upd and Prev then add it back before closing 
           the final file.'''
        dbNext.write(self.trailerTxt)
            
# Main Entry Point
if __name__ == '__main__':
    context = DropContext()
    if len(sys.argv) > 1:
        # Prints the absolute pathname to the filename specified in sys.argv[1].
        # If the filename cannot be found from the current directory up to 
        # the root (i.e where .buildrc is located), it assumes the file is 
        # in *topSrc*/drop/src.
        pathname = None
        try:
            dir, pathname = searchBackToRoot(sys.argv[1],
                   os.path.dirname(context.configFilename))
        except IOError:
            pathname = os.path.join(context.environ['topSrc'].value,'drop',
                               'src',sys.argv[1])
        print pathname

    print context.configFilename
