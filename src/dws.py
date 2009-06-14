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


import dcontext, re, os, shutil, subprocess, sys, tempfile
import optparse

def findFiles(base,name):
    '''Search the directory tree rooted at *base* for files named *name*
       and returns a list of absolute pathnames to those files.'''
    result = []
    for p in os.listdir(base):
        path = os.path.join(base,p)
        if os.path.isdir(path):
            result += findFiles(path,name)
        elif path.endswith(name):
            result += [ path ]
    return result


def index(dbPathname,topSrc):
    '''Consolidate local dependencies information into a glabal
    dependency database.'''
    createIndexPathname(dbPathname,findFiles(topSrc,'index.xml'))


def createIndexPathname(dbIndexPathname,dbPathnames):
    '''create a global dependency database (i.e. index file) out of
    a set local dependency index files.'''
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
        parser = dcontext.xmlDbParser()
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
                installMode, version = parser.installMode(projPrev)
                parser.setInstallMode(dbNext,installMode,version)
                # It is critical this line appears after we set the installMode
                # because it guarentees that the install mode will always be
                # the first line after the package tag.
                parser.copy(dbNext,dbUpd)
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

class InstallGenerator(dcontext.DependencyGenerator):
    '''Aggregate dependencies for a set of projects only when prerequisites
    can not be found on the system.'''

    def __init__(self, projects):
        dcontext.DependencyGenerator.__init__(self, projects)
        self.installs = {}

    def expanded(self, names):
        '''Returns a list of rows where each row contains expanded information
        for each project in *names*.'''
        print "expands " + ' '.join(names) + " ..."
        results = []
        for name in names:
            # Either the name is a root project or should have been seen 
            # at least once by shouldAddDep() in order to be added 
            # to the installs dictionnary.
            if name in self.projects:
                results += [ [ name, "unknown" ] ]
            else:
                results += [ [ name, self.installs[name] ] ]
        return results

    def shouldAddDep(self, name, bins, includes, libs):
        # Find executables, then filters out versions
        # known to be incompatible.
        print "should add " + name + " ?"
        version = None
        installedBins = []
        foundBins = dcontext.findBin(bins.keys())
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
        foundIncludes = dcontext.findIncludes(includes)
        for header in foundIncludes:
            installedIncludes += [ header[0] ]
            if header[1]:
                version = header[1]
        if len(installedIncludes) != len(includes):
            self.installs[name] = InstallInfo()
            self.installs[name].version = version
            return True
        installedLibs = dcontext.findLib(libs,version)
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
            print 'deliver ' + self.source + ' version ' + text
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

def updateWorkspace(context):
    # download latest db
    # merge db into local db
    mergeBuildConf(context.localDbPathname(),context.dbPathname())
    context = dcontext.DropContext()
    # update all packages in topological order.
    # roots are passed as arguments to update.
    #if len(context.repositories) > 0:
    #    sys.stdout.write('update ' + ' '.join(context.repositories) + '...\n')


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
        dcontext.shellCommand("curl --location -O " + location + package)
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
            paths = dcontext.findBin(manager)
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
            dcontext.shellCommand('tar zxf ' + os.path.join(cacheDir,finkPackage))
            os.chdir(name)
            dcontext.shellCommand('./bootstrap /sw')
            dcontext.shellCommand('/sw/bin/fink selfupdate')
            os.chdir(p)
            context.linkPath('/sw/bin/fink','binDir')
        else:
            raise Error(1,finkPackage + " not installed properly")
    return None

# download a package using the development platform
# package manager.
def download(packages):
    packageInstall, packageDownload = packageManagerCommands()
    status = dcontext.shellCommand(packageDownload + ' '.join(packages))
    if status != 0:
        raise dcontext.Error("download of packages" + ' '.join(packages))


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
        status = dcontext.shellCommand(packageInstall + ' '.join(packages))
        if status != 0:
            raise dcontext.Error("installation of packages" + ' '.join(packages))


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

class UpdateHandler(dcontext.PdbHandler):
    '''Aggregate dependencies for a set of projects only when prerequisites
    can not be found on the system.'''

    def __init__(self, projects):
        dcontext.PdbHandler.__init__(self)
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
    parser = dcontext.xmlDbParser()
    handler = UpdateHandler(projects)
    parser.parse(context.localDbPathname(),handler)
    for name in projects:
        control = handler.asProject(name).control
        if control:
            if control.type == 'git':
                if not os.path.exists(os.path.join(context.srcDir(name),'.git')):
                    os.rmdir(context.srcDir(name))
                    cmdline = 'git clone ' + control.url + ' ' + context.srcDir(name)
                    dcontext.shellCommand(cmdline)
                else:
                    cwd = os.getcwd()
                    os.chdir(context.srcDir(name))
                    cmdline = 'git pull'
                    dcontext.shellCommand(cmdline)
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
    # Get list from arguments.
    # update()
    dgen = InstallGenerator(args)
    controlCandidates = dgen.expanded(context.closure(dgen))

    controls = selectMultiple('''The following dependencies need to be present on your system. 
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
    print "controls: "
    print controls
    # Set the install mode in the local db 
    # and checkout projects from a source repository through an update.
    # setInstallMode(controls,packages)
    update(controls + packages)


def pubIndex(args):
    '''index    Generate an index database out of specification files
    '''
    index(context.dbPathname(),context.environ['topSrc'].value)
    if not os.path.exists(context.localDbPathname()):
        shutil.copy(context.dbPathname(),context.localDbPathname())


def pubInit(args):
    '''init     Create a .buildrc config file in the current directory 
                and bootstrap a workspace.
    '''
    for d in dcontext.environ:
        print d.name + ': ' +  d.descr
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

        dirname = raw_input("Enter a directory name for " + dir.name \
                                + " [" + default + "]: ")
        if dirname == '':
            dirname = default
        dirname = os.path.normpath(os.path.abspath(dirname))
        dir.value = dirname
        if not os.path.exists(dirname):
            print dirname + ' does not exist.'
            yesNo = raw_input("Would you like to create it [Y/n]: ")
            if yesNo == 'Y' or yesNo == 'y':
                os.makedirs(dirname)
        if dir != d:
            d.value = os.path.join(d.base.value,leafDir)
        # \todo add *d* to .buildrc 


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
    setInstallMode([],packages)
    update(packages)


def pubIntegrate(args):
    '''integrate    Integrate a patch into a source package
    '''
    while len(sys.argv) > 0:
        srcdir = sys.argv.pop(0)
        pchdir = srcdir + '-patch'
        integrate(srcdir,pchdir)


class ListPdbHandler(dcontext.PdbHandler):

    def startProject(self, name):
        sys.stdout.write(name + '\n')

def pubList(args):
    '''list    list available packages
    '''
    parser = dcontext.xmlDbParser()
    parser.parse(context.localDbPathname(),ListPdbHandler())


def pubUpdate(args):
        '''update    Update packages and repositories installed in the workspace
        '''
        # Get list from cwd (and/or arguments?)
        print '<build>'
        # Update repositories which are in the current workspace.
        # As a side effect, the build dependency database will also
        # be updated.
        updateWorkspace(context)

        # Merge the repository database with the local workspace configuration.
        # With an up-to-date build dependency database, we can now check
        # projects and packages which are required.
        mergeBuildConf(context.localDbPathname(),context.dbPathname())
        context = dcontext.DropContext()

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


def setInstallMode(controls,packages):
    '''Add corresponding install mode in the local db for projects 
    listed in controls and packages.'''
    parser = dcontext.xmlDbParser()
    dbLocal = open(context.localDbPathname(),'r')
    dbNext = tempfile.TemporaryFile()
    proj = parser.copy(dbNext,dbLocal)
    while proj != None:
        parser.startProject(dbNext,proj)
        # mergeBuildConf() guarentees that the install mode is the first
        # line after the project tag. We keep this true here so as to avoid
        # loosing information on the project.
        installMode, version = parser.installMode(dbLocal)
        if proj in controls:
            parser.setInstallMode(dbNext,'control')
        elif proj in packages:
            parser.setInstallMode(dbNext,'package',packages[proj])            
        proj = parser.copy(dbNext,dbLocal)
    parser.trailer(dbNext)
    dbNext.seek(0)
    dbLocal.close()
    dbLocal = open(context.localDbPathname(),'wb')
    shutil.copyfileobj(dbNext,dbLocal)
    dbLocal.close()
    dbNext.close()


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
        context = dcontext.DropContext()
        command = 'pub' + arg.capitalize()
        if command in __main__.__dict__:
            __main__.__dict__[command](args)

    except dcontext.Error, err:
        err.show(sys.stderr)
        sys.exit(err.code)
