#!/usr/bin/env python

"""buildpkg.py -- Build OS X packages for Apple's Installer.app.

This is an experimental command-line tool for building packages to be
installed with the Mac OS X Installer.app application. 

Sebastien Mirolo, 
smirolo@fortylines.com
June 2009

Based on work from 

Dinu C. Gherman, 
gherman@europemail.com
September 2002

!! USE AT YOUR OWN RISK !!
"""

__version__ = 0.4
__license__ = "FreeBSD"


import re, os, subprocess, sys, glob, fnmatch, shutil, string, copy, getopt
from os.path import basename, dirname, join, islink, isdir, isfile
import hashlib, shutil, dws

Error = "buildpkg.Error"

PKG_INFO_FIELDS = """\
Title
Version
Description
DefaultLocation
Diskname
DeleteWarning
NeedsAuthorization
DisableStop
UseUserMask
Application
Relocatable
Required
InstallOnly
RequiresReboot
InstallFat\
"""

######################################################################
# Helpers
######################################################################

class FedoraSpecWriter(dws.PdbHandler):
    '''As the index file parser generates callback, an instance 
    of this class will rewrite the exact same information in a format 
    compatible with rpmbuild.'''

    def __init__(self, specfile):
        self.specfile = specfile

    def project(self, p):
        self.specfile.write('Name: ' + p.name.replace(os.sep,'_') + '\n')
        self.specfile.write('Distribution: Fedora\n')
        self.specfile.write('Release: 0\n')
        self.specfile.write('Summary: None\n')
        self.specfile.write('License: Unknown\n')
        self.specfile.write('\n%description\n' + p.description + '\n')
        self.specfile.write('Packager: ' + p.maintainer.name \
                                + ' <' + p.maintainer.email + '>\n')
        self.specfile.write('''\n%build
./configure --prefix=/usr/local
make

%install
make install
''')


class UbuntuSpecWriter(dws.PdbHandler):
    '''As the index file parser generates callback, an instance 
    of this class will rewrite the exact same information in a format 
    compatible with debuild.'''

    def __init__(self, control, changelog):
        self.controlf = control
        self.changelog = changelog
    
    def project(self, p):
        self.controlf.write('Version:' + p.version)
        self.controlf.write('Source: ' + p.name + '\n')
        self.controlf.write('Description: ' + p.description)
        self.controlf.write('Maintainer: ' + p.maintainer.name \
                                + ' <' + p.maintainer.email + '>\n')
        self.controlf.write('\nPackage: ' + p.name + '\n')
        self.controlf.write('Architecture: any\n')
        self.controlf.write('Depends: ' + ','.join(p.depends) + '\n')
        self.controlf.write('\n')


def pubSpec(args):
    '''spec                   Writes out the specification files used 
                       to build a distribution package.
    '''
    dist = context.host()
    name = context.cwdProject() 
    if dist == 'Darwin':
        # For OSX, there does not seem to be an official packaging script
        # so we use buildpkg.py and the index file directly.
        None
    elif dist == 'Fedora':
        specfile = open(args[0] + '.spec','w')
        writer = FedoraSpecWriter(specfile)
        parser = xmlDbParser()
        parser.parse(context.srcDir(os.path.join(name,'index.xml')),writer)
        specfile.close()
    elif dist == 'Ubuntu':
        control = open('control','w')
        changelog = open('changelog','w')
        writer = UbuntuSpecWriter(control,changelog)
        parser = xmlDbParser()
        parser.parse(context.srcDir(os.path.join(name,'index.xml')),writer)
        control.close()
        changelog.write(writer.projectName + ' (' + args[0] + '-ubuntu1' + ') jaunty; urgency=low\n\n')
        changelog.write('  * debian/rules: generate ubuntu package\n\n')
        changelog.write(' -- ' + writer.maintainerName \
                            + ' <' + writer.maintainerEmail + '>  ' \
                            + 'Sun, 21 Jun 2009 11:14:35 +0000' + '\n\n')
        changelog.close()
        rules = open('rules','w')
        rules.write('''#! /usr/bin/make -f

export DH_OPTIONS

#include /usr/share/quilt/quilt.make

PREFIX 		:=	$(CURDIR)/debian/tmp/usr/local

build:
\t./configure --prefix=$(PREFIX)
\tmake

clean:
\techo "make clean"

install:
\tdh_testdir
\tdh_testroot
\tdh_clean -k
\tmake install

binary: install
\tdh_installdeb
\tdh_gencontrol
\tdh_md5sums
\tdh_builddeb

''')
        rules.close()
        copyright = open('copyright','w')
        copyright.close()
    else:
        raise


# Convenience class, as suggested by /F.

class GlobDirectoryWalker:
    "A forward iterator that traverses files in a directory tree."

    def __init__(self, directory, pattern="*"):
        self.stack = [directory]
        self.pattern = pattern
        self.files = []
        self.index = 0


    def __getitem__(self, index):
        while 1:
            try:
                file = self.files[self.index]
                self.index = self.index + 1
            except IndexError:
                # pop next directory from stack
                self.directory = self.stack.pop()
                self.files = os.listdir(self.directory)
                self.index = 0
            else:
                # got a filename
                fullname = join(self.directory, file)
                if isdir(fullname) and not islink(fullname):
                    self.stack.append(fullname)
                if fnmatch.fnmatch(file, self.pattern):
                    return fullname


######################################################################
# The real thing
######################################################################
class ImageMaker:
    """A class to generate Mac OS X images (.dmg) out of 
    a directory tree."""

    def __init__(self, project, version, sourceDir):
        self.name = os.path.basename(project.name) + '-' + version
        self.sourceDir = sourceDir
        self.image = self.name + '.dmg'
 
    def build(self):
        print 'sourceDir: ' + self.sourceDir
        cmd = ['du', '-sk', self.sourceDir]
        p = subprocess.Popen(cmd,stdout=subprocess.PIPE)
        line = p.stdout.readline()
        look = re.match('^(.\S+)\s',line)
        estimatedSize = look.group(1)
        p.poll()
        estimatedSectors = str(2.1 * float(estimatedSize))
 
        print 'estimatedSize: ' + estimatedSize \
            + ', estimatedSectors: ' + estimatedSectors

        # Format the disk image before using it 
        os.system('hdiutil create -ov ' + self.image \
                      + ' -srcfolder ' + self.sourceDir)
        return self.image


class PackageMaker:
    """A class to generate packages for Mac OS X.

    This is intended to create OS X packages (with extension .pkg)
    containing archives of arbitrary files that the Installer.app 
    (Apple's OS X installer) will be able to handle.

    As of now, PackageMaker instances need to be created with the 
    title, version and description of the package to be built. 
    
    The package is built after calling the instance method 
    build(root, resources, **options). The generated package is 
    a folder hierarchy with the top-level folder name equal to the 
    constructor's title argument plus a '.pkg' extension. This final
    package is stored in the current folder.
    
    The sources from the root folder will be stored in the package
    as a compressed archive, while all files and folders from the
    resources folder will be added to the package as they are.

    Example:
    
    With /my/space being the current directory, the following will
    create /my/space/distutils-1.0.2.pkg/:

      PM = PackageMaker
      pm = PM("distutils-1.0.2", "1.0.2", "Python distutils.")
      pm.build("/my/space/sources/distutils-1.0.2")
      
    After a package is built you can still add further individual
    resource files or folders to its Contents/Resources subfolder
    by using the addResource(path) method: 

      pm.addResource("/my/space/metainfo/distutils/")
    """

    packageInfoDefaults = {
        'Title': None,
        'Version': None,
        'Description': '',
        'DefaultLocation': '/',
        'Diskname': '(null)',
        'DeleteWarning': '',
        'NeedsAuthorization': 'NO',
        'DisableStop': 'NO',
        'UseUserMask': 'YES',
        'Application': 'NO',
        'Relocatable': 'YES',
        'Required': 'NO',
        'InstallOnly': 'NO',
        'RequiresReboot': 'NO',
        'InstallFat': 'NO'}


    def __init__(self, project, version, installTop):
        "Init. with mandatory title/version/description arguments."

        info = {"Title": os.path.basename(project.name) + "-" + version, 
                "Version": version, 
                "Description": project.description }
        self.packageInfo = copy.deepcopy(self.packageInfoDefaults)
        self.packageInfo.update(info)
        self.sourceFolder = installTop
        self.packageName = info["Title"]

        # variables set later
        self.packageRootFolder = None
        self.packageResourceFolder = None
        self.resourceFolder = None


    def _escapeBlanks(self, s):
        "Return a string with escaped blanks."
        
        return s.replace(' ', '\ ')
                

    def build(self, resources=None, options = {}):
        """Create a package for some given root folder.

        With no 'resources' argument set it is assumed to be the same 
        as the root directory. Option items replace the default ones 
        in the package info.
        """

        # set folder attributes
        if resources == None:
            self.resourceFolder = None
        else:
            self.resourceFolder = resources

        # replace default option settings with user ones if provided
        fields = self. packageInfoDefaults.keys()
        for k, v in options.items():
            if k in fields:
                self.packageInfo[k] = v
            elif not k in ["OutputDir"]:
                raise Error, "Unknown package option: %s" % k
        
        # Check where we should leave the output. Default is current directory
        outputdir = options.get("OutputDir", os.getcwd())
        self.packageRootFolder = os.path.join(outputdir, self.packageName + ".pkg")
 
        # do what needs to be done
        self._makeFolders()
        self._addInfo()
        self._addBom()
        self._addArchive()
        self._addPkgInfo()
        self._addResources()
        self._addSizes()


    def addResource(self, path):
        "Add arbitrary file or folder to the package resource folder."
        
        # Folder basenames become subfolders of Contents/Resources.
        # This method is made public for those who wknow what they do!
   
        prf = self.packageResourceFolder
        if isfile(path) and not isdir(path):
            shutil.copy(path, prf)
        elif isdir(path):
            path = self._escapeBlanks(path)
            prf = self._escapeBlanks(prf)
            os.system("cp -r %s %s" % (path, prf))
        

    def _makeFolders(self):
        "Create package folder structure."

        # Not sure if the package name should contain the version or not...
        # packageName = "%s-%s" % (self.packageInfo["Title"], 
        #                          self.packageInfo["Version"]) # ??

        self.packageContentFolder = join(self.packageRootFolder, "Contents")
        self.packageResourceFolder = join(self.packageContentFolder, 
                                          "Resources")
        if os.path.exists(self.packageRootFolder):
            shutil.rmtree(self.packageRootFolder, ignore_errors=True)
        os.mkdir(self.packageRootFolder)
        os.mkdir(self.packageContentFolder)
        os.mkdir(self.packageResourceFolder)


    def _addInfo(self):
        "Write .info file containing installing options."

        # Not sure if options in PKG_INFO_FIELDS are complete...

        info = ""
        for f in string.split(PKG_INFO_FIELDS, "\n"):
            info = info + "%s %%(%s)s\n" % (f, f)
        info = info % self.packageInfo
        path = join(self.packageContentFolder, 'Info.plist')
        f = open(path, "w")
        f.write('''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleGetInfoString</key>
	<string>1.0, buildpkg, Inc</string>
	<key>CFBundleIdentifier</key>
	<string>com.fortylines.application</string>
	<key>CFBundleName</key>
	<string>buildpkg</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>IFMajorVersion</key>
	<integer>1</integer>
	<key>IFMinorVersion</key>
	<integer>0</integer>
	<key>IFPkgFlagAllowBackRev</key>
	<true/>
<!--	
        <key>IFPkgFlagAuthorizationAction</key>
	<string>RootAuthorization</string>
-->
	<key>IFPkgFlagBackgroundAlignment</key>
	<string>left</string>
	<key>IFPkgFlagBackgroundScaling</key>
	<string>proportional</string>
	<key>IFPkgFlagDefaultLocation</key>
	<string>/usr/local</string>
	<key>IFPkgFlagFollowLinks</key>
	<true/>
	<key>IFPkgFlagInstallFat</key>
	<false/>
<!--
	<key>IFPkgFlagInstalledSize</key>
	<integer>375068</integer>
-->
	<key>IFPkgFlagIsRequired</key>
	<false/>
	<key>IFPkgFlagOverwritePermissions</key>
	<false/>
	<key>IFPkgFlagRelocatable</key>
	<true/>
	<key>IFPkgFlagRestartAction</key>
	<string>NoRestart</string>
	<key>IFPkgFlagRootVolumeOnly</key>
	<false/>
	<key>IFPkgFlagUpdateInstalledLanguages</key>
	<false/>
	<key>IFPkgFlagUseUserMask</key>
	<integer>0</integer>
	<key>IFPkgFormatVersion</key>
	<real>0.10000000000000001</real>
</dict>
</plist>
''')


    def _addBom(self):
        "Write .bom file containing 'Bill of Materials'."

        # Currently ignores if the 'mkbom' tool is not available.

        try:
            base = self.packageInfo["Title"] + ".bom"
            bomPath = join(self.packageResourceFolder, base)
            base = 'Archive.bom'
            bomPath = join(self.packageContentFolder, base)
            bomPath = self._escapeBlanks(bomPath)
            sourceFolder = self._escapeBlanks(self.sourceFolder)
            cmd = "mkbom %s %s" % (sourceFolder, bomPath)
            res = os.system(cmd)
        except:
            pass


    def _addArchive(self):
        "Write .pax.gz file, a compressed archive using pax/gzip."

        # Currently ignores if the 'pax' tool is not available.

        cwd = os.getcwd()

        # create archive
        os.chdir(self.sourceFolder)
        base = basename(self.packageInfo["Title"]) + ".pax"
        self.archPath = join(self.packageResourceFolder, base)
        base = 'Archive.pax'
        self.archPath = join(self.packageContentFolder, base)
        self.archPath = self._escapeBlanks(self.archPath)
        cmd = "pax -w -f %s %s" % (self.archPath, ".")
        res = os.system(cmd)
        
        # compress archive
        cmd = "gzip %s" % self.archPath
        res = os.system(cmd)
        os.chdir(cwd)

    def _addPkgInfo(self):
        filename = os.path.join(self.packageContentFolder,'PkgInfo')
        f = open(filename,'w')
        f.write('pmkrpkg1\n')
        f.close()


    def _addResources(self):
        "Add all files and folders inside a resources folder to the package."

        # This folder normally contains Welcome/ReadMe/License files, 
        # .lproj folders and scripts.

        if not self.resourceFolder:
            return

        files = glob.glob("%s/*" % self.resourceFolder)
        for f in files:
            self.addResource(f)
        

    def _addSizes(self):
        "Write .sizes file with info about number and size of files."

        # Not sure if this is correct, but 'installedSize' and 
        # 'zippedSize' are now in Bytes. Maybe blocks are needed? 
        # Well, Installer.app doesn't seem to care anyway, saying 
        # the installation needs 100+ MB...

        numFiles = 0
        installedSize = 0
        zippedSize = 0

        files = GlobDirectoryWalker(self.sourceFolder)
        for f in files:
            numFiles = numFiles + 1
            installedSize = installedSize + os.lstat(f)[6]

        try:
            zippedSize = os.stat(self.archPath+ ".gz")[6]
        except OSError: # ignore error 
            pass
        base = self.packageInfo["Title"] + ".sizes"
        f = open(join(self.packageResourceFolder, base), "w")
        format = "NumFiles %d\nInstalledSize %d\nCompressedSize %d\n"
        f.write(format % (numFiles, installedSize, zippedSize))


# Shortcut function interface

def buildPackage(project, version, installTop):
    "A shortcut function for building a package."
    
    pm = PackageMaker(project, version, installTop)
    pm.build()
    im = ImageMaker(project, version, pm.packageRootFolder)
    return im.build()



def buildPackageSpecification(project,packageName):
    '''Buils a package specification file named *packageSpec* 
    that describes how to find and install the binary package.
    The package specification is made out of *sourceSpec*. 
    '''
    packageSpec = os.path.splitext(packageName)[0] + '.dsx'
    package = open(packageSpec,'w')
    package.write('<?xml version="1.0" ?>\n')
    package.write(dws.xmlDbParser.tagDb + '\n')
    package.write('\t<' + dws.xmlDbParser.tagProject \
                      + ' name="' + project.name + '">\n')
    package.write('\t\t<' + dws.xmlDbParser.tagPackage \
                      + ' name="' + packageName + '">\n')
    package.write('\t\t\t<size>' + str(os.path.getsize(packageName)) \
                      + '</size>\n')        
    f = open(packageName,'rb')
    package.write('\t\t\t<md5>' + hashlib.md5(f.read()).hexdigest() \
                      + '</md5>\n')
    f.seek(0)
    package.write('\t\t\t<' + dws.xmlDbParser.tagSha1 + '>' \
                      + hashlib.sha1(f.read()).hexdigest() \
                      + '</' + dws.xmlDbParser.tagSha1 + '>\n')
    f.seek(0)
    package.write('\t\t\t<sha256>' + hashlib.sha256(f.read()).hexdigest() \
                      + '</sha256>\n')
    f.close()
    package.write('\t\t</' + dws.xmlDbParser.tagPackage + '>\n')
    package.write('\t</' + dws.xmlDbParser.tagProject + '>\n')
    package.write('</' + dws.xmlDbParser.tagDb + '>\n')
    package.close()


if __name__ == "__main__":
    from optparse import OptionParser

    parser = OptionParser(description=
'''builds an OSX package
    Usage: %s [options] <root> [<resources>]"
    with arguments:
           (mandatory) root:         the package root folder
           (optional)  resources:    the package resources folder
''')
    parser.add_option('-v', '--version', dest='version', action='store',
                      help='Set version of the package')
    parser.add_option('-s', '--spec', dest='spec', 
                      action='store', help='Set specification of the package')

    options, args = parser.parse_args()

    context = dws.Context()
    index = dws.IndexProjects(context,options.spec)
    handler = dws.Unserializer([ '.*' ])
    index.parse(handler)
    project = handler.projects[handler.projects.keys()[0]]

    buildPackageSpecification(project,
                              buildPackage(project,options.version,args[0]))
