#!/usr/bin/env python

"""buildpkg.py -- Build OS X packages for Apple's Installer.app.

This is an experimental command-line tool for building packages to be
installed with the Mac OS X Installer.app application. 

Sebastien Mirolo, 
smirolo@hotmail.com
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
import hashlib, dws

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

    def __init__(self, name, sourceDir):
        self.name = name
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


    def __init__(self, title, version, desc):
        "Init. with mandatory title/version/description arguments."

        info = {"Title": title, "Version": version, "Description": desc}
        self.packageInfo = copy.deepcopy(self.packageInfoDefaults)
        self.packageInfo.update(info)
        
        # variables set later
        self.packageRootFolder = None
        self.packageResourceFolder = None
        self.sourceFolder = None
        self.resourceFolder = None


    def _escapeBlanks(self, s):
        "Return a string with escaped blanks."
        
        return s.replace(' ', '\ ')
                

    def build(self, root, resources=None, options = {}):
        """Create a package for some given root folder.

        With no 'resources' argument set it is assumed to be the same 
        as the root directory. Option items replace the default ones 
        in the package info.
        """

        # set folder attributes
        self.sourceFolder = root
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
        packageName = self.packageInfo["Title"]
        print packageName
        self.packageRootFolder = os.path.join(outputdir, packageName + ".pkg")
 
        # do what needs to be done
        self._makeFolders()
        self._addInfo()
        self._addBom()
        self._addArchive()
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

        contFolder = join(self.packageRootFolder, "Contents")
        self.packageResourceFolder = join(contFolder, "Resources")
        os.mkdir(self.packageRootFolder)
        os.mkdir(contFolder)
        os.mkdir(self.packageResourceFolder)


    def _addInfo(self):
        "Write .info file containing installing options."

        # Not sure if options in PKG_INFO_FIELDS are complete...

        info = ""
        for f in string.split(PKG_INFO_FIELDS, "\n"):
            info = info + "%s %%(%s)s\n" % (f, f)
        info = info % self.packageInfo
        base = self.packageInfo["Title"] + ".info"
        path = join(self.packageResourceFolder, base)
        f = open(path, "w")
        f.write(info)


    def _addBom(self):
        "Write .bom file containing 'Bill of Materials'."

        # Currently ignores if the 'mkbom' tool is not available.

        try:
            base = self.packageInfo["Title"] + ".bom"
            bomPath = join(self.packageResourceFolder, base)
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
        archPath = self._escapeBlanks(self.archPath)
        cmd = "pax -w -f %s %s" % (archPath, ".")
        res = os.system(cmd)
        
        # compress archive
        cmd = "gzip %s" % archPath
        res = os.system(cmd)
        os.chdir(cwd)


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

def buildPackage(args,options):
    "A shortcut function for building a package."
    
    o = options
    title, version, desc = o["Title"], o["Version"], o["Description"]
    pm = PackageMaker(title, version, desc)
    pm.build(args[0],options=options)
    im = ImageMaker(title, pm.packageRootFolder)
    return im.build()



def buildPackageSpecification(sourceSpec,packageName):
    '''Buils a package specification file named *packageSpec* 
    that describes how to find and install the binary package.
    The package specification is made out of *sourceSpec*. 
    '''
    packageSpec = os.path.splitext(packageName)[0] + '.dsx'
    parser = dws.xmlDbParser()
    source = open(sourceSpec,'r')
    package = open(packageSpec,'w')
    proj = parser.copy(package,source)
    while proj != None:
        parser.startProject(package,proj)
        package.write('<package>\n')
        package.write('<size>' + str(os.path.getsize(packageName)) \
                          + '</size>\n')        
        f = open(packageName,'rb')
        package.write('<md5>' + hashlib.md5(f.read()).hexdigest() \
                          + '</md5>\n')
        f.seek(0)
        package.write('<sha1>' + hashlib.sha1(f.read()).hexdigest() \
                          + '</sha1>\n')
        f.seek(0)
        package.write('<sha256>' + hashlib.sha256(f.read()).hexdigest() \
                          + '</sha256>\n')
        f.close()
        package.write('</package>\n')
        proj = parser.copy(package,source)
    parser.trailer(package)
    source.close()
    package.close()


if __name__ == "__main__":
    from optparse import OptionParser

    parser = OptionParser(description=
'''builds an OSX package
    Usage: %s <opts1> [<opts2>] <root> [<resources>]"
    with arguments:
           (mandatory) root:         the package root folder
           (optional)  resources:    the package resources folder
''')
    parser.add_option('-t', '--Title', dest='title', action='store',
                      help='Set title of the package')
    parser.add_option('-v', '--Version', dest='version', action='store',
                      help='Set version of the package')
    parser.add_option('-s', '--Specification', dest='specification', 
                      action='store', help='Set specification of the package')

    options, args = parser.parse_args()

    optsDict = {}
    optsDict['Title'] = options.title 
    optsDict['Version'] = options.version 
    optsDict['Description'] = 'unknow description'

    buildPackageSpecification(options.specification,
                              buildPackage(args,optsDict))
