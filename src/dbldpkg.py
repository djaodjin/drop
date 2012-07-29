#!/usr/bin/env python
#
# Copyright (c) 2009-2012, Fortylines LLC
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

# This script contains code to build Fedora, OSX and Ubuntu packages.
#
# Primary Author(s): Sebastien Mirolo <smirolo@fortylines.com>
#
# The OSX code has been derived from code released under the FreeBSD license
# and originally written by
#
# Dinu C. Gherman,
# gherman@europemail.com
# September 2002

__version__ = None
__license__ = "FreeBSD"


import re, os, subprocess, sys, glob, fnmatch, shutil, string, copy, getopt
from os.path import basename, dirname, join, islink, isdir, isfile
import datetime, hashlib, shutil
import cStringIO
import datetime, time
from email import utils

SRC_DIR = None
noInstallDoc = False
noPathUpdate = False

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
                "Description": project.descr }
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
                raise dws.Error("Unknown package option: %s" % k)

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
	<string>1.0, dbldpkg, Inc</string>
	<key>CFBundleIdentifier</key>
	<string>com.fortylines.application</string>
	<key>CFBundleName</key>
	<string>dbldpkg</string>
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


def recursive_listdir(dirname):
    results = []
    for filename in os.listdir(dirname):
        if os.path.isdir(os.path.join(dirname, filename)):
            results += recursive_listdir(os.path.join(dirname, filename))
        else:
            results += [ os.path.join(dirname, filename) ]
        return results


def buildPackage(project, version, installTop):
    '''Writes out the necessary files such as specification, control, etc.
    then builds a binary distribution package based on the local system.

    This routine with returns the name of the package that was built.
    '''

    dist = dws.context.host()
    if dist == 'Darwin':
        pm = PackageMaker(project, version, installTop)
        pm.build()
        im = ImageMaker(project, version, pm.packageRootFolder)
        return im.build()

    elif dist == 'Fedora':
        tarball = project.name.replace(os.sep,'_') + '-' + version + '.tar.bz2'
        specname = project.name + '.spec'
        with open(specname, 'w') as specfile:
            specfile.write('Name: ' + project.name.replace(os.sep,'_') + '\n')
            specfile.write('Distribution: Fedora\n')
            specfile.write('Release: 0\n')
            specfile.write('Version: %s\n' % version)
            specfile.write('Summary: None\n')
            specfile.write('License: Unknown\n')
            specfile.write('Source: http://www.example.com/%s\n' % tarball)
            specfile.write('\n%description\n' + project.descr + '\n')
            specfile.write('Packager: ' + str(project.maintainer) + '\n')
            specfile.write('''
%prep
%setup -q

%build
%configure
make

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

''')
            sysconfdir = False
            datarootdir = False
            unitdir = False
            pythondir = True
            rpm_root = '/home/' + os.environ['LOGNAME'] + '/rpmbuild/BUILDROOT/' + tarball[:-8] + '-0.x86_64'
            if False:
                for filename in recursive_listdir(rpm_root):
                    print "!!! " + filename
                    filename = filename[len(rpm_root):]
                    if filename.startswith('etc'):
                        sysconfdir = True
                    elif filename.startswith('share'):
                        datarootdir = True
                    elif filename.startswith('usr/lib/systemd/system'):
                        unitdir = True
                    elif filename.startswith('lib64/python2.7/site-packages'):
                        pythondir = True

            specfile.write('%files\n')
            specfile.write('%{_prefix}/*\n')
            if sysconfdir:
                specfile.write('%{_sysconfdir}/*\n')
            if datarootdir:
                specfile.write('%{_datarootdir}/*\n')
            if unitdir:
                specfile.write('%{_unitdir}/*\n')
            if pythondir:
                specfile.write('/lib64/python2.7/site-packages/*\n')
            postinst = os.path.join('usr', 'share',
                                    project.name.replace(os.sep,'_'),
                                    'postinst')
            if os.path.exists(postinst):
                specfile.write('\n%%post -p sh /%s\n' % postinst)
        # '--clean'
        rpmlog = dws.shellCommand(['rpmbuild', '-bb', specname],
                                  pat='Wrote: (.*)')
        genFiles = []
        for line in rpmlog:
            look = re.match('Wrote: (.*)', line)
            if look:
                genFiles += [ look.group(1) ]
        return genFiles[0]

    elif dist == 'Ubuntu':
        cmd = subprocess.Popen("getconf LONG_BIT",shell=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
        longBit = cmd.stdout.readline().strip()
        cmd.wait()
        if cmd.returncode != 0:
            raise dws.Error("problem reading `getconf LONG_BIT`")
        packageVersion = version
        distExtUbuntu = '_all.deb'
        if not os.path.exists('debian'):
            os.makedirs('debian')
        control = open(os.path.join('debian','control'),'w')
        control.write('Source: ' + project.name + '\n')
        control.write('Maintainer: ' + str(project.maintainer) + '\n')
        # \todo Temporarly disable the Build-Depends because of "boost"
        #       prerequisites and how debuild makes packages.
        if None:
            if project.repository:
                control.write('Build-Depends: ' \
                                  + ', '.join(dws.basenames(
                project.repository.prerequisiteNames([dws.context.host()]))) + '\n')
            elif project.patch:
                control.write('Build-Depends: ' \
                                  + ', '.join(dws.basenames(
                project.patch.prerequisiteNames([dws.context.host()]))) + '\n')

        control.write('\nPackage: ' + project.name + '\n')
        control.write('Priority: extra\n')

        if (not dws.context.host() in project.packages
            or not 'architecture' in project.packages[dws.context.host()].configure.envvars):
            control.write('Architecture: any\n')
            distExtUbuntu = '_amd64.deb'
            if longBit == '32':
                distExtUbuntu = '_i386.deb'
        if dws.context.host() in project.packages:
            envvars = project.packages[dws.context.host()].configure.envvars
            for key, val in envvars.iteritems():
                if isinstance(val,dws.Metainfo):
                    control.write(key.capitalize() + ': ' + val.value + '\n')
            control.write('Depends: ${shlibs:Depends}, ' \
                              + ', '.join(dws.basenames(
            project.packages[dws.context.host()].prerequisiteNames([dws.context.host()]))) + '\n')        
        descr = ''
        for i in range(0,len(project.descr),77):
            descr += ' ' + project.descr[i:i+77] + '\n'
        #descr += ' ' + project.descr[i:] + '\n'
        control.write('Description: ' + str(project.title) \
                          + '\n' + str(descr) + '\n')
        control.write('\n')
        control.close()
        distribCodename = None
        if os.path.isfile('/etc/lsb-release'):
            release = open('/etc/lsb-release')
            line = release.readline()
            while line:
                look = re.match('DISTRIB_CODENAME=\s*(\S+)',line)
                if look:
                    distribCodename = look.group(1)
                    break
                line = release.readline()
            release.close()
        changelog = open(os.path.join('debian','changelog'),'w')
        changelog.write(project.name + ' (' + packageVersion + ') ' \
                            + str(distribCodename) + '; urgency=low\n\n')
        changelog.write('  * debian/rules: generate ubuntu package\n\n')
        changelog.write(' -- ' + str(project.maintainer) + '  ' \
           + utils.formatdate(time.mktime(datetime.datetime.now().timetuple()))\
           + '\n\n')
        changelog.close()
        # TODO getting rid of the warning actually produces a completely
        # different output. For some reasons /usr/bin, etc. do not make
        # it into the package...
        # write debian/compat to fix 'Compatibility level before ...'
        # messages, see 'man debhelper'.
        # '1' written previously
        with open(os.path.join('debian','compat'),'w') as compat:
            compat.write('5\n')

        if noInstallDoc:
            installDocTarget = ''
        else:
            installDocTarget = '\n\tmake install-doc'
        if noPathUpdate:
            path = ''
        else:
            path = 'PATH=' + dws.context.binBuildDir() + ':${PATH} '
        rules = open(os.path.join('debian','rules'),'w')
        rules.write('''#! /usr/bin/make -f

DH_VERBOSE := 1

%:
\tdh $@

''')
        rules.close()
        copyrightPath = None
        for name in [ 'COPYING', 'LICENSE' ]:
            if os.path.exists(name):
                # The function is executed from within the source tree
                # so we just need to copy the copyright file if it exists
                # from the currrent directory.
                copyrightPath = name
                break
        if copyrightPath:
            shutil.copy(copyrightPath, os.path.join('debian','copyright'))
        else:
            copyright = open(os.path.join('debian','copyright'),'w')
            copyright.write('Copyright ' + str(datetime.datetime.now().year) \
                                + str(project.maintainer))
            copyright.close()

        # We have generated all files debuild requires to create a binary
        # package so now let's invoke it.
        #
        # alternative:
        #   apt-get install pbuilder
        #   pbuilder create
        #   pdebuild --buildresult ..
        #
        # debuild will try to install the packages in /usr/local so it needs
        # permission access to the directory.
        # Remove sudo and use prefix on bootstrap.sh in boost/debian/rules
        #
        # Can only find example in man pages of debuild but cannot
        # find description of options: "-i -us -uc -b".
        dws.shellCommand(['debuild', '-i', '-us', '-uc', '-b'])
        return '../' + project.name + '_' + packageVersion + distExtUbuntu

    else:
        # unknown host, we don't know how to make a package for it.
        raise dws.Error("unknown distribution '" + dist + "'")

def tabStop(n):
    result = ''
    for i in range(0,n):
        result += '  '
    return result

def buildPackageSpecification(project,packageName):
    '''Buils a package specification file named *packageSpec*
    that describes how to find and install the binary package.
    The package specification is made out of *sourceSpec*.
    '''
    with open('.packagename','w') as packagename:
        packagename.write(packageName)
    packageSpec = os.path.splitext(packageName)[0] + '.dsx'
    package = open(packageSpec,'w')
    package.write('<?xml version="1.0" ?>\n')
    package.write('<' + dws.xmlDbParser.tagDb + '>\n')
    package.write(tabStop(1) + '<' + dws.xmlDbParser.tagProject \
                      + ' name="' + project.name + '">\n')
    package.write(tabStop(2) + '<' + dws.xmlDbParser.tagPackage + '>\n')
    package.write(tabStop(3) + '<' + dws.xmlDbParser.tagTag + '>' \
                      + dws.context.host() \
                      + '</' + dws.xmlDbParser.tagTag + '>\n')
    package.write(tabStop(3) + '<' + dws.xmlDbParser.tagFetch \
                      + ' name="' + packageName + '">\n')
    package.write(tabStop(4) + '<size>' + str(os.path.getsize(packageName)) \
                      + '</size>\n')
    f = open(packageName,'rb')
    package.write(tabStop(4) + '<md5>' + hashlib.md5(f.read()).hexdigest() \
                      + '</md5>\n')
    f.seek(0)
    package.write(tabStop(4) + '<' + dws.xmlDbParser.tagHash + '>' \
                      + hashlib.sha1(f.read()).hexdigest() \
                      + '</' + dws.xmlDbParser.tagHash + '>\n')
    f.seek(0)
    package.write(tabStop(4) + '<sha256>' + hashlib.sha256(f.read()).hexdigest() \
                      + '</sha256>\n')
    f.close()
    package.write(tabStop(3) + '</' + dws.xmlDbParser.tagFetch + '>\n')
    package.write(tabStop(2) + '</' + dws.xmlDbParser.tagPackage + '>\n')
    package.write(tabStop(1) + '</' + dws.xmlDbParser.tagProject + '>\n')
    package.write('</' + dws.xmlDbParser.tagDb + '>\n')
    package.close()


if __name__ == "__main__":
    import imp
    from optparse import OptionParser

    try:
        import dws
    except:
        dws = imp.load_source('dws',
                              os.path.join(os.path.dirname(\
                    os.path.realpath(sys.argv[0])),'dws'))
    parser = OptionParser(usage="%prog [options] <root> [<resources>]",
                          description=
'''builds a distribution package''',
                          epilog='''with arguments:
    root          the package root folder
    resources     the package resources folder
''',formatter=dws.CommandsFormatter())
    parser.add_option('-v', '--version', dest='version', action='store',
                      help='Set version of the package')
    parser.add_option('-s', '--spec', dest='spec',
                      action='store', help='Set specification of the package')
    parser.add_option('--help-book', dest='helpBook', action='store_true',
                      help='Print help in docbook format')
    parser.add_option('--no-install-doc', dest='noInstallDoc',
                      action='store_true',
                      help='Do not execute "make install-doc"')
    parser.add_option('--no-path-update', dest='noPathUpdate',
                      action='store_true',
                      help='Assumes all tools required by configure (dws, etc.) are already in PATH.')

    options, args = parser.parse_args()

    if options.helpBook:
        help = cStringIO.StringIO()
        parser.print_help(help)
        dws.helpBook(help)
        sys.exit(0)

    if options.noInstallDoc:
        noInstallDoc = True

    if options.noPathUpdate:
        noPathUpdate = True

    dws.context = dws.Context()
    dws.context.locate()
    index = dws.IndexProjects(dws.context,options.spec)
    handler = dws.Unserializer([ '.*' ])

    SRC_DIR = os.path.dirname(options.spec)

    index.parse(handler)
    project = handler.firstProject
    # Removes any leading directory name from the project name
    # else debuild is not very happy.
    project.name = os.path.basename(project.name)

    buildPackageSpecification(project,
                              buildPackage(project,options.version,args[0]))
