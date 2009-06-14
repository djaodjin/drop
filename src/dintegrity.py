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

# topBackup == topSrc
# topReplicate == topBackup
#
# or
# topReplicate == topSrc
# topBackup == topReplicate
#
# backupPaths
#   archivePath
# replicatePaths
#   duplicatePath
# systemPaths



import dcontext, dstamp, re, os, sys

if __name__ == '__main__':
    try:
        context = dcontext.DropContext()

        logDir = context.environ['logDir']
        backupDir = context.environ['backupDir']
        backupTops = [ logDir, '/home', context.environ['topSrc'] ]
        replicatePath = context.environ['replicatePath']
        replicateTops = [ '/data' ]
        # This exclude list is taken out of executing 'ls /' right
        # after an Ubuntu 8.10 system has been installed on a machine.
        # '/initrd.img' and '/vmlinuz' are links
        excludes = [ '/cdrom', '/dev', '/lost+found',
                     '/media', '/mnt', '/proc', '/sys',
                     '/tmp' ] + replicateTops + backupTops
        exclFile = open('excludes-Ubuntu8.10')
        for e in excludes:
            exclFile.write(e + '\n')
        excl.close()

        # == 1. Take a fingerprint of the machine ==

        os.chdir(logDir)
        fingerPrintCmd = "mtree -c -K sha1digest "
        dcontext.shellCommand(fingerPrintCmd + " -p / " \
                                  + "-X excludes" \
                                  + " > system.mtree")
        dcontext.shellCommand(fingerPrintCmd + ' -p ' + ' -p '.join(replicateTops) \
                                  + " > replicate.mtree")

        exclFile = open('patterns')
        for e in [ 'build' ]:
            exclFile.write(e + '\n')
        excl.close()
        dcontext.shellCommand(fingerPrintCmd + ' -p ' + ' -p '.join(backupTops) \
                                  + "-X patterns " \
                                  + " > backup.mtree")

        # == 2. Create an archive out of each backupTop ==

        os.chdir(backupDir)
        for backupTop in backupTops:
            basename = os.path.basename(backupTop)
            archive = dstamp.stamp(basename)
            dcontext.shellCommand("tar --bzip2 -cf " + archive \
                              + " -C " + os.path.dirname(backupTop) \
                              + "--exclude build/" \
                              + " " + basename)
        dstamp.cleanUpAgedFiles(backupDir)
        
        # == 3. Replicate important paths onto remote server ==

        look = re.match('\S+@\S+:\S+',replicatePath)         
        if look != None:
            remote = "-e ssh "
        # Description of rsync flags used in the command (taken out of the man pages).
        #
        # -a, --archive
        #   The  files  are  transferred in "archive" mode, which ensures that sym-
        #   bolic links, devices, attributes,  permissions,  ownerships,  etc.  are
        #   preserved  in  the transfer. (same as -rlptgoD)
        # -z
        #   Compression will be used to the reduce the size of the transfer.
        # --delete                
        #   Delete extraneous files from dest dirs
        # --exclude=PATTERN
        #   Exclude files matching PATTERN
        #
        # Since transfering in archive mode will preserve mod-time, we do not
        # use -c (skip based on checksum, not mod-time & size) even when transfering
        # to another machine.
        dcontext.shellCommand("rsync -az --delete --exclude=build/ " \
                                  + ' '.join(replicateTops) \
                                  + replicatePath)

    except dcontext.Error, e:
        e.show(sys.stderr)
        sys.exit(e.code)
