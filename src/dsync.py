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

# Synchronize two list of folders. It first guesses the most recent copy
# and uses rsync to do the work. The use of the '--delete' rsync flag makes
# it very important to predetermine the most recent copy.

import datetime, re, os, sys 
import dws

def findMostRecent(dirname):
    '''Returns the filename and timestamp for the most recent file in the hierarchy
    rooted in dirname.'''
    mostRecentFilename = None
    mostRecentTimestamp = None
    if os.path.isdir(dirname):
        for filename in os.listdir(dirname):
            pathname = os.path.join(dirname,filename)
            if os.path.isdir(pathname):
                recentFilename, recentTimestamp = findMostRecent(pathname)
            else:
                recentFilename = pathname
                os.stat_float_times(True)
                recentTimestamp = os.stat(pathname).st_mtime
            if not mostRecentTimestamp or recentTimestamp > mostRecentTimestamp:
                mostRecentFilename = recentFilename
                mostRecentTimestamp = recentTimestamp
    return mostRecentFilename, mostRecentTimestamp 


def findMostRecentFile(paths):
    '''Returns the filename and timestamp for the most recent file in the hierarchy
    rooted in the list of *paths*.'''
    mostRecentFilename = None
    mostRecentTimestamp = None
    for path in paths:
        recentFilename, recentTimestamp = findMostRecent(path)
        if not mostRecentTimestamp or recentTimestamp > mostRecentTimestamp:
            mostRecentFilename = recentFilename
            mostRecentTimestamp = recentTimestamp
    return mostRecentFilename, mostRecentTimestamp 
       

if __name__ == '__main__':

    if 'test' in sys.argv:
        replicateTops = [ 'a', 'b' ]
        firstReplicatePath = os.path.join(os.getcwd(),'first')
        secondReplicatePath = os.path.join(os.getcwd(),'second')
    else:
        replicateTops = [ 'Library/Application\ Support/Firefox/Profiles/bookmarks.html',
                          'Library/Application\ Support/AddressBook',
                          'workspace/codeSpin',
                          'workspace/machines' ]
        firstReplicatePath = '/Users/smirolo'
        secondReplicatePath = '/Volumes/DIESEL'

    firstReplicateTops = []
    secondReplicateTops = []
    for r in replicateTops:
        firstReplicateTops += [ os.path.join(firstReplicatePath,'.',r) ]
        secondReplicateTops += [ os.path.join(secondReplicatePath,'.',r) ]        
    firstRecentFilename, firstRecentTimestamp = findMostRecentFile(firstReplicateTops)
    secondRecentFilename, secondRecentTimestamp = findMostRecentFile(secondReplicateTops)

    firstSyncTimestamp = None
    firstSyncFilename = os.path.join(firstReplicatePath,'.dsync') 
    if os.path.exists(firstSyncFilename):
        firstSyncTimestamp = os.stat(firstSyncFilename).st_mtime
    secondSyncTimestamp = None
    secondSyncFilename = os.path.join(secondReplicatePath,'.dsync') 
    if os.path.exists(secondSyncFilename):
        secondSyncTimestamp = os.stat(secondSyncFilename).st_mtime

    if firstRecentTimestamp: 
        sys.stdout.write('recent: first: ' + str(datetime.datetime.fromtimestamp(firstRecentTimestamp)))
    else:
        sys.stdout.write('recent: first: ' + str(firstRecentTimestamp))
    if secondRecentTimestamp:
        sys.stdout.write(', second: ' + str(datetime.datetime.fromtimestamp(secondRecentTimestamp)))
    else:
        sys.stdout.write(', second: ' + str(secondRecentTimestamp))
    sys.stdout.write('\n')
    if firstSyncTimestamp: 
        sys.stdout.write('sync: first: ' + str(datetime.datetime.fromtimestamp(firstSyncTimestamp)))
    else:
        sys.stdout.write('sync: first: ' + str(firstSyncTimestamp))
    if secondSyncTimestamp:
        sys.stdout.write(', second: ' + str(datetime.datetime.fromtimestamp(secondSyncTimestamp)))
    else:
        sys.stdout.write(', second: ' + str(secondSyncTimestamp))
    sys.stdout.write('\n')

    firstIsMoreRecentThanSync = False
    secondIsMoreRecentThanSync = False
    if firstRecentTimestamp:
        if secondSyncTimestamp:
            firstIsMoreRecentThanSync = (firstRecentTimestamp > secondSyncTimestamp)
        if secondRecentTimestamp:
            if firstSyncTimestamp:
                secondIsMoreRecentThanSync = (secondRecentTimestamp > firstSyncTimestamp)
            if firstRecentTimestamp > secondRecentTimestamp:
                replicateTops = firstReplicateTops
                replicatePath = secondReplicatePath
            else:
                replicateTops = secondReplicateTops
                replicatePath = firstReplicatePath
        else:
            replicateTops = firstReplicateTops
            replicatePath = secondReplicatePath            
    else:
        if secondRecentTimestamp:
            replicateTops = secondReplicateTops
            replicatePath = firstReplicatePath
        else:
            sys.stderr.write('error: cannot retrieve most recent timestamps out of [' \
                                 + ', '.join(replicateTops) + ']\n')
            sys.exit(1)

    if (firstSyncTimestamp and secondSyncTimestamp
        and firstIsMoreRecentThanSync and secondIsMoreRecentThanSync):
        sys.stdout.write('error: Both sides have been modified after the sync. Need manual sync.\n')
        sys.exit(1)

    sys.stdout.write('sync to ' + replicatePath + '\n\n')
        
    # Description of rsync flags used in the command (taken out of the man pages).
    #
    # -r recursive, -t preserve time. We do not use -a as the permissions, group
    # and owner cannot be preserved when copying
    # to a usb drive formatted as FAT. Also --modify-window=1 needs to be added
    # when copying from HFS to FAT or else everything is copied all over again.
    #
    # -a, --archive
    #   The  files  are  transferred in "archive" mode, which ensures that sym-
    #   bolic links, devices, attributes,  permissions,  ownerships,  etc.  are
    #   preserved  in  the transfer. (same as -rlptgoD)
    # -n, --dry-run
    #   Show what would have been transferred
    # -v, --verbose
    #   Increase verbosity
    # --delete                
    #   Delete extraneous files from dest dirs
    # --exclude=PATTERN
    #   Exclude files matching PATTERN
    rsyncArgs = "-rvtuRh --modify-window=1 --delete --exclude=build/ --exclude='*~' " \
                + ' '.join(replicateTops) \
                + ' ' + replicatePath
    dws.shellCommand("rsync -n " + rsyncArgs)
    answer = 'Yes'
    if not '--force' in sys.argv:
        answer = raw_input("Should we proceed with the sync[(Y)es/(N)o] ?")
    if answer.capitalize().startswith('Y'):
        dws.shellCommand("rsync " + rsyncArgs)
        dws.shellCommand("touch " + os.path.join(firstReplicatePath,'.dsync') \
                              + " " + os.path.join(secondReplicatePath,'.dsync'))
        
