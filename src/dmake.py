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

# This scripts implements building the workspace
#
# dws for managing (installing, updating, etc.) source and tools used
# during the build process.
# dmake executes the build - Makefile, distributed batchs.

import dcontext, os, sys

# Issue make command and log output
def makeProject(name,targets):
    sys.stdout.write('<book id="' + name + '">\n')
    makefile = context.srcDir(name) \
        + os.sep + 'Makefile'
    objDir = context.objDir(name)
    if objDir != os.getcwd():
        if not os.path.exists(objDir):
            os.makedirs(objDir)
        os.chdir(objDir)
    cmdline = 'make -f ' + makefile + ' ' + ' '.join(targets)
    print cmdline
    retCode = os.system(cmdline)
    sys.stdout.write('</book>\n')
    if retCode > 0:
        raise Exception('error: Make returns ' + str(retCode))
    return retCode


# Main Entry Point
if __name__ == '__main__':
    recurse = 'recurse' in sys.argv
    if 'recurse' in sys.argv:
        sys.argv.remove('recurse')

    # Find the build information
    context = dcontext.DropContext()

    # Find build information
    print '<build>'
    try:
        repositories = context.repositories(recurse)
        print repositories
        last = repositories.pop()
        # Recurse through projects that need to be rebuilt first 
        for repository in repositories:
            makeProject(repository,['install'])

        # Make current project
        if not recurse or len(sys.argv[1:]) > 0:
            makeProject(last,sys.argv[1:])
        print '</build>'

    except Exception, e:
        print e
        print '</build>'
