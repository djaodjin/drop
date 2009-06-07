#!/usr/bin/env python
#
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
