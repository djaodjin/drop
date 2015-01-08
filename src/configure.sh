#!/bin/bash
#
# Copyright (c) 2015, DjaoDjin inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


# This shell script provides the illusion of an autoconf-like configuration
# while using the workspace manangement tool (dws) instead.

set -e

projmk=dws.mk
prefix=/usr/local
sysconfdir=/etc
while [ $# -gt 0 ] ; do
    case $1 in
	--prefix=*)
	prefix=${1#--prefix=}
	shift
	;;
	--sysconfdir=*)
	sysconfdir=${1#--sysconfdir=}
	shift
	;;
	--libdir=*)
	libDir=${1#--libdir=}
	shift
	;;
	*)
	    echo "warning: $1 is an unknown option."
	    shift
    esac
done

buildDir=`pwd`
buildTop=`dirname $buildDir`
srcDir=`echo $0 | sed -e 's,\(.*\)/.*$,\\1,'`
srcDir=`cd $srcDir ; pwd`
srcTop=`dirname $srcDir`
binBuildDir=${buildDir}/bin

if [ -z "$libDir" ] ; then
	libDir=${prefix}/lib
fi

echo buildTop=${buildTop} > ${projmk}
echo srcTop=${srcTop} >> ${projmk}
echo siteTop=${srcDir} >> ${projmk}
echo binBuildDir=${binBuildDir} >> ${projmk}
echo libBuildDir=${buildDir}/lib >> ${projmk}
echo installTop=${prefix} >> ${projmk}
echo binDir=${prefix}/bin >> ${projmk}
echo etcDir=${sysconfdir} >> ${projmk}
echo includeDir=${prefix}/include >> ${projmk}
echo libDir=${libDir} >> ${projmk}
echo shareDir=${prefix}/share >> ${projmk}

# Copy dws files into binDir and ${buildTop}/share/dws because that's where they
#  will be searched for when drop is specified as a prerequisite 
# for the project.
mkdir -p ${binBuildDir}
cp ${srcDir}/dws ${binBuildDir}
helpers=`ls -l ${srcDir}/share/dws/*.{mk,sh} 2>/dev/null | wc -l`
if [ ${helpers} -gt 0 ] ; then
	mkdir -p ${buildTop}/share/dws
    cp -r ${srcDir}/share/dws/*.{mk,sh} ${buildTop}/share/dws
fi
${binBuildDir}/dws --default configure

sed -e s",\$(shell dws context),${projmk}," \
    -e s',$(shell dws context \(.*\)),$(buildTop)/share/dws/\1,' \
	Makefile.in > Makefile
echo "type 'make' to build, followed by 'make install' to install."

