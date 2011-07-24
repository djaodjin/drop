#!/bin/sh
#
# This shell scricpt provides the illusion of an autoconf-like configuration
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
	*)
	    echo "warning: $1 is an unknown option."
	    shift
    esac
done

buildDir=`pwd`
buildTop=`dirname $buildDir`
etcDir=${sysconfdir}
srcDir=`echo $0 | sed -e 's,\(.*\)/.*$,\\1,'`
srcDir=`cd $srcDir ; pwd`
srcTop=`dirname $srcDir`
binBuildDir=${buildDir}/bin

echo buildTop=${buildTop} > ${projmk}
echo srcTop=${srcTop} >> ${projmk}
echo siteTop=${srcDir} >> ${projmk}
echo binBuildDir=${binBuildDir} >> ${projmk}
echo libBuildDir=${buildDir}/lib >> ${projmk}
echo binDir=${prefix}/bin >> ${projmk}
echo etcDir=${etcDir} >> ${projmk}
echo includeDir=${prefix}/include >> ${projmk}
echo libDir=${prefix}/lib >> ${projmk}
echo shareDir=${prefix}/share >> ${projmk}

# Copy dws files into binDir and ${buildTop}/share/dws because that's where they
#  will be searched for when drop is specified as a prerequisite 
# for the project.
mkdir -p ${binBuildDir}
mkdir -p ${buildTop}/share/dws
cp ${srcDir}/dws ${binBuildDir}
helpers=`ls -l ${srcDir}/share/dws/*.{mk,sh} > /dev/null 2>&1 | wc -l`
if [ ${helpers} -gt 0 ] ; then
    cp -r ${srcDir}/share/dws/*.{mk,sh} ${buildTop}/share/dws
fi
${binBuildDir}/dws --default configure

sed -e s",\$(shell dws context),${projmk}," \
    -e s',$(shell dws context \(.*\)),$(buildTop)/share/dws/\1,' \
	Makefile.in > Makefile
echo "type 'make' to build, followed by 'make install' to install."

