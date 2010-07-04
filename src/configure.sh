#!/bin/sh
#
# This shell script provides the illusion of an autoconf-like configuration
# while using the workspace manangement tool (dws) instead. 

set -e

prefix=/usr/local
while [ $# -gt 0 ] ; do
	case $1 in
		--prefix=*)
		    prefix=${1#--prefix=}
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
etcBuildDir=${buildDir}/etc

echo buildTop=${buildTop} > ws.mk
echo srcTop=${srcTop} >> ws.mk
echo siteTop=${buildDir}/cache >> ws.mk
echo binBuildDir=${binBuildDir} >> ws.mk
echo etcBuildDir=${etcBuildDir} >> ws.mk
echo libBuildDir=${buildDir}/lib >> ws.mk
echo includeBuildDir=${buildDir}/include >> ws.mk
echo shareBuildDir=${buildDir}/share >> ws.mk
echo binDir=${prefix}/bin >> ws.mk
echo etcDir=${prefix}/etc >> ws.mk
echo includeDir=${prefix}/include >> ws.mk
echo libDir=${prefix}/lib >> ws.mk
echo shareDir=${prefix}/share >> ws.mk

# Copy dws files into binDir and etcDir because that's where they will 
# be searched when drop is specified as a prerequisite for the project.
mkdir -p ${binBuildDir}
mkdir -p ${etcBuildDir}/dws
cp ${srcDir}/dws ${binBuildDir}
cp -r ${srcDir}/etc/*.mk ${etcBuildDir}/dws
cp -r ${srcDir}/etc/*.sh ${etcBuildDir}/dws
${binBuildDir}/dws --default configure

sed -e s',$(shell dws context),ws.mk,' \
    -e s',$(shell dws context \(.*\)),$(etcDir)/\1,' \
	Makefile.in > Makefile
echo "type 'make' to build, followed by 'make install' to install."

