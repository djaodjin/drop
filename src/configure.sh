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
binDir=${buildDir}/bin
etcDir=${buildDir}/etc

echo buildTop=${buildTop} > ws.mk
echo srcTop=${srcTop} >> ws.mk
echo siteTop=${buildDir}/cache >> ws.mk
echo binDir=${binDir} >> ws.mk
echo etcDir=${buildDir}/etc >> ws.mk
echo libDir=${buildDir}/lib >> ws.mk
echo includeDir=${buildDir}/include >> ws.mk
echo installBinDir=${prefix}/bin >> ws.mk
echo installEtcDir=${prefix}/etc >> ws.mk
echo installIncludeDir=${prefix}/include >> ws.mk
echo installLibDir=${prefix}/lib >> ws.mk
echo installShareDir=${prefix}/share >> ws.mk

# Copy dws files into binDir and etcDir because that's where they will 
# be searched when drop is specified as a prerequisite for the project.
mkdir -p ${binDir}
mkdir -p ${etcDir}/dws
cp ${srcDir}/dws ${binDir}
cp -r ${srcDir}/etc/*.mk ${etcDir}/dws
cp -r ${srcDir}/etc/*.sh ${etcDir}/dws
${binDir}/dws --default configure

sed -e s',$(shell dws context),ws.mk,' \
    -e s',$(shell dws context \(.*\)),$(etcDir)/\1,' \
	Makefile.in > Makefile
echo "type 'make' to build, followed by 'make install' to install."

