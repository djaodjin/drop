#!/bin/sh

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

echo buildTop=${buildTop} > ws.mk
echo srcTop=${srcTop} >> ws.mk
echo cacheTop=${buildDir}/cache >> ws.mk
echo binDir=${buildDir}/bin >> ws.mk
echo etcDir=${buildDir}/etc >> ws.mk
echo libDir=${buildDir}/lib >> ws.mk
echo includeDir=${buildDir}/include >> ws.mk
echo installBinDir=${prefix}/bin >> ws.mk
echo installEtcDir=${prefix}/etc >> ws.mk
echo installIncludeDir=${prefix}/include >> ws.mk
echo installLibDir=${prefix}/lib >> ws.mk
#echo srcDir=$srcDir >> ws.mk

${srcDir}/dws --default configure

sed -e s',$(shell dws context),ws.mk,' \
    -e s',$(shell dws context \(.*\)),$(etcDir)/\1,' \
	Makefile.in > Makefile
echo "type 'make' to build, followed by 'make install' to install."

