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

buildTop=`pwd`
srcTop=`echo $0 | sed -e 's,\(.*\)/.*$,\\1,'`
srcTop=`cd $srcTop ; pwd`

echo buildTop=${buildTop} > ws.mk
echo srcTop=$srcTop >> ws.mk
echo binDir=${buildTop}/bin >> ws.mk
echo etcDir=${buildTop}/etc >> ws.mk
echo libDir=${buildTop}/lib >> ws.mk
echo includeDir=${buildTop}/include >> ws.mk
echo installBinDir=${prefix}/bin >> ws.mk
echo installEtcDir=${prefix}/etc >> ws.mk
echo installIncludeDir=${prefix}/include >> ws.mk
echo installLibDir=${prefix}/lib >> ws.mk

${srcTop}/dws configure

sed -e s',$(shell dws context),ws.mk,' \
    -e s',$(shell dws context \(.+\)),$(srcTop)/\1,' \
	Makefile.in > Makefile
echo "type 'make' to build, followed by 'make install' to install."

