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
#     * Neither the name of fortylines nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
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

.DEFAULT_GOAL 	:=	all

# Paths to "normalized" prerequisites
binBuildDir 	:= 	$(buildTop)/bin
includeBuildDir :=	$(buildTop)/include
libBuildDir	:=	$(buildTop)/lib
shareBuildDir	:=	$(buildTop)/share


# We cannot initialize buildpkg to $(binBuildDir)/buildpkg, 
# else the drop package cannot be built. See comments associated
# to searchPath() in dws.py
buildpkg	:=	buildpkg
ibtool          :=      /Developer/usr/bin/ibtool
installDirs 	:=	/usr/bin/install -d
installFiles	:=	/usr/bin/install -p -m 644
installExecs	:=	/usr/bin/install -p -m 755
FOP		:=	fop
LN_S		:=	/bin/ln -fs
SED		:=	sed
SEMILLA		:=	$(binBuildDir)/semilla
XSLTPROC	:=	xsltproc -xinclude 		\
			--stringparam use.extensions 0 	\
			--stringparam fop1.extensions 1

# workspace make fragment and project index file
dwsmk		:=	dws.mk
projindex	:=	dws.xml

# \note For some reason when a '\' is inserted in the following line in order
#       to keep a maximum of 80 characters per line, the sed command:
#           sed -e 's,$$(srcDir),$(srcDir),g'
#       complains about an extra '\n' character.
srcDir		?=	$(subst $(realpath $(buildTop))/,$(srcTop)/,$(realpath $(shell pwd)))
objDir		:=	$(subst $(srcTop),$(buildTop),$(srcDir))
logDir		:=	$(subst $(srcTop),$(siteTop)/log,$(srcDir))

resourcesDir	?=	$(siteTop)/resources

incSearchPath	:=	$(srcDir)/include $(includeBuildDir) $(includeDir)
libSearchPath	:=	$(libBuildDir) $(libDir)

CFLAGS		:=	-g -MMD -Wall
CXXFLAGS	:=	-g -MMD -Wall
CPPFLAGS	+=	$(patsubst %,-I%,$(incSearchPath))
LDFLAGS		+=	$(patsubst %,-L%,$(libSearchPath))

# Configuration for distribution packages

distExtDarwin	:=	.dmg
distExtFedora	:=	$(shell uname -r | sed -e 's/.*\(\.fc.*\)/\1/').rpm
distExtUbuntu	:=	_i386.deb
project		:=	$(notdir $(srcDir))

# ATTENTION: We use ifeq ... endif here instead of ?= because
# we want the version to be set as "immediate". ?= will defer
# the evaluation of the shell script, hence generating different 
# date/time. 
# http://www.gnu.org/software/make/manual/make.html, "Variable Assignment"
ifeq ($(version),)
version		:=	$(shell date +%Y-%m-%d-%H-%M-%S)
endif

ifeq ($(distHost),Ubuntu)
# cat /etc/lsb-release
ifneq ($(shell getconf LONG_BIT),32)
distExtUbuntu	:=	_amd64.deb
endif
endif

# Name of the binary distribution package
binDist		:=	$(project)-$(version)$(distExt$(distHost))

# stylesheets to produce .html and .fo markups out of docbook (.book) markups
htmlxsl		:=	$(shareBuildDir)/docbook-xsl/html/docbook.xsl
foxsl		:=	$(shareBuildDir)/docbook-xsl/fo/docbook.xsl
graphicSuffix	:=	png
#graphicSuffix	:=	svg

# extract dependencies to build a .pdf article out of xinclude statements 
# in the docbook source.
bookdeps	=	$(1) $(shell grep 'include xlink:href' $(1) \
				| sed -e 's/.*href="\(.*\)".*/\1/')

nonZeroExit	   =	@echo "$(1)" && ($(1) \
	|| echo "$@:$$?:error: functional test expected zero exit code")
unexpectedZeroExit =	@echo "$(1)" && ($(1) \
	&& echo "$@:$$?:error: functional test expected non-zero exit code")


vpath %.a 	$(libSearchPath)
vpath %.so	$(libSearchPath)
vpath %.hh      $(incSearchPath)
vpath %.cc 	$(srcDir)/src
vpath %.py	$(srcDir)/src
vpath %.sh	$(srcDir)/src
vpath %.c 	$(srcDir)/src
vpath %.m 	$(srcDir)/src
vpath %.book 	$(srcDir)/doc

define bldUnitTest

$(1): $(1).cc $(testDepencencies)

endef

# List of files to be published on the website
# --------------------------------------------
htmlSite	:=	$(patsubst $(srcDir)/%.hh,%.html,                 \
				$(wildcard $(srcDir)/include/*.hh))       \
			$(patsubst $(srcDir)/%.tcc,%.html,                \
				$(wildcard $(srcDir)/include/*.tcc))      \
			$(patsubst $(srcDir)/%.cc,%.html,                 \
				$(wildcard $(srcDir)/src/*.cc             \
					   $(srcDir)/test/src/*.cc))      \
			$(patsubst $(srcDir)/%Makefile,%Makefile.html,    \
				$(wildcard $(srcDir)/Makefile             \
					   $(srcDir)/test/src/Makefile))  \
			$(patsubst $(srcDir)/%.book,%.html,               \
				$(wildcard $(srcDir)/doc/*.book))

# The rules to produce HTML are relative to the project top directory (srcDir)
# so we need to set the search path accordingly.
vpath %.hh      $(srcDir)
vpath %.cc 	$(srcDir)
vpath %.py	$(srcDir)
vpath %.book 	$(srcDir)
vpath %Makefile $(srcDir)


# List of files to be installed
# -----------------------------
bins	:=
libs	:=
includes:=	$(wildcard $(srcDir)/include/*.hh \
	          	   $(srcDir)/include/*.tcc)
