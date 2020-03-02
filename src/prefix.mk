# Copyright (c) 2018, DjaoDjin inc.
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

# Prefix intended to be included at the top of a project Makefile
#
# Primary Author(s): Sebastien Mirolo <smirolo@fortylines.com>

.DEFAULT_GOAL 	:=	all

buildTop        ?= $(installTop)/build
etcDir          ?= $(installTop)/etc

# names of variables as expected by autoconf-like tools
PREFIX          := $(installTop)
SYSCONFDIR      := $(etcDir)
LOCALSTATEDIR   := $(PREFIX)/var
DATAROOTDIR     := $(PREFIX)/share

# Paths to "normalized" prerequisites
binBuildDir 	:= 	$(buildTop)/bin
includeBuildDir :=	$(buildTop)/include
etcBuildDir		:=	$(buildTop)/etc
libBuildDir		:=	$(buildTop)/lib
shareBuildDir	:=	$(buildTop)/share

# Paths to installed file, ready to be packaged
# These are defined here (and not in suffix.mk) because we do not always
# want to include suffix.mk to avoid overriding contrib/ specifics rules.
buildInstallDir	:= 	$(CURDIR)/install
buildUsrLocalDir:=	$(buildInstallDir)/usr/local


# We cannot initialize dbldpkg to $(binBuildDir)/dbldpkg,
# else the drop package cannot be built. See comments associated
# to searchPath() in dws.py
dbldpkg			:=	dbldpkg
ibtool          :=  /Developer/usr/bin/ibtool
installBins		:=	/usr/bin/install -s -p -m 755
installDynLibs	:=	/usr/bin/install -p -m 755
installDirs 	:=	/usr/bin/install -d
installFiles	:=	/usr/bin/install -p -m 644
installScripts	:=	/usr/bin/install -p -m 755

FOP         :=	fop
JAR         :=	jar
JAVAC       :=	javac
LN_S        :=	/bin/ln -fs
MXMLC       :=	mxmlc
PYTHON      := $(binDir)/python
SED         :=	sed
SEMILLA     :=	semilla --themeDir $(themeDir)
XSLTPROC    :=	xsltproc -xinclude 		\
			--stringparam use.extensions 0 	\
			--stringparam fop1.extensions 1

# workspace make fragment and project index file
dwsmk		:=	dws.mk
projindex	:=	dws.xml

# realpath on an empty directory will return ''.
srcDir		?=	$(subst $(if $(realpath $(buildTop)),$(realpath $(buildTop)),$(buildTop))/,$(srcTop)/,$(realpath $(CURDIR)))
objDir		:=	$(subst $(srcTop),$(buildTop),$(srcDir))
logDir		:=	$(subst $(srcTop),$(siteTop)/log,$(srcDir))

resourcesDir	?=	$(siteTop)/htdocs/resources

incSearchPath	:=	$(srcDir)/include $(includeBuildDir) $(includeDir)
libSearchPath	:=	$(objDir) $(if $(wildcard $(libBuildDir)/*),$(libBuildDir)) $(if $(wildcard $(libDir)/*),$(libDir))

# Building dynamic libraries
# If we do not set the default *dylSuffix*, the rule %$(dylSuffix): in suffix.mk
# will be triggered by accident.
ifneq ($(filter Darwin,$(distHost)),)

dylSuffix		:=	.dylib
SHAREDLIBFLAGS  := -dynamiclib

else

dylSuffix		:=	.so
SHAREDLIBFLAGS	= -pthread -shared -Wl,-soname,$@

endif

# NOTE: We used to add -g by default into CFLAGS and CXXFLAGS in order
# to make debugging a lot more convienient. Fedora packager (rpm) will
# report a "Requires:" on the debug symbols (which by default get packaged
# in a different .rpm file). As a result rpm will refuse to install our
# packaged project by itself.
CFLAGS		?= -Wall
CXXFLAGS	?= -Wall
# We need -fPIC to build shared libraries so we force it.
CFLAGS		+= -fPIC
CXXFLAGS	+= -fPIC
CPPFLAGS	+=	-MMD $(patsubst %,-I%,$(incSearchPath))
LDFLAGS		+=	$(patsubst %,-L%,$(libSearchPath))

# Configuration for distribution packages

distExtDarwin	:=	.dmg
distExtFedora	:=	$(shell uname -r | $(SED) -e 's/.*\(\.fc.*\)/\1/').rpm
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
# We use '=' and not ':=' here because the version might be defined
# later in the Makefile.
_binDistDarwin	=	$(project)-$(version)$(distExtDarwin)
_binDistUbuntu	=	$(project)_$(version)$(distExtUbuntu)
_binDistFedora	=	$(project)-$(version)$(distExtFedora)
binDist		=	$(_binDist$(distHost))


DOCBOOK_SCHEMA := $(shareBuildDir)/schemas/docbook.xsd
DOCBOOK_SCHEMA := $(shareBuildDir)/docbook-xsl/slides/schema/xsd/docbook.xsd

# stylesheets to produce .html and .fo markups out of docbook (.book) markups
htmlxsl		:=	$(shareBuildDir)/docbook-xsl/html/docbook.xsl
foxsl		:=	$(shareBuildDir)/docbook-xsl/fo/docbook.xsl
manxsl		:=	$(shareBuildDir)/docbook-xsl/manpages/docbook.xsl
graphicSuffix	:=	png
#graphicSuffix	:=	svg

# extract dependencies to build a .pdf article out of xinclude statements 
# in the docbook source.
bookdeps	=	$(1) $(shell grep 'include xlink:href' $(1) \
				| sed -e 's/.*href="\(.*\)".*/\1/')

nonZeroExit	   =	@echo "$(1)" && (($(1) \
	|| echo "$@:$$?:error: functional test expected zero exit code") 2>&1) $(testOutputFilter)
unexpectedZeroExit =	@echo "$(1)" && (($(1) \
	&& echo "$@:$$?:error: functional test expected non-zero exit code") 2>&1) $(testOutputFilter) 

# Favor static libraries over dynamic ones. This matches *findLib* in dws.py
# If we leave the default, dynamic before static, since make search for 
# -llibname in vpath, VPATH and /lib, /usr/lib, and prefix/lib, it will always
# find the dynamic one instead of the one we linked in *libBuildDir*.
.LIBPATTERNS	:=	lib%.a lib%.so

vpath %.a 		$(libSearchPath)
vpath %.so		$(libSearchPath)
vpath %.h       $(incSearchPath) $(srcDir)
vpath %.hh      $(incSearchPath) $(srcDir)
vpath %.cc 		$(srcDir)/src
vpath %.cpp 	$(srcDir)/src
vpath %.py		$(srcDir)/src
vpath %.sh		$(srcDir)/src
vpath %.c 		$(srcDir)/src
vpath %.m 		$(srcDir)/src
vpath %.book 	$(srcDir)/doc
vpath %.mxml 	$(srcDir)/src
vpath %Makefile $(srcDir)

define bldUnitTest

$(1): $(1).cc $(testDepencencies)

endef

# List of files to be published on the website
# --------------------------------------------
htmlSite	:=	\
			$(patsubst $(srcDir)/%.h,%.html,              \
				$(wildcard $(srcDir)/include/*.h))        \
			$(patsubst $(srcDir)/%.hh,%.html,             \
				$(wildcard $(srcDir)/include/*.hh))       \
			$(patsubst $(srcDir)/%.tcc,%.html,            \
				$(wildcard $(srcDir)/include/*.tcc))      \
			$(patsubst $(srcDir)/%.cc,%.html,             \
				$(wildcard $(srcDir)/src/*.cc             \
					   $(srcDir)/test/src/*.cc))          \
			$(patsubst $(srcDir)/%Makefile,%Makefile.html,\
				$(wildcard $(srcDir)/Makefile             \
					   $(srcDir)/test/src/Makefile))      \
			$(patsubst $(srcDir)/%.book,%.html,           \
				$(wildcard $(srcDir)/doc/*.book))


# List of files to be installed
# -----------------------------
bins	:=
scripts :=
libs	:=
includes:=	$(wildcard $(srcDir)/include/*.h $(srcDir)/include/*.hh \
	          	   $(srcDir)/include/*.tcc)
