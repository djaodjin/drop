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

ibtool          :=      /Developer/usr/bin/ibtool
installDirs 	:=	/usr/bin/install -d
installFiles	:=	/usr/bin/install -p -m 644
installExecs	:=	/usr/bin/install -p -m 755
FOP		:=	fop
SED		:=	sed
XSLTPROC	:=	xsltproc -xinclude 		\
			--stringparam use.extensions 0 	\
			--stringparam fop1.extensions 1

# \note For some reason when a '\' is inserted in the following line in order
#       to keep a maximum of 80 characters per line, the sed command 
#       in contributors/smirolo/Makefile complains about an extra 
#       '\n' character.
srcDir		?=	$(subst $(realpath $(buildTop))/,$(srcTop)/,$(realpath $(shell pwd)))

CFLAGS		:=	-g -MMD
CXXFLAGS	:=	-g -MMD
CPPFLAGS	+=	-I$(srcDir)/include -I$(includeDir)
LDFLAGS		+=	-L$(libDir)

# Configuration for distribution packages

distExtDarwin	:=	.dmg
distExtFedora	:=	$(shell uname -r | sed -e 's/.*\(\.fc.*\)/\1/').rpm
distExtUbuntu	:=	_i386.deb
project		:=	$(notdir $(srcDir))
version		?=	$(shell date +%Y-%m-%d-%H-%M-%S)

ifeq ($(distHost),Ubuntu)
# cat /etc/lsb-release
ifneq ($(shell getconf LONG_BIT),32)
distExtUbuntu	:=	_amd64.deb
endif
endif

# stylesheets to produce .html and .fo markups out of docbook (.book) markups
htmlxsl		:=	$(shareDir)/docbook-xsl/html/docbook.xsl
foxsl		:=	$(shareDir)/docbook-xsl/fo/docbook.xsl

# extract dependencies to build a .pdf article out of xinclude statements 
# in the docbook source.
bookdeps	=	$(1) $(shell grep 'include xlink:href' $(1) \
				| sed -e 's/.*href="\(.*\)".*/\1/')

nonZeroExit	   =	echo "$@:$$?: error: non-zero exit code"
unexpectedZeroExit =	echo "$@:$$?: error: expected non-zero exit code"


vpath %.a 	$(libDir)
vpath %.so	$(libDir)
vpath %.cc 	$(srcDir)/src
vpath %.py	$(srcDir)/src
vpath %.c 	$(srcDir)/src
vpath %.m 	$(srcDir)/src
vpath %.book 	$(srcDir)/doc

define bldUnitTest

$(1): $(1).cc $(testDepencencies)

endef

# List of files to be installed
# -----------------------------
bins	:=
libs	:=
includes:=	$(wildcard $(srcDir)/include/*.hh \
	          	   $(srcDir)/include/*.tcc)
