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
#     * Neither the name of codespin nor the
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

# -*- Makefile -*-

installBinDir		?=	$(binDir)
installIncludeDir	?=	$(includeDir)
installLibDir		?=	$(libDir)

.PHONY:	all install

all::	$(bins) $(libs) $(includes)

clean::
	rm -rf *

install:: $(bins) $(libs) $(includes)
	$(if $(bins),$(installDirs) $(installBinDir))
	$(if $(bins),$(installExecs) $(bins) $(installBinDir))
	$(if $(libs),$(installDirs) $(installLibDir))
	$(if $(libs),$(installFiles) $(libs) $(installLibDir))
	$(if $(includes),$(installDirs) $(installIncludeDir))
	$(if $(includes),$(installFiles) $(includes) $(installIncludeDir))

%.a:
	$(AR) $(ARFLAGS) $@ $^

%: %.cc
	$(LINK.cc) $(filter-out %.hh %.hpp %.ipp %.tcc,$^) $(LOADLIBES) $(LDLIBS) -o $@

%: %.py
	$(installFiles)	$< $@


# Builds packages for distribution
#
# The source package will be made of the current source tree
# so a shell script to distribute a specific tag would actually
# look like:
# 	git checkout -b branchname tag
#	make dist

project		:=	$(notdir $(srcDir))
version		:=	0.1
description	:=  'web-based source code browser'
buildInstallDir	:= $(CURDIR)/install
packageDir	:=	${project}.pkg

# \todo insert the prefix.mk, suffix.mk. Maybe the dcontext as well.
dist:
	tar -cj --exclude '.*' --exclude '*~' -f $(project).tar.bz2 \
		-C $(dir $(srcDir)) $(project)

# This rule is used to create a OSX distribution package
# \todo It certainly should move to an *host* specific part of the Makefiles
package: all
	${MAKE} -f $(srcDir)/Makefile install     \
		installBinDir=${buildInstallDir}/bin         \
		installIncludeDir=${buildInstallDir}/include \
		installLibDir=${buildInstallDir}/lib
	buildpkg --Title ${project} --Version ${version} --Description ${description} ${buildInstallDir}

-include *.d
