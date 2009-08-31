# -*- Makefile -*-
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

installBinDir		?=	$(binDir)
installIncludeDir	?=	$(includeDir)
installLibDir		?=	$(libDir)
installLogDir		?=	$(logDir)

.PHONY:	all install check

all::	$(bins) $(libs) $(includes) $(logs)

clean::
	rm -rf install-stamp $(bins) $(libs) *.o *.d *.dSYM

install:: $(bins) $(libs) $(includes) $(logs)
	$(if $(bins),$(installDirs) $(installBinDir))
	$(if $(bins),$(installExecs) $(bins) $(installBinDir))
	$(if $(libs),$(installDirs) $(installLibDir))
	$(if $(libs),$(installFiles) $(libs) $(installLibDir))
	$(if $(includes),$(installDirs) $(installIncludeDir))
	$(if $(includes),$(installFiles) $(includes) $(installIncludeDir))
	$(if $(logs),$(installDirs) $(installLogDir))
	$(if $(logs),$(installFiles) $(logs) $(installLogDir))

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

hostdist	:=	$(shell dws host)
project		:=	$(notdir $(srcDir))
version		?=	$(shell date +%Y-%m-%d-%H-%M-%S)
buildInstallDir	:= 	$(CURDIR)/install/usr/local

dist: $(hostdist)-dist

Darwin-dist: $(project)-$(version).dmg

Fedora-dist: $(project)-$(version).rpm

Ubuntu-dist: $(project)-$(version).deb

dist-src: $(project)-$(version).tar.bz2

# 	git archive -b branchname tag
#	make dist
$(project)-$(version).tar.bz2:
	cp -rf $(srcDir) $(basename $(basename $@))
	mv $(basename $(basename $@))/Makefile \
		$(basename $(basename $@))/Makefile.in
	$(installExecs) $(shell dws context configure.sh) \
		$(basename $(basename $@))/configure
	$(installExecs) $(shell which dws) $(basename $(basename $@))
	$(installFiles) $(shell dws context prefix.mk) \
			$(shell dws context suffix.mk) \
		$(basename $(basename $@))
	tar -cj --exclude 'build' --exclude '.*' --exclude '*~' \
		-f $@ $(basename $(basename $@))

install-from-srctar:: $(project)-$(version).tar.bz2


# This rule is used to create a OSX distribution package
# \todo It certainly should move to an *host* specific part of the Makefiles
$(project)-$(version).dmg: $(project)-$(version).tar.bz2
	${MAKE} -f $(srcDir)/Makefile install-from-srctar    \
		installBinDir=${buildInstallDir}/bin         \
		installIncludeDir=${buildInstallDir}/include \
		installLibDir=${buildInstallDir}/lib
	buildpkg --version=${version} \
			 --spec=$(srcDir)/index.xml ${buildInstallDir}


vpath %.spec $(srcDir)/src
#vpath %.tar.bz2 $(srcDir)/src

%-$(version).rpm: %.spec \
		$(wildcard $(srcDir)/src/$(project)*.tar.bz2) \
		$(wildcard $(srcDir)/src/$(project)-*.patch)
	rpmdev-setuptree -d
	cp $(filter %.tar.bz2 %.patch,$^) $(HOME)/rpmbuild/SOURCES
	rpmbuild -bb --clean $<

%.spec: $(srcDir)/index.xml
	echo '%files' > $@ 
	echo $(bins) >> $@
	echo $(includes) >> $@
	echo $(libs) >> $@

vpath %.deb $(srcDir)/src

# alternative:
#   apt-get install pbuilder
#   pbuilder create
#   pdebuild --buildresult ..
#
# debuild will try to install the packages in /usr/local so it needs
# permission access to the directory.
# Remove sudo and use prefix on bootstrap.sh in boost/debian/rules
%.deb: pkgdeb
	cd $</$(basename $@) && debuild


# Rules to build unit test logs
# -----------------------------
check:
	$(installDirs) test
	cd test && $(MAKE) -k -f $(srcDir)/test/Makefile results ; \
	echo "ok to get positive error code" > /dev/null
	cd test && $(MAKE) -f $(srcDir)/test/Makefile regression.book

regression.book: regression.log $(srcDir)/src/book.xsl
	xsltproc $(word 2,$^) $< > $@

regression.log: results.log $(wildcard $(srcDir)/data/results-*.log)
	dregress -o $@ $^ 

results.log: $(wildcard *Test.cout)
	echo "<config name=\"$(version)\">" >> $@
	dws host >> $@
	echo "</config>" >> $@
	for testunit in $(testunits) ; do \
		echo "@@ test: $$testunit @@" >> $@ ; \
		if [ ! -f $$testunit ] ; then \
			echo "<status>compile error</status>" >> $@ ; \
		else \
			if [ -f $${testunit}.cout ] ; then \
				cat $${testunit}.cout >> $@ ; \
			fi ; \
		fi ; \
	done

results: $(patsubst %,%.cout,$(testunits))

%Test.cout: %Test
	./$< $(filter-out $<,$^) > $@ 2>&1

%.log:	%.cout $(wildcard $(srcDir)/data/results-*.log)
	dregress -o $@ $^

-include *.d
