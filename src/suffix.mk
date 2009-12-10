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

buildInstallDir	:= 	$(CURDIR)/install/usr/local
dists		?=	$(project)-$(version)$(distExt$(distHost)) \
			$(project)-$(version).tar.bz2

dist:: $(dists)

# \todo From http://www.gelato.unsw.edu.au/archives/git/0511/11390.html,
# 'git-tar-tree branchname' can be an alternative to the rsync command.
#  git archive -b branchname tag
#  make dist
$(project)-$(version).tar.bz2:
	rsync -r --exclude=.git $(srcDir)/* $(basename $(basename $@))
	$(SED) -e s,$(project),$(subst .tar.bz2,,$@),g \
		$(srcDir)/index.xml > $(basename $(basename $@))/index.xml 
	$(SED) -e 's,$$(shell dws context),ws.mk,' \
	    -e 's,$$(shell dws context \(..*\)),etc/\1,' \
		$(srcDir)/Makefile > $(basename $(basename $@))/Makefile.in
	rm $(basename $(basename $@))/Makefile
	$(installDirs) $(basename $(basename $@))/etc
	$(installExecs) $(shell dws context configure.sh) \
		$(basename $(basename $@))/configure
	$(installExecs) $(dws) $(basename $(basename $@))
	$(installFiles) $(shell $(dws) context prefix.mk) \
			$(shell $(dws) context suffix.mk) \
		$(basename $(basename $@))/etc
	tar -cj --exclude 'build' --exclude '.*' --exclude '*~' \
		-f $@ $(basename $(basename $@))


# This rule is used to create a OSX distribution package
# \todo It certainly should move to an *host* specific part of the Makefiles
$(project)-$(version).dmg: $(project)-$(version).tar.bz2
	tar jxf $<
	cd $(basename $(basename $<)) && ./configure --prefix=${buildInstallDir}
	cd $(basename $(basename $<)) && ${MAKE} install
	buildpkg --version=$(subst $(project)-,,$(basename $(basename $<))) \
	         --spec=$(srcDir)/index.xml ${buildInstallDir}

%-$(version).rpm: $(srcDir)/index.xml $(project)-$(version).tar.bz2 \
		$(wildcard $(srcDir)/src/$(project)-*.patch)
	rpmdev-setuptree -d
	$(dws) spec $(basename $@)
	cp $(filter %.tar.bz2 %.patch,$^) $(HOME)/rpmbuild/SOURCES
	rpmbuild -bb --clean $(basename $@)

#%.spec: $(srcDir)/index.xml
#	$(dws) spec $(basename $@)
#	echo '%files' >> $@ 
#	echo $(bins) >> $@
#	echo $(includes) >> $@
#	echo $(libs) >> $@

# alternative:
#   apt-get install pbuilder
#   pbuilder create
#   pdebuild --buildresult ..
#
# debuild will try to install the packages in /usr/local so it needs
# permission access to the directory.
# Remove sudo and use prefix on bootstrap.sh in boost/debian/rules

# Can only find example in man pages of debuild but cannot 
# find description of options: "-i -us -uc -b".
%$(distExtUbuntu): %.tar.bz2
	bzip2 -dc $< | gzip > $(shell echo $< | $(SED) -e 's,\([^-][^-]*\)-\(.*\).tar.bz2,\1_\2.orig.tar.gz,')
	tar jxf $<
	$(installDirs) $(basename $(basename $<))/debian
	cd $(basename $(basename $<))/debian \
		&& $(dws) spec $(shell echo $@ | \
			$(SED) -e 's,[^-][^-]*-\(.*\)$(distExtUbuntu),\1,')
	cd $(basename $(basename $<)) && debuild -i -us -uc -b


# Rules to build unit test logs
# -----------------------------
check:
	$(installDirs) test
	cd test && $(MAKE) -k -f $(srcDir)/test/Makefile results ; \
	echo "ok to get positive error code" > /dev/null
	cd test && $(MAKE) -f $(srcDir)/test/Makefile regression.book

# \todo book.xsl might have to move into drop but since it is used
#       for interaction with the website, it might also have to move
#	to the themeDir, though it might not be directly theme related...
regression.book: regression.log $(srcTop)/seed/test/src/book.xsl
	xsltproc $(word 2,$^) $< > $@

regression.log: results.log $(wildcard $(srcDir)/data/results-*.log)
	dregress -o $@ $^ 

# \todo Why does that trigger a recompile when building regression.book?
# $(wildcard *Test.cout)
results.log: 
	echo "<config name=\"$(version)\">" >> $@
	dws host >> $@
	echo "</config>" >> $@
	for testunit in $(testunits) ; do \
		echo "@@ test: $$testunit @@" >> $@ ; \
		if [ ! -f $${testunit}.cout ] ; then \
			echo "error: No output file for $${testunit}" >> $@ ; \
		else \
			cat $${testunit}.cout >> $@ ; \
		fi ; \
	done

results: $(patsubst %,%.cout,$(testunits))

%Test.cout: %Test
	./$< $(filter-out $<,$^) > $@ 2>&1

%.log:	%.cout $(wildcard $(srcDir)/data/results-*.log)
	dregress -o $@ $^

-include *.d
