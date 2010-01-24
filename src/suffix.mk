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

.PHONY:	all install check dist

all::	$(bins) $(libs) $(includes) $(logs)

clean::
	rm -rf *-stamp $(bins) $(libs) *.o *.d *.dSYM

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
	$(LINK.cc) $(filter-out %.hh %.hpp %.ipp %.tcc,$^) \
		$(LOADLIBES) $(LDLIBS) -o $@

%: %.py
	$(installFiles)	$< $@


# Rules to build packages for distribution
# ----------------------------------------
#
# The source package will be made of the current source tree
# so a shell script to distribute a specific tag would actually
# look like:
# 	git checkout -b branchname tag
#	make dist

buildInstallDir	:= 	$(CURDIR)/install
buildUsrLocalDir:=	$(buildInstallDir)/usr/local
dists		?=	$(project)-$(version)$(distExt$(distHost)) \
			$(project)-$(version).tar.bz2

dist:: $(dists)

$(project)-$(version).tar.bz2:
	$(if $(patchedSources),                                  \
		$(installDirs) $(basename $(basename $@))/cache \
		&& rsync -aR $(patchedSources)                   \
			$(basename $(basename $@))/cache)
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
	$(installExecs) $(shell which dws) $(basename $(basename $@))
	$(installFiles) $(shell dws context prefix.mk) \
			$(shell dws context suffix.mk) \
		$(basename $(basename $@))/etc
	tar -cj --exclude 'build' --exclude '.*' --exclude '*~' \
		-f $@ $(basename $(basename $@))


# 'make install' might just do nothing and we still want to build an empty
# package for that case so we create ${buildInstallDir} before buildpkg 
# regardless such that mkbom has something to work with. 
%$(distExtDarwin): %.tar.bz2
	tar jxf $<
	cd $(basename $(basename $<)) \
		&& ./configure --prefix=${buildUsrLocalDir}
	cd $(basename $(basename $<)) && ${MAKE} install
	$(installDirs) ${buildInstallDir}
	buildpkg --version=$(subst $(project)-,,$(basename $(basename $<))) \
	         --spec=$(srcDir)/index.xml ${buildInstallDir}

%$(distExtFedora): %.tar.bz2 $(srcDir)/index.xml \
		$(wildcard $(srcDir)/src/$(project)-*.patch)
	rpmdev-setuptree -d
	buildpkg --version=$(subst $(project)-,,$(basename $@)) \
	         --spec=$(srcDir)/index.xml $(basename $@)
	cp $(filter %.tar.bz2 %.patch,$^) $(HOME)/rpmbuild/SOURCES
	rpmbuild -bb --clean $(basename $@)

#%.spec: $(srcDir)/index.xml
#	dws spec $(basename $@)
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
		&& buildpkg --version=$(subst $(project)-,,$(basename $@)) \
	         --spec=$(srcDir)/index.xml $(shell echo $@ | \
			$(SED) -e 's,[^-][^-]*-\(.*\)$(distExtUbuntu),\1,')
	cd $(basename $(basename $<)) && debuild -i -us -uc -b


# Rules to build unit test logs
# -----------------------------
check:
	@if [ -f $(srcDir)/test/Makefile ] ; then \
		echo "cd test && $(MAKE) -f $(srcDir)/test/Makefile" ; \
		$(installDirs) test \
		&& cd test && $(MAKE) -f $(srcDir)/test/Makefile ; \
	else \
		echo "$(basename $(srcDir)): warning: 'make check' expects to find a Makefile in $(srcDir)/test." ; \
	fi

regression.log: results.log $(wildcard $(srcDir)/data/results-*.log)
	dregress -o $@ $^ 

.PHONY: results.log

# \todo When results.log depends on $(wildcard *Test.cout), it triggers 
#       a recompile and rerunning of *Test when making regression.log.
#       It should not but why it does in unknown yet.
results.log: 
	$(MAKE) -k -f $(srcDir)/Makefile results ; \
		echo "ok to get positive error code" > /dev/null
	@echo "<config name=\"$(version)\">" > $@
	@echo $(distHost) >> $@
	@echo "</config>" >> $@
	@for testunit in $(testunits) ; do \
		echo "append $${testunit}.cout to $@ ..." ; \
		if [ ! -f $${testunit}.cout ] ; then \
		  echo "@@ test: $$testunit fail @@" >> $@ ; \
		  echo "$${testunit}: error: Cannot find .cout file" >> $@ ; \
		else \
		grep "error:" $${testunit}.cout > /dev/null 2>&1 ; \
		if [ $$? -eq 0 ] ; then \
		  echo "@@ test: $$testunit fail @@" >> $@ ; \
		else \
		  echo "@@ test: $$testunit pass @@" >> $@ ; \
		fi ; \
		  cat $${testunit}.cout >> $@ ; \
		fi ; \
	done

results: $(patsubst %,%.cout,$(testunits))

%Test.cout: %Test
	./$< $(filter-out $<,$^) > $@ 2>&1

%.log:	%.cout $(wildcard $(srcDir)/data/results-*.log)
	dregress -o $@ $^

# Rules to validate the intra-projects dependency file
# ----------------------------------------------------
validate: index.xml
	xmllint --noout --schema $(srcTop)/drop/src/index.xsd $<

-include *.d
