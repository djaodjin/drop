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

installBinDir		?=	$(binDir)
installIncludeDir	?=	$(includeDir)
installLibDir		?=	$(libDir)
installShareDir		?=	$(shareDir)

.PHONY:	all check dist doc install site

all::	$(bins) $(libs) $(includes) $(logs)

clean::
	rm -rf *-stamp $(bins) $(libs) *.o *.d *.dSYM

install:: $(bins)
	$(if $^,$(installDirs) $(installBinDir))
	$(if $^,$(installExecs) $^ $(installBinDir))

install:: $(libs)
	$(if $^,$(installDirs) $(installLibDir))
	$(if $^,$(installFiles) $^ $(installLibDir))

install:: $(includes)
	$(if $^,$(installDirs) $(installIncludeDir))
	$(if $^, $(installFiles) $^ $(installIncludeDir))

install:: $(resources)
	$(if $^,$(installDirs) $(resourcesDir))
	$(if $^, $(installFiles) $^ $(resourcesDir))

%.a:
	$(AR) $(ARFLAGS) $@ $^

%: %.cc
	$(LINK.cc) $(filter-out %.hh %.hpp %.ipp %.tcc,$^) \
		$(LOADLIBES) $(LDLIBS) -o $@

%: %.py
	$(installExecs)	$< $@


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
			$(shell dws context configure.sh) \
		$(basename $(basename $@))/etc
	tar -cj --exclude 'build' --exclude '.*' --exclude '*~' \
		-f $@ $(basename $(basename $@))


# 'make install' might just do nothing and we still want to build an empty
# package for that case so we create ${buildInstallDir} before buildpkg 
# regardless such that mkbom has something to work with. 
%$(distExtDarwin): %.tar.bz2 $(srcDir)/index.xml
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
	cp $(filter %.tar.bz2 %.patch,$^) $(HOME)/rpmbuild/SOURCES
	buildpkg --version=$(subst $(project)-,,$(basename $@)) \
	         --spec=$(srcDir)/index.xml $(basename $@)

%$(distExtUbuntu): %.tar.bz2
	bzip2 -dc $< | gzip > $(shell echo $< | $(SED) -e 's,\([^-][^-]*\)-\(.*\).tar.bz2,\1_\2.orig.tar.gz,')
	tar jxf $<
	cd $(basename $(basename $<)) \
		&& buildpkg --version=$(subst $(project)-,,$(basename $@)) \
	         --spec=$(srcDir)/index.xml $(shell echo $@ | \
			$(SED) -e 's,[^-][^-]*-\(.*\)$(distExtUbuntu),\1,')

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
	@for funtest in $(testunits) ; do \
		echo "append $${funtest}.cout to $@ ..." ; \
		if [ ! -f $${funtest}.cout ] ; then \
		  echo "@@ test: $$funtest fail @@" >> $@ ; \
		  echo "$${funtest}: error: Cannot find .cout file" >> $@ ; \
		else \
		grep "error: functional test" $${funtest}.cout > /dev/null 2>&1 ; \
		if [ $$? -eq 0 ] ; then \
		  echo "@@ test: $$funtest fail @@" >> $@ ; \
		else \
		  echo "@@ test: $$funtest pass @@" >> $@ ; \
		fi ; \
		  cat $${funtest}.cout >> $@ ; \
		fi ; \
	done

results: $(patsubst %,%.cout,$(testunits))

%Test.cout: %Test
	./$< $(filter-out $<,$^) > $@ 2>&1

%.log:	%.cout $(wildcard $(srcDir)/data/results-*.log)
	dregress -o $@ $^


# Rules to build printable documentation out of docbook sources.
# --------------------------------------------------------------
doc: $(shares)

%.pdf:	%.fo
	$(FOP) -fo $< -pdf $@

%.fo: %.book
	$(XSLTPROC) --output $@ $(foxsl) $<


# Rules to build the website
# --------------------------
siteDir	:=	$(subst $(srcTop)/,$(resourcesDir)/,$(srcDir))

site::
	$(installDirs) $(siteDir)
	$(installFiles) $(shell dws context) $(resourcesDir)
	cd $(siteDir)     \
	   && $(MAKE) -f $(srcDir)/Makefile srcDir=$(srcDir) site-stamp

site-stamp:: $(htmlSite)

%.html: %.cc
	@$(installDirs) $(dir $@)
	$(SEED) $< | tail +2 > $@

%.html: %.hh
	@$(installDirs) $(dir $@)
	$(SEED) $< | tail +2 > $@

%.html: %.py
	@$(installDirs) $(dir $@)
	$(SEED) $< | tail +2 > $@

%.html: %.book
	@$(installDirs) $(dir $@)
	$(SEED) $< | tail +2 > $@

Makefile.html: Makefile
	@[ -d $(dir $@) ] || $(installDirs) $(dir $@)
	$(SEED) $< | tail +2 > $@

%Makefile.html: %Makefile
	@$(installDirs) $(dir $@)
	$(SEED) $< | tail +2 > $@


# Rules to validate the intra-projects dependency file
# ----------------------------------------------------
validate: index.xml
	xmllint --noout --schema $(srcTop)/drop/src/index.xsd $<


# docbook validation
# schema taken from http://www.docbook.org/xml/5.0/xsd/docbook.xsd
validbook: $(shell find $(srcDir) -name '*.book')
	xmllint --noout --schema $(shareDir)/docbook-xsd/docbook.xsd $^

validxhtml: $(subst .book,.html,\
		$(notdir $(shell find $(srcDir) -name '*.book')))
	xmllint --noout --valid $^

.PHONY: lint

lint:	$(patsubst $(srcDir)/%.xml,%.lint,$(wildcard $(srcDir)/*.book))

%.lint:	%.book
	xmllint --format --output $@ $<

-include *.d
