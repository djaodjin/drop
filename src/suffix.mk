# Copyright (c) 2009, Fortylines LLC
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
#   THIS SOFTWARE IS PROVIDED BY Fortylines LLC ''AS IS'' AND ANY
#   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL Fortylines LLC BE LIABLE FOR ANY
#   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Suffix intended to be included at the bottom of a project Makefile
#
# Primary Author(s): Sebastien Mirolo <smirolo@fortylines.com>

binDir		?=	$(binBuildDir)
etcDir		?=	$(etcBuildDir)
includeDir	?=	$(includeBuildDir)
libDir		?=	$(libBuildDir)
shareDir	?=	$(shareBuildDir)

.PHONY:	all check dist doc install site

all::	$(bins) $(scripts) $(libs) $(includes) $(etcs)

all::	$(logs)
	$(if $^,-dregress -o regression.log $^ \
	    	$(wildcard $(logDir)/results-*.log) \
		$(wildcard $(srcDir)/data/results-*.log))

clean::
	rm -rf $(objDir)/*

install:: $(bins)
	$(if $^,$(installDirs) $(binDir))
	$(if $^,$(installBins) $^ $(binDir))

install:: $(scripts)
	$(if $^,$(installDirs) $(binDir))
	$(if $^,$(installScripts) $^ $(binDir))

install:: $(libs)
	$(if $^,$(installDirs) $(libDir))
	$(if $^,$(installFiles) $^ $(libDir))

install:: $(includes)
	$(if $^,$(installDirs) $(includeDir))
	$(if $^, $(installFiles) $^ $(includeDir))

install:: $(etcs)
	$(if $^,$(installDirs) $(etcDir))
	$(if $^,$(installFiles) $^ $(etcDir))

# install the stamped result logs and builds the regression log in-place.
install:: $(logs)
	$(if $^,$(installDirs) $(logDir))
	$(if $^,$(binBuildDir)/dstamp install $^ $(logDir))
	$(if $^,-dregress -o $(logDir)/regression.log \
	    $(logDir)/results-*.log $(wildcard $(srcDir)/data/results-*.log))

install:: $(resources)
	$(if $^,$(installDirs) $(resourcesDir))
	$(if $^, $(installFiles) $^ $(resourcesDir))

%.a:
	$(AR) $(ARFLAGS) $@ $^

%: %.cc
	$(LINK.cc) $(filter-out %.hh %.hpp %.ipp %.tcc,$^) \
		$(LOADLIBES) $(LDLIBS) -o $@

%: %.py
	$(installScripts) $< $@

%: %.sh
	$(installScripts) $< $@

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
dists		?=	$(binDist) $(project)-$(version).tar.bz2

dist:: $(dists)

dist-src: $(project)-$(version).tar.bz2


define distVersion
	sed -e 's,__version__ = None,__version__ = "$(version)",' $(1) > $@/src/$(notdir $(1))

endef

$(project)-$(version).tar.bz2: $(project)-$(version)
	tar -cj --exclude 'build' --exclude '.*' --exclude '*~' -f $@ $<


$(project)-$(version)::
	$(if $(patchedSources),$(installDirs) $@ \
	    && rsync -aR $(patchedSources) $@)
	rsync -r --exclude=.git $(srcDir)/* $@
	$(foreach script,$(wildcard $(srcDir)/src/*.py),$(call distVersion,$(script)))
	if [ -f $(srcDir)/$(projindex) ] ; then \
		$(SED) -e "s,<project  *name=\".*$(project),<project name=\"$@,g" \
		$(srcDir)/$(projindex) > $@/$(projindex) ; \
	fi
	$(SED) -e 's,$$(shell dws context),$(dwsmk),' \
	    -e 's,$$(shell dws context \(..*\)),share/dws/\1,' \
	    -e 's,$$(srcTop)/drop,$$(srcTop)/$@,' \
		$(srcDir)/Makefile > $@/Makefile.in
	rm -f $@/Makefile
	$(installDirs) $@/share/dws
	$(installScripts) $(makeHelperDir)/configure.sh $@/configure
	$(installScripts) $(shell which dws) $@
	$(installFiles) $(makeHelperDir)/prefix.mk $(makeHelperDir)/suffix.mk $(makeHelperDir)/configure.sh $@/share/dws


# 'make install' might just do nothing and we still want to build an empty
# package for that case so we create ${buildInstallDir} before dbldpkg 
# regardless such that mkbom has something to work with. 
%$(distExtDarwin): %.tar.bz2 
	tar jxf $<
	cd $(basename $(basename $<)) \
		&& ./configure --prefix=${buildUsrLocalDir}
	cd $(basename $(basename $<)) && ${MAKE} install
	$(installDirs) ${buildInstallDir}
	$(dbldpkg) --version=$(subst $(project)-,,$(basename $(basename $<))) \
	         --spec=$(srcDir)/$(projindex) ${buildInstallDir}

%$(distExtFedora): %.tar.bz2 \
		$(wildcard $(srcDir)/src/$(project)-*.patch)
	rpmdev-setuptree -d
	cp $(filter %.tar.bz2 %.patch,$^) $(HOME)/rpmbuild/SOURCES
	$(dbldpkg) --version=$(subst $(project)-,,$(basename $(basename $<))) \
	         --spec=$(srcDir)/$(projindex) $(basename $@)

%$(distExtUbuntu): %.tar.bz2
	bzip2 -dc $< | gzip > $(shell echo $< | $(SED) -e 's,\([^-][^-]*\)-\(.*\).tar.bz2,\1_\2.orig.tar.gz,')
	tar jxf $<
	cd $(basename $(basename $<)) \
		&& $(dbldpkg) \
		 --version=$(subst $(project)-,,$(basename $(basename $<))) \
	         --spec=$(srcDir)/$(projindex) $(shell echo $@ | \
			$(SED) -e 's,[^-][^-]*-\(.*\)$(distExtUbuntu),\1,')

# Rules to build unit test logs
# -----------------------------
.PHONY: results.log

# \todo When results.log depends on $(wildcard *Test.cout), it triggers 
#       a recompile and rerunning of *Test when making regression.log.
#       It should not but why it does in unknown yet.
results.log: 
	$(MAKE) -k -f $(srcDir)/Makefile results ; \
		echo "ok to get positive errcodes" > /dev/null
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
# We install documentation files, both in shareDir and resourcesDir
# such that those are available for generating a distribution package
# as well as acessible through the website.
install-doc:: $(shares)
	$(installDirs) $(shareDir)/doc/$(subst -%,,$(project))
	$(installFiles) $^ $(shareDir)/doc/$(subst -%,,$(project))
	$(installFiles) $^ $(resourcesDir)

install-doc:: $(manpages)
	$(installDirs) $(shareDir)/man/man1
	$(installFiles) $(filter %.1,$^) $(shareDir)/man/man1

%.pdf:	%.fo
	$(FOP) -fo $< -pdf $@

%.fo: %.book
	$(XSLTPROC) --output $@ $(foxsl) $<

%.1: %.book
	$(XSLTPROC) --output $@ $(manxsl) $<


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
validate: $(projindex)
	xmllint --noout --schema $(srcTop)/drop/src/index.xsd $<


# docbook validation
# schema taken from http://www.docbook.org/xml/5.0/xsd/docbook.xsd
validbook: $(shell find $(srcDir) -name '*.book') \
	   $(shell find $(srcDir) -name '*.corp')
	xmllint --noout --schema $(shareDir)/schemas/docbook.xsd $^

validxhtml: $(subst .book,.html,\
		$(notdir $(shell find $(srcDir) -name '*.book')))
	xmllint --noout --valid $^

.PHONY: lint

lint:	$(patsubst $(srcDir)/%.xml,%.lint,$(wildcard $(srcDir)/*.book))

%.lint:	%.book
	xmllint --format --output $@ $<

-include *.d
