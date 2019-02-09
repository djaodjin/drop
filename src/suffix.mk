# Copyright (c) 2015, DjaoDjin inc.
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

# Suffix intended to be included at the bottom of a project Makefile
#
# Primary Author(s): Sebastien Mirolo <smirolo@fortylines.com>

.PHONY:	all check dist doc install site

# *dropShareDir* will be defined in drop/Makefile because this is a bottom
# turtle. We need drop to build packages but it is not a dependency of drop
# itself to avoid an infinite dependency loop.
dropShareDir 	?=		$(shareBuildDir)/dws

# This code is here and not prefix.mk because CXXFLAGS is often set to a default
# value in prefix.mk and extended in the actual Makefile.
ifneq ($(filter Darwin,$(distHost)),)
ifneq ($(filter -std=c++0x,$(CXXFLAGS)),)
ifneq ($(filter g++,$(CXX)),)
$(warning warning: g++ does not accept -std=c++0x on Darwin, switching to CXX=clang++)
CXX			:=  clang++
endif
endif
endif

all::	$(bins) $(apps) $(scripts) $(dynlibs) $(libs) $(includes) $(etcs)

all::	$(logs)
	$(if $^,-dregress -o regression.log $^ \
	    	$(wildcard $(logDir)/results-*.log) \
		$(wildcard $(srcDir)/data/results-*.log))

# Used to be "rm -rf $(objDir)/*" but that would create issues
# when intermediate files are created in the same directory.
clean::
	rm -rf $(bins) $(apps) $(scripts) $(libs) *.o *.d *~ *.dSYM

# OSX GUI Applications are compiled but not installed.
install:: $(apps)

install:: $(bins)
	$(if $^,$(installDirs) $(DESTDIR)$(binDir))
	$(if $^,$(installBins) $^ $(DESTDIR)$(binDir))

install:: $(scripts)
	$(if $^,$(installDirs) $(DESTDIR)$(binDir))
	$(if $^,$(installScripts) $^ $(DESTDIR)$(binDir))

install:: $(libs)
	$(if $^,$(installDirs) $(DESTDIR)$(libDir))
	$(if $^,$(installFiles) $^ $(DESTDIR)$(libDir))

# We have to install dynamically shared libraries as executables
# otherwise rpmbuild find-provides will not detect the library
# and automatically add it to the Provides: field.
install:: $(dynlibs)
	$(if $^,$(installDirs) $(DESTDIR)$(libDir))
	$(if $^,$(installDynLibs) $^ $(DESTDIR)$(libDir))

install:: $(includes)
	$(if $^,$(installDirs) $(DESTDIR)$(includeDir))
	$(if $^, $(installFiles) $^ $(DESTDIR)$(includeDir))

# Copy all template configuration files that appear in the *srcDir*/etc
# subdirectory.
install-etc: $(etcs)
	$(if $^,$(installDirs) $(DESTDIR)$(etcDir))
	$(if $^,cp -rpf $(srcDir)/etc/* $(DESTDIR)$(etcDir))

# install the stamped result logs and builds the regression log in-place.
install:: $(logs)
	$(if $^,$(installDirs) $(logDir))
	$(if $^,dstamp install $^ $(logDir))
	$(if $^,-dregress -o $(logDir)/regression.log \
	    $(logDir)/results-*.log $(wildcard $(srcDir)/data/results-*.log))

install:: $(resources)
	$(if $^,$(installDirs) $(resourcesDir))
	$(if $^, $(installFiles) $^ $(resourcesDir))

%.a:
	$(AR) $(ARFLAGS) $@ $^

%$(dylSuffix):
	$(LINK.o) $(SHAREDLIBFLAGS) $(filter-out %.h %.hh %.hpp %.ipp %.tcc %.def $(dylSuffix),$^) $(LOADLIBES) $(LDLIBS) -o $@

# %.def appears in dependency (.d) files through an #include of LLVM headers.
%: %.c
	$(LINK.c) $(filter-out %.h %.hh %.hpp %.ipp %.tcc %.def $(dylSuffix),$^) $(LOADLIBES) $(LDLIBS) -o $@

%: %.cc
	$(LINK.cc) $(filter-out %.h %.hh %.hpp %.ipp %.tcc %.def $(dylSuffix),$^) $(LOADLIBES) $(LDLIBS) -o $@

%: %.cpp
	$(LINK.cc) $(filter-out %.h %.hh %.hpp %.ipp %.tcc %.def $(dylSuffix),$^) $(LOADLIBES) $(LDLIBS) -o $@

%.class: %.java
	$(JAVAC) $(JAVAC_FLAGS) $(subst $(srcDir)/src/,,$<)

%.swf: %.mxml
	$(MXMLC) $(MXMLFLAGS) -output $@ $<

# We set the actual version in the script here (through "make").
# "make install" will copy the script in the bin directory.
%: %.py
	$(SED) -e "s,^#!/usr/bin/env python,#!$(PYTHON),g" -e "s,\$${libDir},$(libDir),g" -e 's,__version__ = None,__version__ = "$(version)",' $< > $@ || (rm -f $@ ; false)
	chmod 755 $@

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

dists		?=	$(binDist) $(project)-$(version).tar.bz2

# The *dist* and *dist-release* targets create a distribution binanry package.
# The difference between both is the source tree used to build the package.
# *dist* builds the package out of the sources currently present in *srcTop*
# while *dist-release* clone the release repository first and update
# an optional release log file.
dist:: $(dists)

dist-release:
	echo "Not Yet Implemented" && false

dist-src: $(project)-$(version).tar.bz2


$(project)-$(version).tar.bz2: $(project)-$(version)
	tar -cj --exclude 'build' --exclude '.*' --exclude '*~' -f $@ $<


# The order of the statements are very important, especially to build the drop
# package itself.
$(project)-$(version)::
	rsync -r --exclude=.git $(srcDir)/* $@
	$(if $(patchedSources),$(installDirs) $@ && rsync -aR $(patchedSources) $@)
	if [ -f $(srcDir)/$(projindex) ] ; then \
		$(SED) -e "s,<project  *name=\".*$(project),<project name=\"$@,g" \
		$(srcDir)/$(projindex) > $@/$(projindex) ; \
	fi
	echo 'include $(dwsmk)' > $@/Makefile.in
	$(SED) -e 's,$$(shell dws context),$(dwsmk),' \
	    -e 's,-include $$(buildTop)/share/dws/,include share/dws/,' \
	    -e 's,$$(srcTop)/drop,$$(srcTop)/$@,' \
		$(srcDir)/Makefile >> $@/Makefile.in
	rm -f $@/Makefile
	$(installScripts) $(binBuildDir)/dws $@
	$(installDirs) $@/share/dws
	$(installScripts) $(dropShareDir)/configure.sh $@/configure
	$(installFiles) $(dropShareDir)/prefix.mk $(dropShareDir)/suffix.mk $(dropShareDir)/configure.sh $@/share/dws


# 'make install' might just do nothing and we still want to build an empty
# package for that case so we create ${buildInstallDir} before dbldpkg
# regardless such that mkbom has something to work with.
%$(distExtDarwin): %.tar.bz2
	tar jxf $<
	cd $(basename $(basename $<)) \
		&& ./configure --prefix=${buildUsrLocalDir}
	cd $(basename $(basename $(notdir $<))) && ${MAKE} install
	$(installDirs) ${buildInstallDir}
	$(dbldpkg) $(subst $(project)-,,$(basename $(basename $(notdir $<))))

%$(distExtFedora): %.tar.bz2 \
		$(wildcard $(srcDir)/src/$(project)-*.patch)
	rpmdev-setuptree -d
	$(installFiles) $(filter %.tar.bz2 %.patch,$^) $(HOME)/rpmbuild/SOURCES
	$(dbldpkg) $(subst $(project)-,,$(basename $(basename $(notdir $<))))

# Ubuntu can sometimes be annoying using '_' instead of '-' here and there.
$(project)_$(version)$(distExtUbuntu): $(project)-$(version).tar.bz2
	bzip2 -dc $< | gzip > $(shell echo $< | $(SED) -e 's,\([^-][^-]*\)-\(.*\).tar.bz2,\1_\2.orig.tar.gz,')
	tar jxf $<
	cd $(basename $(basename $(notdir $<))) \
		&& $(dbldpkg) $(subst $(project)-,,$(basename $(basename $(notdir $<))))

# Rules to build unit test logs
# -----------------------------
.PHONY: results.log

# \todo When results.log depends on $(wildcard *Test.cout), it triggers
#       a recompile and rerunning of *Test when making regression.log.
#       It should not but why it does in unknown yet.
#
# Unconditionally add an eol after the test output.
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
		  echo "" >> $@ ; \
		fi ; \
	done

results: $(patsubst %,%.cout,$(testunits))

%Test.cout: %Test
	./$< $(filter-out $<,$^) > $@ 2>&1

%.log: %.cout $(wildcard $(srcDir)/data/results-*.log)
	dregress -o $@ $^


# Rules to build printable documentation out of docbook sources.
# --------------------------------------------------------------
doc: $(shares)

# We install documentation files, both in shareDir and resourcesDir
# such that those are available for generating a distribution package
# as well as acessible through the website.
install-doc:: $(shares)
	$(if $^,$(installDirs) $(DESTDIR)$(shareDir)/doc/$(subst -%,,$(project)))
	$(if $^,$(installFiles) $^ $(DESTDIR)$(shareDir)/doc/$(subst -%,,$(project)))
	$(if $^,$(installFiles) $^ $(resourcesDir))

install-doc:: $(manpages)
	$(if $^,$(installDirs) $(DESTDIR)$(shareDir)/man/man1)
	$(if $^,$(installFiles) $(filter %.1,$^) $(DESTDIR)$(shareDir)/man/man1)

# For debugging issues running fop the following command used to work
#   fop --execdebug -fo $< -pdf $@
# With 0.95, it fails with an invalid argument and the command should be
#   DEBUG_WRAPPER=1 fop -fo $< -pdf $@
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
	$(SEMILLA) $< | tail +2 > $@

%.html: %.h
	@$(installDirs) $(dir $@)
	$(SEMILLA) $< | tail +2 > $@

%.html: %.hh
	@$(installDirs) $(dir $@)
	$(SEMILLA) $< | tail +2 > $@

%.html: %.py
	@$(installDirs) $(dir $@)
	$(SEMILLA) $< | tail +2 > $@

%.html: %.book
	@$(installDirs) $(dir $@)
	$(SEMILLA) $< | tail +2 > $@

Makefile.html: Makefile
	@[ -d $(dir $@) ] || $(installDirs) $(dir $@)
	$(SEMILLA) $< | tail +2 > $@

%Makefile.html: %Makefile
	@$(installDirs) $(dir $@)
	$(SEMILLA) $< | tail +2 > $@


# Rules to validate the intra-projects dependency file
# ----------------------------------------------------
validate: $(projindex)
	xmllint --noout --schema $(srcTop)/drop/src/index.xsd $<


# docbook validation
# schema taken from http://www.docbook.org/xml/5.0/xsd/docbook.xsd
validbook: $(wildcard $(srcDir)/doc/*.book) \
			$(wildcard $(srcDir)/doc/*.corp)
	xmllint --noout --schema $(shareBuildDir)/schemas/docbook.xsd $^

validxhtml: $(subst .book,.html,\
		$(notdir $(wildcard $(srcDir)/doc/*.book)))
	xmllint --noout --valid $^

.PHONY: lint

lint: $(patsubst $(srcDir)/%.xml,%.lint,$(wildcard $(srcDir)/*.book))

%.lint: %.book
	xmllint --format --output $@ $<

-include *.d
