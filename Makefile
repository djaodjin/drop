# Copyright (c) 2020, DjaoDjin inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-include $(shell \
	d=`pwd` ; \
	config='dws.mk_not_found' ; \
	while [ $$d != '/' ] ; do \
		if [ -f $$d/dws.mk ] ; then \
			config=$$d/dws.mk ; \
			break ; \
		fi ; \
		d=`dirname $$d` ; \
	done ; \
	echo $$config)

srcDir        ?= $(abspath $(dir $(filter %Makefile,$(MAKEFILE_LIST))))
installTop    ?= $(VIRTUAL_ENV)
binDir        ?= $(installTop)/bin

include $(srcDir)/src/prefix.mk

shareItemDirs ?= $(shell cd $(srcDir)/share && find playbooks profiles -type d)

scripts := dws dtero
manpages:= $(addsuffix .1,$(scripts))

install:: $(srcDir)/src/prefix.mk \
		$(srcDir)/src/suffix.mk \
		$(srcDir)/src/configure.sh \
		$(srcDir)/src/index.xsd
	$(installDirs) $(shareDir)/dws
	$(installScripts) $(filter %.sh,$^) $(shareDir)/dws
	$(installFiles) $(filter %.mk %.xsd,$^) $(shareDir)/dws

install::
	cd $(srcDir)/src && $(PYTHON) setup.py --quiet build \
		-b $(CURDIR)/build install --prefix=$(DESTDIR)$(PREFIX)

install:: $(foreach shareItemDir,$(shareItemDirs),$(wildcard $(srcDir)/share/$(shareItemDir)/*))
	for dir in $(shareItemDirs); do $(installDirs) $(shareDir)/dws/$$dir ; done
	cd $(srcDir)/share && find playbooks profiles -path playbooks/group_vars -prune -o -type f -exec $(installFiles) {} $(shareDir)/dws/{} \;

doc:
	$(installDirs) docs
	cd $(srcDir) && sphinx-build -b html ./docs $(CURDIR)/docs

dtero: dtero.py
	sed -e "s,settings_path=None,settings_path='$(etcDir)/tero/config'," $< > $@
	chmod 755 $@

dws: tero/__init__.py
	$(SED) -e 's,__version__ = None,__version__ = "$(version)",' $< > $@ || (rm -f $@ ; false)
	chmod 755 $@

include $(srcDir)/src/suffix.mk
