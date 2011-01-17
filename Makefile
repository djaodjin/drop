# Copyright (c) 2009-2011, Fortylines LLC
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

include $(shell \
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

srcDir		:=	$(srcTop)/drop
makeHelperDir	:=	$(srcTop)/drop/src

include $(srcDir)/src/prefix.mk

docbook2man	:=	docbook-to-man

scripts	:=	dbldpkg dregress dstamp dws dtimeout
manpages:=	$(addsuffix .1,$(scripts))

%.book: %
	python $< --help-book > $@ || rm -f $@

include $(srcDir)/src/suffix.mk

install:: $(srcDir)/src/prefix.mk \
		$(srcDir)/src/suffix.mk \
		$(srcDir)/src/configure.sh \
		$(srcDir)/src/index.xsd
	$(installDirs)  $(shareDir)/dws
	$(installScripts) $(filter %.sh,$^) $(shareDir)/dws
	$(installFiles) $(filter %.mk %.xsd,$^) $(shareDir)/dws

install:: dws.py dstamp.py
	$(installDirs)  $(libDir)/python
	$(installFiles) $(filter %.py,$^) $(libDir)/python

install:: dws
	$(installDirs) $(resourcesDir)
	$(installFiles) $^ $(resourcesDir)

# There is already a package called dmake in Ubuntu :(.
dmake:
	echo '#!/bin/sh' > $@
	echo 'dws make $$*' >> $@


