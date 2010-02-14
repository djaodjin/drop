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

include $(shell \
	d=`pwd` ; \
	config='ws.mk_not_found' ; \
	while [ $$d != '/' ] ; do \
		if [ -f $$d/ws.mk ] ; then \
			config=$$d/ws.mk ; \
			break ; \
		fi ; \
		d=`dirname $$d` ; \
	done ; \
	echo $$config)

srcDir	:=	$(srcTop)/drop

include $(srcTop)/drop/src/prefix.mk

bins	:=	buildpkg dmake dregress dstamp dws
shares	:=	drop.pdf devinfra.pdf

doc/dws.book: dws
	$(installDirs) $(dir $@)
	(echo '<?xml version="1.0"?>' \
	&& echo '<section xmlns="http://docbook.org/ns/docbook" xmlns:xlink="http://www.w3.org/1999/xlink"><info><title>dws --help</title></info><title>dws --help</title><para role="code">' \
	&& python ./dws --help \
	&& echo "</para></section>") > $@ || rm -f $@

drop.fo: $(call bookdeps,$(srcDir)/doc/drop.book)

devinfra.fo: $(call bookdeps,$(srcDir)/doc/devinfra.book)

include $(srcTop)/drop/src/suffix.mk

all:: doc/dws.book

install:: dws.py dstamp.py $(srcTop)/drop/src/prefix.mk \
		$(srcTop)/drop/src/suffix.mk \
		$(srcTop)/drop/src/configure.sh \
		$(srcTop)/drop/src/index.xsd \
		doc/dws.book
	$(installFiles) $(filter %.py,$^) $(binDir)
	$(installDirs)  $(etcDir)/dws
	$(installFiles) $(filter %.sh %.mk %.xsd,$^) $(etcDir)/dws

dmake:
	echo '#!/bin/sh' > $@
	echo 'dws make $$*' >> $@

