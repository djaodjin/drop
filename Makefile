# -*- Makefile -*-

include $(shell \
	d=`pwd` ; \
	config='.buildrc_not_found' ; \
	while [ $$d != '/' ] ; do \
		if [ -f $$d/.buildrc ] ; then \
			config=$$d/.buildrc ; \
			break ; \
		fi ; \
		d=`dirname $$d` ; \
	done ; \
	echo $$config)

srcDir	:=	$(topSrc)/drop

include $(topSrc)/drop/src/prefix.mk

bins	:=	dintegrity dcontext dmake dregress dstamp dsync dws

include $(topSrc)/drop/src/suffix.mk

install:: dcontext.py
	$(installFiles) $^ $(binDir)