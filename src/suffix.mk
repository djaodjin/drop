# -*- Makefile -*-

.PHONY:	all install

all::	$(bins) $(libs) $(includes)

clean::
	rm -rf *

install:: $(bins) $(libs) $(includes)
	$(if $(bins),$(installDirs) $(binDir))
	$(if $(bins),$(installExecs) $(bins) $(binDir))
	$(if $(libs),$(installDirs) $(libDir))
	$(if $(libs),$(installFiles) $(libs) $(libDir))
	$(if $(includes),$(installDirs) $(includeDir))
	$(if $(includes),$(installFiles) $(includes) $(includeDir))

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
#
# \todo insert the prefix.mk, suffix.mk. Maybe the dcontext as well.
dist:
	tar -cj --exclude '.*' --exclude '*~' -f $(notdir $(srcDir)).tar.bz2 \
		-C $(dir $(srcDir)) $(notdir $(srcDir))

-include *.d
