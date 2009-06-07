# -*- Makefile -*-

.DEFAULT_GOAL 	:=	all

installDirs 	:=	install -d
installFiles	:=	install -m 644
installExecs	:=	install -m 755

srcDir		?=	$(subst $(dir $(shell dcontext)),$(topSrc)/,$(shell pwd))

includes	:=	$(wildcard $(srcDir)/include/*.hh $(srcDir)/include/*.tcc)

CXXFLAGS	:=	-g -MMD
CPPFLAGS	+=	-I$(srcDir)/include -I$(includeDir)
LDFLAGS		+=	-L$(libDir)

vpath %.a 	$(libDir)
vpath %.cc 	$(srcDir)/src
vpath %.py	$(srcDir)/src
