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
#     * Neither the name of codespin nor the
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

# -*- Makefile -*-

.DEFAULT_GOAL 	:=	all

installDirs 	:=	install -d
installFiles	:=	install -m 644
installExecs	:=	install -m 755

# \note For some reason when a '\' is inserted in the following line in order
#       to keep a maximum of 80 characters per line, the sed command 
#       in contributors/smirolo/Makefile complains about an extra 
#       '\n' character.
srcDir		?=	$(subst $(dir $(shell dws context)),$(srcTop)/,$(shell pwd))

includes	:=	$(wildcard $(srcDir)/include/*.hh \
	                           $(srcDir)/include/*.tcc)

CXXFLAGS	:=	-g -MMD
CPPFLAGS	+=	-I$(srcDir)/include -I$(includeDir)
LDFLAGS		+=	-L$(libDir)

vpath %.a 	$(libDir)
vpath %.cc 	$(srcDir)/src
vpath %.py	$(srcDir)/src


define bldUnitTest

$(1): $(1).cc $(testDepencencies)

endef
