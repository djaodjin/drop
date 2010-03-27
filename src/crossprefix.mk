# -*- Makefile -*-

CC.host		:= gcc
CXX.host      	:= g++
AR.host	     	:= ar

CFLAGS.host	:=	-g -MMD
CXXFLAGS.host	:=	-g -MMD

targetOS	:=	
target 		:= 

include $(etcDir)/builder/prefix.mk

# Fix installed directory
includeDir	:=	$(buildTop)/$(target)/include
libDir		:=	$(buildTop)/$(target)/lib
