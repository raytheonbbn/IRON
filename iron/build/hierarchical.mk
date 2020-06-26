#=============================================================================
# hierarchical.mk
#
# Purpose:  This file is used for a hierarchical make, in which a hierarchical
#           makefile (based on Makefile.hierarchical) lists all of the 
#           subdirectories which require building.
#
# Two symbols may be defined by a hierarchical makefile:
#
#   SRC_DIRS : A list of directories which have regular C and C++ code to
#              build.
#
#   ADJACENT_MAKEFILES : A list of makefiles in the current directory which
#                        should be executed.
#=============================================================================

#-----------------------------------------------------------------------------
# Store the working directory.
#-----------------------------------------------------------------------------

CURRENT_PWD := $(shell pwd)

#-----------------------------------------------------------------------------
# Targets.
#-----------------------------------------------------------------------------

default: segment

all: LIB SHOBJ exe

world: clean lib shobj exe

shobj: SHOBJ

lib: LIB

#-----------------------------------------------------------------------------
# Rules.
#-----------------------------------------------------------------------------

RECURSIVE_TARGETS = dirs clean segment SHOBJ LIB exe install docs test-style test-flags test-lists test-all

${RECURSIVE_TARGETS}:
ifdef SRC_DIRS
	@for i in ${SRC_DIRS}; do \
	  echo "====> MAKE Recursion: TARGET($@) DIR(${CURRENT_PWD}/$$i)"; \
	  cd ${CURRENT_PWD}/$$i; \
	  set -e; ${MAKE} "PWD=${PWD}/$$i" "PWD_START=${PWD}" $@ ; \
	done
endif
ifdef ADJACENT_MAKEFILES
	@for i in ${ADJACENT_MAKEFILES}; do \
	  echo "====> ADJACENT MAKE: TARGET($@) FILE(${CURRENT_PWD}/$$i)"; \
	  set -e; ${MAKE} -f $$i "PWD=${PWD}" "PWD_START=${PWD}" $@ ; \
	done
endif

#
# End of hierarchical.mk.
#
