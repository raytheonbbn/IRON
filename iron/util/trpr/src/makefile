#=============================================================================
# Makefile.terminal
#
# NOTE:  Please refrain from defining flags in the terminal Makefiles (this
#        Makefile), their proper place is in the build/BUILD_STYLE file.  If
#        necessary, create a separate build/BUILD_STYLE that has the required
#        flags defined.
#=============================================================================

#-----------------------------------------------------------------------------
# Include path.  Use this section if any source files to be compiled require
# header files outside of this directory.
#-----------------------------------------------------------------------------

#
# Define the include paths to be used in compiling all source files
# (e.g. -I../include).
#
INCLUDE_PATH = -I.

#-----------------------------------------------------------------------------
# Compiler flags.  Use this section if any source files to be compiled require
# special flags.
#-----------------------------------------------------------------------------

#
# Define the compiler flags to be used in compiling all source files
# (e.g. -pthread for multi-threaded code, -fpic (or -fPIC) for shared
# object code, -rdynamic for linking executables utilizing shared objects,
# etc.).
#
OPT_FLAGS = -pthread

#-----------------------------------------------------------------------------
# Shared object creation.  Use this section if you are building a shared
# object.
#-----------------------------------------------------------------------------

#
# Define name of shared object to be created (e.g. libSONAME.so).
#
SO_NAME = 

#
# Define the shared object major, minor and revision numbers.
#
SO_MAJ_NUM = 
SO_MIN_NUM = 
SO_REV_NUM = 

#
# Define source code associated with shared object (e.g. SRC1.c SRC2.cc ...).
#
SO_SOURCE = 

#
# Define libraries needed for shared object creation (e.g. -lLIBNAME).
#
SO_LIBS = 

#
# Define library paths needed for the libraries above (e.g. -LLIBPATH).
#
SO_LIBRARY_PATH = 

#-----------------------------------------------------------------------------
# Library creation.  Use this section if you are building a library.
#-----------------------------------------------------------------------------

#
# Define name of library to be created (e.g. libLIBNAME.a).
#
LIB_NAME = 

#
# Define source code associated with library (e.g. SRC1.c SRC2.cc ...).
#
LIB_SOURCE = 

#-----------------------------------------------------------------------------
# Executable creation.  Use this section if you are building an executable.
#-----------------------------------------------------------------------------

#
# Define name of executable to be created (e.g. PROG).
#
EXE_NAME = trpr

#
# Define source code associated with executable (e.g. EXESRC1.c EXESRC2.cc).
#
EXE_SOURCE = trpr.cpp

#
# Define libraries needed for executable creation (e.g. -lLIBNAME).
#
EXE_LIBS = -lm

#
# Define library paths needed for the libraries above (e.g. -LLIBPATH).
#
EXE_LIBRARY_PATH = -L${LIB_LOCATION}

#-----------------------------------------------------------------------------
# LinkEm-specific settings.  These are NON-STANDARD SETTINGS!  These are only
# here to force LinkEm to be compiled with optimizations regardless of the
# current build style.  Comment these out for LinkEm to build using the
# current build style.
#-----------------------------------------------------------------------------

BUILD_MODE  = optimized
BUILD_STYLE = ${OSNAME}_${OSREL}_${BUILD_MODE}

#-----------------------------------------------------------------------------
# Internals.  Do not modify anything below.
#-----------------------------------------------------------------------------

#
# Include the standard terminal makefile.
#
include ${MAKE_HOME}/terminal.mk
