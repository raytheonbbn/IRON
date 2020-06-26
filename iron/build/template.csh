#!/bin/csh

#=============================================================================
# template.csh
#
# This script sets the environment variables necessary for software builds in
# ${BUILD_MODE} mode.
#
# Assumptions:  This script requires that the following environment variable
# be set before sourcing this script:
#
#   IRON_HOME
#
# An example of IRON_HOME would be /home/juser/IRON-current/IRON/iron.
#=============================================================================

if(! $?IRON_HOME ) then
  echo "IRON_HOME is not set, please set it and re-source this file."
  exit
endif

#-----------------------------------------------------------------------------
# Add any default locations for required third-party tools or libraries here.
#-----------------------------------------------------------------------------

if(! $?CPPUNIT_HOME ) then
  setenv CPPUNIT_HOME /usr
  echo "IRON depends on the cppunit system."
  echo "Setting CPPUNIT_HOME to ${CPPUNIT_HOME}."
endif

#-----------------------------------------------------------------------------
# Set the file creation mask, the OS name and release, and the project name.
#-----------------------------------------------------------------------------

umask 002
setenv OSNAME        `uname -s`
setenv OSREL         `uname -r | awk 'BEGIN { FS = "." } { print $1 "." $2 }'`
setenv PROJECT_NAME  iron

#-----------------------------------------------------------------------------
# Support for Makefile functionality.  Generate the "style" of the build.
#-----------------------------------------------------------------------------

if(! $?BUILD_STYLE ) then
  setenv BUILD_STYLE "${OSNAME}_${OSREL}_${BUILD_MODE}"
else
  echo "BUILD_STYLE was set to ${BUILD_STYLE}"
  setenv BUILD_STYLE "${OSNAME}_${OSREL}_${BUILD_MODE}"
  echo "BUILD_STYLE now set to ${BUILD_STYLE}"
endif

setenv BUILD_SUBDIR ${BUILD_STYLE}

#-----------------------------------------------------------------------------
# Detect support for GCC visibility.
#-----------------------------------------------------------------------------

set GCCVCNT=`/usr/bin/gcc -v --help |& grep "fvisibility" | wc -l`

if ( $GCCVCNT > 0 ) then
  setenv IRON_GCC_VISENV "-DGCC_HASCLASSVISIBILITY"
  setenv IRON_GCC_VISSOF "-fvisibility=hidden -fvisibility-inlines-hidden"
else
  setenv IRON_GCC_VISENV ""
  setenv IRON_GCC_VISSOF ""
endif

unset GCCVCNT

#-----------------------------------------------------------------------------
# Establish the location of subsystems which are combined during builds.
#-----------------------------------------------------------------------------

setenv PROJECT_HOME                ${IRON_HOME}
setenv MAKE_HOME                   ${PROJECT_HOME}/build

setenv IRON_COMMON_HOME             ${PROJECT_HOME}/common

#-----------------------------------------------------------------------------
# Add the IRON shared object location to the load library path.
#-----------------------------------------------------------------------------

if(! $?LD_LIBRARY_PATH ) then
  setenv LD_LIBRARY_PATH ${PROJECT_HOME}/lib/${BUILD_STYLE}
else
  setenv LD_LIBRARY_PATH ${PROJECT_HOME}/lib/${BUILD_STYLE}:${LD_LIBRARY_PATH}
endif

#-----------------------------------------------------------------------------
# Add the executable location to the PATH.
#-----------------------------------------------------------------------------

setenv PATH ${PROJECT_HOME}/bin/${BUILD_STYLE}:${PATH}
rehash

#-----------------------------------------------------------------------------
# Add any third-party run-time libraries to the load library path.
#-----------------------------------------------------------------------------

setenv LD_LIBRARY_PATH ${CPPUNIT_HOME}/lib:$LD_LIBRARY_PATH

#-----------------------------------------------------------------------------
# Add any third-party run-time tools to the path and load library path.
#-----------------------------------------------------------------------------

# if( $?BAR_HOME ) then
#   echo "BAR_HOME was set to ${BAR_HOME}"
#   setenv LD_LIBRARY_PATH ${BAR_HOME}/lib:${LD_LIBRARY_PATH}
#   setenv PATH ${BAR_HOME}/bin:${PATH}
# endif

#-----------------------------------------------------------------------------
# Add the IRON common python modules to the python path.
#-----------------------------------------------------------------------------

PYTHON_PACKAGE_DIR=${PROJECT_HOME}/python
if(! $?PYTHONPATH ) then
  setenv PYTHONPATH ${PYTHON_PACKAGE_DIR}
else
  setenv PYTHONPATH ${PYTHON_PACKAGE_DIR}:${PYTHONPATH}
endif
