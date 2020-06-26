#!/bin/sh

#=============================================================================
# template.bash
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

if [ -z ${IRON_HOME} ]; then
  echo "IRON_HOME is not set, please set it and re-source this file."
  return
fi

#-----------------------------------------------------------------------------
# Add any default locations for required third-party tools or libraries here.
#-----------------------------------------------------------------------------

if [ -z ${CPPUNIT_HOME} ]; then
  export CPPUNIT_HOME=/usr
  echo "IRON depends on the cppunit system."
  echo "Setting CPPUNIT_HOME to ${CPPUNIT_HOME}."
fi

#-----------------------------------------------------------------------------
# Set the file creation mask, the OS name and release, and the project name.
#-----------------------------------------------------------------------------

umask 002
export OSNAME=`uname -s`
export OSREL=`uname -r | awk 'BEGIN { FS = "." } { print $1 "." $2 }'`
export PROJECT_NAME=iron

#-----------------------------------------------------------------------------
# Support for Makefile functionality.  Generate the "style" of the build.
#-----------------------------------------------------------------------------

if [ -z ${BUILD_STYLE} ]; then
  export BUILD_STYLE="${OSNAME}_${OSREL}_${BUILD_MODE}"
else
  echo "BUILD_STYLE was set to ${BUILD_STYLE}"
  export BUILD_STYLE="${OSNAME}_${OSREL}_${BUILD_MODE}"
  echo "BUILD_STYLE now set to ${BUILD_STYLE}"
fi

export BUILD_SUBDIR=${BUILD_STYLE}

#-----------------------------------------------------------------------------
# Detect support for GCC visibility.
#-----------------------------------------------------------------------------

GCCVCNT=`/usr/bin/gcc -v --help 2>&1 | grep "fvisibility" | wc -l`

if [ ${GCCVCNT} -gt "0" ]; then
  export IRON_GCC_VISENV="-DGCC_HASCLASSVISIBILITY"
  export IRON_GCC_VISSOF="-fvisibility=hidden -fvisibility-inlines-hidden"
else
  export IRON_GCC_VISENV=
  export IRON_GCC_VISSOF=
fi

GCCVCNT=

#-----------------------------------------------------------------------------
# Establish the location of subsystems which are combined during builds.
#-----------------------------------------------------------------------------

export PROJECT_HOME=${IRON_HOME}
export MAKE_HOME=${PROJECT_HOME}/build

export IRON_COMMON_HOME=${PROJECT_HOME}/common

#-----------------------------------------------------------------------------
# Add the IRON shared object location to the load library path.
#-----------------------------------------------------------------------------

if [ -z "${LD_LIBRARY_PATH}" ]; then
  export LD_LIBRARY_PATH=${PROJECT_HOME}/lib/${BUILD_STYLE}
else
  export LD_LIBRARY_PATH=${PROJECT_HOME}/lib/${BUILD_STYLE}:${LD_LIBRARY_PATH}
fi

#-----------------------------------------------------------------------------
# Add the executable location to the PATH.
#-----------------------------------------------------------------------------

export PATH=${PROJECT_HOME}/bin/${BUILD_STYLE}:${PATH}

#-----------------------------------------------------------------------------
# Add any third-party run-time libraries to the load library path.
#-----------------------------------------------------------------------------

export LD_LIBRARY_PATH=${CPPUNIT_HOME}/lib:$LD_LIBRARY_PATH

#-----------------------------------------------------------------------------
# Add any third-party run-time tools to the path and load library path.
#-----------------------------------------------------------------------------

# if [ ${BAR_HOME} ]; then
#   echo "BAR_HOME was set to ${BAR_HOME}"
#   export LD_LIBRARY_PATH=${BAR_HOME}/lib:$LD_LIBRARY_PATH
#   export PATH=${BAR_HOME}/bin:${PATH}
# fi

#-----------------------------------------------------------------------------
# Add the IRON common python modules to the python path.
#-----------------------------------------------------------------------------

PYTHON_PACKAGE_DIR=${PROJECT_HOME}/python
if [ -z "${PYTHONPATH}" ]; then
  export PYTHONPATH=${PYTHON_PACKAGE_DIR}
else
  export PYTHONPATH=${PYTHON_PACKAGE_DIR}:${PYTHONPATH}
fi
