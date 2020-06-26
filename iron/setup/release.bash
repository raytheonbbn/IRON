#!/bin/sh

# IRON: iron_headers
#
# Distribution A
#
# Approved for Public Release, Distribution Unlimited
#
# EdgeCT (IRON) Software Contract No.: HR0011-15-C-0097
# DCOMP (GNAT)  Software Contract No.: HR0011-17-C-0050
# Copyright (c) 2015-20 Raytheon BBN Technologies Corp.
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contracts No. HR0011-15-C-0097 and
# HR0011-17-C-0050. Any opinions, findings and conclusions or
# recommendations expressed in this material are those of the author(s)
# and do not necessarily reflect the views of the Defense Advanced
# Research Project Agency.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# IRON: end

#=============================================================================
# release.bash
#
# This script sets the environment variables necessary for running binary
# releases.
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
# Add any default locations for required third-party tools here.
#-----------------------------------------------------------------------------

# if [ -z ${FOO_HOME} ]; then
#   export FOO_HOME=/usr/local/src/foo
#   echo "IRON depends on the foo system."
#   echo "Setting FOO_HOME to ${FOO_HOME}."
# fi

#-----------------------------------------------------------------------------
# Add the IRON shared object location to the load library path.
#-----------------------------------------------------------------------------

if [ "X${LD_LIBRARY_PATH}" == "X" ]; then
  export LD_LIBRARY_PATH=${IRON_HOME}/lib
else
  export LD_LIBRARY_PATH=${IRON_HOME}/lib:${LD_LIBRARY_PATH}
fi

#-----------------------------------------------------------------------------
# Add the executable location to the PATH.
#-----------------------------------------------------------------------------

export PATH=${IRON_HOME}/bin:${PATH}

#-----------------------------------------------------------------------------
# Add any required third-party tools to the load library path.
#-----------------------------------------------------------------------------

if [ ${CPPUNIT_HOME} ]; then
  export LD_LIBRARY_PATH=${CPPUNIT_HOME}/lib:$LD_LIBRARY_PATH
fi
