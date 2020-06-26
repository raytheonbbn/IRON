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

Quick-Start Guide
==============================================================================

1.  Make sure you are using bash, tcsh or csh.

2.  Set the "IRON_HOME" environment variable to where this file is located

        export IRON_HOME="<IRON install dir>/IRON/iron"

    or

        setenv IRON_HOME <IRON install dir>/IRON/iron

    where <IRON install dir> is the location of the IRON installation. This
    may be placed in your .bashrc or .cshrc file for convenience. However,
    make sure that this file tests if this environment variable has already
    been set before setting it. A bash example of this is:

        if [ -z "$IRON_HOME" ] ; then
          export IRON_HOME=<IRON install dir>/IRON/iron
        fi

    A tcsh/csh example of this is:

        if (! $?IRON_HOME ) then
          setenv IRON_HOME    <IRON install dir>/IRON/iron
        endif

3.  Source the appropriate setup file, e.g., for bash:

        cd $IRON_HOME
        . setup/debug.bash

    or for tcsh/csh:

        cd $IRON_HOME
        source setup/debug.csh

    Substitute the correct path and setup file name (currently debug.bash,
    optimized.bash, debug.csh, or optimized.csh) depending on your shell and
    how you would like the software built.

4.  If the UNIX platform you are using is something different than Linux with
    a 3.13 or 3.2 kernel, then create the needed debug and optimized style
    files for your platform in the iron/build directory using the
    Linux_3.2_debug and Linux_3.2_optimized style files as templates.  The
    platform name may be determined using the command "uname -s", and the
    version number (of the form X.Y) may be determined using the command
    "uname -r" and ignoring everything after the first and second
    numbers. Replace instances of -DLINUX_3_2 with -DLINUX_X_Y.

5.  To build all native code (C/C++) software, perform the following:

        cd $IRON_HOME
        make clean
        make

6.  To build the unit test code, perform the following:

        cd $IRON_HOME
        make -f makefile.unittest clean
        make -f makefile.unittest

7.  To execute the unit test code, perform the following:

        cd $IRON_HOME
        ./bin/{style-file-name}/testironamp
        ./bin/{style-file-name}/testironbpf
        ./bin/{style-file-name}/testironcommon
        ./bin/{style-file-name}/testirontcpproxy
        ./bin/{style-file-name}/testironudpproxy

    where {style-file-name} is the name of the file described in step 4 -
    for example Linux_3.2_debug.

    The unit tests print out dots while they are executing and a status
    message.

8.  To build the IRON documentation, perform the following:

        cd $IRON_HOME/doc
        make docs

9.  To access the IRON documentation, use a web browser to open the file
    $IRON_HOME/doc/html/index.html


