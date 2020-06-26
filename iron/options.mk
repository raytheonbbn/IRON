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
# options.mk
#=============================================================================

#-----------------------------------------------------------------------------
# Compiler flags.  Use this section if all source files to be compiled within
# the entire project require special flags.
#-----------------------------------------------------------------------------

#
# Define the build options compiler flags to be used in compiling all source
# files in the project.
#
# Include -DSHM_STATS to track and log statistics relating to shared memory
# writes.
#
# Include -DPKT_LEAK_DETECT to track packet ownership, and -DPACKET_TRACKING
# for more detailed packet tracking.
#
# Include -DDROP_TRACKING to count expected packet drops per code location.
# These counts are printed at INFO log level, if enabled.
#
# Include -DLAT_MEASURE to measure the latency of UDP flows in demo mode.
#
# Include -DDEBUG_STATS to enable custom in-memory stats collection.
#
# Include -DXPLOT to enable generating xplot graphs on the fly.
#
# Include -DTTG_TRACKING to enable tracking of TTG values in the log files
# for post-run analysis (see apps/ttg_tracking/README.txt).

#PROJ_FLAGS = -DLAT_MEASURE -DPKT_LEAK_DETECT -DDROP_TRACKING -DXPLOT
PROJ_FLAGS = -DLAT_MEASURE
