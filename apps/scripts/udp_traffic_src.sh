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

#
# This script starts a udp traffic flow. The details of the flow are
# captured in a text file that includes the following information for
# each desired flow:
#
# <dst addr> <dst port> <start time> <end time> <packet size> <data rate>
#
# See the file '3_udp_flows.txt' in the IRON/apps/cfg directory for an
# example input file.
#

#
# The script's name for error messages.
#
this="${0##*/}"

#
# Ensure that we have provided the correct number of command-line
# arguments to the script.
#
if [ $# != 2 ]; then
    echo "Usage: $this <input file> <src|dest>"
    exit 1
fi

# 
# Generate the mgen input file. This is accomplished by running a
# python script. We pass the input file describing the desired flows
# and whether we are going to be a src or a dest into the python
# script.
#
python generate_mgen_input_file.py $1 $2 > /tmp/mgen_input.mgn

#
# Start mgen with the generated file as input.
#
mgen input /tmp/mgen_input.mgn
