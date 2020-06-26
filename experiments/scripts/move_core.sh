#!/usr/bin/env bash

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


this="${0##*/}"

# This script checks to see whether a core file exists (on the local machine).
# If so, it renames it based on the argument exp_label, which is intended to
# help a user link it to the experiment that generated the core file. The
# name is placed in a file called core_file.txt in the experiment results
# directory.
#
# This should be run with exactly two arguments:
#
#   results_dir    : the path to the results directory
#   exp_label       : a unique label to be used to rename core files
#
if [ "$#" -ne 2 ]; then
    echo "Usage:"
    echo "  ${this} results_dir exp_label"
    exit 1
fi

RESULTS_DIR=$1

# Append a random number to help get uniqueness
EXP_LABEL="$2-$((100 + RANDOM % 1000000))"

if [ -e core ]; then
    echo "Found a core file! Moving to core-${EXP_LABEL}."
    echo "core-${EXP_LABEL}" > ${RESULTS_DIR}/core_file.txt
    mv core core-${EXP_LABEL}
fi
