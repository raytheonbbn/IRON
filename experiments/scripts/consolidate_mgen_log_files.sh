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


#
# Consolidate mgen log files. This script expects 3 command line arguments, the
# experiment base directory, the experiment name and the run directory.

# This script's name for error messages.
this="${0##*/}"

# Make sure we have the correct number of command line arguments.
if [ "$#" -ne 3 ]; then
    echo "Usage: ${this} experiment_base_dir experiment_name run_dir"
    exit 1
fi

EXP_BASE_DIR=$1
EXP_NAME=$2
RUN_DIR=$3
EXP_DIR=${EXP_BASE_DIR}/iron_exps

# Check that there are logs to be consolidated.
if ls ${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/logs/mgen_input* 1> /dev/null 2>&1; then
    cd ${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/logs

    # If mgen.log doesn't exist, create it
    if [ ! -e mgen.log ]; then
	# mgen_input logs are sorted, so only have to merge them
	sort -m -k1 mgen_input*.log > mgen.log
        rm mgen_input*.log
    fi
fi

# Exit the script successfully.
exit 0
