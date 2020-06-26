#!/usr/bin/env bash
#
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


# Start mgen. This script expects 4 command line arguments, the
# experiment base directory, the experiment name, the run directory,
# and the generic node name.

# This script's name for error messages.
this="${0##*/}"

# Make sure we have the correct number of command line arguments.
if [ "$#" -ne 4 ]; then
    echo "Usage: ${this} experiment_base_dir experiment_name run_dir" \
        "generic_node_name"
    exit 1
fi

EXP_BASE_DIR=$1
EXP_NAME=$2
RUN_DIR=$3
NODE_NAME=$4
EXP_DIR=${EXP_BASE_DIR}/iron_exps
EXP_RUN_DIR=${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/${RUN_DIR}

# Start mgen processes
MGEN_CFG_FILES=$(find ${EXP_RUN_DIR}/cfgs -name "mgen_input_${NODE_NAME}_*.mgn" -print)

for MGEN_FILE in $MGEN_CFG_FILES; do
    mgen_file_name=$(basename $MGEN_FILE)
    mfn_no_ext=${mgen_file_name%.*}
    screen -d -m mgen input ${MGEN_FILE} txlog output ${EXP_RUN_DIR}/logs/$mfn_no_ext.log
done
# Exit the script successfully.
exit 0
