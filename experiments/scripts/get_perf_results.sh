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

# Make sure we have the correct number of command line arguments.
# This should be run with exactly four arguments:
#
#   iron_exp_dir    : the path to iron_exps
#   experiment_name : the name of the experiment e.g. '2-node'
#   run_dir         : The name of the run directory.
if [ "$#" -ne 3 ]; then
    echo "Usage:"
    echo "  ${this} iron_exp_dir exp_name run_dir"
    exit 1
fi

IRON_EXP_DIR=$1
EXP_NAME=$2
RUN_DIR=$3

# Set up the environment for the script.
source $IRON_EXP_DIR/${EXP_NAME}/exp.cfg

RESULTS_DIR=${IRON_EXP_DIR}/${EXP_NAME}/${RUN_DIR}/results
if [ ! -f "${RESULTS_DIR}" ]; then
    mkdir -p ${RESULTS_DIR}
fi

LOG_DIR=${IRON_EXP_DIR}/${EXP_NAME}/${RUN_DIR}/logs

IRON_COMPONENTS=(bpf tcp_proxy udp_proxy amp)

for COMP in ${IRON_COMPONENTS[*]}; do
    # Process the performance data for each component.
    if [ -e ${LOG_DIR}/${COMP}-perf.log ]; then
        ${IRON_EXP_DIR}/scripts/get_perf.sh ${LOG_DIR} ${COMP} > \
            ${RESULTS_DIR}/${COMP}-perf.txt
    fi
done

# Move the gmon.pid files to more meaningful names
if [ -e $IRON_EXP_DIR/$EXP_NAME/${RUN_DIR}/logs/pidmap.txt ]; then
    for COMP in ${IRON_COMPONENTS[*]}; do
        # Process the performance data for each component.

        CPID=`grep ${COMP} $IRON_EXP_DIR/$EXP_NAME/${RUN_DIR}/logs/pidmap.txt \
                | cut -d " " -f2`
        if [ -e $IRON_EXP_DIR/$EXP_NAME/${RUN_DIR}/logs/gmon.${CPID} ]; then
            mv $IRON_EXP_DIR/$EXP_NAME/${RUN_DIR}/logs/gmon.${CPID} \
                $IRON_EXP_DIR/$EXP_NAME/${RUN_DIR}/logs/${COMP}.gmon
        fi
    done

    rm $IRON_EXP_DIR/$EXP_NAME/${RUN_DIR}/logs/pidmap.txt
fi
