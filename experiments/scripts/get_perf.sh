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


# Compute performance metrics for an IRON binary.
#
# Currently, this only computes Average CPU utilization. In the future
# additional metrics may be added.

# This script's name for error messages.
this="${0##*/}"

# Make sure we have the correct number of command line arguments.
if [ "$#" -ne 2 ]; then
    echo "Usage: ${this} log_directory iron_binary"
    exit 1
fi

LOG_DIR=$1
BIN=$2
NUM_SAMPLES=0
CUMULATIVE_CPU_UTILIZATION=0
MAX_CPU_UTILIZATION=0

if [ ! -e ${LOG_DIR}/${BIN}-perf.log ]; then
    echo "${LOG_DIR}/${BIN}-perf.log does not exist."
    exit 1
fi

for i in `grep CPU -A 1 ${LOG_DIR}/${BIN}-perf.log | grep -v CPU | grep -v "\-\-" | tr -s ' ' | cut -d " " -f8`;
do
    if (( $(echo "$i > 5.00" | bc -l) )); then
        NUM_SAMPLES=`echo ${NUM_SAMPLES}+1 | bc`
        CUMULATIVE_CPU_UTILIZATION=`echo ${CUMULATIVE_CPU_UTILIZATION}+$i |bc`
        if (( $(echo "$i > ${MAX_CPU_UTILIZATION}" | bc -l) )); then
            MAX_CPU_UTILIZATION=$i
        fi
    fi
done

echo "Number of samples: ${NUM_SAMPLES}"
echo "Cumulative CPU Utilization: ${CUMULATIVE_CPU_UTILIZATION}"

if [ ${NUM_SAMPLES} -gt 0 ]; then
    AVERAGE_CPU_UTILIZATION=$(echo "scale=2; ${CUMULATIVE_CPU_UTILIZATION}/${NUM_SAMPLES}" | bc -l)
fi
echo "Average CPU Utilization: ${AVERAGE_CPU_UTILIZATION}%"
echo "Maximum CPU Utilization: ${MAX_CPU_UTILIZATION}%"

# Exit script successfully.
exit 0
