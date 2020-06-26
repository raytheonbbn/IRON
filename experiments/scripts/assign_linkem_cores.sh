#!/bin/bash

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

echo "Assigning LinkEm processes to cores on host ${HOSTNAME}"

PID_LIST="$(ps ax | grep "LinkEm -1 " | \
    grep -v "0:00" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)"

# Cast the string as an array
LINKEM_PIDS=( $PID_LIST )

#NUM_PIDS=${#LINKEM_PIDS[@]}
#if [ ${NUM_PIDS} != 1 ]; then
#    echo "  Found ${NUM_PIDS} LinkEm processes"
#else
#    echo "  Found ${NUM_PIDS} LinkEm process"
#fi

NUM_CORES=`cat /proc/cpuinfo |grep -c '^process'`
CORE=$((NUM_CORES-1))
for PID in ${LINKEM_PIDS[@]}; do
#    echo "    Assigning process id ${PID} to core ${CORE}"
    sudo taskset -cp ${CORE} ${PID}
    if [ ${CORE} -ge 1 ] 
    then
	CORE=$((CORE-1))
    fi
done

# Exit the script successfully.
exit 0
