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


# This script's name for usage /error messages.
this="${0##*/}"

usage() {
    echo "Usage:"
    echo "  ${this} [-p] <command to monitor> <log dir> <period>"
    echo ""
    echo "Options:"
    echo "  -p    the command passed is a python script therefore don't use pidof to find process id."
    exit 1
}

PYTHON_SCRIPT=false
while getopts ph option; do
    case $option in
        p)
            PYTHON_SCRIPT=true;;
        h|?)
            usage;;
    esac
done

# Grab the command line arguments.
shift $(($OPTIND - 1))

if [ $# -ne 3 ]; then
    usage
fi

BIN=$1
LOG_DIR=$2
PERIOD=$3

if ${PYTHON_SCRIPT}; then
    PID=$(ps -aef | grep ${BIN} | grep python  | sed 's/[[:space:]][[:space:]]*/ /g' | cut -f 2 -d ' ')
else
    PID=$(pidof ${BIN})
fi

pidstat -r -u -p ${PID} ${PERIOD} 1>${LOG_DIR}/${BIN}-perf.log 2>&1

