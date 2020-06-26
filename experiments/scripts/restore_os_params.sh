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


# This script restores OS parameters.

# This script's name for error messages.
this="${0##*/}"

EXP_BASE_DIR=""
EXP_NAME=""

# Print out the usage information and exit.
usage() {
    echo ""
    echo "Usage:"
    echo "  ${this} -b <exp_base_dir> -e <exp_name>"
    echo ""
    echo "Options:"
    echo "  -b <exp_base_dir>  The experiment base directory."
    echo ""
    echo "  -e <exp_name>      The experiment name."
    exit 1
}

# Process the command line options.
while getopts b:e:h OPTION; do
    case ${OPTION} in
        b)
            EXP_BASE_DIR="$OPTARG";;
        e)
            EXP_NAME="$OPTARG";;
        h|?)
            usage;;
    esac
done

if [ "${EXP_BASE_DIR}" == "" ] || [ "${EXP_NAME}" == "" ]; then
    usage
fi

source ${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/exp.cfg

# Configure pdflush
echo "Restoring OS parameters to default values..."
if [ -n "$dirty_background_ratio" ]; then
    sudo sysctl -w vm.dirty_background_bytes=0
    sudo sysctl -w vm.dirty_background_ratio=10
fi

if [ -n "$dirty_background_bytes" ]; then
    sudo sysctl -w vm.dirty_background_bytes=0
    sudo sysctl -w vm.dirty_background_ratio=10
fi

if [ -n "$dirty_ratio" ]; then
    sudo sysctl -w vm.dirty_bytes=0
    sudo sysctl -w vm.dirty_ratio=20
fi

if [ -n "$dirty_bytes" ]; then
    sudo sysctl -w vm.dirty_bytes=0
    sudo sysctl -w vm.dirty_ratio=20
fi

if [ -n "$dirty_expire_centisecs" ]; then
    sudo sysctl -w vm.dirty_expire_centisecs=3000
fi

if [ -n "$dirty_writeback_centisecs" ]; then
    sudo sysctl -w vm.dirty_writeback_centisecs=500
fi

if [ -n "$swappiness" ]; then
    sudo sysctl -w vm.swappiness=60
fi

if [ -n "$max_dgram_qlen" ]; then
    sudo sysctl -w net.unix.max_dgram_qlen=10
fi

# Exit the script successfully.
exit 0
