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


# Start gulp capture on a testbed node. NOTE: This script should only
# be executed on the target testbed node. The start_gulp.sh script
# should be used to start the gulp captures on ALL of the experiment's
# testbed nodes from a single machine.
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - Experiments have been installed
#
# This script requires 5 command line arguments:
#   1. the experiment base directory
#   2. the experiment name
#   3. the experiment run directory
#   4. the interface name for the capture
#   5. the generic link name.

# This script's name for error messages.
this="${0##*/}"

#=============================================================================
# Print out usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Start gulp capture on a testbed node. NOTE: This script should"
    echo "only be executed on the target testbed node. The start_gulp.sh"
    echo "script should be used to start the gulp captures on ALL of the"
    echo "experiment's testbed nodes from a single machine."
    echo ""
    echo "This script requires the following:"
    echo "  - Testbed nodes have been reserved"
    echo "  - Experiments have been installed"
    echo ""
    echo "Usage:"
    echo "  ${this} exp_base_dir exp_name run_dir interface_name"
    echo "    generic_link_name"
    echo ""
    if [ "${ERROR_MSG}" != "" ]; then
	echo ""
	echo "${ERROR_MSG}"
	echo ""
	echo ""
    fi
    exit 1
}

#=============================================================================

# Process the command line options.
while getopts h OPTION; do
    case ${OPTION} in
        h|?)
            usage;;
    esac
done

# Make sure we have the correct number of command line arguments.
if [ "$#" -ne 5 ]; then
    usage "Error: Expected 5 command line arguments, $# provided."
fi

EXP_BASE_DIR=$1
EXP_NAME=$2
RUN_DIR=$3
INF_NAME=$4
LINK_NAME=$5
EXP_DIR=${EXP_BASE_DIR}/iron_exps

export RUNTIME=`date +%Y_%m_%d_%H_%M_%S.pcap`

# Start the capture.
screen -d -m ${EXP_DIR}/bin/gulp -i ${INF_NAME} \
    -o ${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/pcaps/ \
    -n ${EXP_NAME}-${INF_NAME}-${LINK_NAME}-${RUNTIME} -s 384 -r 1000

# Exit the script successfully.
exit 0
