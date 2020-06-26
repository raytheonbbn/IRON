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


# Starts LinkEm Path adjustments on the experiment's reserved testbed nodes
# per the experiment's configuration.
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - Experiments have been installed
#   - LinkEm instances are running on the experiment nodes

# This script's name for error messages.
this="${0##*/}"

RUN_DIR="run1"
DEBUG_FLAG=0

#=============================================================================
# Print out the usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Starts the Path LinkEm adjustments on the experiment's reserved"
    echo "testbed per the experiment's configuration."
    echo ""
    echo "This script requires the following:"
    echo "  - Testbed nodes have been reserved"
    echo "  - Experiments have been installed"
    echo "  - LinkEm instances are running on the experiment nodes"
    echo ""
    echo "Usage:"
    echo "  ${this} [-r <run_dir>] [-h] exp_name"
    echo ""
    echo "Options:"
    echo "  -r <run_dir>  Experiment run directory (e.g., run1, run2, etc)."
    echo "                Default: run1"
    echo "  -h            Display usage information."
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
while getopts r:h OPTION; do
    case ${OPTION} in
	r)
	    RUN_DIR=${OPTARG};;
        h|?)
            usage;;
    esac
done

# Grab the command line arguments.
shift $(($OPTIND - 1))

# Make sure we have the correct number of command line arguments.
if [ "$#" -ne 1 ]; then
    usage "Error: 1 command line argument expected, $# provided."
fi

EXP_NAME=$1
STAGING_DIR=${HOME}/iron_exp_staging

# Start LinkEm adjustments with full system up and running
LEM_SCRIPT=${STAGING_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/lem.sh
if [ -f ${LEM_SCRIPT} ]; then
    ${LEM_SCRIPT} < /dev/null \
		  2>&1 > ${STAGING_DIR}/${EXP_NAME}/${RUN_DIR}/LinkEmClient.log &
fi

echo ""

# Exit the script successfully.
exit 0
