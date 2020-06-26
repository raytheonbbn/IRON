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


# Starts the traffic sources/sinks on the experiment's reserved
# testbed nodes.
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - Experiments have been installed

# This script's name for error messages.
this="${0##*/}"

DEBUG=0
RUN_DIR="run1"

#=============================================================================
# Print out the usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Starts the traffic sources/sinks on the experiment's reserved"
    echo "testbed nodes."
    echo ""
    echo "This script requires the following:"
    echo "  - Testbed nodes have been reserved"
    echo "  - Experiments have been installed"
    echo ""
    echo "Usage:"
    echo "  ${this} [-d] [-r <run_dir>] [-h] exp_name"
    echo ""
    echo "Options:"
    echo "  -d            Enable debug logging."
    echo "                Default: Disabled"
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
while getopts dr:h OPTION; do
    case ${OPTION} in
	d)
	    DEBUG=1;;
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
    usage "Error: Expected 1 command line argument, $# provided."
fi

EXP_NAME=$1
STAGING_DIR=${HOME}/iron_exp_staging

# Set up the environment for the script.
#
# EXP_BASE_DIR and USER_NAME are defined in exp.cfg
source ${STAGING_DIR}/${EXP_NAME}/exp.cfg
source ${STAGING_DIR}/scripts/log.sh
source ${STAGING_DIR}/scripts/common_start.sh

EXP_DIR=${EXP_BASE_DIR}/iron_exps

# Run application scripts, if any, on the mgen nodes.
if ls ${STAGING_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/*_app_* 1> /dev/null 2>&1; then
    for NODE_INFO in ${MGEN_NODES[*]}; do
        GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
        FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
        echo "Starting node specific scripts on ${FQ_NODE_NAME}..."
        ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
	    ${EXP_DIR}/scripts/run_node_scripts.sh \
            ${EXP_BASE_DIR} ${EXP_NAME} ${RUN_DIR} ${GENERIC_NODE_NAME}
    done
fi

# Start the mgen sources and sinks.
log echo -n "${this}: mgen START "; log date_timeval
for NODE_INFO in ${MGEN_NODES[*]}; do
    GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
    FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
    log echo -n "Starting mgen on ${FQ_NODE_NAME}... "; log date_timeval
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
	${EXP_DIR}/scripts/run_mgen.sh ${EXP_BASE_DIR} ${EXP_NAME} \
	${RUN_DIR} ${GENERIC_NODE_NAME}
    echo "ssh ${USER_NAME}@${FQ_NODE_NAME} ${EXP_DIR}/scripts/run_mgen.sh"
    echo "${EXP_BASE_DIR} ${EXP_NAME} ${RUN_DIR} ${GENERIC_NODE_NAME}"
    log echo -n "start.sh: mgen $FQ_NODE_NAME "; log date_timeval
done

# Start the video sources and sinks.
if ls ${STAGING_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/gst_* 1> /dev/null 2>&1; then
    log echo -n "${this}: gst START "; log date_timeval
    for NODE_INFO in ${MGEN_NODES[*]}; do
        GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
        FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
        log echo -n "Starting gstreamer on ${FQ_NODE_NAME}... "; log date_timeval
        ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
	    ${EXP_DIR}/scripts/run_gst.sh ${EXP_BASE_DIR} \
	    ${EXP_NAME} $RUN_DIR ${GENERIC_NODE_NAME}
        log echo -n "${this}: gst $FQ_NODE_NAME "; log date_timeval
    done
fi

# Exit the script successfully.
exit 0
