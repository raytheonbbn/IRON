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
# Starts the IRON components (AMP, BPF, TCP Proxy, and UDP Proxy) on
# the experiment's reserved testbed nodes.
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - Experiments have been installed

# This script's name for error messages.
this="${0##*/}"

RUN_DIR="run1"
DEBUG_FLAG=0
DEBUG_OPTION=""

#=============================================================================
# Print out the usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Starts the IRON components (AMP, BPF, TCP Proxy, and UDP Proxy)"
    echo "on the experiment's reserved testbed nodes."
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
            DEBUG_FLAG=1
	    DEBUG_OPTION="-d";;
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
DONE_FILE_WAIT=0.2
STAGING_DIR=${HOME}/iron_exp_staging
INITIAL_START_TIMESTAMP=$(date -u "+%Y_%m_%dT%H_%M_%SZ")
STAGE_TMP_DIR=/tmp/${INITIAL_START_TIMESTAMP}/${EXP_NAME}/${RUN_DIR}

mkdir -p ${STAGE_TMP_DIR}

# Set up the environment for the script.
#
# EXP_BASE_DIR and USER_NAME are defined in exp.cfg
source ${STAGING_DIR}/${EXP_NAME}/exp.cfg
source ${STAGING_DIR}/scripts/common_start.sh
source ${STAGING_DIR}/scripts/log.sh

EXP_DIR=${EXP_BASE_DIR}/iron_exps
LOG_DIR=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/logs

echo ""

# Start the IRON software (in parallel).
NO_PROXY_INBOUND_IF="-------"
for NODE_INFO in ${IRON_NODES[*]}; do
    GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
    FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)

    PROXY_INBOUND_IF=${NO_PROXY_INBOUND_IF}
    for PROXY_INFO in ${PROXY_INBOUND_IFS[*]}; do
        NODE_NAME=$(echo ${PROXY_INFO} | cut -d ':' -f1)
        IF_NAME=$(echo ${PROXY_INFO} | cut -d ':' -f2)
        if [ "${GENERIC_NODE_NAME}" == "${NODE_NAME}" ]; then
            PROXY_INBOUND_IF=${IF_NAME}
            break
        fi
    done
    CFG=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/udp_proxy_${GENERIC_NODE_NAME}.cfg
    if [ "${PROXY_INBOUND_IF}" == "${NO_PROXY_INBOUND_IF}" ] && [ -e "${CFG}" ]; then
        echo ""
        echo "Inbound Interface not found for ${GENERIC_NODE_NAME}."
        echo "Exiting..."
        echo ""
        exit 1
    fi

    MONITOR_OPTION=""
    if [ -z ${MONITOR_PERF} ]; then
        MONITOR_PERF=false
    fi
    if [ ${MONITOR_PERF} ]; then
	MONITOR_OPTION="-m"
    fi
    if [ -z ${MONITOR_PERIOD} ]; then
        MONITOR_PERIOD=1
    fi
    log echo ""
    echo "Starting IRON components on ${FQ_NODE_NAME}..."
    DONE_FILE=${STAGE_TMP_DIR}/${GENERIC_NODE_NAME}_iron_start.done
    (ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
	 sudo ${EXP_DIR}/scripts/start_iron.sh \
         -b ${EXP_BASE_DIR} ${DEBUG_OPTION} ${MONITOR_OPTION} \
	 -p ${MONITOR_PERIOD} -r ${RUN_DIR} ${EXP_NAME} ${GENERIC_NODE_NAME} \
         ${PROXY_INBOUND_IF} \
         > ${STAGE_TMP_DIR}/${GENERIC_NODE_NAME}_iron_startup.log; \
     touch ${DONE_FILE}) &
done

# Wait for each node to complete startup
for NODE_INFO in ${IRON_NODES[*]}; do
    GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
    FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
    DONE_FILE=${STAGE_TMP_DIR}/${GENERIC_NODE_NAME}_iron_start.done
    echo ""
    echo "Waiting for ${FQ_NODE_NAME} to finish starting ..."
    until [ -e ${DONE_FILE} ]; do
        sleep ${DONE_FILE_WAIT}
    done
    echo ""
    echo "${FQ_NODE_NAME} startup output:"
    cat ${STAGE_TMP_DIR}/${GENERIC_NODE_NAME}_iron_startup.log

    echo ""
done

# Remove the temporary directory that was created to wait for the IRON
# nodes to complete their startup.
rm -rf /tmp/${INITIAL_START_TIMESTAMP}

# Exit the script successfully.
exit 0
