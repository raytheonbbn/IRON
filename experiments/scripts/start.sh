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


# Start an experiment. This script expects 2 at least command line arguments:
# the experiment name and the run directory. There are options for not
# starting gulp, not running the IRON components and for enabling debug
# logging.

# This script's name for error messages.
this="${0##*/}"

DEBUG_FLAG=0
DEMO_FLAG=false

source ${HOME}/iron_exp_staging/scripts/log.sh

# Print out the usage information and exit.
usage() {
    echo "Usage:"
    echo "  ${this} [-n] [-z] [-b] [-d] experiment_name run_dir"
    echo "Options:"
    echo "  -n               do not start gulp capture."
    echo "  -b               do not run IRON components."
    echo "  -z               run in demo mode."
    echo ""
    echo "  -d                      Enable debug logging."
    echo ""
    exit 1
}

START_GULP=true
RUN_BASELINE=false

# Process the command line options.
while getopts dnzb OPTION; do
    case ${OPTION} in
        n)
            START_GULP=false;;
        b)
            RUN_BASELINE=true;;
        z)
            DEMO_FLAG=true;;
        d)
            DEBUG_FLAG=1;;
        h|?)
            usage;;
    esac
done

# Grab the command line arguments. 
shift $(($OPTIND - 1))

# Make sure we have the correct number of command line arguments.
if [ "$#" -ne 2 ]; then
    usage
fi

EXP_NAME=$1
RUN_DIR=$2
DONE_FILE_WAIT=0.2
STAGING_DIR=${HOME}/iron_exp_staging
STAGE_TMP_DIR=/tmp/${INITIAL_START_TIMESTAMP}/${EXP_NAME}/${RUN_DIR}

mkdir -p ${STAGE_TMP_DIR}

# Set up the environment for the script.
source ${STAGING_DIR}/${EXP_NAME}/exp.cfg
source ${STAGING_DIR}/scripts/common_start.sh

EXP_DIR=${EXP_BASE_DIR}/iron_exps
LOG_DIR=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/logs

echo ""

if ${START_GULP}; then
    # Start the gulp captures.
    start_gulps PCAPS[@] ${EXP_DIR} ${EXP_BASE_DIR} ${EXP_NAME} ${RUN_DIR}
fi

if ${RUN_BASELINE}; then
    echo ""
    echo "Running baseline experiment. Not starting IRON."
else
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

        if [ -z ${MONITOR_PERF} ]; then
            MONITOR_PERF=false
        fi
        if [ -z ${MONITOR_PERIOD} ]; then
            MONITOR_PERIOD=1
        fi
        log echo ""
        log echo "Starting IRON components on ${FQ_NODE_NAME}..."
        DONE_FILE=${STAGE_TMP_DIR}/${GENERIC_NODE_NAME}_iron_start.done
        (ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} sudo ${EXP_DIR}/scripts/run_iron.sh \
            ${EXP_BASE_DIR} ${EXP_NAME} ${RUN_DIR} ${GENERIC_NODE_NAME} \
            ${PROXY_INBOUND_IF} ${MONITOR_PERF} ${MONITOR_PERIOD} ${DEBUG_FLAG}\
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
    done
fi

# Remove the temporary directory that was created to wait for the IRON
# nodes to complete their startup.
rm -rf /tmp/${INITIAL_START_TIMESTAMP}

echo ""
if [ "${DEMO_FLAG}" == true ]; then
    echo "Running in demo mode. NOT starting applications."
    exit 0
fi

# Run application scripts, if any, on the mgen nodes.
if ls ${STAGING_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/*_app_* 1> /dev/null 2>&1; then
    for NODE_INFO in ${MGEN_NODES[*]}; do
        GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
        FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
        echo "Starting node specific scripts on ${FQ_NODE_NAME}..."
        ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} ${EXP_DIR}/scripts/run_node_scripts.sh \
            ${EXP_BASE_DIR} ${EXP_NAME} ${RUN_DIR} ${GENERIC_NODE_NAME}
    done
fi

# Start the mgen sources and sinks.
log echo -n "start.sh: mgen START "; log date_timeval
for NODE_INFO in ${MGEN_NODES[*]}; do
    GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
    FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
    log echo -n "Starting mgen on ${FQ_NODE_NAME}... "; log date_timeval
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} ${EXP_DIR}/scripts/run_mgen.sh \
        ${EXP_BASE_DIR} ${EXP_NAME} ${RUN_DIR} ${GENERIC_NODE_NAME}
    echo "ssh ${USER_NAME}@${FQ_NODE_NAME} ${EXP_DIR}/scripts/run_mgen.sh"
    echo "${EXP_BASE_DIR} ${EXP_NAME} ${RUN_DIR} ${GENERIC_NODE_NAME}"
    log echo -n "start.sh: mgen $FQ_NODE_NAME "; log date_timeval
done

#
# Start the video sources and sinks.
#
if ls ${STAGING_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/gst_* 1> /dev/null 2>&1; then
    log echo -n "start.sh: gst START "; log date_timeval
    for NODE_INFO in ${MGEN_NODES[*]}; do
        GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
        FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
        log echo -n "Starting gstreamer on ${FQ_NODE_NAME}... "; log date_timeval
        ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} ${EXP_DIR}/scripts/run_gst.sh ${EXP_BASE_DIR} ${EXP_NAME} $RUN_DIR ${GENERIC_NODE_NAME}
        log echo -n "start.sh: gst $FQ_NODE_NAME "; log date_timeval
    done
fi
exit 0
