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


# Starts LinkEm on the experiment's reserved testbed nodes, assigns
# the LinkEm instances to testbed node cores, and initializes the
# LinkEm instances per the experiment's configuration.
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - Experiments have been installed

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
    echo "Starts LinkEm on the experiment's reserved testbed nodes, assigns"
    echo "the LinkEm instances to testbed node cores, and initializes the"
    echo "LinkEm instances per the experiment's configuration."
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
    echo "                Default: disabled"
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
	    DEBUG_FLAG=1;;
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

# Set up the environment for the script.
#
# EXP_BASE_DIR and USER_NAME are defined in exp.cfg
source ${STAGING_DIR}/${EXP_NAME}/exp.cfg
source ${STAGING_DIR}/scripts/log.sh

# Unique LinkEm node list. This is used when the processor affinities
# are assigned to the LinkEm instances.
LINKEM_FQDN_LIST=()

echo ""

# Start LinkEm.
echo "Starting LinkEm instances..."
for LINKEM_NODE in ${LINKEM_NODES[*]}; do
    GENERIC_NODE_NAME=$(echo ${LINKEM_NODE} | cut -d ':' -f1)
    FQ_NODE_NAME=$(echo ${LINKEM_NODE} | cut -d ':' -f2)
    LINKEM_PORT=$(echo ${LINKEM_NODE} | cut -d ':' -f3)
    REF_IP_ADDRESS=$(echo ${LINKEM_NODE} | cut -d ':' -f4)
    LINKEM_FQDN_LIST+=($FQ_NODE_NAME)
    log echo "Starting LinkEm on ${FQ_NODE_NAME}..."
    CMD="${EXP_BASE_DIR}/iron_exps/scripts/start_linkem.sh"
    CMD="${CMD} -b ${EXP_BASE_DIR}/iron_exps -p ${LINKEM_PORT}"
    CMD="${CMD} -r ${RUN_DIR} ${REF_IP_ADDRESS} ${EXP_NAME}"
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} "${CMD}" &
done

echo ""

# Make sure all LinkEms are started
LEC_BIN="${EXP_BASE_DIR}/iron_exps/bin/LinkEmClient"
for LINKEM_NODE in ${LINKEM_NODES[*]}; do
    GENERIC_NODE_NAME=$(echo ${LINKEM_NODE} | cut -d ':' -f1)
    FQ_NODE_NAME=$(echo ${LINKEM_NODE} | cut -d ':' -f2)
    LINKEM_PORT=$(echo ${LINKEM_NODE} | cut -d ':' -f3)
    echo "Waiting for LinkEm on ${FQ_NODE_NAME}..."
    failed=1
    count=0
    while [ "$failed" -eq 1 ]; do
        count=$((count+1))
	status=$(ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
                     "${LEC_BIN} -p=${LINKEM_PORT} -S" 2>/dev/null)

	# Can potentially use LinkEmClient directly; need local/remote
	# execution test
	#
	# status=$(${STAGING_DIR}/bin/LinkEmClient -h ${FQ_NODE_NAME} \
	#   -p=${LINKEM_PORT} -q 2>&1 > /dev/null)

        failed=0
	if [ "${status}" != "LinkEm Operational" ]; then
            failed=1
            sleep 0.1
	fi
        if [ $count -eq 150 ]; then
            echo "Waited too long for LinkEm to start. Exiting"
            exit 1
        fi
    done
    if [ "$count" != "1" ]; then
        echo "  LinkEm up status checked $count times"
    fi
done

echo ""

# Assign processor affinities
UNIQ_LINKEM_NODES=( `for i in ${LINKEM_FQDN_LIST[@]}; do \
	                     echo $i; done | sort -u` )
for LINKEM_NODE in ${UNIQ_LINKEM_NODES[*]}; do
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${LINKEM_NODE} \
        ${EXP_BASE_DIR}/iron_exps/scripts/assign_linkem_cores.sh
done

echo ""

# Initialize LinkEm per the experiment's configuration.
LEM_SCRIPT=${STAGING_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/lem_init.sh
if [ -f ${LEM_SCRIPT} ]; then
    ${LEM_SCRIPT} || \
	{ echo "Error initializing LinkEm. Aborting..." ; exit 1; }
fi

echo ""

# Exit the script successfully.
exit 0
