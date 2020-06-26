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
# Collects the results from an experiment, including the following:
#   - Log files and post processing results from application sources
#     and sinks
#   - IRON component log files and log file post processing analysis
#     results
#   - LinkEm log files
#   - Packet captures
#
# The results are placed in a results directory whose name is a
# combination of:
#   - RES_LOC, identified in the experiment's exp.cfg configuration file
#   - top level results directory name (this is a portion of the fully
#     qualified results directory name)
#   - experiment name
#   - run directory
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - Experiments have been installed
#   - Experiment components have been stopped and any desired post
#     processing scripts have been executed

# This script's name for error messages.
this="${0##*/}"

RUN_DIR="run1"
RES_TOP_LEVEL_DIR_NAME=""

#=============================================================================
# Print out the usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Collects the results from an experiment, including the following:"
    echo "  - Log files and post processing results from application sources"
    echo "    and sinks"
    echo "  - IRON component log files and log file post processing analysis"
    echo "  - LinkEm log files"
    echo "  - Packet captures"
    echo ""
    echo "The results are placed in a results directory whose name is a"
    echo "combination of:"
    echo "  - RES_LOC, identified in the experiment's exp.cfg configuration"
    echo "    file"
    echo "  - top level results directory name (this is a portion of the "
    echo "    fully qualified results directory name)"
    echo "  - experiment name"
    echo "  - run directory"
    echo ""
    echo "This script requires the following:"
    echo "  - Testbed nodes have been reserved"
    echo "  - Experiments have been installed"
    echo "  - Experiment components have been stopped and any desired post"
    echo "    processing scripts have been executed"
    echo ""
    echo "Usage:"
    echo "  ${this} [-r <run_dir>] [-t <dir_name>] exp_name"
    echo ""
    echo "Options:"
    echo "  -r <run_dir>   Experiment run directory (e.g., run1, run2, etc)."
    echo "                 Default: run1"
    echo "  -t <dir_name>  Top level results directory name."
    echo "                 Default: Current date and time"
    echo "                          (e.g., 2019_06_18T11_17_43Z)"
    echo "  -h             Display usage information."
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
# Execute a command, either locally or on the results host.
results_host_execute() {
    CMD=$@
    if [ ${RES_HOST} != ${HOSTNAME} ]; then
        ssh -oStrictHostKeyChecking=no ${USER_NAME}@${RES_HOST} $CMD
    else
        /usr/bin/env bash -c "${CMD}"
    fi
}

#=============================================================================
# Copy a file, either locally or via scp to the results host.
results_host_copy() {
    SRC=$1
    DST=$2
    if [ ${RES_HOST} != ${HOSTNAME} ]; then
        scp -q -r -oStrictHostKeyChecking=no -p ${1} ${USER_NAME}@${RES_HOST}:${2}
    else
        cp -p ${1} ${2}
    fi
}

#=============================================================================

# Process the command line options.
while getopts r:t:h OPTION; do
    case ${OPTION} in
	r)
	    RUN_DIR=${OPTARG};;
	t)
	    RES_TOP_LEVEL_DIR_NAME=${OPTARG};;
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
# EXP_BASE_DIR, USER_NAME, and RES_LOC are defined in exp.cfg
source ${STAGING_DIR}/${EXP_NAME}/exp.cfg

# If the user has not provided a results top level directory name,
# generate one.
if [ "${RES_TOP_LEVEL_DIR_NAME}" == "" ]; then
    RES_TOP_LEVEL_DIR_NAME=$(date -u "+%Y_%m_%dT%H_%M_%SZ")
fi

# Create the results directory name.
RES_DIR=${RES_LOC}/${RES_TOP_LEVEL_DIR_NAME}/${EXP_NAME}/${RUN_DIR}

# Create the location to tuck away the executables for the experiment.
BIN_DIR=${RES_LOC}/${RES_TOP_LEVEL_DIR_NAME}/bin

# Save the name of the name of the last experiment's results
# directory.
results_host_execute "echo "${RES_DIR}/" > ${RES_LOC}/last_run_experiment.txt"

# Create the location for the experiment artifacts.
results_host_execute mkdir -p ${RES_DIR}

# Copy the params.txt file to the experiment results directory.
if [ -e ${HOME}/iron_exp_staging/${EXP_NAME}/cfgs/params.txt ]; then
    results_host_copy \
	${HOME}/iron_exp_staging/${EXP_NAME}/cfgs/params.txt \
	${RES_DIR}/..
fi

# Define the list of IRON components.
IRON_COMPONENTS=(amp bpf gulp LinkEm LinkEmClient sliqdecap sonddecap \
		     tcp_proxy trpr udp_proxy)

# Also tuck away a copy of each executable.
results_host_execute mkdir ${BIN_DIR}

for COMP in ${IRON_COMPONENTS[*]}; do
    if [ -e ${HOME}/iron_exp_staging/bin/${COMP} ]; then
	results_host_copy ${HOME}/iron_exp_staging/bin/${COMP} ${BIN_DIR}
    fi
done

# Copy the git revision information.
results_host_copy "${HOME}/iron_exp_staging/bin/GIT*" ${BIN_DIR}

echo ""

# Copy LinkEmClient log from staging to results.
echo "Copying LinkEmClient log..."
results_host_copy ${HOME}/iron_exp_staging/${EXP_NAME}/${RUN_DIR}/LinkEmClient.log \
    ${RES_LOC}/${RES_TOP_LEVEL_DIR_NAME}/${EXP_NAME}/${RUN_DIR}

echo ""

# Decapsulate pcaps
for PCAP in ${DECAP[*]}; do
    FQ_NODE_NAME=$(echo ${PCAP} | cut -d ':' -f1)
    LINK=$(echo ${PCAP} | cut -d ':' -f2)
    TYPE=$(echo ${PCAP} | cut -d ':' -f3)
    echo "Decapsulating Link $LINK on ${FQ_NODE_NAME}..."
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
        ${EXP_BASE_DIR}/iron_exps/bin/${TYPE}decap \
        ${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/${RUN_DIR}/pcaps/*${LINK}* \
        ${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/${RUN_DIR}/pcaps/${LINK}.pcap \
        >/dev/null
done

# Collect experiment artifacts if the option is specified.
for NODE_INFO in ${NODE_LIST[*]}; do
    GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
    FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
    echo "Retrieving experiment data from ${FQ_NODE_NAME}..."
    results_host_execute mkdir -p ${RES_DIR}/${GENERIC_NODE_NAME}
    results_host_execute scp -q -r -oStrictHostKeyChecking=no -p \
        ${USER_NAME}@${FQ_NODE_NAME}:${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/${RUN_DIR}/* \
	${RES_DIR}/${GENERIC_NODE_NAME}/
done

# Copy the node_to_enclave_map.txt file to the experiment results directory.
if [ -e ${HOME}/iron_exp_staging/node_to_enclave_map.txt ]; then
    results_host_copy ${HOME}/iron_exp_staging/node_to_enclave_map.txt ${RES_DIR}
fi

# Copy the exp.cfg file to the experiment results directory.
results_host_copy ${HOME}/iron_exp_staging/${EXP_NAME}/exp.cfg ${RES_DIR}

# Copy the enclaves.cfg file to the experiment results directory.
if [ -e ${HOME}/iron_exp_staging/enclaves.cfg ]; then
    results_host_copy ${HOME}/iron_exp_staging/enclaves.cfg ${RES_DIR}
fi

# Move the results from generic node named directories (node1, node2,
# node3, etc) to enclave named directories (enclave1, enclave2,
# enclave3, etc), if experiment artifacts are being collected. The
# mapping from generic node names to its corresponding enclave
# directory is in the node_to_enclave_map.txt file (which is generated
# when the experiment configuration templates are converted to
# experiment configuration files).
if [ -e ${RES_DIR}/node_to_enclave_map.txt ]; then
    for NODE_INFO in ${NODE_LIST[*]}; do
	GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)

	NEW_DIR=$(grep -w ${GENERIC_NODE_NAME} \
		       ${RES_DIR}/node_to_enclave_map.txt | cut -d " " -f3)

	results_host_execute mkdir -p ${RES_DIR}/${NEW_DIR}
	results_host_execute mv ${RES_DIR}/${GENERIC_NODE_NAME}/* ${RES_DIR}/${NEW_DIR}
	results_host_execute rmdir ${RES_DIR}/${GENERIC_NODE_NAME}
    done
fi

echo ""
echo "Experiment results found in ${RES_DIR}"

# Exit the script successfully.
exit 0
