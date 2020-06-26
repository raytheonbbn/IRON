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
# Processes the results from an experiment run on the reserved testbed
# nodes.
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - Experiments have been installed
#   - Experiment components have been stopped

# This script's name for error messages.
this="${0##*/}"

RUN_DIR="run1"
DEBUG_ARG=""

#=============================================================================
# Print out the usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Processes the results from an experiment run on the reserved"
    echo "testbed nodes."
    echo ""
    echo "This script requires the following:"
    echo "  - Testbed nodes have been reserved"
    echo "  - Experiments have been installed"
    echo "  - Experiment components have been stopped"
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
	    DEBUG_ARG="-d";;
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
# EXP_BASE_DIR and USER_NAME are defined in exp.cfg
source ${STAGING_DIR}/${EXP_NAME}/exp.cfg

echo "Processing results..."
for NODE_INFO in ${MGEN_NODES[*]}; do
    FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
    GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)

    # Consolidate mgen logs
    GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
    echo "Consolidating mgen logs on ${FQ_NODE_NAME}..."
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} sudo \
        ${EXP_BASE_DIR}/iron_exps/scripts/consolidate_mgen_log_files.sh \
        ${EXP_BASE_DIR} ${EXP_NAME} ${RUN_DIR}

    echo "Processing mgen logs for node ${FQ_NODE_NAME}..."
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
	${EXP_BASE_DIR}/iron_exps/scripts/process.sh ${DEBUG_ARG}\
	-r ${RUN_DIR} -e ${EXP_BASE_DIR}/iron_exps/${EXP_NAME} \
	-s ${EXP_BASE_DIR}/iron_exps/scripts \
	-c ${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/cfgs/process.cfg

    echo ""
done

for NODE_INFO in ${IRON_NODES[*]}; do
    FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
    echo "Processing iron logs for node ${FQ_NODE_NAME}..."
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
	${EXP_BASE_DIR}/iron_exps/scripts/process.sh \
	-r ${RUN_DIR} -e ${EXP_BASE_DIR}/iron_exps/${EXP_NAME} \
	-s ${EXP_BASE_DIR}/iron_exps/scripts \
	-c ${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/cfgs/process.cfg
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
	sudo ${EXP_BASE_DIR}/iron_exps/scripts/move_core.sh \
	"${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/${RUN_DIR}/results" \
	"${RES_TOP_LEVEL_DIR_NAME}-${RUN_DIR}"
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
        sudo ${EXP_BASE_DIR}/iron_exps/scripts/get_perf_results.sh \
        ${EXP_BASE_DIR}/iron_exps ${EXP_NAME} ${RUN_DIR}
done

echo ""

# Exit the script successfully.
exit 0
