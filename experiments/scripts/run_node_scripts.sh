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


# Execute any node specific scripts. This script expects 4 command line arguments, the
# experiment base directory, the experiment name, the run directory,
# and the generic node name.

# This script's name for error messages.
this="${0##*/}"

# Make sure we have the correct number of command line arguments.
if [ "$#" -ne 4 ]; then
    echo "Usage: ${this} experiment_base_dir experiment_name run_dir" \
        "generic_node_name"
    exit 1
fi

EXP_BASE_DIR=$1
EXP_NAME=$2
RUN_DIR=$3
NODE_NAME=$4
EXP_RUN_DIR=${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/${RUN_DIR}

# Dynamic log files for screen
LOG_SCREEN_RUN=true
SCREEN_LOG_DIR=${EXP_RUN_DIR}/logs
if [ "${LOG_SCREEN_RUN}" = true ] ; then
    mkdir -p ${SCREEN_LOG_DIR}
fi
log_screen(){
    SCRIPT=$1
    SESSION_NAME=$2

    SCRIPT_NAME=`basename ${SCRIPT}`
    SCREEN_LOG_FILE=${SCREEN_LOG_DIR}/${SCRIPT_NAME}.log
    SCREEN_RC_FILE=${SCREEN_LOG_DIR}/${SCRIPT_NAME}.screenrc
    echo "screen log file: ${SCREEN_LOG_FILE}"
    cat <<EOF > ${SCREEN_RC_FILE}
logfile ${SCREEN_LOG_FILE}
EOF
    screen -S ${SESSION_NAME} -c ${SCREEN_RC_FILE} -L -d -m bash ${SCRIPT}
}

# run any app scripts
SCRIPTS=$(find ${EXP_RUN_DIR}/cfgs -name "${NODE_NAME}_app*" -print0)
if [ "${SCRIPTS}" != "" ]; then
    SCRIPTS=$(find ${EXP_RUN_DIR}/cfgs -name "${NODE_NAME}_app*" -print0 | xargs -0 ls)
    SCRIPT_NUM=0
    for SCRIPT in ${SCRIPTS}; do
        echo "Running app script ${SCRIPT} on node $NODE_NAME."

        SESSION_NAME="iron_${NODE_NAME}_app_${SCRIPT_NUM}"
        if [ "${LOG_SCREEN_RUN}" = true ] ; then
            log_screen ${SCRIPT} ${SESSION_NAME}
        else
            screen -S ${SESSION_NAME} -d -m bash ${SCRIPT}
        fi
        SCRIPT_NUM=$((SCRIPT_NUM+1))
    done
fi

# Exit the script successfully.
exit 0
