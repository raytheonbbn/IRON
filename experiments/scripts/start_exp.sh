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


# Start the experiment components, sleep for the duration of the
# experiment, stop the experiment components, and collect the
# experiment artifacts.

# This script's name for error messages.
this="${0##*/}"

source ${HOME}/iron_exp_staging/scripts/common_start.sh
source ${HOME}/iron_exp_staging/scripts/log.sh

PROCESS_OPTION=""
COLLECT_OPTION=""
BASELINE_OPTION=""
TESTBED_TOPO_FILE=""
ANNOTATION=""
DEBUG_FLAG=0
DEMO_OPTION=""

# Print out the usage information and exit.
usage() {
    echo ""
    echo "Usage:"
    echo "  ${this} [-p] [-b] [-z] [-e <exp_name>] [-a <annotation>] [-d] experiment..."
    echo ""
    echo "Options:"
    echo "  -p               Process the experiment results."
    echo "  -c               Collect the experiment logs / results / artifacts."
    echo "  -b               Do not run IRON components."
    echo "  -d               Enable debug logging."
    echo "  -z               Demo mode. The script will start the experiment and"
    echo "                   return successfully. The user must tear down the"
    echo "                   experiment separately."
    echo "  -e <exp_name>    The DETER experiment name. Only required"
    echo "                   for experiments that are to be run on"
    echo "                   DETER."
    echo "  -a <annotation>  Annotation appended to the results directory"
    echo "                   name. Any spaces in this tag will be replaced"
    echo "                   with '_' characters."
    echo ""

    exit 1
}

# \todo Sometimes, the script uses the STAGING_DIR variable, and
# sometimes, the value is open-coded.  Either clean this up, or
# explain the plan.
STAGING_DIR="${HOME}/iron_exp_staging"

# Process the command line options.
while getopts dipcbzo:e:a: OPTION; do
    case ${OPTION} in
        p)
            PROCESS_OPTION="-p";;
        c)
            COLLECT_OPTION="-c";;
        b)
            BASELINE_OPTION="-b";;
        z)
            DEMO_OPTION="-z";;
        e)
            DETER_EXP_NAME="$OPTARG";;
        a)
            ANNOTATION="_$OPTARG"
            ANNOTATION=`echo ${ANNOTATION} | tr ' ' '_'`;;
        d)
            DEBUG_FLAG=1;;
        h|?)
            usage;;
    esac
done

export DEBUG_FLAG=${DEBUG_FLAG}

# Grab the command line arguments. These contain the names of the
# experiments that are to be run.
shift $(($OPTIND - 1))
EXPERIMENTS=$*
EXP_COUNT=$#

echo ""
echo "Running experiments..."
echo "----------------------"

export INITIAL_START_TIMESTAMP=$(date -u "+%Y_%m_%dT%H_%M_%SZ")
export RES_TOP_LEVEL_DIR_NAME=${INITIAL_START_TIMESTAMP}${ANNOTATION}


EXP_NUM=1
# Iterate over the experiments.
for arg; do
    source ${STAGING_DIR}/${arg}/exp.cfg

    if [ ${DEBUG_FLAG} -eq 1 ]; then
        DEBUG_ARG="-d"
    else
        DEBUG_ARG=""
    fi

    source ${STAGING_DIR}/${arg}/exp.cfg
    echo ${arg} > ${STAGING_DIR}/current_exp.txt
    LEC_BIN="${EXP_BASE_DIR}/iron_exps/bin/LinkEmClient"

    # Gulp captures traffic into pcaps.  The standard approach is to
    # record the entire experiment, but sometimes the experiment is
    # long and it is desired to only have pcaps for the very beginning
    # portion.  In that case, gulp_to_be_started_separately is set to
    # true instead of false.
    start_gulp_sep=$(gulp_to_be_started_separately)
    START_GULP_FLAG=
    if ${start_gulp_sep}; then
        START_GULP_FLAG=-n
        echo "Starting gulp separately."
    fi

    # Iterate over the experiment runs.
    for DIR in ${STAGING_DIR}/${arg}/run*; do
        RUN=`basename ${DIR}`
        echo "Running experiment ${arg} ${RUN}"
        echo ""

	# Clean up the artifacts from previous runs.
	./cleanup.sh ${DEBUG_ARG} ${STAGING_DIR} ${EXP_BASE_DIR}/ ${arg} ${RUN}

        # Stop old LinkEm that might have been running from a partial
        # previous experiment run.  In an ideal world, none will be
        # running.
        # \todo Explain why this is here, instead of only once before
        # the iteration over runs.
	LINKEM_FQDN_LIST=()
        for LINKEM_NODE in ${LINKEM_NODES[*]}; do
            GENERIC_NODE_NAME=$(echo ${LINKEM_NODE} | cut -d ':' -f1)
            FQ_NODE_NAME=$(echo ${LINKEM_NODE} | cut -d ':' -f2)
	    LINKEM_PORT=$(echo ${LINKEM_NODE} | cut -d ':' -f3)
            REF_IP_ADDRESS=$(echo ${LINKEM_NODE} | cut -d ':' -f4)
	    LINKEM_FQDN_LIST+=($FQ_NODE_NAME)
            # \todo If we find a linkem process running, that is
            # irregular and should be logged.
            echo "Clearing LinkEm on ${FQ_NODE_NAME}..."
            ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
                ${EXP_BASE_DIR}/iron_exps/scripts/StopLinkEm.sh ${REF_IP_ADDRESS}
        done

	UNIQ_LINKEM_NODES=( `for i in ${LINKEM_FQDN_LIST[@]}; do \
	                     echo $i; done | sort -u` )

        echo ""
        # Start LinkEm.
        for LINKEM_NODE in ${LINKEM_NODES[*]}; do
            GENERIC_NODE_NAME=$(echo ${LINKEM_NODE} | cut -d ':' -f1)
            FQ_NODE_NAME=$(echo ${LINKEM_NODE} | cut -d ':' -f2)
	    LINKEM_PORT=$(echo ${LINKEM_NODE} | cut -d ':' -f3)
            REF_IP_ADDRESS=$(echo ${LINKEM_NODE} | cut -d ':' -f4)
            echo "Starting LinkEm on ${FQ_NODE_NAME}..."
            ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
                "${EXP_BASE_DIR}/iron_exps/scripts/StartLinkEm.sh -p ${LINKEM_PORT} ${REF_IP_ADDRESS} ${EXP_BASE_DIR}/iron_exps ${arg} ${RUN}" &
        done

        echo ""
        # Make sure all LinkEms are started
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

# Can potentially use LinkEmClient directly; need local/remote execution test
# status=$(${STAGING_DIR}/bin/LinkEmClient -h ${FQ_NODE_NAME} -p=${LINKEM_PORT} -q 2>&1 > /dev/null)

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
        for LINKEM_NODE in ${UNIQ_LINKEM_NODES[*]}; do
            ssh -oStrictHostKeyChecking=no ${USER_NAME}@${LINKEM_NODE} \
                ${EXP_BASE_DIR}/iron_exps/scripts/AssignLinkEmCores.sh
	done

        echo ""
        # Configure LinkEm
	LEM_SCRIPT=${STAGING_DIR}/${arg}/${RUN}/cfgs/lem_init.sh
	if [ -f ${LEM_SCRIPT} ]; then
	    ${STAGING_DIR}/${arg}/${RUN}/cfgs/lem_init.sh || \
		{ stop_exp ${DEBUG_ARG} ${PROCESS_OPTION} ${COLLECT_OPTION} \
			   ${arg} ${RUN}; exit 1; }
	fi

        echo ""

        # Initialize the black network
        CFG=${STAGING_DIR}/${arg}/${RUN}/cfgs/exp_init.aal
        if [ -f ${CFG} ]; then
            echo "Initializing Magi on control.${DETER_EXP_NAME}"
            # Give click enough time to start
            sleep 5
            ssh -oStrictHostKeyChecking=no control.${DETER_EXP_NAME}.edgect.isi.deterlab.net "sudo magi_orchestrator.py -c localhost -f ${CFG}"
        fi

        # Start the experiment components.
        ./start.sh ${DEBUG_ARG} ${DEMO_OPTION} ${START_GULP_FLAG} ${BASELINE_OPTION} ${arg} ${RUN}

        if [ "$?" == "0"  ]; then
            # Start sond rate adjustments if sonds are being used
            CFG=${STAGING_DIR}/${arg}/${RUN}/cfgs/sond.bfc
            if [ -f ${CFG} ]; then
                echo "Starting bpfctl on ${HOSTNAME}..."
                ${STAGING_DIR}/scripts/bpfctl -e ${STAGING_DIR}/${arg}/exp.cfg \
                    -f ${CFG} &
            fi

            # Start LinkEm adjustments with full system up and running
	    LEM_SCRIPT=${STAGING_DIR}/${arg}/${RUN}/cfgs/lem.sh
	    if [ -f ${LEM_SCRIPT} ]; then
		${STAGING_DIR}/${arg}/${RUN}/cfgs/lem.sh < /dev/null \
			      2>&1 > ${STAGING_DIR}/${arg}/${RUN}/LinkEmClient.log &
	    fi

            # Start the black network script
            CFG=${STAGING_DIR}/${arg}/${RUN}/cfgs/exp.aal
            if [ -f ${CFG} ]; then
                echo "Starting Magi on control.${DETER_EXP_NAME}"
                ssh -oStrictHostKeyChecking=no control.${DETER_EXP_NAME}.edgect.isi.deterlab.net "screen -d -m sudo magi_orchestrator.py -c localhost -f ${CFG}"
            fi

            # Wait for the experiment to run.
            sleep_dur=${DURATION}
            if ${start_gulp_sep}; then
                sleep_dur=$(expr ${DURATION} - ${GULP_DURATION})
            fi
            if [ "${DEMO_OPTION}" == "-z" ]; then
                exit 0
            fi
            echo "Sleeping for ${sleep_dur} seconds while mgen runs zzZZzzZZzzZZ..."
            sleep ${sleep_dur}

            if ${start_gulp_sep}; then
                EXP_DIR=${EXP_BASE_DIR}/iron_exps
                start_gulps PCAPS[@] ${EXP_DIR} ${EXP_BASE_DIR} ${arg} ${RUN}
                echo "Sleeping for an additional ${GULP_DURATION} seconds" \
                    "while mgen and gulp runs zzZZzzZZzzZZ..."
                sleep ${GULP_DURATION}
            fi
        fi

        # Stop the experiment and pull back the logs.
        echo ""
        echo "Stopping experiment and collecting artifacts..."
        ./stop.sh ${DEBUG_ARG} ${PROCESS_OPTION} ${COLLECT_OPTION} ${arg} ${RUN}

        echo ""
    done
    echo "Done executing runs for ${arg}"
done

# Exit the script successfully.
exit 0
