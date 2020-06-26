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


# Stop an experiment and pull back the logs, configuration files, and
# scripts. This script expects 2 command line argument, the name of
# the experiment and the run directory.
#
# This script relies on environment variables set by the caller:
#
#   USER_NAME: The user to operate as on experiment nodes.
#
#   EXP_BASE_DIR: The home directory to be used on experiment nodes,
#   typically /home/${USER_NAME}. It is expected that this will
#   contain a directory "iron_exps".
#
#   HOME: A directory which typically contains "iron_exp_staging".
#   Almost certainly the home directory of the user running the
#   script, on the machine that the script is running on.
#
#   RES_HOST: The name of the host where results will be stored.
#
#   RES_LOC: The top-level place where results are stored. A typical
#   value is ${HOME}/iron_results. Stored in runN/exp.cfg.
#
#   RES_TOP_LEVEL_DIR_NAME: A single pathname component giving the
#   directory name where results are stored, set by start_exp.sh. A
#   typical value is of the form "2017_11_07T16_51_18Z".

# This script's name for error messages.
this="${0##*/}"

EXP_NAME=""
RUN_DIR=""
DEBUG_FLAG=0
DEBUG_ARG=""

# Print out the usage information and exit.
usage() {
    echo ""
    echo "Usage:"
    echo "  ${this} [-p] [-c] [-d] experiment_name run_dir"
    echo ""
    echo "Options:"
    echo "  -p  Process the experiment results."
    echo "  -c  Collect the experiment results / artifacts."
    echo "  -d  Enable debug logging."
    exit 1
}

# Print explosion
explosion_core() {
    echo "             . . .                        "
    echo "              \|/                         "
    echo "             --+--                        "
    echo "              /|\                         "
    echo "             . | .                        "
    echo "               |                          "
    echo "               |                          "
    echo "           ,-- # --.                      "
    echo "           |#######|                      "
    echo "        _.- ####### -._                   "
    echo "     ,- ### CORE ###### -.                "
    echo "    , ########## CORE #####,              "
    echo "  /# CORE ### CORE #########              "
    echo " |################ CORE #####|            "
    echo "|######### CORE ###### CORE ##|           "
    echo "|## CORE #### CORE ###########|           "
    echo "|############### CORE ########|           "
    echo "|##### CORE ######## CORE ####|           "
    echo " |############# CORE ########|            "
    echo "   #### CORE ####### CORE ##/             "
    echo "    .######## CORE #######,               "
    echo "      ._###############_,                 "
    echo "         --..#####..--                    "
}

# Execute a command, either locally or on the results host.
results_host_execute() {
    CMD=$@
    if [ ${RES_HOST} != ${HOSTNAME} ]; then
        ssh -oStrictHostKeyChecking=no ${USER_NAME}@${RES_HOST} $CMD
    else
        /usr/bin/env bash -c "${CMD}"
    fi
}

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

PROCESS_FLAG=0
COLLECT_FLAG=0

# Process the command line options.
while getopts pcdh OPTION; do
    case ${OPTION} in
        p)
            PROCESS_FLAG=1;;
        c)
            COLLECT_FLAG=1;;
        d)
            DEBUG_FLAG=1;;
        h|?)
            usage;;
    esac
done

# Grab the command line arguments.
shift $(($OPTIND - 1))

EXP_NAME=$1
RUN_DIR=$2

if [ "${EXP_NAME}" == "" ] || [ "${RUN_DIR}" == "" ]; then
    usage
fi

# Set up the environment for the script.
source ${HOME}/iron_exp_staging/${EXP_NAME}/exp.cfg
source ${HOME}/iron_exp_staging/scripts/log.sh

if [ ${DEBUG_FLAG} -eq 1 ]; then
    DEBUG_ARG="-d"
else
    DEBUG_ARG=""
fi

# RES_TOP_LEVEL_DIR_NAME is an environment variable exported by the
# start_exp.sh script.
RES_DIR=${RES_LOC}/${RES_TOP_LEVEL_DIR_NAME}/${EXP_NAME}/${RUN_DIR}

# Create the location to tuck away the executables for this run.
BIN_DIR=${RES_LOC}/${RES_TOP_LEVEL_DIR_NAME}/bin

# Save the name of the name of the last experiment's results
# directory.
results_host_execute "echo "${RES_DIR}/" > ${RES_LOC}/last_run_experiment.txt"

# Create the location for the experiment artifacts.
results_host_execute mkdir -p ${RES_DIR}

# Define the list of IRON components
IRON_COMPONENTS=(addvif amp bpf delvif gulp LinkEm LinkEmClient \
    sliqdecap sonddecap tcp_proxy trpr udp_proxy)

# Copy the params.txt file to the experiment results directory. We
# only have to do this one time.
if [ "${RUN_DIR}" == "run1" ]; then
    if [ -e ${HOME}/iron_exp_staging/${EXP_NAME}/cfgs/params.txt ]; then
	results_host_copy \
	    ${HOME}/iron_exp_staging/${EXP_NAME}/cfgs/params.txt \
	    ${RES_DIR}/..
    fi

    # Also tuck away a copy of each executable.
    results_host_execute mkdir ${BIN_DIR}

    for COMP in ${IRON_COMPONENTS[*]}; do
        if [ -e ${HOME}/iron_exp_staging/bin/${COMP} ]; then
	    results_host_copy ${HOME}/iron_exp_staging/bin/${COMP} ${BIN_DIR}
        fi
    done

    # Copy the git revision information.
    results_host_copy "${HOME}/iron_exp_staging/bin/GIT*" ${BIN_DIR}
fi

echo ""

# Stop the mgen and gst processes 
for NODE_INFO in ${MGEN_NODES[*]}; do
    FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
    GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
    echo "Stopping mgen processes on ${FQ_NODE_NAME}..."
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
        sudo ${EXP_BASE_DIR}/iron_exps/scripts/stop_mgen.sh
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} sudo \
        ${EXP_BASE_DIR}/iron_exps/scripts/stop_gst.sh ${EXP_NAME}/${RUN_DIR}
done

# Stop the IRON components.
for NODE_INFO in ${IRON_NODES[*]}; do
    GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
    FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
    echo "Stopping IRON components on ${FQ_NODE_NAME}..."
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
        ${EXP_BASE_DIR}/iron_exps/scripts/stop_iron.sh ${EXP_BASE_DIR} \
        ${EXP_NAME} ${RUN_DIR} ${GENERIC_NODE_NAME} ${DEBUG_FLAG}
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
        "mv ${EXP_BASE_DIR}/iron_exps/iptables.txt" \
        "${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/${RUN_DIR}/logs/"

    echo ""
done

if [ ${COLLECT_FLAG} -eq 1 ]; then
    # Consolidate mgen logs
    for NODE_INFO in ${MGEN_NODES[*]}; do
        FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
        GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
        echo "Consolidating mgen logs on ${FQ_NODE_NAME}..."
        ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} sudo \
            ${EXP_BASE_DIR}/iron_exps/scripts/consolidate_mgen_log_files.sh \
            ${EXP_BASE_DIR} ${EXP_NAME} ${RUN_DIR}
    done
fi

echo ""

# Stop the gulp processes.
echo "Stopping gulp processes."
for NODE_INFO in ${PCAPS[*]}; do
    FQ_NODE_NAME=$(echo $NODE_INFO | cut -d ':' -f1)
    log echo "Stopping gulp processes on ${FQ_NODE_NAME}..."
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
        sudo ${EXP_BASE_DIR}/iron_exps/scripts/stop_gulp.sh
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
        sudo chmod 777 ${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/${RUN_DIR}/pcaps/*
done

echo ""

echo "Stopping LinkEm, turning LinkEm nodes into bridges..."
for LINKEM_NODE in ${LINKEM_NODES[*]}; do
    GENERIC_NODE_NAME=$(echo ${LINKEM_NODE} | cut -d ':' -f1)
    FQ_NODE_NAME=$(echo ${LINKEM_NODE} | cut -d ':' -f2)
    REF_IP_ADDRESS=$(echo ${LINKEM_NODE} | cut -d ':' -f4)
    log echo "Stopping LinkEm on ${FQ_NODE_NAME}..."
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
	"${EXP_BASE_DIR}/iron_exps/scripts/StopLinkEm.sh ${REF_IP_ADDRESS}"
done

echo ""

# Copy LinkEmClient log from staging to results.
echo "Copying LinkEmClient log..."
results_host_copy ${HOME}/iron_exp_staging/${EXP_NAME}/${RUN_DIR}/LinkEmClient.log \
    ${RES_LOC}/${RES_TOP_LEVEL_DIR_NAME}/${EXP_NAME}/${RUN_DIR}

echo ""

# Decapsulate pcaps
if [ ${COLLECT_FLAG} -eq 1 ]; then
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
fi
# Process the results if the option is specified
if [ ${PROCESS_FLAG} -eq 1 ]; then
    echo "Processing results..."
    for NODE_INFO in ${MGEN_NODES[*]}; do
        FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
        echo "Processing mgen logs for node ${FQ_NODE_NAME}..."
        ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
			${EXP_BASE_DIR}/iron_exps/scripts/process.sh ${DEBUG_ARG}\
			-r ${RUN_DIR} -e ${EXP_BASE_DIR}/iron_exps/${EXP_NAME} \
			-s ${EXP_BASE_DIR}/iron_exps/scripts \
			-c ${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/cfgs/process.cfg
    done
    echo ""
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
fi

echo ""

# Stop all screen sessions.
echo "Stopping screen sessions."
for NODE_INFO in ${NODE_LIST[*]}; do
  GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
  FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
  log echo "Stopping node scripts on ${FQ_NODE_NAME}..."
  ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
      ${EXP_BASE_DIR}/iron_exps/scripts/stop_node_scripts.sh ${GENERIC_NODE_NAME}

  log echo "Stopping screen sessions on ${FQ_NODE_NAME}..."
  ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
      ${EXP_BASE_DIR}/iron_exps/scripts/stop_screen.sh

  # Collect experiment artifacts if the option is specified.
  if [ ${COLLECT_FLAG} -eq 1 ]; then
    echo "Retrieving experiment data from ${FQ_NODE_NAME}..."
    results_host_execute mkdir -p ${RES_DIR}/${GENERIC_NODE_NAME}
    results_host_execute scp -q -r -oStrictHostKeyChecking=no -p \
        ${USER_NAME}@${FQ_NODE_NAME}:${EXP_BASE_DIR}/iron_exps/${EXP_NAME}/${RUN_DIR}/* \
        ${RES_DIR}/${GENERIC_NODE_NAME}/
  fi
done

# Check for core files
if [ ${RES_HOST} == ${HOSTNAME} ]; then
    for NODE_INFO in ${IRON_NODES[*]}; do
        GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
        if [ -e ${RES_DIR}/${GENERIC_NODE_NAME}/results/core_file.txt ]; then
	    explosion_core
        fi
    done
fi

# Perform analysis on gstreamer logs if any
for NODE_INFO in ${MGEN_NODES[*]}; do
    NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
    for GST_LOG in "${RES_DIR}/${NODE_NAME}"/logs/gst_*
    do
        if [ -f "$GST_LOG" ];then
    		mkdir -p ${RES_DIR}/${NODE_NAME}/results
            FILE_NAME=$(basename $GST_LOG)
            cat $GST_LOG | grep "Packet.*lost" > ${RES_DIR}/${NODE_NAME}/results/lost_${FILE_NAME}
            cat $GST_LOG | grep "too late as" > ${RES_DIR}/${NODE_NAME}/results/late_${FILE_NAME}
            echo "results for $GST_LOG"
            NUMOFLOST=$(wc -l < "${RES_DIR}/${NODE_NAME}/results/lost_${FILE_NAME}")
            NUMOFLATE=$(wc -l < "${RES_DIR}/${NODE_NAME}/results/late_${FILE_NAME}")
            echo "Num lost: $NUMOFLOST . Num late: $NUMOFLATE"
        fi
    done
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
if [ ${COLLECT_FLAG} -eq 1 ]; then
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
fi

# Perform all-nodes per-run post-rename processing.  This cannot be called
# from process.sh because that is run on the nodes themselves where only one
# node's data is present. This should be run after we've moved to generically
# named directories so that these scripts can be run outside of the normal
# experiment process. The analysis script expects to be in the run
# directory. This analysis script cannot be run on Deter, so check for
# isi.deterlab.net domain.
RES_DOMAIN=`echo ${RES_HOST} | cut -d '.' -f 2-`
if [ ${PROCESS_FLAG} -eq 1 ]; then
    if [ "${RES_DOMAIN}" == "isi.deterlab.net" ]; then
	echo "All-nodes processing skipped; Cannot execute on ${RES_HOST}."
    elif [ ! -d ${RES_DIR} ]; then
	echo "All-nodes processing skipped; ${RES_DIR} does not exist."
    else
	echo "Performing all-nodes processing:"
	(cd ${RES_DIR} &&
	    python ${HOME}/iron_exp_staging/scripts/process_trpr.py
	)
    fi
fi

echo "Experiment results found in ${RES_DIR}"

# Exit the script successfully.
exit 0
