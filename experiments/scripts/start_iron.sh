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


# Start the IRON components (AMP, BPF, TCP Proxy, and UDP Proxy) on a
# testbed node. NOTE: This script should only be executed on the
# target testbed node. The ecp_start_iron.sh script should be used to
# start the IRON components on ALL of the experiment's testbed nodes
# from a staging machine.
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - Experiments have been installed

# This script's name for error messages.
this="${0##*/}"

DEBUG_FLAG=0
EXP_BASE_DIR="${HOME}"
MONITOR_PERF=false
MONITOR_PERIOD=1
RUN_DIR="run1"

#=============================================================================
# Print out usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Starts the IRON components (AMP, BPF, TCP Proxy, and UDP Proxy)"
    echo "on a testbed node. NOTE: This script should only be executed on"
    echo "the target testbed node. The ecp_start_iron.sh script should be"
    echo "used to start the IRON components on ALL of the experiment's"
    echo "testbed nodes from a staging machine."
    echo ""
    echo "This script requires the following:"
    echo "  - Testbed nodes have been reserved"
    echo "  - Experiments have been installed"
    echo ""
    echo "Usage:"
    echo "  ${this} [-b <exp_base_dir>] [-d] [-m] [-p <monitor_period>]"
    echo "    [-r <run_dir>] [-h] exp_name generic_node_name"
    echo "    proxy_inbound_if_name"
    echo ""
    echo "Options:"
    echo "  -b <exp_base_dir>    The experiment base directory."
    echo "                       Default: ${HOME}"
    echo "  -d                   Enable debug logging."
    echo "                       Default: Disabled"
    echo "  -m                   Monitor performance."
    echo "                       Default: Disabled"
    echo "  -p <monitor_period>  Monitor performance period."
    echo "                       Default: 1"
    echo "  -r <run_dir>         Experiment run directory (e.g., run1, run2,"
    echo "                       etc.)"
    echo "                       Default: run1"
    echo "  -h                   Display usage information."
    echo ""
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
while getopts b:dmp:r:h OPTION; do
    case ${OPTION} in
	b)
	    EXP_BASE_DIR=${OPTARG};;
	d)
	    DEBUG_FLAG=1;;
	m)
	    MONITOR_PERF=true;;
	p)
	    MONITOR_PERIOD=${OPTARG};;
	r)
	    RUN_DIR=${OPTARG};;
        h|?)
            usage;;
    esac
done

# Grab the command line arguments.
shift $(($OPTIND - 1))

# Make sure we have the correct number of command line arguments.
if [ "$#" -ne 3 ]; then
    usage "Error: 3 command line arguments expected, $# provided."
fi

EXP_NAME=$1
GENERIC_NODE_NAME=$2
PROXY_INBOUND_IF=$3

EXP_DIR=${EXP_BASE_DIR}/iron_exps
BIN_DIR=${EXP_DIR}/bin
SCRIPT_DIR=${EXP_DIR}/scripts
LOG_DIR=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/logs

source ${EXP_DIR}/scripts/log.sh

# Tune the OS parameters for the experiment.
log ${EXP_BASE_DIR}/iron_exps/scripts/tune_os_params.sh -b ${EXP_BASE_DIR} \
    -e ${EXP_NAME} || exit 1

# Allow core dump files.
ulimit -c unlimited

# Disable Generic Receive Offload (GRO) on the LAN-facing interface of
# the IRON node.
sudo ethtool -K ${PROXY_INBOUND_IF} gro off

# Disable Generic Receive Offload (GRO) on all of the WAN-facing interfaces
# of the IRON node.
BPF_CFG=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/bpf_${GENERIC_NODE_NAME}.cfg
if [ ! -e "${BPF_CFG}" ]; then
    echo "Config file ${BPF_CFG} not found, not disabling GRO on WAN interfaces..."
else
    ETH_IFS=$(ifconfig 2>/dev/null | awk '/Ethernet/ {print $1}')
    for IF in ${ETH_IFS}; do
        IF_IP=$(ifconfig ${IF} 2>/dev/null | awk -F"[: ]+" '/inet addr:/ {print $4}')
        if [ -n "${IF_IP}" ]; then
            ENDPT_CHK=$(grep PathController ${BPF_CFG} | grep Endpoints | grep -F "${IF_IP}")
            if [ -n "${ENDPT_CHK}" ]; then
                echo "Disabling GRO on WAN interface ${IF} address ${IF_IP}..."
                sudo ethtool -K ${IF} gro off
            fi
        fi
    done
fi

# Setup the gmon prefix in case we are profiling
export GMON_OUT_PREFIX="${LOG_DIR}/gmon"

# Clear the mangle table
echo "Clearing the iptables mangle table..."
sudo iptables -t mangle -F

err=""
while [ "$err" == "" ]
do
    err=`sudo ip rule del from all fwmark 0x4 lookup 4 2>&1`
done

err=""
while [ "$err" == "" ]
do
    err=`sudo ip rule del from all fwmark 0x1 lookup 200 2>&1`
done

# Add specialized iptables plumbing, if it exists.
if [ -e ${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/iptables.cfg ]; then
    . ${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/iptables.cfg start
fi

NUM_CORES=`cat /proc/cpuinfo |grep -c '^process'`

# Start the IRON bpf.
BIN=bpf
CFG=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/${BIN}_${GENERIC_NODE_NAME}.cfg
if [ ! -e "${CFG}" ]; then
    echo "Config file ${CFG} not found, running bpf without config file..."
    screen -d -m ${BIN_DIR}/${BIN} -l ${LOG_DIR}/${BIN}.log
    echo "[Warning] Starting BPF without configuration file."
else
    echo "Starting BPF..."
    screen -d -m nice -n -20 ${BIN_DIR}/${BIN} -c ${CFG} \
        -l ${LOG_DIR}/${BIN}.log
fi

sleep 2
BPF_CORE_MASK=1
if [ ${NUM_CORES} -gt 1 ]
then
    BPF_CORE_MASK=2
fi

BPF_PID=`pgrep bpf`
log taskset -p ${BPF_CORE_MASK} ${BPF_PID}

# Start the IRON UDP Proxy.
BIN=udp_proxy
STARTED_UDP=false
CFG=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/${BIN}_${GENERIC_NODE_NAME}.cfg
if [ -e "${BIN_DIR}/${BIN}" ]; then
    if [ ! -e "${CFG}" ]; then
        echo "[Warning] Config file ${CFG} not found, NOT starting UDP proxy."
    else
        echo "Starting UDP proxy..."
        screen -d -m nice -n -20 ${BIN_DIR}/${BIN} -c ${CFG} \
            -l ${LOG_DIR}/${BIN}.log -I ${PROXY_INBOUND_IF}

        STARTED_UDP=true

        sleep 2
        UDP_CORE_MASK=1
        if [ ${NUM_CORES} -gt 2 ]
        then
            UDP_CORE_MASK=4
        fi
        UDP_PROXY_PID=`pgrep udp_proxy`
        log taskset -p ${UDP_CORE_MASK} ${UDP_PROXY_PID}
    fi
fi

# Start the IRON TCP Proxy.
BIN=tcp_proxy
STARTED_TCP=false
CFG=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/${BIN}_${GENERIC_NODE_NAME}.cfg
if [ -e "${BIN_DIR}/${BIN}" ]; then
    if [ ! -e "${CFG}" ]; then
        echo "[Warning] Config file ${CFG} not found, NOT starting tcp_proxy."
    else
        echo "Starting TCP proxy..."
        screen -d -m nice -n -20 ${BIN_DIR}/${BIN} -c ${CFG} \
            -l ${LOG_DIR}/${BIN}.log -I ${PROXY_INBOUND_IF}

        STARTED_TCP=true

        sleep 2
        TCP_CORE_MASK=1
        if [ ${NUM_CORES} -gt 3 ]
        then
            TCP_CORE_MASK=8
        fi
        TCP_PROXY_PID=`pgrep tcp_proxy`
        log taskset -p ${TCP_CORE_MASK} ${TCP_PROXY_PID}

    fi
fi

sleep 1

# Start the Admission Planner. It is best to start this AFTER the
# proxies have started.
BIN=amp
STARTED_AMP=false
CFG=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/${BIN}_${GENERIC_NODE_NAME}.cfg
if [ -e "${BIN_DIR}/${BIN}" ]; then
    if [ ! -e "${CFG}" ]; then
	echo "{Warning] Config file ${CFG} not found, NOT starting AMP."
    else
	CMD_ARG=""
	CMD=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/${BIN}_services.cfg
	if [ -e "${CMD}" ]; then
	    CMD_ARG="-f ${CMD}"
	fi
	CFG_ARG="-c ${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/system.cfg"
	CFG=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/${BIN}_${GENERIC_NODE_NAME}.cfg
	if [ -e "${CFG}" ]; then
	    CFG_ARG="-c ${CFG}"
	fi

	echo ${BIN_DIR}/${BIN} ${CMD_ARG} ${CFG_ARG} -l ${LOG_DIR}/${BIN}.log
	screen -d -m ${BIN_DIR}/${BIN} ${CMD_ARG} ${CFG_ARG} -l ${LOG_DIR}/${BIN}.log

	STARTED_AMP=true

	AMP_CORE_MASK=1
	if [ ${NUM_CORES} -gt 4 ]
	then
	    AMP_CORE_MASK=16
	fi

	AMP_PID=`pgrep amp`
	log taskset -p ${AMP_CORE_MASK} ${AMP_PID}
    fi
fi

# Starting the monitoring processes now. If started right after the processes
# sometimes pidof ${BIN} fails to find the process ID...
if ${MONITOR_PERF}; then
    BIN=bpf
    echo "Starting bpf performance monitoring..."
    screen -d -m ${SCRIPT_DIR}/run_pidstat.sh ${BIN} ${LOG_DIR} \
	   ${MONITOR_PERIOD}
    if ${STARTED_UDP}; then
        BIN=udp_proxy
        echo "Starting udp_proxy performance monitoring..."
        screen -d -m ${SCRIPT_DIR}/run_pidstat.sh ${BIN} ${LOG_DIR} \
               ${MONITOR_PERIOD}
    fi
    if ${STARTED_TCP}; then
        BIN=tcp_proxy
        echo "Starting tcp_proxy performance monitoring..."
        screen -d -m ${SCRIPT_DIR}/run_pidstat.sh ${BIN} ${LOG_DIR} \
               ${MONITOR_PERIOD}
    fi

    if ${STARTED_AMP}; then
	BIN=amp
	echo "Starting amp performance monitoring..."

	# Using -p option here because it's a python script.
	screen -d -m ${SCRIPT_DIR}/run_pidstat.sh -p ${BIN} ${LOG_DIR} \
               ${MONITOR_PERIOD}
    fi
fi

# Save away the process IDs in case we are profiling.
echo "bpf $BPF_PID" > ${LOG_DIR}/pidmap.txt
if ${STARTED_UDP}; then
    echo "udp_proxy $UDP_PROXY_PID" >> ${LOG_DIR}/pidmap.txt
fi
if ${STARTED_TCP}; then
    echo "tcp_proxy $TCP_PROXY_PID" >> ${LOG_DIR}/pidmap.txt
fi
if ${STARTED_AMP}; then
    echo "amp $AMP_PID" >> ${LOG_DIR}/pidmap.txt
fi

# Exit script successfully.
exit 0
