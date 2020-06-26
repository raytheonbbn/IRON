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


# Stop the IRON components (AMP, BPF, TCP Proxy, and UDP Proxy) on a
# testbed node. NOTE: This script should only be executed on the
# target testbed node. The ecp_stop_iron.sh script should be used to
# stop the IRON components on ALL of the experiment's testbed nodes
# from a staging machine.
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - Experiments have been installed

# This script's name for error messages.
this="${0##*/}"

DEBUG_FLAG=0
EXP_BASE_DIR="${HOME}"
RUN_DIR="run1"

#=============================================================================
# Print out usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Stop the IRON components (AMP, BPF, TCP Proxy, and UDP Proxy)"
    echo "on a testbed node. NOTE: This script should only be executed on"
    echo "the target testbed node. The ecp_stop_iron.sh script should be"
    echo "used to stop the IRON components on ALL of the experiment's"
    echo "testbed nodes from a staging machine."
    echo ""
    echo "This script requires the following:"
    echo "  - Testbed nodes have been reserved"
    echo "  - Experiments have been installed"
    echo ""
    echo "Usage:"
    echo "  ${this} [-b <exp_base_dir>] [-d] [-r <run_dir>] [-h]"
    echo "    exp_name generic_node_name"
    echo ""
    echo "Options:"
    echo "  -b <exp_base_dir>    The experiment base directory."
    echo "                       Default: ${HOME}"
    echo "  -d                   Enable debug logging."
    echo "                       Default: Disabled"
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
while getopts b:dr:h OPTION; do
    case ${OPTION} in
	b)
	    EXP_BASE_DIR=${OPTARG};;
        d)
            DEBUG_FLAG=1;;
        r)
            RUN_DIR=${OPTARG};;
        h|?)
            usage;;
    esac
done

# Grab the command line argument. This contains the name of the
# experiment that is to be stopped.
shift $(($OPTIND - 1))

# Make sure we have the correct number of command line arguments.
if [ "$#" -ne 2 ]; then
    usage "Error: 2 command line arguments expected, $# provided."
fi

EXP_NAME=$1
GENERIC_NODE_NAME=$2

EXP_DIR=${EXP_BASE_DIR}/iron_exps
BIN_DIR=${EXP_DIR}/bin
LOG_DIR=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/logs

source ${EXP_DIR}/scripts/log.sh

# Dump the iptable rules.
sudo iptables-save > ${EXP_BASE_DIR}/iron_exps/iptables.txt

# Remove any specialized iptables
if [ -e ${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/iptables.cfg ]; then
    . ${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/iptables.cfg stop
fi

# Do this just for good hygiene
sudo iptables -t mangle -F

#Check that the IRON components are still runnning
# bpf is always supposed to run
BIN=bpf
RES_FILE=${LOG_DIR}/${BIN}-endcheck.log
pid=$(ps -ef | grep ${BIN} | grep -v grep | awk '{print $2}')

if [ -n "${pid}" ]; then
    echo "alive" > ${RES_FILE}
else
    echo "died" > ${RES_FILE}
fi

# udp_proxy runs only if binary and config file are present
BIN=udp_proxy
CFG=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/${BIN}_${GENERIC_NODE_NAME}.cfg
RES_FILE=${LOG_DIR}/${BIN}-endcheck.log
if [ -e "${BIN_DIR}/${BIN}" ]; then
    if [ ! -e "${CFG}" ]; then
        echo "not started" > ${RES_FILE}
    else
        pid=$(ps -ef | grep ${BIN} | grep -v grep | awk '{print $2}')
            if [ -n "${pid}" ]; then
                echo "alive" > ${RES_FILE}
            else
                echo "died" > ${RES_FILE}
            fi
    fi
else
    echo "not started" > ${RES_FILE}
fi

# tcp_proxy runs only if binary and config file are present
BIN=tcp_proxy
CFG=${EXP_DIR}/${EXP_NAME}/${RUN_DIR}/cfgs/${BIN}_${GENERIC_NODE_NAME}.cfg
RES_FILE=${LOG_DIR}/${BIN}-endcheck.log
if [ -e "${BIN_DIR}/${BIN}" ]; then
    if [ ! -e "${CFG}" ]; then
        echo "not started" > ${RES_FILE}
    else
        pid=$(ps -ef | grep ${BIN} | grep -v grep | awk '{print $2}')
            if [ -n "${pid}" ]; then
                echo "alive" > ${RES_FILE}
            else
                echo "died" > ${RES_FILE}
            fi
    fi
else
    echo "not started" > ${RES_FILE}
fi

# amp is always supposed to run
BIN=amp
RES_FILE=${LOG_DIR}/${BIN}-endcheck.log
pid=$(ps -ef | grep ${BIN} | grep -v grep | awk '{print $2}')

if [ -n "${pid}" ]; then
    echo "alive" > ${RES_FILE}
else
    echo "died" > ${RES_FILE}
fi

# Stop amp before the proxies, and wait for GUI connections to close.
echo "killing proc: amp"
sudo pkill -u root -SIGINT -f "amp"
sleep 1

# Stop the IRON components.

VALGRIND_BIN_IDS=$(ps -ef | grep valgrind | grep -v -i screen | grep -v grep | awk '{print $2}')

for BIN_ID in ${VALGRIND_BIN_IDS}; do
  BIN_NAME=$(ps -p $BIN_ID -o comm=)
  echo "killing valgrind proc: ${BIN_NAME}"
  sudo kill -SIGINT ${BIN_ID}
done

sleep 1

EXECS=(bpf tcp_proxy udp_proxy)
for BIN in ${EXECS[*]}; do
    for pid in $(pgrep ${BIN}); do
        echo "killing proc: ${BIN}"
        sudo pkill -u root -SIGINT ${BIN}
    done
done

# Restore the OS parameters to their default values now that the
# experiment is done.
log ${EXP_BASE_DIR}/iron_exps/scripts/restore_os_params.sh -b ${EXP_BASE_DIR} \
    -e ${EXP_NAME} || exit 1

# Exit the script successfully.
exit 0
