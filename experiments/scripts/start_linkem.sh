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

# Starts LinkEm on a testbed node. NOTE: This script should only be
# executed on the target testbed node. The ecp_start_linkem.sh script
# should be used to start the LinkEm instances on ALL of the
# experiment's testbed nodes from a staging machine.
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - Experiments have been installed

# This script's name for error messages.
this="${0##*/}"

EXP_BASE_DIR="${HOME}"
PORT="3456"
RUN_DIR="run1"

# Allow core dump files.
ulimit -c unlimited

#=============================================================================
# Print out the usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Starts LinkEm on a testbed node. NOTE: This scripts should only"
    echo "be executed on the target testbed node. The ecp_start_linkem.sh"
    echo "script should be used to start the LinkEm instances on ALL of the"
    echo "experiment's testbed nodes from a staging machine."
    echo ""
    echo "This script requires the following:"
    echo "  - Testbed nodes have been reserved"
    echo "  - Experiments have been installed"
    echo ""
    echo "Usage:"
    echo "  ${this} [-b <exp_base_dir>] [-p <port>] [-r <run_dir>] [-h]"
    echo "    <ref_addr> <exp_name>"
    echo ""
    echo "Options:"
    echo "  -b <exp_base_dir>  The experiment base directory."
    echo "                     Default: ${HOME}"
    echo "  -p <port>          The LinkEm port number."
    echo "                     Default: 3456"
    echo "  -r <run_dir>       Experiment run directory (e.g., run1, run2,"
    echo "                     etc.)"
    echo "                     Default: run1"
    echo "  -h                 Print out usage information."
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
while getopts b:p:r:h OPTION; do
    case ${OPTION} in
	b)
	    EXP_BASE_DIR=${OPTARG};;
        p)
            PORT="${OPTARG}";;
	r)
	    RUN_DIR=${OPTARG};;
        h|?)
            usage;;
    esac
done

# Grab the command line arguments.
shift $(($OPTIND - 1))

# Make sure we have the correct number of command line arguments.
if [ "$#" -ne 2 ]; then
    usage "Error: 2 command line arguments expected, $# provided."
fi

REF_ADDR=$1
EXP_NAME=$2

# If there is a LinkEm running with the provided port log an error and
# exit.
if [[ $(ps ax | grep "LinkEm -1" | grep "p ${PORT}" | grep -v grep) ]]; then
    echo ""
    echo "Already LinkEm running with port ${PORT}. Exiting..."
    exit 1
fi

WAN_SIDE_SUFFIX="101"
LAN_SIDE_SUFFIX="102"

IP=${REF_ADDR}
V1=${IP%%.*}
IP=${IP#*.}
V2=${IP%%.*}
IP=${IP#*.}
V3=${IP%%.*}

WAN_SIDE_IF=""
LAN_SIDE_IF=""

WAN_SIDE_ADDR=${V1}.${V2}.${V3}.${WAN_SIDE_SUFFIX}
LAN_SIDE_ADDR=${V1}.${V2}.${V3}.${LAN_SIDE_SUFFIX}
WAN_SIDE_IF=$(netstat -ie | grep -B1 ${WAN_SIDE_ADDR} | \
    head -n1 | awk '{print $1}')
LAN_SIDE_IF=$(netstat -ie | grep -B1 ${LAN_SIDE_ADDR} | \
    head -n1 | awk '{print $1}')

# Validate the WAN and LAN side interfaces.
if [ "${WAN_SIDE_IF}" == "" ]; then
    echo ""
    echo "Unable to find WAN side IF. Exiting..."
    exit 1
fi

if [ "${LAN_SIDE_IF}" == "" ]; then
    echo ""
    echo "Unable to find LAN side IF. Exiting..."
    exit 1
fi

# If the output from the netstat command has a trailing ':' character
# (as is the case in Ubuntu 18.04), strip it off the interface names.
LASTCHAR=${WAN_SIDE_IF:(-1)}
if [ "${LASTCHAR}" == ":" ]; then
    WAN_SIDE_IF=${WAN_SIDE_IF::-1}
fi

LASTCHAR=${LAN_SIDE_IF:(-1)}
if [ "${LASTCHAR}" == ":" ]; then
    LAN_SIDE_IF=${LAN_SIDE_IF::-1}
fi

# The bridge is named as follows: br_${WAN_SIDE_IF}_S{LAN_SIDE_IF}
#
# The interface names on Ubuntu 16.04 have increased in length as they
# typically include a portion of the devices MAC
# Address. Additionally, there is a maximum size for an interface
# name. When constructing the bridge name with the increased 16.04
# interface names, the maximum interface name size was exceeded. As a
# solution, the length of the interfaces names that are being bridged
# are checked. If an interface length is greater than 5 characters,
# the last 5 characters will used in the bridge name (the last 5
# characters are the most unique).
SHORT_WAN_SIDE_IF=${WAN_SIDE_IF}
SHORT_LAN_SIDE_IF=${LAN_SIDE_IF}
if [ ${#WAN_SIDE_IF} -gt 5 ]; then
    SHORT_WAN_SIDE_IF=${WAN_SIDE_IF:${#WAN_SIDE_IF}-5:${#WAN_SIDE_IF}}
fi
if [ ${#LAN_SIDE_IF} -gt 5 ]; then
    SHORT_LAN_SIDE_IF=${LAN_SIDE_IF:${#LAN_SIDE_IF}-5:${#LAN_SIDE_IF}}
fi

BRIDGE_NAME=br_${SHORT_WAN_SIDE_IF}_${SHORT_LAN_SIDE_IF}

sudo ip link set ${WAN_SIDE_IF} nomaster
sudo ip link set ${LAN_SIDE_IF} nomaster

if [[ $(ifconfig | grep ${BRIDGE_NAME}) ]]; then
    sudo ip link delete ${BRIDGE_NAME} type bridge
fi

sudo ethtool -K ${WAN_SIDE_IF} gro off
sudo ethtool -K ${LAN_SIDE_IF} gro off
sudo ethtool -C ${WAN_SIDE_IF} rx-usecs 0 2>/dev/null
sudo ethtool -C ${LAN_SIDE_IF} rx-usecs 0 2>/dev/null
sudo ethtool -C ${WAN_SIDE_IF} rx-frames 1 2>/dev/null
sudo ethtool -C ${LAN_SIDE_IF} rx-frames 1 2>/dev/null
sudo ethtool -C ${WAN_SIDE_IF} rx-usecs-irq 0 2>/dev/null
sudo ethtool -C ${LAN_SIDE_IF} rx-usecs-irq 0 2>/dev/null
sudo ethtool -C ${WAN_SIDE_IF} rx-frames-irq 0 2>/dev/null
sudo ethtool -C ${LAN_SIDE_IF} rx-frames-irq 0 2>/dev/null
sudo ethtool -C ${WAN_SIDE_IF} tx-usecs 0 2>/dev/null
sudo ethtool -C ${LAN_SIDE_IF} tx-usecs 0 2>/dev/null
sudo ethtool -C ${WAN_SIDE_IF} tx-frames 1 2>/dev/null
sudo ethtool -C ${LAN_SIDE_IF} tx-frames 1 2>/dev/null
sudo ethtool -C ${WAN_SIDE_IF} tx-usecs-irq 0 2>/dev/null
sudo ethtool -C ${LAN_SIDE_IF} tx-usecs-irq 0 2>/dev/null
sudo ethtool -C ${WAN_SIDE_IF} tx-frames-irq 0 2>/dev/null
sudo ethtool -C ${LAN_SIDE_IF} tx-frames-irq 0 2>/dev/null

# The following controls the maximum size that can be locked into
# memory. We are leaving this commented out to assist in a "state
# reboot" in the event that we wish to experiment with this some more
# in the future.
#
#sudo bash -c "ulimit -l 256 -H"
#sudo bash -c "ulimit -l 256"

# Start LinkEm and direct the output to the log file located in the
# ${EXP_BASE_DIR}/${EXP_NAME}/${RUN_DIR}/logs directory.

sudo nice -n -20 ${EXP_BASE_DIR}/bin/LinkEm -1 ${WAN_SIDE_IF} \
    -2 ${LAN_SIDE_IF} -p=${PORT} \
    -l ${EXP_BASE_DIR}/${EXP_NAME}/${RUN_DIR}/logs/LinkEm_${PORT}.log &

# Exit the script successfully.
exit 0
