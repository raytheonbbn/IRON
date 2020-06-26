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

# Stops the running LinkEm instances on a testbed node. NOTE: This
# script should only be executed on the target testbed node. The
# ecp_stop_linkem.sh script should be used to stop the LinkEm
# instances on ALL of the experiment's testbed nodes from a staging
# machine.
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - Experiments have been installed

# This script's name for error messages.
this="${0##*/}"

#=============================================================================
# Print out the usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Stops the running LinkEm instances on a testbed node. NOTE: This"
    echo "script should only be executed on the target testbed node. The"
    echo "ecp_stop_linkem.sh script should be used to stop the LinkEm"
    echo "instances on ALL of the experiment's testbed nodes from a"
    echo "staging machine."
    echo ""
    echo "This script requires the following:"
    echo "  - Testbed nodes have been reserved"
    echo "  - Experiments have been installed"
    echo ""
    echo "Usage:"
    echo "  ${this} <ref_addr>"
    echo ""

    exit 1
}

# Verify that the required command line argument, the reference
# address, has been provided.
if [ "$#" -ne 1 ]; then
    usage "Error: 1 command line argument expected, $# provided."
fi

REFADDR=$1

WAN_SIDE_SUFFIX="101"
LAN_SIDE_SUFFIX="102"

IP=${REFADDR}
V1=${IP%%.*}
IP=${IP#*.}
V2=${IP%%.*}
IP=${IP#*.}
V3=${IP%%.*}

WAN_SIDE_ADDR=${V1}.${V2}.${V3}.${WAN_SIDE_SUFFIX}
LAN_SIDE_ADDR=${V1}.${V2}.${V3}.${LAN_SIDE_SUFFIX}

WAN_SIDE_IF=""
LAN_SIDE_IF=""

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

LINKEM_PID="$(ps ax | grep "LinkEm -1 "${WAN_SIDE_IF} | grep -v "0:00" | \
    sed -e 's/^[ \t]*//' | cut -d ' ' -f1)"

if [[ ${LINKEM_PID} ]]; then
    sudo kill -2 $LINKEM_PID
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

if [[ ! $(ifconfig | grep ${BRIDGE_NAME}) ]]; then
    sudo ip link add name ${BRIDGE_NAME} type bridge
    sudo ip link set ${BRIDGE_NAME} up
    sudo ip link set ${WAN_SIDE_IF} master ${BRIDGE_NAME}
    sudo ip link set ${LAN_SIDE_IF} master ${BRIDGE_NAME}
    sudo ifconfig ${WAN_SIDE_IF} ${WAN_SIDE_ADDR}
    sudo ifconfig ${LAN_SIDE_IF} ${LAN_SIDE_ADDR}
fi

# Exit the script successfully.
exit 0
