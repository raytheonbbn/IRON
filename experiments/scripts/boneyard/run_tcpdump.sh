#!/usr/bin/env bash

#
# Start tcpdump capture. This script expects 3 command line arguments,
# the experiment base directory, the experiment name and the interface
# name for the capture.
#

#
# This script's name for error messages.
#
this="${0##*/}"

#
# Make sure we have the correct number of command line arguments.
#
if [ "$#" -ne 3 ]; then
    echo "Usage: ${this} experiment_base_dir experiment_name interface_name"
    exit 1
fi

EXP_BASE_DIR=$1
EXP_NAME=$2
INF_NAME=$3
EXP_DIR=${EXP_BASE_DIR}/iron_exps

export RUNTIME=`date +%Y_%m_%d_%H_%M_%S.pcap`

#
# Start the capture.
#
screen -d -m tcpdump -i ${INF_NAME} -w ${EXP_DIR}/${EXP_NAME}/pcaps/${EXP_NAME}-${INF_NAME}-${RUNTIME} -s 128

exit 0
