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
# Bootstrap the Deter testbed node by executing the node specific
# bootstrap script for the node.

# This script's name for error messages.
this="${0##*/}"

NODE_NAME=""
EXPERIMENT=""

# Print out usage information and exit.
usage() {
    echo ""
    echo "Usage:"
    echo "  ${this} -n <generic_node_name> -e <experiment_name>"
    echo ""
    echo "Options:"
    echo "  -n <generic_node_name>  The generic node name."
    echo "  -e <experiment_name>    The experiment name."
    echo ""
    echo "  -h                      Print out usage information."
    echo ""
    exit 1
}

# Process the command line options.
while getopts n:e:h option; do
    case $option in
        n)
            NODE_NAME="$OPTARG";;
        e)
            EXPERIMENT="$OPTARG";;
        h|?)
            usage;;
    esac
done

# Make sure that the node name and the experiment have been provided.
if [ "${NODE_NAME}" == "" ]; then
    echo "Missing node name"
    exit 1
fi

if [ "${EXPERIMENT}" == "" ]; then
    echo "Missing experiment name"
    exit 1
fi

STAGING_DIR="${HOME}/iron_exp_staging"

# Execute node specific bootstrap script.
if [ ! -e /iron/${NODE_NAME}_bootstrap.done ]; then
    if [ -e ${STAGING_DIR}/${EXPERIMENT}/cfgs/bootstrap_deter_${NODE_NAME}.sh ]; then
	echo "Bootstrapping ${HOSTNAME}..."
	${STAGING_DIR}/${EXPERIMENT}/cfgs/bootstrap_deter_${NODE_NAME}.sh 2>&1 \
	    /dev/null || exit 1
    fi

    sudo touch /iron/${NODE_NAME}_bootstrap.done
fi

exit 0
