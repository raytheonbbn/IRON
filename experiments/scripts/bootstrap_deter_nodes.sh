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


# Bootstrap the Deter testbed nodes by executing the node specific
# bootstrap script for the node.

# This script's name for error messages.
this="${0##*/}"

USER_NAME=""
EXPERIMENT=""

# Print out usage information and exit.
usage() {
    echo ""
    echo "Usage:"
    echo "  ${this} -u <user_name> -e <experiment_name>"
    echo ""
    echo "Options:"
    echo "  -u <user_name>        The user the experiments are to run as."
    echo "  -e <experiment_name>  The name of the experiment."
    echo ""
    echo "  -h                    Print out usage information."
    echo ""
    exit 1
}

# Process the command line options.
while getopts u:e:h option; do
    case $option in
        u)
            USER_NAME="$OPTARG";;
        e)
            EXPERIMENT="$OPTARG";;
        h|?)
            usage;;
    esac
done

# Make sure that the user name has been provided.
if [ "${USER_NAME}" == "" ]; then
    echo "Missing user name..."
    usage
fi

# Make sure that an experiment has been provided.
if [ "${EXPERIMENT}" == "" ]; then
    echo "An experiment must be specified. Aborting..."
    usage
fi

# Set up the environment for the script.
STAGING_DIR="${HOME}/iron_exp_staging"
source ${STAGING_DIR}/${EXPERIMENT}/exp.cfg

echo ""
echo "Bootstrapping Deter experiment nodes..."
echo "---------------------------------------"

# Bootstrap the nodes.
for NODE_INFO in ${NODE_LIST[*]}; do
    GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
    FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)

    # Execute node specific bootstrap script on the node.
    CMD="${STAGING_DIR}/scripts/bootstrap_deter_node.sh"
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
        "${CMD} -n ${GENERIC_NODE_NAME} -e ${EXPERIMENT}"
done

exit 0
