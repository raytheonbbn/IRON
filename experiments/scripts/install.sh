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


# Install the configured experiments, located in
# ${HOME}/iron_exp_staging, on the reserved testbed nodes. Everything
# in the local staging directory is installed on the testbed
# nodes. The size of the tarball is small, so we don't worry about per
# node installations (e.g., we don't install only IRON components on
# IRON_NODES, only LinkEm components on LINKEM_NODES, etc). Instead
# everything pertaining to the experiment is installed (in total) on
# all experiment nodes.
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - Staged experiments have been configured

# This script's name for error messages.
this="${0##*/}"

STAGING_DIR="${HOME}/iron_exp_staging"
# XXX DEBUG_FLAG is not used. Do we need the -d in this script? Should
# all scripts have -d for consistency?
DEBUG_FLAG=0

#=============================================================================
# Print out usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Installs the configured experiments, located in"
    echo "${STAGING_DIR}, on the reserved testbed nodes. Everything in the"
    echo "local staging directory is installed on the testbed nodes. The"
    echo "size of the tarball is small, so we don't worry about per node"
    echo "installations (e.g., we don't install only IRON components on"
    echo "IRON_NODES, only LinkEm components on LINKEM_NODES, etc). Instead"
    echo "everything pertaining to the experiment is installed (in total) on"
    echo "all experiment nodes."
    echo ""
    echo "This script requires the following:"
    echo "  - Testbed nodes have been reserved"
    echo "  - Staged experiments have been configured"
    echo ""
    echo "Usage:"
    echo "  ${this} [-d] [-h] exp1[...expN]"
    echo ""
    echo "Options:"
    echo "  -d  Enable debug logging."
    echo "      Default: Disabled"
    echo "  -h  Display usage information."
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
while getopts dh OPTION; do
    case ${OPTION} in
        d)
            DEBUG_FLAG=1;;
        h|?)
            usage;;
    esac
done

# Make sure that at least 1 experiment has been provide.
if [ $(($# - $OPTIND + 1)) -eq 0 ]; then
    usage "Error: At least 1 experiment must be provided."
fi

shift $(($OPTIND - 1))
EXPERIMENTS=$*
UNIQUE_NODE_LIST=( )

echo ""
echo "Installing experiments..."
echo "-------------------------"

# Generate the unique node list for all of the experiments. This is
# the union of nodes in the NODE_LIST of each of the exp.cfg files. We
# do this so we don't unnecessarily do an install to a node more than
# one time. To create this unique node list do the following:
#
#  1. Iterate over the experiments
#  2. Source the experiment exp.cfg file
#  3. echo the current unique node list and the current experiment's node list
#  4. Replace the spaces with newlines
#  5. Uniquely sort the entries
#  6. Replace newlines with spaces and save in unique node list
for arg; do
    source ${STAGING_DIR}/${arg}/exp.cfg
    UNIQUE_NODE_LIST=$(echo "${UNIQUE_NODE_LIST[@]}" "${NODE_LIST[@]}" | \
        tr ' ' '\n' | sort -u | tr '\n' ' ')
done

# Do the installation.
for NODE_INFO in ${UNIQUE_NODE_LIST}; do
    GENERIC_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f1)
    FQ_NODE_NAME=$(echo ${NODE_INFO} | cut -d ':' -f2)
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
        "rm -rf core"

    echo "Installing on ${FQ_NODE_NAME}..."
    scp -oStrictHostKeyChecking=no -q ${STAGING_DIR}/exp.tgz \
        ${USER_NAME}@${FQ_NODE_NAME}:${EXP_BASE_DIR}

    EXP_DIR=${EXP_BASE_DIR}/iron_exps
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} \
        "mkdir -p ${EXP_DIR} && cd ${EXP_DIR} && sudo rm -rf * && tar xfz ../exp.tgz"
done

# Exit the script successfully.
exit 0
