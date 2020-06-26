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
# Script to run a command on all nodes used in an experiment. The name
# of the experiment can be provided. If not provided, the commands
# apply to the current experiment. All arguments are passed to ssh.

# This script's name for error messages.
this="${0##*/}"

EXP_NAME=""

# Print out the usage information and exit.
usage() {
    echo ""
    echo "Usage:"
    echo "  ${this} [-e <exp_name>] cmd"
    echo ""
    echo "-e <exp_name>  The name of the experiment to which the cmd applies."
    exit 1
}

# Process the command line options.
while getopts u:t:e:h OPTION; do
    case ${OPTION} in
        e)
            EXP_NAME="$OPTARG";;
        h|?)
            usage;;
    esac
done

if [ "${EXP_NAME}" == "" ]; then
    if [ ! -f ${HOME}/iron_exp_staging/current_exp.txt ]; then
        echo "${this}: No experiment running and experiment name not" \
            "provided. Aborting..."
        exit 1
    fi

    EXP_NAME=`cat ${HOME}/iron_exp_staging/current_exp.txt`
    if [ ! -f ${HOME}/iron_exp_staging/${EXP_NAME}/hosts.txt ]; then
        echo "Experiment ${EXP_NAME} not configured. Please stage and " \
            "configure experiment first."
        exit 1
    fi
fi

# Grab the command line arguments. This is the command that will be executed.
shift $(($OPTIND - 1))
EXPERIMENTS=$*

# Source the hosts.txt file. This contains the hosts that the remote
# command will be executed on.
source ${HOME}/iron_exp_staging/${EXP_NAME}/hosts.txt

for HOST in ${exp_hosts[*]}; do
  echo ${HOST}
  ssh $USER_NAME@$HOST $@
  echo ""
done

# Exit the script successfully.
exit 0
