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


# This script stages the experiments (binaries, scripts, and
# configuration files) that are to be run. The staged experiments are
# placed in the ${HOME}/iron_exp_staging directory.
#
# The script requires the following:
#   - BUILD_STYLE environment variable is set

# This script's name for error messages.
this="${0##*/}"

STAGING_DIR="${HOME}/iron_exp_staging"

#=============================================================================
# Print out usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Stages the experiments (binaries, scripts, and configuration"
    echo "files) to be run. The staged experiments are placed in the"
    echo "${HOME}/iron_exp_staging directory."
    echo ""
    echo "This script requires the following:"
    echo "  - BUILD_STYLE environment variable is set"
    echo ""
    echo "Usage:"
    echo "  ${this} testbed_cfg_file_name exp_name1[...exp_nameN]"
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
while getopts h OPTION; do
    case ${OPTION} in
        h|?)
            usage;;
    esac
done

# Verify that at least 2 command-line arguments have been
# provided. The script must have the name of the testbed topology file
# and 1 experiment. Note that multiple experments may be provided.
if [ "$#" -lt 2 ]; then
    usage "Error: Incorrect number of command-line arguments ($#) provided."
fi

# Verify that the build style is set up correctly.
if [ -z ${BUILD_STYLE} ]; then
    usage "Error: BUILD_STYLE is not set, please set it and re-run the"\
	  "script."
fi

# Grab the command line arguments. The first argument is the testbed
# topology file name. The remaining arguments are the names of the
# experiments that are to be staged.
TESTBED_TOPO_FILE=$1
shift
EXPERIMENTS=$*

echo ""
echo "Staging experiments..."
echo "----------------------"

# Prepare the local staging area in the user's home directory. This
# includes removing any existing files and copying the IRON binaries,
# automated test scripts, and experiment configuration files that are
# required to run the desired experiments.
rm -rf ${STAGING_DIR}/*
mkdir -p ${STAGING_DIR}/bin
mkdir -p ${STAGING_DIR}/testbeds
mkdir -p ${STAGING_DIR}/scripts
for EXP in ${EXPERIMENTS}; do
    mkdir -p ${STAGING_DIR}/${EXP}
    mkdir -p ${STAGING_DIR}/${EXP}/logs
    mkdir -p ${STAGING_DIR}/${EXP}/pcaps
done

# Copy the experiment information to the local staging area.
echo "Copying iron binaries to ${STAGING_DIR}/bin..."
cp -R ${IRON_HOME}/bin/${BUILD_STYLE}/* ${STAGING_DIR}/bin

echo "Storing git revision information in ${STAGING_DIR}/bin..."

# If in a git tree, save information about which commit was used, and
# if there are unstaged and/or unpushed changes.  Be careful to limit
# information to hashes, dates, and file names, and omit source code
# and log statements.
if git status 2>&1 > /dev/null; then
    git describe > ${STAGING_DIR}/bin/GIT.describe
    git log -1 | head -3 > ${STAGING_DIR}/bin/GIT.commit
    git status > ${STAGING_DIR}/bin/GIT.status
else
    echo "not a git tree" > ${STAGING_DIR}/bin/GIT.describe
fi

echo "Copying ../testbeds/${TESTBED_TOPO_FILE} to ${STAGING_DIR}/testbeds..."
if [ ! -f ../testbeds/${TESTBED_TOPO_FILE} ]; then
    echo "Error: Testbed config file ../testbeds/${TESTBED_TOPO_FILE}" \
         "does not exist."
    exit 1
fi
cp ../testbeds/${TESTBED_TOPO_FILE} ${STAGING_DIR}/testbeds

# The following command always generates output on stderr for
# omiting directories. This is not useful and is redirected.
echo "Copying scripts to ${STAGING_DIR}/scripts..."
cp * ${STAGING_DIR}/scripts 2>/dev/null

echo "Copying ctl scripts to ${STAGING_DIR}/scripts..."
cp -r ${IRON_HOME}/python/iron ${STAGING_DIR}/scripts
cp ${IRON_HOME}/python/cli/*ctl ${STAGING_DIR}/scripts

# Grab all of the experiments that were provided as arguments.
DEFAULT_ENCLAVES_CFG_FILE_COPIED=0
for EXP in ${EXPERIMENTS}; do
    echo "Copying experiment ../${EXP} to ${STAGING_DIR}/${EXP}..."
    if [ ! -d ../${EXP} ]; then
        echo "Error: Experiment ../${EXP} does not exist."
        exit 1
    fi
    cp -R ../${EXP} ${STAGING_DIR}
    if [ -e ${STAGING_DIR}/${EXP}/exp.cfg ]; then
	echo "BUILD_MODE=${BUILD_MODE}" >> ${STAGING_DIR}/${EXP}/exp.cfg
    fi
    if [ -e ${STAGING_DIR}/${EXP}/exp.tmpl ]; then
	echo "BUILD_MODE=${BUILD_MODE}" >> ${STAGING_DIR}/${EXP}/exp.tmpl
    fi
    rm -rf ${STAGING_DIR}/${EXP}/results

    # Copy the default 'enclaves.cfg' to the staging directory. We
    # only need to do this one time. If multiple experiments have been
    # provided this is still fine as all experiments that are to be
    # run must run on the same set of experiment enclaves.
    if [ ${DEFAULT_ENCLAVES_CFG_FILE_COPIED} -eq 0 ]; then
	if [ -e ../${EXP}/enclaves.cfg ]; then
	    echo "Copying default enclaves.cfg file to staging directory" \
		 "${STAGING_DIR}..."
	    cp ../${EXP}/enclaves.cfg ${STAGING_DIR}
	    DEFAULT_ENCLAVES_CFG_FILE_COPIED=1
	fi
    fi
done

# If there is a remote execution node identified in the testbed
# topology file, copy the tarball to this node and untar it. The
# remaining commands will be run on this remote execution node.
REMOTE_EXECUTION_NODE=`grep -i REMOTE_EXECUTION_NODE ${STAGING_DIR}/testbeds/${TESTBED_TOPO_FILE} | cut -d ' ' -f2`
if [ "${REMOTE_EXECUTION_NODE}" != "" ]; then
    # Create the tarball that will be installed on the experiment nodes.
    pushd ${STAGING_DIR} >/dev/null
    tar czf exp.tgz *
    popd >/dev/null

    # Put the experiment test execution staging area on the remote node.
    echo "REMOTE_EXECUTION_NODE=${REMOTE_EXECUTION_NODE}" > \
        ${HOME}/iron_exp_staging/remote_execution_node.cfg
    echo "Placing experiment staging area on ${REMOTE_EXECUTION_NODE}..."
    scp ${STAGING_DIR}/exp.tgz ${REMOTE_EXECUTION_NODE}:'${HOME}'
    ssh ${REMOTE_EXECUTION_NODE} 'rm -rf ${HOME}/iron_exp_staging; mkdir -p ${HOME}/iron_exp_staging ; cd ${HOME}/iron_exp_staging ; mv ../exp.tgz . ; tar xzf exp.tgz'
fi

echo ""

# Exit the script successfully.
exit 0
