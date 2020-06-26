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
# Script that controls interaction with the testbed reservation
# system. The script does the following:
#
#  - Installs the most recent version of the reserve.sh script on the
#    testbed reservation server in a user unique directory
#  - Installs the testbed topology file of interest on the testbed
#    reservation server in a user unique directory
#  - Invokes the testbed reservation script on the testbed reservation
#    server

# This script's name for error messages.
this="${0##*/}"

BASE_DIR="${HOME}/iron_exp_staging"
SCRIPT_DIR="${HOME}/iron_exp_staging/scripts"
LOCK_FLAG=0
REQUESTED_ENCLAVES=""
NUM_REQUESTED_ENCLAVES=""
RELEASE_FLAG=0
RELEASE_ENCLAVES=""
QUERY_FLAG=0
SERVER="gnat0.bbn.com"
USER_NAME="iron"

#=============================================================================
# Print diagnostic message to stderr.
errmsg(){
    >&2 echo $@;
}

#=============================================================================
# Print out usage information and exit.
usage() {
    echo ""
    echo "Usage:"
    echo "  ${this} [-B <base directory>] [-l <enclaves>] [-L <num enclaves>]"
    echo "    [-q] [-r <enclaves>] [-s <server>] [-u <user>] [-h] "
    echo "    testbed_topology_file"
    echo ""
    echo "Options:"
    echo "  -B <base directory>   The testbed topology file base directory."
    echo "                        Default: ${BASE_DIR}"
    echo "  -S <script directory> The scripts direction."
    echo "                        Default: ${SCRIPT_DIR}" 
    echo "  -l <enclaves>         Colon separated list of the testbed"
    echo "                        enclaves that are to be reserved."
    echo "  -L <num enclaves>     Number of requested enclaves to be reserved."
    echo "  -q                    Query the status of the testbed."
    echo "  -r <enclaves>         Colon separated list of the testbed"
    echo "                        enclaves that are to be released."
    echo "  -s <server>           Reservation server host. Default: ${SERVER}"
    echo "  -u <user>             The user that is interacting with the"
    echo "                        testbed reservation system."
    echo "                        Default: ${USER_NAME}"
    echo "  -h                    Usage information."
    echo ""

    # Exit the script with an error.
    exit 1
}

# Process the command line options.
while getopts B:S:l:L:qr:s:u:h option; do
    case $option in
	B)
	    BASE_DIR=${OPTARG};;
        S)
            SCRIPT_DIR=${OPTARG};;
        l)
	    LOCK_FLAG=1
            REQUESTED_ENCLAVES=${OPTARG};;
	L)
	    LOCK_FLAG=1
	    NUM_REQUESTED_ENCLAVES=${OPTARG};;
	q)
	    QUERY_FLAG=1;;
	r)
	    RELEASE_FLAG=1
	    RELEASE_ENCLAVES=${OPTARG};;
	s)
	    SERVER=${OPTARG};;
	u)
	    USER_NAME=${OPTARG};;
	h|?)
	    usage;;
    esac
done

# Grab the testbed topology file command line argument.
shift $((${OPTIND} - 1))
if [ "$#" -ne 1 ]; then
    errmsg ""
    errmsg "Expected 1 command line argument, $# provided. Aborting..."
    usage
fi
TESTBED_TOPO_FILE=$*

# Prepare the reservation server node:
#
#  - Create /home/${USER_NAME}/${USER}_reserve directory on
#    reservation server
#  - Copy reserve.sh script to /home/${USER_NAME}/${USER}_reserve
#    directory on reservation server
#  - Copy testbed topology file to /home/${USER_NAME}/${USER}_reserve
#    directory on reservation server
ssh -oStrictHostKeyChecking=no ${USER_NAME}@${SERVER} \
    mkdir -p ${USER}_reserve || \
    { errmsg "Error creating ${USER}_reserve directory on reservation " \
    "server." ; exit 1; }
scp -q -oStrictHostKeyChecking=no ${BASE_DIR}/${TESTBED_TOPO_FILE} \
    ${USER_NAME}@${SERVER}:${USER}_reserve || \
    { errmsg "Error copying ${BASEDIR}/${TESTBED_TOPO_FILE} to " \
    "${USER}_reserve directory on reservation server." ; exit 1; }
scp -q -oStrictHostKeyChecking=no ${SCRIPT_DIR}/reserve.sh \
    ${USER_NAME}@${SERVER}:${USER}_reserve || \
    { errmsg "Error copying reserve.sh to ${USER}_reserve directory on" \
    "reservation server." ; exit 1; }

# Construct the appropriate reserve.sh command from the information
# provided and run it on the testbed reservation server.
CMD=""
if [ ${LOCK_FLAG} == 1 ]; then
    if [ "${REQUESTED_ENCLAVES}" != "" ]; then
	CMD="reserve.sh -l ${REQUESTED_ENCLAVES} -u ${USER} "
	CMD="${CMD} ${TESTBED_TOPO_FILE}"
    else
	CMD="reserve.sh -L ${NUM_REQUESTED_ENCLAVES} -u ${USER} "
	CMD="${CMD} ${TESTBED_TOPO_FILE}"
    fi
elif [ ${RELEASE_FLAG} == 1 ]; then
    CMD="reserve.sh -r ${RELEASE_ENCLAVES} -u ${USER} ${TESTBED_TOPO_FILE}"
elif [ ${QUERY_FLAG} == 1 ]; then
    CMD="reserve.sh -q ${TESTBED_TOPO_FILE}"
fi

if [ "${CMD}" != "" ]; then
    # Execute the command on the testbed reservation server.
    ssh -oStrictHostKeyChecking=no ${USER_NAME}@${SERVER} \
	"cd ${USER}_reserve ; ./${CMD}" || exit 1
fi

# Exit the script successfully.
exit 0
