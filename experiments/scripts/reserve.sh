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
# Script that controls the reservation and release of testbed nodes.

# This script's name for error messages.
this="${0##*/}"

BASE_DIR="."
LOCK_FLAG=0
REQUESTED_ENCLAVES=""
NUM_REQUESTED_ENCLAVES=""
QUERY_FLAG=0
RELEASE_FLAG=0
RELEASE_ENCLAVES=""
TESTBED_TOPO_FILE=""
TESTBED_TOPO_BASE_NAME=""
TESTBED_LOCK_DIR=""
TESTBED_ENCLAVE_CNT=""
LOCKFILE_TOUCH_PID=""
WHO=""
DATE_TIME=""

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
    echo "    [-q] [-r <enclaves>] [-u <user>] [-h] testbed_topology_file"
    echo ""
    echo "Options:"
    echo "  -B <base directory>  The testbed topology file base directory."
    echo "  -l <enclaves>        Colon separated list of the testbed"
    echo "                       enclaves that are to be reserved."
    echo "  -L <num enclaves>    Number of requested enclaves to be reserved."
    echo "  -q                   Query the status of the provide testbed."
    echo "  -r <enclaves>        Colon separated list of the testbed"
    echo "                       enclaves that are to be released."
    echo "  -u <user>            The user that is requesting the testbed"
    echo "                       enclaves."
    echo "  -h                   Usage information."
    echo ""

    # Exit the script with an error.
    exit 1
}

#=============================================================================
# Grab the testbed lockfile.
create_lockfile() {
    # Make sure the lockfile directory exists.
    if [ ! -d /run/lock/iron_testbeds ]; then
	mkdir -p /run/lock/iron_testbeds
    fi

    # Create the lockfile for manipulating the testbed information.
    lockfile-create /run/lock/iron_testbeds/${TESTBED_TOPO_BASE_NAME} || \
	{ errmsg "Error creating lockfile " \
	"/run/lock/iron_testbeds/${TESTBED_TOPO_BASE_NAME}"; exit 1; }

    # Make sure we touch the lockfile while we are reserving the nodes.
    lockfile-touch ${TESTBED_LOCK_DIR} &

    # Save the PID of the lockfile-touch process.
    LOCKFILE_TOUCH_PID="$!"
}

#=============================================================================
# Remove the testbed lockfile.
remove_lockfile() {
    # Kill the lockfile-touch process.
    kill "${LOCKFILE_TOUCH_PID}" 2> /dev/null

    # Remove the testbed lockfile.
    lockfile-remove /run/lock/iron_testbeds/${TESTBED_TOPO_BASE_NAME} || \
	{ errmsg "Error removing lockfile " \
	"/run/lock/iron_testbeds/${TESTBED_TOPO_BASE_NAME}"; exit 1; }
}

#=============================================================================
lock_requested_enclaves() {
    # Grab the testbed lockfile.
    create_lockfile

    ORIG_IFS=${IFS}
    IFS=":"
    for ENC in ${REQUESTED_ENCLAVES}; do
	ENC_IN_USE=$(ls ${TESTBED_LOCK_DIR} | grep enclave${ENC}.lock)
	if [ "${ENC_IN_USE}" != "" ]; then
	    errmsg "Enclave ${ENC} is not available for use in testbed" \
		"${TESTBED_TOPO_FILE}. Aborting..."

	    # Remove the testbed lockfile.
	    remove_lockfile

	    IFS=${ORIG_IFS}

	    # Exit the script with an error.
	    exit 1
	fi
    done

    # If we get here, we know that all of the requested enclaves are
    # available for use. Now we just need to "lock" them.
    ASSIGNED_ENCLAVES=""
    for ENC in ${REQUESTED_ENCLAVES}; do
	ASSIGNED_ENCLAVES="${ASSIGNED_ENCLAVES} ${ENC}"
	LOCKFILE=${TESTBED_LOCK_DIR}/enclave${ENC}.lock
	touch ${LOCKFILE}

	# Put identifying information in the enclave lock file, who
	# locked the enclave when.
	echo "Locked by: ${WHO}" >> ${LOCKFILE}
	echo "Reserved on: ${DATE_TIME}" >> ${LOCKFILE}
    done

    IFS=${ORIG_IFS}

    TRIMMED_ASSIGNED_ENCLAVES=$(echo ${ASSIGNED_ENCLAVES}|xargs)
    echo "ENCLAVES=(${TRIMMED_ASSIGNED_ENCLAVES})"
    RELEASE_ENCLAVES=$(echo ${TRIMMED_ASSIGNED_ENCLAVES} | tr " " ":")
    echo "ENCLAVES_TO_RELEASE=${RELEASE_ENCLAVES}"

    # Remove the testbed lockfile.
    remove_lockfile
}

#=============================================================================
lock_num_requested_enclaves() {
    # Grab the testbed lockfile.
    create_lockfile

    LOCKED_ENCLAVES=$(ls ${TESTBED_LOCK_DIR} | grep lock | wc -l)
    AVAILABLE_ENCLAVES=$(echo ${TESTBED_ENCLAVE_CNT}-${LOCKED_ENCLAVES} | bc)

    if [ "${AVAILABLE_ENCLAVES}" -lt "${NUM_REQUESTED_ENCLAVES}" ]; then
	errmsg "${NUM_REQUESTED_ENCLAVES} enclaves are not available " \
	    "for use in testbed ${TESTBED_TOPO_FILE}. Aborting..."

	# Remove the testbed lockfile.
	remove_lockfile

	# Exit the script with an error.
	exit 1
    fi

    ASSIGNED_ENCLAVES=""
    ASSIGNED_ENCLAVE_CNT=0
    for ENC in `seq 1 ${TESTBED_ENCLAVE_CNT}`; do
	ENC_IN_USE=$(ls ${TESTBED_LOCK_DIR} | grep enclave${ENC}.lock)
	if [ "${ENC_IN_USE}" == "" ]; then
	    ASSIGNED_ENCLAVES="${ASSIGNED_ENCLAVES} ${ENC}"
	    ASSIGNED_ENCLAVE_CNT=$((ASSIGNED_ENCLAVE_CNT+1))

	    LOCKFILE=${TESTBED_LOCK_DIR}/enclave${ENC}.lock
	    touch ${LOCKFILE}
	    echo "Locked by: ${WHO}" >> ${LOCKFILE}
	    echo "Reserved on: ${DATE_TIME}" >> ${LOCKFILE}

	    if [ "${ASSIGNED_ENCLAVE_CNT}" -eq "${NUM_REQUESTED_ENCLAVES}" ]; then
		break
	    fi
	fi
    done

    TRIMMED_ASSIGNED_ENCLAVES=$(echo ${ASSIGNED_ENCLAVES}|xargs)
    echo "ENCLAVES=(${TRIMMED_ASSIGNED_ENCLAVES})"
    RELEASE_ENCLAVES=`echo ${TRIMMED_ASSIGNED_ENCLAVES} | tr " " ":"`
    echo "ENCLAVES_TO_RELEASE=${RELEASE_ENCLAVES}"

    # Remove the testbed lockfile.
    remove_lockfile
}

#=============================================================================
# Release testbed enclaves.
release_enclaves() {
    # Grab the testbed lockfile.
    create_lockfile

    ORIG_IFS=${IFS}
    IFS=":"

    # Verify that all of the enclaves are locked and that the
    # user requesting the release is the "owner" of them.
    ERROR=0
    for ENC in ${RELEASE_ENCLAVES}; do
	if [ ! -f ${TESTBED_LOCK_DIR}/enclave${ENC}.lock ]; then
	    errmsg "Enclave ${ENC} is not locked."
	    continue
	else
	    OWNER=$(grep Locked ${TESTBED_LOCK_DIR}/enclave${ENC}.lock | \
		cut -d " " -f3)
	    if [ "${OWNER}" != "${WHO}"  ]; then
		errmsg "${WHO} is not the owner of Enclave ${ENC}. Aborting..."
		ERROR=1
	    fi
	fi
    done

    if [ ${ERROR} -ne 1 ]; then
	for ENC in ${RELEASE_ENCLAVES}; do
	    rm -f ${TESTBED_LOCK_DIR}/enclave${ENC}.lock
	done
    fi

    IFS=${ORIG_IFS}

    # Remove the testbed lockfile.
    remove_lockfile
}

#=============================================================================
# Query the status of the testbed enclaves.
query_testbed() {
    # Grab the testbed lockfile.
    create_lockfile

    LOCKS=$(ls ${TESTBED_LOCK_DIR}/*.lock 2> /dev/null)
    if [ "${LOCKS}" == "" ]; then
	echo ""
	echo "All enclaves available."
	echo ""
    else
	echo ""
	for FILE in ${TESTBED_LOCK_DIR}/*.lock; do
	    ENC=$(basename ${FILE} | cut -d "." -f1)
	    echo "${ENC}:"
	    cat "${FILE}"
	    echo ""
	done
    fi

    # Release the testbed lockfile.
    remove_lockfile
}

# Grab the date and time. This will be echoed into the enclave lock
# files.
DATE_TIME=$(date)

# Process the command line options.
while getopts B:l:L:qr:u:h option; do
    case $option in
	B)
	    BASE_DIR=${OPTARG};;
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
	u)
	    WHO=${OPTARG};;
	h|?)
	    usage;;
    esac
done

# Grab the testbed topology file command line argument.
shift $((${OPTIND} - 1))
if [ "$#" -ne 1 ]; then
    errmsg "Expected 1 command line argument, $# provided. Aborting..."

    # Exit the script with an error.
    exit 1
fi
TESTBED_TOPO_FILE=$*

# Verify that the testbed topology file exists.
if [ ! -f ${BASE_DIR}/${TESTBED_TOPO_FILE} ]; then
    errmsg "Testbed topology file ${TESTBED_TOPO_FILE} not found."
    "Aborting..."

    # Exit the script with an error.
    exit 1
fi

# Remove the suffix from the testbed topology file name.
TESTBED_TOPO_BASE_NAME=$(echo ${TESTBED_TOPO_FILE} | cut -d "." -f1)

# The directory where the testbed's enclave lock files are located.
TESTBED_LOCK_DIR="${HOME}/testbed_reservations/${TESTBED_TOPO_BASE_NAME}"

# Extract the total number of enclaves supported in the testbed.
TESTBED_ENCLAVE_CNT=$(grep num_enclaves ${BASE_DIR}/${TESTBED_TOPO_FILE} \
    | cut -d " " -f 2)
if [ "${TESTBED_ENCLAVE_CNT}" == "" ]; then
    errmsg "Testbed topology file ${TESTBED_TOPOLOGY_FILE} missing "
    "'num_enclaves' line. Aborting..."

    # Exit the script with an error.
    exit 1
fi

# Make the directory for the testbed's enclave lock files.
mkdir -p ${HOME}/testbed_reservations/${TESTBED_TOPO_BASE_NAME}

# Take the appropriate action. We are either locking testbed enclaves,
# releasing testbed enclaves, or querying the state of the testbed.
if [ ${LOCK_FLAG} == 1 ]; then
    # The '-l' and '-L' options are mutually exclusive. Make sure the
    # user did not provide both of them.
    if [[ "${REQUESTED_ENCLAVES}" != "" && \
	"${NUM_REQUESTED_ENCLAVES}" != "" ]]; then
	errmsg "-l and -L options are mutually exclusive. Aborting..."

	# Exit the script with an error.
	exit 1
    elif [ "${REQUESTED_ENCLAVES}" != "" ]; then
	lock_requested_enclaves
    elif [ "${NUM_REQUESTED_ENCLAVES}" != "" ]; then
	lock_num_requested_enclaves
    fi
elif [ ${RELEASE_FLAG} == 1 ]; then
    release_enclaves
elif [ ${QUERY_FLAG} == 1 ]; then
    query_testbed
fi

# Exit the script successfully.
exit 0
