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


# This script controls the stages of running an experiment on a
# testbed. This script (and all scripts that are called) works on the
# local testbed.

# This script's name for error messages.
this="${0##*/}"

MAKE_FLAG=0
STAGE_FLAG=0
VALIDATE_FLAG=0
INSTALL_FLAG=0
CONFIGURE_FLAG=0
RUN_FLAG=0
DEBUG_FLAG=0
RESERVATION_FLAG=0
PROCESS_OPTION=""
COLLECT_OPTION="-c"
BASELINE_OPTION=""
INSTALL_OPTION=""
RUN_OPTION=""
RESERVATION_HOST="gnat0.bbn.com"
REQUESTED_ENCLAVES=""
NUM_REQUESTED_ENCLAVES=""
EXP_USER_NAME="iron"
TESTBED_TOPO_FILE=""
DETER_EXP_OPTION=""
ANNOTATION_OPTION=""
EXPERIMENTS=""
DEMO_OPTION=""
DOMAIN=""

#=============================================================================
# Print out usage information and exit.
usage() {
    echo ""
    echo "Usage:"
    echo "  ${this} [-msvcirp] [-nbz] [-o <reservation_host>] [-u <user_name>]"
    echo "     [-l <enclaves>] [-L <num_enclaves>]"
    echo "     [-t <testbed_topo_file>] [-e <exp_name>] [-a <annotation>]"
    echo "     [-d] experiment..."
    echo ""
    echo "Options:"
    echo "  -m                      Build the IRON executables."
    echo "  -s                      Stage the experiments."
    echo "  -v                      Validate the experiments (only valid if "
    echo "                          staging)."
    echo "  -c                      Configure the experiments."
    echo "  -i                      Install the experiments."
    echo "  -r                      Run the experiments."
    echo "  -p                      Process the experiment results (only valid"
    echo "                          if running)."
    echo "  -n                      Do not collect the experiment results "
    echo "                          and artifacts."
    echo "  -b                      Do not start IRON components."
    echo "  -o <reservation_host>   Host or address of testbed reservation"
    echo "                          server. Set to 'none' if there is no"
    echo "                          testbed reservation server available"
    echo "                          (reservation of testbed nodes will not"
    echo "                          be attempted)."
    echo "                          Default value: ${RESERVATION_HOST}"
    echo "  -u <user_name>          The user the experiments are to run as."
    echo "                          Default value: ${EXP_USER_NAME}"
    echo "  -l <enclaves>           Colon separated list of the testbed"
    echo "                          enclaves that are to be reserved."
    echo "  -L <num enclaves>       Number of requested enclaves to be"
    echo "                          reserved."
    echo "  -t <testbed_topo_file>  The name of the testbed config file."
    echo "  -e <exp_name>           The DETER experiment name. Only required"
    echo "                          for experiments that are to be run on"
    echo "                          DETER."
    echo "  -a <annotation>         Annotation appended to the results directory"
    echo "                          name. Any spaces in this tag will be"
    echo "                          replaced with '_' characters."
    echo "  -z                      Demo mode. The script will start the experiment and"
    echo "                          return successfully. The user must tear down the"
    echo "                          experiment separately."
    echo ""
    echo "  -d                      Enable debug logging."
    echo ""
    echo ""
    echo "Example:"
    echo ""
    echo "1. Run 2-node experiment on testbed, skip build step:"
    echo ""
    echo "   ${this} -scir -u iron -t example_testbed.cfg 2-node"
    echo ""
    exit 1
}

STAGING_DIR="${HOME}/iron_exp_staging"

#=============================================================================
# Execute a command, either locally or via the REMOTE_EXECTION_NODE if
# it exists.
execute() {
    CMD=$@
    if [ "${REMOTE_EXECUTION_NODE}" != "" ]; then
        ssh ${REMOTE_EXECUTION_NODE} ""'cd ${HOME}/iron_exp_staging/scripts ; '"$CMD"
    else
        $CMD
    fi
}

#=============================================================================
# Determine whether we have uncompiled changes. If so, let the user decide
# what to do.
#
# Exits the script if there are uncompiled changes and the user chooses not
# to contine.
#
# Returns 1 if there are uncompiled changes and user DOES want to contine (or
# doesn't answer so the read times out).
#
# Returns 0 if there are no uncompiled changes.
built_check() {
    if ! [[ -e ${IRON_HOME}/amp && \
            -e ${IRON_HOME}/bpf && \
            -e ${IRON_HOME}/common && \
            -e ${IRON_HOME}/makefile && \
            -e ${IRON_HOME}/options.mk && \
            -e ${IRON_HOME}/sliq && \
            -e ${IRON_HOME}/tcp_proxy && \
            -e ${IRON_HOME}/udp_proxy && \
            -e ${IRON_HOME}/bin/${BUILD_STYLE}/amp && \
            -e ${IRON_HOME}/bin/${BUILD_STYLE}/tcp_proxy && \
            -e ${IRON_HOME}/bin/${BUILD_STYLE}/udp_proxy && \
            -e ${IRON_HOME}/bin/${BUILD_STYLE}/bpf ]]; then
        # Code doesn't exit or has never been built. There's nothing we can do.
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo "Code or executable not found!"
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        exit 1
    fi
    # Are there any files in the code directories with a modification time
    # newer than the modification time of the bpf executable?
    if [[ -n $(find \
            ${IRON_HOME}/amp \
            ${IRON_HOME}/bpf \
            ${IRON_HOME}/common \
            ${IRON_HOME}/sliq \
            ${IRON_HOME}/tcp_proxy \
            ${IRON_HOME}/udp_proxy \
            ${IRON_HOME}/makefile \
            ${IRON_HOME}/options.mk \
        -newermm ${IRON_HOME}/bin/${BUILD_STYLE}/bpf) ]]; then
        echo "!!!!!!!!!!!!!!!!!!!!!!"
        echo "FOUND UNCOMPILED CODE!"
        echo "!!!!!!!!!!!!!!!!!!!!!!"
        # What does the user want to do?
        read -t 10 -p 'Continue anyway? [y|N]  ' response
	if [[ $? = 0 && ! ( $response && ("${response,,}" = "y" || \
                "${response,,}" = "yes") ) ]]; then
            # User answered, but not with "y" or "yes" (case insensitive)
            exit 1
        else
            # User said "y" or "yes", case insensitive, or the read timed
            # out. Continue, but return 1 so we know to print a warning after
            # the test completes.
            echo ""
            return 1
        fi
    fi
    return 0
}

#=============================================================================
# Release the testbed enclaves that were locked for the experiment.
release_enclaves() {
    # We only need to worry about releasing locked testbed enclaves
    # for locally run experiments.
    if [ "${DOMAIN}" == "isi.deterlab.net" ]; then
	return
    fi

    if [ ${RESERVATION_FLAG} -ne 1 ]; then
	return
    fi

    ENCLAVES_TO_RELEASE=$(grep ENCLAVES_TO_RELEASE \
	${STAGING_DIR}/enclaves.cfg | cut -d "=" -f2)
    ./reserve_ctl.sh -u ${EXP_USER_NAME} -r ${ENCLAVES_TO_RELEASE} \
	-B ../testbeds -s ${RESERVATION_HOST} ${TESTBED_TOPO_FILE} || \
	{ echo "Error releasing enclaves ${ENCS_TO_RELEASE}" \
	"from testbed ${TESTBED_TOPO_FILE}"; exit 1; }
}

# Process the command line options.
while getopts msvicrpnbzo:u:l:L:t:e:a:dh option; do
    case $option in
        m)
            MAKE_FLAG=1;;
        s)
            STAGE_FLAG=1;;
        v)
            VALIDATE_FLAG=1;;
        i)
            INSTALL_FLAG=1
            INSTALL_OPTION="-i";;
        c)
            CONFIGURE_FLAG=1;;
        r)
            RUN_FLAG=1
            RUN_OPTION="-r";;
        p)
	    # One might expect that process is a step like each of
	    # -msvic which can be invoked separately.  However, it is
	    # intertwined with the stop part of run, because
	    # significant parts of processing is done on the
	    # experiment nodes prior to copying results.
            PROCESS_OPTION="-p";;
        o)
            RESERVATION_HOST=${OPTARG};;
        n)
            COLLECT_OPTION="";;
        b)
            BASELINE_OPTION="-b";;
        z)
            DEMO_OPTION="-z";;
        u)
            EXP_USER_NAME="$OPTARG";;
	l)
	    if [ ${RESERVATION_FLAG} -eq 1 ]; then
		echo "-l and -L options are mutually exclusive."
		usage
	    fi
	    RESERVATION_FLAG=1
	    REQUESTED_ENCLAVES=${OPTARG};;
	L)
	    if [ ${RESERVATION_FLAG} -eq 1 ]; then
		echo "-l and -L options are mutually exclusive."
		usage
	    fi
	    RESERVATION_FLAG=1
	    NUM_REQUESTED_ENCLAVES=${OPTARG};;
        t)
            TESTBED_TOPO_FILE="$OPTARG";;
        e)
            DETER_EXP_OPTION="-e $OPTARG";;
        a)
            # If the annotative tag for the results directory name
            # contains spaces, replace the spaces with '_'.
            ANNOTATION=$OPTARG
            ANNOTATION=$(echo ${ANNOTATION} | tr ' ' '_')
            ANNOTATION_OPTION="-a $ANNOTATION";;
        d)
            DEBUG_FLAG=1;;
        h|?)
            usage;;
    esac
done

# Validate that the required command line options are provided for the
# chosen options.
if [ ${CONFIGURE_FLAG} -eq 1 ] && [ "${EXP_USER_NAME}" == "" ]; then
    echo "Missing required -u option for configure action."
    usage
fi

if [ ${STAGE_FLAG} -eq 1 ] || [ ${CONFIGURE_FLAG} -eq 1 ] \
    && [ "${TESTBED_TOPO_FILE}" == "" ]; then
    echo "Missing required -t option for stage or configure action."
    usage
fi

if [ ${VALIDATE_FLAG} -eq 1 ] && [ ${STAGE_FLAG} -eq 0 ]; then
    echo "Validation requires that the experiment is staged."
    usage
fi

if [ ! "${RESERVATION_HOST,,}" = "none" ] && [ ${RESERVATION_FLAG} -eq 0 ] && \
    { [ ${CONFIGURE_FLAG} -eq 1 ] || [ ${INSTALL_FLAG} -eq 1 ] || \
    [ ${RUN_FLAG} -eq 1 ]; }; then
    echo "Missing required -l or -L option to configure and/or install and/or run experiment."
    usage
fi

if [ "${PROCESS_OPTION}" = "-p" ] && [ "${RUN_FLAG}" -eq 0 ]; then
    echo "Processing can only be done as part of running."
    usage
fi

# Grab the command line arguments. These contain the names of the
# experiments that are to be run.
shift $(($OPTIND - 1))
EXPERIMENTS=$*

if [ ${MAKE_FLAG} -eq 1 ] && [ $# -eq 0 ]; then
    usage
fi

COMPILED=0
if [ ${MAKE_FLAG} -eq 1 ]; then
    # Build the IRON software.
    ./make.sh || exit 1
else
    built_check
    COMPILED=$?
fi

if [ ${STAGE_FLAG} -eq 1 ]; then
    # Stage the experiments.
    ./stage.sh ${TESTBED_TOPO_FILE} ${EXPERIMENTS} || exit 1
fi

if [ ${VALIDATE_FLAG} -eq 1 ]; then
    if [ ${DEBUG_FLAG} -eq 1 ]; then
        QUIET_ARG=""
    else
        QUIET_ARG="--quiet"
    fi
    echo ""
    echo "Validating experiments..."
    echo "--------------------------"
    # Validate the experiments.
    python ${STAGING_DIR}/scripts/validate_experiment.py ${QUIET_ARG} \
        ${EXPERIMENTS} || exit 1
fi

# If the staging process created a remote execution node configuration
# file, load it now.
if [ -e ${STAGING_DIR}/remote_execution_node.cfg ]; then
    source ${STAGING_DIR}/remote_execution_node.cfg
fi

DOMAIN=`echo ${REMOTE_EXECUTION_NODE} | cut -d '.' -f2-`

# Reserve the testbed enclaves. Do this before the configuration stage
# so we can generate the configuration files from the configuration
# file templates, if necessary.
if [ "${DOMAIN}" != "isi.deterlab.net" ]; then
    if [ "${REQUESTED_ENCLAVES}" != "" ]; then
	./reserve_ctl.sh -l ${REQUESTED_ENCLAVES} -B ../testbeds \
	    -s ${RESERVATION_HOST} -u ${EXP_USER_NAME} \
	    ${TESTBED_TOPO_FILE} > ${STAGING_DIR}/enclaves.cfg || \
	    { echo "Error reserving enclaves ${REQUESTED_ENCLAVES}" \
	    "from testbed ${TESTBED_TOPO_FILE}"; exit 1; }
    else
	EXPERIMENT_TEMPLATES=$(ls -R ${STAGING_DIR} | fgrep "tmpl")
	if [ "${EXPERIMENT_TEMPLATES}" == "" ]; then
	    # If there are no templated configuration files in the
	    # staging area, we can not use the -L option. Older
	    # experiments (non-templated configured experiments) are
	    # developed to work with very specific enclaves.
	    echo ""
	    echo "-L option can not be used for \"untemplated\" legacy" \
		"experiments."
	    exit 1
	fi
	if [ ${RESERVATION_FLAG} -eq 1 ]; then
	    ./reserve_ctl.sh -L ${NUM_REQUESTED_ENCLAVES} -B ../testbeds \
		-s ${RESERVATION_HOST} -u ${EXP_USER_NAME} \
		${TESTBED_TOPO_FILE} > ${STAGING_DIR}/enclaves.cfg || \
		{ echo "Error reserving ${NUM_REQUESTED_ENCLAVES} enclaves" \
		"from testbed ${TESTBED_TOPO_FILE}" ; exit 1; }
	fi
    fi
fi

#*****************************************************************************
# NOTE: From this point on in the script, we MUST be sure to call the
# release_enclaves() function if an error occurs to ensure that we
# release any testbed enclaves that may have been locked. Otherwise,
# they could be left in a locked state.
#*****************************************************************************

if [ ${DEBUG_FLAG} -eq 1 ]; then
    DEBUG_ARG="-d"
else
    DEBUG_ARG=""
fi

if [ ${CONFIGURE_FLAG} -eq 1 ]; then
    # Configure the experiments.
    execute ./configure.sh ${DEBUG_ARG} -u ${EXP_USER_NAME} \
        ${DETER_EXP_OPTION} ${TESTBED_TOPO_FILE} ${EXPERIMENTS} || \
	{ release_enclaves ; exit 1; }
fi

if [ "${DOMAIN}" == "isi.deterlab.net" ]; then
    # We currently only permit the user to provide 1 experiment to run
    # on the command line for DeterLab experiments. The main reason
    # for this is that we need to "bootstrap" the Deter nodes. Part of
    # the "bootstrapping" process includes node specific bootstraping
    # scripts to be run that are experiment dependent. For simplicity,
    # once we "bootstrap" a set of Deter nodes we don't undo this or
    # do it more than once.
    CHAR=" "
    NUM_EXPS=`echo "${EXPERIMENTS}" | awk -F"${CHAR}" '{print NF}'`

    if [ ${NUM_EXPS} != 1 ]; then
	echo "Only 1 experiment can be run at a time on DeterLab. Aborting..."
	exit 1
    fi

    # Verify that the OS update has completed on the Deter testbed
    # nodes.
    execute ./verify_deter_os_update_complete.sh -u ${EXP_USER_NAME} \
	-e ${EXPERIMENTS} || exit 1

    # Bootstrap the Deter testbed nodes.
    execute ./create_deter_exp_disks.sh -u ${EXP_USER_NAME} \
	-e ${EXPERIMENTS} || exit 1
fi

if [ ${INSTALL_FLAG} -eq 1 ]; then
    # Install the experiments.
    execute ./install.sh ${DEBUG_ARG} ${EXPERIMENTS} || \
	{ release_enclaves ; exit 1; }
fi

if [ "${DOMAIN}" == "isi.deterlab.net" ]; then
    # Bootstrap the Deter nodes. If this fails, we don't need to call
    # the release_enclaves() function because testbed enclaves are not
    # reserved for DeterLab experiments.
    execute ./bootstrap_deter_nodes.sh -u ${EXP_USER_NAME} -e ${EXPERIMENTS} \
	|| exit 1
fi

if [ ${RUN_FLAG} -eq 1 ]; then
    # Run the experiments.
    execute ./ecp_exe_exps.sh ${PROCESS_OPTION} ${DEBUG_ARG} \
        ${COLLECT_OPTION} ${BASELINE_OPTION} \
        ${DEMO_OPTION} ${ANNOTATION_OPTION} ${DETER_EXP_OPTION} \
        ${EXPERIMENTS} || \
	{ release_enclaves; exit 1; }
fi

# Release the enclaves that were locked.
if [ ${RESERVATION_FLAG} -eq 1 ] && [ ${DEMO_OPTION} == ""]; then
    release_enclaves
fi

if [ ${COMPILED} != 0 ]; then
    echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
    echo 'REMINDER: CODE WAS NOT COMPILED BEFORE RUNNING THIS TEST!'
    echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
fi

# Exit the script successfully.
exit 0
