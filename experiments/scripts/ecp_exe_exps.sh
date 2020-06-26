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


# Executes a collection of experiments, identified by the command-line
# arguments, on the experiment's reserved testbed nodes. For each
# experiment:
#  - Artifacts from previous runs are removed
#  - LinkEm instances are started
#  - gulp captures are started
#  - IRON components are started, if not in BASELINE mode
#  - Traffic sources/sinks are started, if not in DEMO mode
#  - LinkEm modifications are started
#  - If DURATION is defined and not 0, the following occur after
#    sleeping DURATION seconds:
#    o Traffic sources/sinks are stopped
#    o IRON components are stopped
#    o gulp captures are stopped
#    o LinkEm instances are stopped
#    o Results are processed, if directed to process results
#    o Experiment artifacts are collected, if directed to collect results
#    o All-nodes per-run post processing occurs, if directed to
#      process results
#
# This script requires the following:
#  - Testbed nodes have been reserved
#  - Experiments have been installed

# This script's name for error messages.
this="${0##*/}"

DURATION=0
ANNOTATION=""
BASELINE_OPTION=""
COLLECT_OPTION=""
DEMO_FLAG=0
DEBUG_OPTION=""
PROCESS_FLAG=0

#=============================================================================
# Print out the usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Executes a collection of experiments, identified by the"
    echo "command-line arguments, on the experiment's reserved testbed nodes."
    echo "For each experiment:"
    echo "  - Artifacts from previous runs are removed"
    echo "  - LinkEm instances are started"
    echo "  - gulp captures are started"
    echo "  - IRON components are started, if not in BASELINE mode"
    echo "  - LinkEm modifications are started"
    echo "  - If DURATION is defined and not 0, the following occur after"
    echo "    sleeping DURATION seconds:"
    echo "    o Traffic sources/sinks are stopped"
    echo "    o IRON components are stopped"
    echo "    o gulp captures are stopped"
    echo "    o LinkEm instances are stopped"
    echo "    o Results are processed, if directed to process results"
    echo "    o Experiment artifacts are collected, if directed to collect"
    echo "      results"
    echo "    o All-nodes per-run post processing occurs, if directed to"
    echo "      process results"
    echo ""
    echo "Usage:"
    echo "  ${this} [-a <annotation>] [-b] [-c] [-d] [-e <exp_name>] [-p]"
    echo "     [-z] experiment..."
    echo ""
    echo "Options:"
    echo "  -a <annotation>  Annotation appended to the results directory"
    echo "                   name. Any spaces in this tag will be replaced"
    echo "                   with '_' characters."
    echo "                   Default: no annotation"
    echo "  -b               Do not run IRON components."
    echo "                   Default: Run IRON components"
    echo "  -c               Collect the experiment logs, results, and"
    echo "                   artifacts."
    echo "                   Default: disabled"
    echo "  -d               Enable debug logging."
    echo "                   Default: disabled"
    echo "  -e <exp_name>    The DETER experiment name. Only required"
    echo "                   for experiments that are to be run on"
    echo "                   DETER."
    echo "  -p               Process the experiment results."
    echo "                   Default: disabled"
    echo "  -z               Demo mode. The script will start the experiment and"
    echo "                   return successfully. The user must tear down the"
    echo "                   experiment separately."
    echo "                   Default: disabled"
    echo "  -h               Display usage information."
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
while getopts a:bcde:pzh OPTION; do
    case ${OPTION} in
        a)
            ANNOTATION="_$OPTARG"
            ANNOTATION=`echo ${ANNOTATION} | tr ' ' '_'`;;
        b)
            BASELINE_OPTION="-b";;
        c)
            COLLECT_OPTION="-c";;
        d)
            DEBUG_OPTION="-d";;
        e)
            DETER_EXP_NAME="$OPTARG";;
        p)
            PROCESS_FLAG=1;;
        z)
            DEMO_FLAG=1;;
        h|?)
            usage;;
    esac
done

# Grab the command line arguments. These contain the names of the
# experiments that are to be run.
shift $(($OPTIND - 1))
EXPERIMENTS=$*

# Make sure we have the correct number of command line arguments.
if [ "$#" -eq 0 ]; then
    usage "Error: Must provide at least 1 command line argument"
fi

STAGING_DIR="${HOME}/iron_exp_staging"
INITIAL_START_TIMESTAMP=$(date -u "+%Y_%m_%dT%H_%M_%SZ")
RES_TOP_LEVEL_DIR_NAME=${INITIAL_START_TIMESTAMP}${ANNOTATION}

echo ""
echo "Running experiments..."
echo "----------------------"

# Iterate over the experiments.
for arg; do
    # Set up the environment for the current experiment.
    #
    # EXP_BASE_DIR and USER_NAME are defined in exp.cfg
    source ${STAGING_DIR}/${arg}/exp.cfg
    echo ${arg} > ${STAGING_DIR}/current_exp.txt

    # Iterate over the experiment runs.
    for DIR in ${STAGING_DIR}/${arg}/run*; do
        RUN=`basename ${DIR}`
        echo "Running experiment ${arg} ${RUN}"
        echo ""

	# Clean up the artifacts from previous runs.
	./ecp_cleanup.sh ${DEBUG_OPTION} -r ${RUN} ${arg}

        # Stop old LinkEm that might have been running from a partial
        # previous experiment run.  In an ideal world, none will be
        # running.
        # \todo Explain why this is here, instead of only once before
        # the iteration over runs.
	./ecp_stop_linkem.sh ${DEBUG_OPTION} -r ${RUN} ${arg}

        # Start LinkEm.
	./ecp_start_linkem.sh ${DEBUG_OPTION} -r ${RUN} ${arg}

        # Start the experiment components.
	./ecp_start_gulp.sh ${DEBUG_OPTION} -r ${RUN} ${arg}
	if [ "${BASELINE_OPTION}" == "" ]; then
	    ./ecp_start_iron.sh ${DEBUG_OPTION} -r ${RUN} ${arg}
	    if [ ${DEMO_FLAG} -eq 0 ]; then
		./ecp_start_traffic.sh ${DEBUG_OPTION} -r ${RUN} ${arg}
	    else
		echo "Running in demo mode. NOT starting applications."
	    fi
	fi

        # Start LinkEm adjustments with full system up and running
	./ecp_start_linkem_mods.sh -r ${RUN} ${arg}

	# If DURATION is 0, exit the script successfully. The
	# experiment will have to be stopped by other means.
	if [ ${DURATION} -eq 0 ]; then
	    exit 0
	fi

	# If we are in demo mode, exit the script successfully. The
	# experiment will have to be stopped by other means.
        if [ ${DEMO_FLAG} -eq 1 ]; then
            exit 0
        fi

        # Wait for the experiment to run.
        echo "Sleeping for ${DURATION} seconds while mgen runs zzZZzzZZzzZZ..."
        sleep ${DURATION}

        # Stop the experiment and pull back the logs.
        echo ""
        echo "Stopping experiment and collecting artifacts..."
	./ecp_stop_traffic.sh ${DEBUG_OPTION} -r ${RUN} ${arg}
	./ecp_stop_iron.sh ${DEBUG_OPTION} -r ${RUN} ${arg}
	./ecp_stop_gulp.sh ${DEBUG_OPTION} -r ${RUN} ${arg}
	./ecp_stop_linkem.sh ${DEBUG_OPTION} -r ${RUN} ${arg}

	if [ ${PROCESS_FLAG} -eq 1 ]; then
	    ./ecp_process_results.sh ${DEBUG_OPTION} -r ${RUN} ${arg}
	fi
	./ecp_collect_exp_results.sh -r ${RUN} -t ${RES_TOP_LEVEL_DIR_NAME} \
				     ${arg}

	# Perform all-nodes per-run post-rename processing.  This
	# cannot be called from process.sh because that is run on the
	# nodes themselves where only one node's data is present. This
	# should be run after we've moved to generically named
	# directories so that these scripts can be run outside of the
	# normal experiment process. The analysis script expects to be
	# in the run directory. This analysis script cannot be run on
	# Deter, so check for isi.deterlab.net domain.
	RES_DOMAIN=`echo ${RES_HOST} | cut -d '.' -f 2-`
	if [ ${PROCESS_FLAG} -eq 1 ]; then
	    RES_DIR=$(cat ${HOME}/iron_results/last_run_experiment.txt)
	    if [ "${RES_DOMAIN}" == "isi.deterlab.net" ]; then
		echo "All-nodes processing skipped; Cannot execute on ${RES_HOST}."
	    elif [ ! -d ${RES_DIR} ]; then
		echo "All-nodes processing skipped; ${RES_DIR} does not exist."
	    else
		echo "Performing all-nodes processing:"
		(cd ${RES_DIR} &&
			python ${STAGING_DIR}/scripts/process_trpr.py
		)
	    fi
	fi

        echo ""
    done
    echo "Done executing runs for ${arg}"
done

# Exit the script successfully.
exit 0
