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


# Finalizes the configuration of the experiments for a reserved set of
# testbed nodes. This entails generating an exp.cfg file with fully
# qualified node names and dynamically determined interface names for
# each of the experiments.
#
# This script requires the following:
#   - Testbed nodes have been reserved
#   - ${HOME}/iron_exp_staging/enclaves.cfg exists for templated
#     experiments.

# This script's name for error messages.
this="${0##*/}"

EXP_USER_NAME="iron"
TESTBED_TOPO_FILE=""
EXP_CFG_FILE=""
DETER_EXP_NAME=""
STAGING_DIR="${HOME}/iron_exp_staging"
EXPERIMENTS=""
DEBUG_FLAG=0

#=============================================================================
# Print out usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Finalizes the configuration of the experiments for a reserved set"
    echo "of testbed nodes. This entails generating an exp.cfg file with"
    echo "fully qualified node names and dynamically determined interface"
    echo "names for each of the experiments."
    echo ""
    echo "This script requires the following:"
    echo "  - Testbed nodes have been reserved"
    echo "  - ${STAGING_DIR}/enclaves.cfg exists for IRON"
    echo "    templated experiments"
    echo ""
    echo ""
    echo "Usage:"
    echo "  ${this} [-d] [-e <exp_name>] [-u <user_name>] [-h]"
    echo "    testbed_cfg_file_name exp_name1[...exp_nameN]"
    echo ""
    echo "Options:"
    echo "  -d              Enable debug logging."
    echo "                  Default: Disabled"
    echo "  -e <exp_name>   The DETER experiment name. Only required for"
    echo "                  experiments that run on the DETER testbed."
    echo "  -u <user_name>  The user the experiments are to run as."
    echo "                  Default: iron"
    echo "  -h              Display usage information."
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
while getopts de:u:h OPTION; do
    case ${OPTION} in
        d)
            DEBUG_FLAG=1;;
        e)
            DETER_EXP_NAME="$OPTARG";;
        u)
            EXP_USER_NAME="$OPTARG";;
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

# Grab the name of the testbed topology file command line argument.
shift $(($OPTIND - 1))
TESTBED_TOPO_FILE=$1

# Grab the remaining command line arguments. These contain the names
# of the experiments that are to be run.
shift 1
EXPERIMENTS=$*

# Make sure that at least 1 experiment has been provided.
if [ $# -eq 0 ]; then
    usage "Error: Must provide at least 1 experiment to configure."
fi

echo ""
echo "Configuring experiments..."
echo "--------------------------"

# Generate the exp.cfg files for the experiments to be run. This
# process replaces the generic node names with fully qualified host
# name and inserts the dynamically determined interface names.
for arg; do
    if [ -e ${STAGING_DIR}/${arg}/exp.tmpl ]; then
	# The experiment is templated. Generate the experiment
	# configuration files from the configuration templates.
	./generate_exp_cfgs.py ${TESTBED_TOPO_FILE} || \
	    exit 1
    fi

    EXP_CFG_FILE=${STAGING_DIR}/${arg}/exp.cfg

    echo "Generating fully qualified exp.cfg file for experiment ${arg}..."
    if [ ${DEBUG_FLAG} -eq 1 ]; then
        python ./generate_testbed_exp_cfg.py ${EXP_USER_NAME} \
            ${STAGING_DIR}/testbeds/${TESTBED_TOPO_FILE} ${EXP_CFG_FILE} \
            ${DETER_EXP_NAME} || exit 1
    else
        python ./generate_testbed_exp_cfg.py --quiet ${EXP_USER_NAME} \
            ${STAGING_DIR}/testbeds/${TESTBED_TOPO_FILE} ${EXP_CFG_FILE} \
            ${DETER_EXP_NAME} || exit 1
    fi

    # The generated file is placed in the top level staging
    # directory. Save the original (in the experiment
    # directory). Then, move the generated file to the appropriate
    # experiment directory.
    mv ${STAGING_DIR}/${arg}/exp.cfg ${STAGING_DIR}/${arg}/exp.cfg.orig || \
        exit 1
    mv ${STAGING_DIR}/exp.cfg ${STAGING_DIR}/${arg} || exit 1

    # The script also creates a hosts.txt file. We move that to the
    # appropriate experiment directory.
    mv ${STAGING_DIR}/hosts.txt ${STAGING_DIR}/${arg} || exit 1
done

# Run the script that performs the parameter substitutions for running
# experiments with different parameter values.
./generate_exp_run_cfgs ${EXPERIMENTS} || exit 1

# Complete the experiment configuration. This includes:
#
#   - Finalization of the LinkEm initialization and impairment scripts
#   - Generation of the mgen input files
for arg; do
    EXP_CFG_FILE=${STAGING_DIR}/${arg}/exp.cfg
    source ${EXP_CFG_FILE}
    for DIR in ${STAGING_DIR}/${arg}/run*; do
	# Finalize LinkEm initialization and impairment scripts.
	echo "Finalizing LinkEm initialization and impairment scripts " \
	     "for experiment ${arg} `basename ${DIR}`"
	for LINKEM_NODE in ${LINKEM_NODES[*]}; do
	    GENERIC_NODE_NAME=$(echo ${LINKEM_NODE} | cut -d ':' -f1)
	    FQ_NODE_NAME=$(echo ${LINKEM_NODE} | cut -d ':' -f2)
	    LINKEM_PORT=$(echo ${LINKEM_NODE} | cut -d ':' -f3)
	    sed -i -e \
		"s/${GENERIC_NODE_NAME} /${FQ_NODE_NAME} -p ${LINKEM_PORT} /g" \
		${DIR}/cfgs/lem_init.sh
	    chmod +x ${DIR}/cfgs/lem_init.sh
	    sed -i -e \
		"s/${GENERIC_NODE_NAME} /${FQ_NODE_NAME} -p ${LINKEM_PORT} /g" \
		${DIR}/cfgs/lem.sh
	    chmod +x ${DIR}/cfgs/lem.sh
	done

	# Generate mgen input files
        echo "Generating mgen input files for experiment ${arg}" \
            "`basename ${DIR}`"

        TRAFFIC_CFG_FILENAME="${DIR}/cfgs/traffic.cfg"
	
        if [ ${DEBUG_FLAG} -eq 1 ]; then
            echo "traffic cfg file: ${TRAFFIC_CFG_FILENAME}"
        fi
	
        if [ -e ${TRAFFIC_CFG_FILENAME} ]; then
            if [ ${DEBUG_FLAG} -eq 1 ]; then
                echo "Generating mgen input files in ${EXP_NAME}/cfgs"
            fi
            pushd ${STAGING_DIR}/scripts >/dev/null
            python ./generate_traffic_input_files.py $DIR \
                   ${STAGING_DIR}/testbeds/${TESTBED_TOPO_FILE} || exit 1
            popd >/dev/null
        fi

    done
done

# Recreate the exp.tgz file as the result of configuring the
# experiments may have changed the contents of the experiment
# configuration directories (there may now be *.mgn files that are
# generated from the mgen input configuration files).
pushd ${STAGING_DIR} >/dev/null
rm -f exp.tgz || exit 1
tar czf exp.tgz * || exit 1
popd >/dev/null

# Exit the script successfully.
exit 0
