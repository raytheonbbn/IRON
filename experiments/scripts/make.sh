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


# Builds the IRON software.
#
# This script requires the following:
#   - IRON_HOME environment variable is set
#   - BUILD_STYLE environment variable is set

# This script's name for error messages.
this="${0##*/}"

#=============================================================================
# Print out usage information and exit.
usage() {
    ERROR_MSG=$1
    echo ""
    echo "Description:"
    echo "------------"
    echo "Builds the IRON software."
    echo ""
    echo "This script requires the following:"
    echo "  - IRON_HOME environment variable is set"
    echo "  - BUILD_STYLE environment variable is set"
    echo ""
    echo "Usage:"
    echo "  ${this}"
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

if [ "$#" -ne 0 ]; then
    usage "Error: no command line arguments expected, $# provided."
fi

# Verify that the build environment is set up correctly.
if [ -z ${IRON_HOME} ]; then
    usage "Error: IRON_HOME is not set, please set it and re-run the script."
fi

if [ -z ${BUILD_STYLE} ]; then
    usage "Error: BUILD_STYLE is not set, please set it and re-run"\
	  "the script."
fi

echo ""
echo "Compiling IRON binaries..."
echo "--------------------------"
echo ""

pushd ${IRON_HOME} >/dev/null || exit 1
make clean >/dev/null || exit 1
make >/dev/null || exit 1
popd >/dev/null || exit 1

# Exit the script successfully.
exit 0
