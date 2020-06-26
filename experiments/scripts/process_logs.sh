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


# Print explosion
explosion() {
    echo "             . . .                        "
    echo "              \|/                         "
    echo "             --+--                        "
    echo "              /|\                         "
    echo "             . | .                        "
    echo "               |                          "
    echo "               |                          "
    echo "           ,-- # --.                      "
    echo "           |#######|                      "
    echo "        _.- ####### -._                   "
    echo "     ,- ############### -.                "
    echo "    , ####### LOGF ########,              "
    echo "  /#########################              "
    echo " |### LOGF ##################|            "
    echo "|############## LOGF #########|           "
    echo "|#############################|           "
    echo "|################## LOGF #####|           "
    echo "|##### LOGF ##################|           "
    echo " |############## LOGF #######|            "
    echo "   #########################/             "
    echo "    .#####################,               "
    echo "      ._###############_,                 "
    echo "         --..#####..--                    "
}
# Print explosion
explosion_core() {
    echo "             . . .                        "
    echo "              \|/                         "
    echo "             --+--                        "
    echo "              /|\                         "
    echo "             . | .                        "
    echo "               |                          "
    echo "               |                          "
    echo "           ,-- # --.                      "
    echo "           |#######|                      "
    echo "        _.- ####### -._                   "
    echo "     ,- ### CORE ###### -.                "
    echo "    , ########## CORE #####,              "
    echo "  /# CORE ### CORE #########              "
    echo " |################ CORE #####|            "
    echo "|######### CORE ###### CORE ##|           "
    echo "|## CORE #### CORE ###########|           "
    echo "|############### CORE ########|           "
    echo "|##### CORE ######## CORE ####|           "
    echo " |############# CORE ########|            "
    echo "   #### CORE ####### CORE ##/             "
    echo "    .######## CORE #######,               "
    echo "      ._###############_,                 "
    echo "         --..#####..--                    "
}

find_iron() {
    GENERIC=$(pwd | rev | cut -d "/" -f1 | rev)
    if [[ ! "${GENERIC}"  == "node"* ]]; then
        # Doing it on each node... 
        GENERIC=""
        IRON_LINE=$( cat ../exp.cfg | grep "IRON_NODES" | cut -d "=" -f2 | \
            cut -d "(" -f2 | cut -d ")" -f1)
        for CHECK in $IRON_LINE
        do
            CHECK_NODE=$(echo ${CHECK} | cut -d ":" -f2)
            if [ "${CHECK_NODE}" == "${HOSTNAME}" ]; then
                #found me...
                GENERIC=$(echo ${CHECK} | cut -d ":" -f1)
                break
            fi 
        done
        if [ "${GENERIC}" == "" ]; then
            #Not an IRON node 
            exit
        fi
    fi 
   # at this point generic should be set or we are no an iron node   
   echo $GENERIC
   GENERIC_NODE_NAME=${GENERIC}
}
BASE_DIR=$1
if [ ! "${BASE_DIR}" == "" ]; then
    BASE_DIR=${BASE_DIR}/
fi 
find_iron

if [ -e ${BASE_DIR}logs/udp_proxy.log ]; then
    echo "Analyzing ${GENERIC_NODE_NAME} log file..."
    echo "${GENERIC_NODE_NAME} UDP proxy log analysis:" > \
        ${BASE_DIR}udp_proxy_log_analysis.txt
    f1=$( grep "[0-9] F \[" ${BASE_DIR}logs/udp_proxy.log | wc -l)
    echo "Number of fatal log messages = $f1" >> \
        ${BASE_DIR}udp_proxy_log_analysis.txt
    n=$( grep "[0-9] E \[" ${BASE_DIR}logs/udp_proxy.log | wc -l)
    echo "Number of error log messages = $n" >> \
        ${BASE_DIR}udp_proxy_log_analysis.txt
    n=$( grep "[0-9] W \[" ${BASE_DIR}logs/udp_proxy.log | wc -l )
    echo "Number of warning log messages = $n" >> \
        ${BASE_DIR}udp_proxy_log_analysis.txt
    cat ${BASE_DIR}udp_proxy_log_analysis.txt
fi 
if [ -e ${BASE_DIR}logs/tcp_proxy.log ]; then
    echo "$GENERIC_NODE_NAME TCP proxy log analysis:" > \
        ${BASE_DIR}tcp_proxy_log_analysis.txt
    f2=$( grep "[0-9] F \[" ${BASE_DIR}logs/tcp_proxy.log | wc -l)
    echo "Number of fatal log messages = $f2" >> \
        ${BASE_DIR}tcp_proxy_log_analysis.txt
    n=$( grep "[0-9] E \[" ${BASE}logs/tcp_proxy.log | wc -l)
    echo "Number of error log messages = $n" >> \
        ${BASE_DIR}tcp_proxy_log_analysis.txt
    n=$( grep "[0-9] W \[" ${BASE_DIR}logs/tcp_proxy.log | wc -l )
    echo "Number of warning log messages = $n" >> \
        ${BASE_DIR}tcp_proxy_log_analysis.txt
    cat ${BASE_DIR}tcp_proxy_log_analysis.txt
fi
if [ -e ${BASE_DIR}logs/bpf.log ]; then
    echo "$GENERIC_NODE_NAME BPF log analysis:" > \
        ${BASE_DIR}bpf_log_analysis.txt
    f3=$( grep "[0-9] F \[" ${BASE_DIR}logs/bpf.log | wc -l )
    echo "Number of fatal log messages = $f3" >> \
        ${BASE_DIR}bpf_log_analysis.txt
    n=$( grep "[0-9] E \[" ${BASE_DIR}logs/bpf.log | wc -l )
     echo "Number of error log messages = $n" >> \
        ${BASE_DIR}bpf_log_analysis.txt
    n=$( grep "[0-9] W \[" ${BASE_DIR}logs/bpf.log | wc -l )
    echo "Number of warning log messages = $n" >> \
        ${BASE_DIR}bpf_log_analysis.txt
    cat ${BASE_DIR}bpf_log_analysis.txt
fi
if [ -e ${BASE_DIR}logs/amp.log ]; then
    echo "$GENERIC_NODE_NAME AMP log analysis:" > \
        ${BASE_DIR}amp_log_analysis.txt
    f4=$( grep "[0-9] F \[" ${BASE_DIR}logs/amp.log | wc -l )
    echo "Number of fatal log messages = $f4" >> \
        ${BASE_DIR}amp_log_analysis.txt
    n=$( grep "[0-9] E \[" ${BASE_DIR}logs/amp.log | wc -l )
     echo "Number of error log messages = $n" >> \
        ${BASE_DIR}amp_log_analysis.txt
    n=$( grep "[0-9] W \[" ${BASE_DIR}logs/amp.log | wc -l )
    echo "Number of warning log messages = $n" >> \
        ${BASE_DIR}amp_log_analysis.txt
    cat ${BASE_DIR}amp_log_analysis.txt
fi
echo ""
if [[ ("$f1" -gt "0") || ("$f2" -gt "0") || ("$f3" -gt "0") || ("$f4" -gt "0") ]]; then
    explosion
fi 
if [ -e ${BASE_DIR}results/core_file.txt ]; then
    explosion_core
fi
