#!/usr/ bin/env bash
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


BIN_DIR=$1
CURRENT_DIR=$2
if [[ $(echo $CURRENT_DIR) ]]; then
    CURRENT_DIR=${CURRENT_DIR}/
    # this way if CURRENT_DIR is blank we dont end up in /
else
    CURRENT_DIR=$(pwd)/
fi
if [ -d ${CURRENT_DIR}results/gprof_tmp ]; then
    rm -r ${CURRENT_DIR}results/gprof_tmp
fi
if [ -d ${CURRENT_DIR}results/gprof ]; then
    rm -r ${CURRENT_DIR}results/gprof
fi
if [ ! -d ${CURRENT_DIR}results ]; then
    mkdir ${CURRENT_DIR}results
fi
mkdir ${CURRENT_DIR}results/gprof_tmp
mkdir ${CURRENT_DIR}results/gprof
IRON_COMPONENTS=(bpf tcp_proxy udp_proxy amp)
if [ -e ${CURRENT_DIR}logs/pidmap.txt ]; then
    for COMP in ${IRON_COMPONENTS[*]}; do 
        CPID=`grep ${COMP} ${CURRENT_DIR}logs/pidmap.txt | cut -d " " -f2`
        if [ -e ${CURRENT_DIR}logs/gmon.${CPID} ]; then
            mv ${CURRENT_DIR}logs/gmon.${CPID} ${CURRENT_DIR}logs/${COMP}.gmon
        fi
    done
fi
for COMP in ${IRON_COMPONENTS[*]}; do
    FOUND=false
    COMBINED_SRCS=""
    if [ -e ${CURRENT_DIR}logs/${COMP}.gmon ]; then
        FOUND_COMP=true 
        CURRENT=$(pwd)
        COUNT=$(grep -o "/" <<< $CURRENT | wc -l)
        if [ -z "${BIN_DIR}" ]; then
            COMP_IN_BIN="bin/${COMP}"
            while [ ! -f ${COMP_IN_BIN} ]; do
                let "COUNT-=1"
                if [ $COUNT -lt 1 ]; then
                    FOUND_COMP=false 
                    break
                fi
                COMP_IN_BIN="../${COMP_IN_BIN}"
            done
        else
            if [ ! -e ${BIN_DIR}/${COMP} ]; then
                FOUND_COMP=false 
            else
                COMP_IN_BIN=${CURRENT_DIR}/${COMP}
            fi  
        fi
        if [ ${FOUND_COMP} = false ]; then
            break
        else 
            gprof ${COMP_IN_BIN} ${CURRENT_DIR}logs/${COMP}.gmon > \
                ${CURRENT_DIR}results/gprof/${COMP}-local-gprof.txt
        fi
    else
        FOUND_COMP=true 
        CURRENT=$(pwd)
        COUNT=$(grep -o "/" <<< $CURRENT | wc -l)
        if [ -z "${BIN_DIR}" ]; then
            COMP_IN_BIN="bin/${COMP}"
            while [ ! -f ${COMP_IN_BIN} ]; do
                let "COUNT-=1"
                if [ $COUNT -lt 1 ]; then
                    FOUND_COMP=false 
                    break
                fi
                COMP_IN_BIN="../${COMP_IN_BIN}"
            done
        else
            if [ ! -e ${BIN_DIR}/${COMP} ]; then
                FOUND_COMP=false 
            else
                COMP_IN_BIN=${CURRENT_DIR}/${COMP}
            fi  
        fi
        if [ ${FOUND_COMP} = false ]; then
            break
        fi
    fi

### part 2 ###

    NO_NODE=$(ls ../ | grep node)
    if [ -z "$NO_NODE" ]; then  ## this means we are on a node
        LAST=$(cat ${CURRENT_DIR}../exp.cfg | grep IRON_NODES | rev | \
        cut -d ":" -f1 | rev | cut -d ")" -f1)
        if [ "${HOSTNAME}" = "${LAST}" ]; then
            FILE_NAME="${CURRENT_DIR}../exp.cfg"
            LINE=$(grep IRON_NODE $FILE_NAME | cut -d "(" -f2 | cut -d ")" -f1)
            IFS=' ' read -r -a NODES <<< "$LINE"
            NUMBER=${#NODES[@]}
            COUNT=0
            COMBINED_SRC=""
            while [ $COUNT -lt $NUMBER ]; do
                NODE_NAME=$(echo ${NODES[${COUNT}]} | cut -d ":" -f2) 
                SHORT_NAME=$(echo ${NODES[${COUNT}]} | cut -d ":" -f1)
                scp -oStrictHostKeyChecking=no \
                    ${USER}@${NODE_NAME}:${CURRENT_DIR}logs/${COMP}.gmon \
                    ${CURRENT_DIR}results/gprof_tmp/${COMP}_${SHORT_NAME}.gmon
                
                if [ -e ${CURRENT_DIR}results/gprof_tmp\
/${COMP}_${SHORT_NAME}.gmon ]; then
                    COMBINED_SRC="${COMBINED_SRC} ${CURRENT_DIR}results\
/gprof_tmp/${COMP}_${SHORT_NAME}.gmon"
                fi

                let "COUNT ++"
            done
            gprof ${COMP_IN_BIN} ${COMBINED_SRC} > \
            ${CURRENT_DIR}results/gprof/${COMP}-gprof.txt
            COUNT=0
            LSCHECK=$(ls ${CURRENT_DIR}results/gprof | grep local-gprof)
            if [[ ! "$LSCHECK" == "" ]]; then  
                mv ${CURRENT_DIR}results/gprof/*-local-gprof.txt \
                    ${CURRENT_DIR}results
            fi 
            while [ $COUNT -lt $NUMBER ]; do
                NODE_NAME=$(echo ${NODES[${COUNT}]} | cut -d ":" -f2) 
                SHORT_NAME=$(echo ${NODES[${COUNT}]} | cut -d ":" -f1)
                scp -oStrictHostKeyChecking=no ${CURRENT_DIR}results/gprof/* \
                    ${USER}@${NODE_NAME}:${CURRENT_DIR}results/gprof
                let "COUNT ++" 
            done
            
            LSCHECK=$(ls ${CURRENT_DIR}results | grep local-gprof)
            if [[ ! "$LSCHECK" == "" ]]; then  
                mv ${CURRENT_DIR}results/*-local-gprof.txt \
                    ${CURRENT_DIR}results/gprof/
            fi
        fi
    else          ## This means we are running post mortem
        LAST=$(cat ${CURRENT_DIR}../exp.cfg | grep IRON_NODES | rev | \
            cut -d ":" -f2 | cut -d " " -f1 | rev)
        ME=$(pwd | rev | cut -d "/" -f1 | rev)
        if [ "${ME}" = "${LAST}" ]; then
            FILE_NAME="${CURRENT_DIR}../exp.cfg"
            LINE=$(grep IRON_NODE $FILE_NAME | cut -d "(" -f2 | cut -d ")" -f1)
            IFS=' ' read -r -a NODES <<< "$LINE"
            NUMBER=${#NODES[@]}
            COUNT=0
            COMBINED_SRC=""
            while [ $COUNT -lt $NUMBER ]; do
                SHORT_NAME=$(echo ${NODES[${COUNT}]} | cut -d ":" -f1)
                if [ -e ${CURRENT_DIR}../${SHORT_NAME}/logs/${COMP}.gmon ]
                then
                    COMBINED_SRC="${COMBINED_SRC} \
                        ${CURRENT_DIR}../${SHORT_NAME}/logs/${COMP}.gmon"
                fi  
                let "COUNT ++"
            done
            gprof ${COMP_IN_BIN} ${COMBINED_SRC} > \
                ${CURRENT_DIR}results/gprof/${COMP}-gprof.txt
            COUNT=0 
            LSCHECK=$(ls ${CURRENT_DIR}results | grep local-gprof)
            if [[ ! "$LSCHECK" == "" ]]; then  
                mv ${CURRENT_DIR}results/gprof/*-local-gprof.txt \
                    ${CURRENT_DIR}results
            fi
            let "NUMBER --"
            while [ $COUNT -lt $NUMBER ]; do
                SHORT_NAME=$(echo ${NODES[${COUNT}]} | cut -d ":" -f1)
                cp ${CURRENT_DIR}results/gprof/* \
                    ${CURRENT_DIR}../${SHORT_NAME}/results/gprof
                let "COUNT ++" 
            done
            LSCHECK=$(ls ${CURRENT_DIR}results | grep local-gprof)
            if [[ ! "$LSCHECK" == "" ]]; then  
                mv ${CURRENT_DIR}results/*-local-gprof.txt \
                    ${CURRENT_DIR}results/gprof/
            fi
        fi

    fi 
done
rm -r results/gprof_tmp
