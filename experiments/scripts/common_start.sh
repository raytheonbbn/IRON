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


# Act like "date +%s", but also include .tv_usec.
date_timeval () {
    python -c 'import time; print "%0.6f" %time.time()'
}

# $1 = pcaps node list
# $2 = experiment dir on node
# $3 = experiment base dir
# $4 = experiment name
# $5 = run dir
start_gulps() {
    pcaps_nodes=(${!1})
    exp_dir=$2
    exp_base_dir=$3
    exp_name=$4
    run_dir=$5
    echo "Starting gulp captures."
    for NODE_INFO in ${pcaps_nodes[*]}; do
        FQ_NODE_NAME=$(echo $NODE_INFO | cut -d ':' -f1)
        INF_NAME=$(echo $NODE_INFO | cut -d ':' -f2)
        LINK_NAME=$(echo $NODE_INFO | cut -d ':' -f3)
        log echo "Starting gulp captures on ${FQ_NODE_NAME}..."
        ssh  -oStrictHostKeyChecking=no ${USER_NAME}@${FQ_NODE_NAME} sudo ${exp_dir}/scripts/run_gulp.sh \
            ${exp_base_dir} ${exp_name} ${run_dir} ${INF_NAME} ${LINK_NAME}
    done
}

# Expect the exp.cfg to have been source
gulp_to_be_started_separately() {
    ret=false
    if [ -n "${GULP_DURATION}" ]; then
        if [ ${GULP_DURATION} -ne ${DURATION} ]; then
            ret=true
        fi
    fi
    echo ${ret}
}
