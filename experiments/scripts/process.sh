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
# process.sh:
#
# Run varying processing steps on the results of an experiment, read
# from node0/cfgs/process.cfg in the top-level directory of an
# experiment.  This file is stored as cfgs/process.cfg in the sources.
#
# This script is run on each node, after the experiment is done, but
# before results are copied back.  Therefore analysis that examines
# data from multiple nodes at once cannot be implemented via this
# script.

DEBUG_FLAG=0

###  Print usage information (but do not exit).
show_help () {
    echo "usage: process.sh"
    echo "              [ -d ] Enable debug logging"
    echo "              [ -e path/to/experiment ]"
    echo "              [ -r runX ]"
    echo "              [ -c path/to/config/file ]"
    echo "              [ -s path/to/scripts/dir "
    echo "                or -s last (uses most recent in ~/iron_results) ]"
    echo
    echo "If no experiment is given, the script will look"
    echo "for the most recent experiment in ~/iron_results."
    echo "If a run is given, it is assumed that the run directory does not"
    echo "contain node directories (due to being on the node itself)."
    echo "If no run is given, all runs are analyzed, and each is assumed"
    echo "to contain node directories (due to being in a global results"
    echo "directory."
    echo
    echo "The default config file is found in run1/node0/cfgs/process.cfg."
    echo
    echo "The default path to scripts is relative to \$IRON_HOME."
}

### call after trpr before gnuplot to add key to graph
add_key_to_graph () {
    sed -i 's/key off/key outside/g' trprResults
}

remove_key () {
    sed -i 's/key bottom right/key off/g' trprResults
}

### call after trpr before gnupot to replace lines with dots
remove_lines_from_graph () {
    while read -r p; do
        if [[ $p == *"->"* ]]; then
            cnt=$(grep -o "-" <<< "$p" | wc -l)
            if [ $cnt == 2 ]; then
                cnt=${#p}
                off=cnt-3;
                if [ ${p:$off:1} == "," ]; then
                    p=${p:0:$off}" with points pt 20 ps .3"${p:$off:3}
                else
                    p=$p" with points pt 20 ps .3"
                fi
            fi
        fi
        echo $p >> nolines
    done<trprResults
    mv nolines trprResults
}

### call after trpr before gnuplot to get pdf output
make_pdf () {
    if [ "$(command -v epstopdf)" == "" ]; then
        echo "epstopdf not installed."
        echo "using png instead"
        FORMAT=png
    else 
        sed -i 's/png/eps/g' trprResults    
        sed -i 's/size 800, 400/size 8.0, 4.0/g' trprResults
    fi
}

### Evaluate a python script.  cwd must be runN/nodeN.  The script is
### expected to evaluate a single node's data.  Arguments to the
### script are in $ARGS; arguments to this function are ignored.  If
### the python script writes files in the current directory, they are
### moved to the results directory.
python_eval () {
    # Pre-create ls1.txt and ls2.txt, so that the before directory
    # listing will include both of them.
    echo "junk" > ls1.txt
    echo "junk" > ls2.txt
    # Store list of files in this directory before we run the script.
    ls > ls1.txt
    PYTHONARGS=""
    #  Read arguments into members of $array.
    IFS=' ' read -r -a array <<< "$ARGS"
    COUNT=0;
    ESCAPE=0;
    MANY=${#array[@]}
    # Iterate over the provided arguments.
    while [ ${COUNT} -lt ${MANY} ]; do 
        if [[ "${array[$COUNT]}" == *".py" ]]; then
	    # If the argument ends in .py, prepend the scripts
	    # directory so that it can be found.
            PYTHONARGS+=" $SCRIPTS_DIR/"
            PYTHONARGS+="${array[$COUNT]}"
        elif [[ "${array[$COUNT]}" == *".log" ]]; then
	    # If the argument ends in .log, check if the name exists
	    # in the logs directory.  If not, terminate argument
	    # processing and do not execute any commands.  If so,
	    # prepend logs/ to the argument and include it in the
	    # command.
	    # \todo Explain the disconnect between ${LOGS_DIR} and logs.
            if [ ! -e ${LOGS_DIR}/"${array[$COUNT]}" ]; then
                ESCAPE=1
                COUNT=MANY  
            fi
            PYTHONARGS+=" logs/"
            PYTHONARGS+="${array[$COUNT]}"
        else
	    # Othewise, include the argument as is.
            PYTHONARGS+=" ${array[$COUNT]}"
        fi
        COUNT=$((COUNT+1))
    done
    if [ $ESCAPE -eq 0 ]; then
	# Evaluate the python command.  Note that the token "python"
	# from process.cfg is now being used as an interpreter name.
	echo "python_eval: running /$PYTHONARGS/"
        eval $PYTHONARGS
	# Obtain list of files after running the script.
        ls > ls2.txt
        ZERO=0
	# As long as the before/after file list is not the same:
        while [ $(cmp ls1.txt ls2.txt | wc -c) -ne $ZERO ]; do
	    # Move the first file present only in ls2 to the results
	    # directory.
            mv $(diff ls1.txt ls2.txt | grep ">" | cut -d " " -f 2) results
            ls > ls2.txt
        done
        rm ls2.txt
    fi
    rm ls1.txt
    # \todo ls2.txt can be leaked if we ESCAPE processing.
}

### For bash scripts, works the same as python_eval
bash_eval () {
    echo "junk" > ls1.txt # used for clean up later
    echo "junk" > ls2.txt # used for clean up later
    ls > ls1.txt
    BASHARGS=""
    IFS=' ' read -r -a array <<< "$ARGS"
    COUNT=0;
    ESCAPE=0;
    MANY=${#array[@]}
    while [ ${COUNT} -lt ${MANY} ]; do 
        if [[ "${array[$COUNT]}" == *".sh" ]]; then
            BASHARGS+=" $SCRIPTS_DIR/"
            BASHARGS+="${array[$COUNT]}"
        elif [[ "${array[$COUNT]}" == *".log" ]]; then
            if [ ! -e ${LOGS_DIR}/"${array[$COUNT]}" ]; then
                ESCAPE=1
                COUNT=MANY  
            fi
            BASHARGS+=" logs/"
            BASHARGS+="${array[$COUNT]}"
        else
            BASHARGS+=" ${array[$COUNT]}"
        fi
        COUNT=$((COUNT+1))
    done
    if [ $ESCAPE -eq 0 ]; then
        eval $BASHARGS
        ls > ls2.txt
        ZERO=0
        while [ $(cmp ls1.txt ls2.txt | wc -c) -ne $ZERO ]; do
            mv $(diff ls1.txt ls2.txt | grep ">" | cut -d " " -f 2) results
            ls > ls2.txt
        done
        rm ls2.txt
    fi
    rm ls1.txt
}
### mgen goodput, latency, loss
plot_mgen () {
    if [ -e $LOGS_DIR/mgen.log ]; then  
        PLOT_TYPE=$(echo $ARGS | cut -d ' ' -f2)
        FORMAT=$(echo $ARGS | cut -d ' ' -f3)
        LINE_TYPE=$(echo $ARGS | cut -d ' ' -f4)
        KEY=$(echo $ARGS | cut -d ' ' -f5)  
        RAMP=$(echo $ARGS | cut -d ' ' -f6) 
        WINDOW=1.0
        NUM_PARAM=$(echo $ARGS | wc -w)
        if [ $NUM_PARAM -eq 7 ]; then
            REGRESS=$(echo $ARGS | cut -d ' ' -f7)
            if [ "${REGRESS}" != regress ]; then
                echo "Bad regress argument /$REGRESS/"
                exit 1
            fi
        else
            REGRESS=
        fi
        if [ $PLOT_TYPE == "goodput" ]; then
            PLOT=""
        else
            PLOT=$PLOT_TYPE
        fi
        if [ $RAMP == "noramp" ]; then
            RAMP=""
        fi
        # Create main trpr and plot, for human consumption.
        logerr ${EXE_DIR}/trpr mgen input $LOGS_DIR/mgen.log $PLOT $RAMP \
	    window $WINDOW auto X output trprResults png mgen.png

        sed -i \
            's/set term png/set term png size 800, 400\nset size ratio .6/g' \
            trprResults
        if [ $KEY == key ]; then
            add_key_to_graph
        else
            remove_key
        fi
        if [ $FORMAT == pdf ]; then
            make_pdf
        fi
        if [ $LINE_TYPE == nolines ]; then
            remove_lines_from_graph
        fi
        gnuplot trprResults
        if [ $FORMAT == "pdf" ]; then
            epstopdf mgen.eps
            rm mgen.eps
        fi
        mv mgen.$FORMAT results/mgen_${PLOT_TYPE}.$FORMAT
        mv trprResults results/mgen_${PLOT_TYPE}.trpr
        # Maybe create trpr file for regression tests.
        if [ "${REGRESS}" = regress ]; then
            # As above, but force ramp (to avoid double points) and a
            # window of 0.1.
            logerr ${EXE_DIR}/trpr mgen input $LOGS_DIR/mgen.log $PLOT ramp \
		window 0.1 auto X output trprResults
            mv trprResults results/mgen_${PLOT_TYPE}_regress.trpr
        fi
    fi
}

### Read $CONFIG, and evaluate all scripts.
### When invoked, cwd must be runN/nodeN (in a global results
### directory) or runN (in a directory on a node).  Either way,
### subdirectories logs, pcap, and so on should be present.  LOGS_DIR
### must be set to the logs subdirectory of this directory.
read_cfg () {
    CFG_LINE=0
    while read -r cfg; do
        CFG_LINE=$((CFG_LINE+1))
	# \todo Explain the next line; because cut is passed an empty
	# separator, it simply assigns $cfg to ARGS.
        ARGS=$(echo $cfg | cut -d '' -f2-)
        if [[ $cfg == \#* ]]; then
            :
        elif [[ $cfg == mgen* ]]; then 
            plot_mgen $cfg
        elif [[ $cfg == python* ]]; then
            python_eval $cfg
        elif [[ $cfg == bash* ]]; then
            bash_eval $cfg    
        else
            echo "cfg line {$CFG_LINE}  not recognized"
            show_help   
            exit 1      
        fi
    done <$CONFIG
}

### Check if $BASE_DIR exists, and if not print usage and exit with an
### error.  If successful, return with cwd of $BASE_DIR.
check_base () {
    cd $BASE_DIR
    if [ ! $pwd == $BASE_DIR ]; then
        echo "Experiment not found"
        show_help   
        exit 1
    fi

}

### Main Script ###
OPTIND=1
CONFIG=""
# BASE_DIR is the directory that contains run directories.
BASE_DIR=""
ONE_RUN=""
###
while getopts "de:r:c:s:" opt; do
    case "$opt" in
    d)
        DEBUG_FLAG=1;;
    e)
        BASE_DIR=$OPTARG
        if [ "$BASE_DIR" == "last" ]; then
            BASE_DIR="$(cat ~/iron_results/last_run_experiment.txt)/../"
        fi
        check_base 
        ;;
    r)
        ONE_RUN=$OPTARG
        ;;
    c)
        CONFIG=$OPTARG
        ;;
    s)
        SCRIPTS_DIR=$OPTARG
        ;;
    *) 
        show_help
        exit 1
        ;;
    esac
done
shift $((OPTIND-1))
[ "$1" = "--" ] && shift
if [ "$BASE_DIR" == "" ]; then
    BASE_DIR="$(cat ~/iron_results/last_run_experiment.txt)/../"
    cd $BASE_DIR
    check_base
fi
if [ "$CONFIG" == "" ]; then
    CONFIG="$BASE_DIR/run1/node0/cfgs/process.cfg"
fi
if [ "$SCRIPTS_DIR" == "" ]; then
    SCRIPTS_DIR="$IRON_HOME/../experiments/scripts"
    cd $BASE_DIR
fi

source $SCRIPTS_DIR/log.sh

EXE_DIR=${BASE_DIR}/../bin

# Evaluate either a single run, or all runs.  When process.sh is
# invoked during an experiment, it runs on each experiment node in the
# ONE_RUN mode.  When invoked after an experiment, e.g. to rerun after
# changing processing scripts, it iterates over all nodes.
if [ "$ONE_RUN" == "" ]; then
    for RUN in */ ; do
        echo "Processing $RUN"
        cd $RUN
	# Evaluate all nodes.
        for NODE in */ ; do
            cd "$NODE"
            echo $NODE
            LOGS_DIR=$(pwd)/logs
            if [ ! -d results ]; then
                mkdir results
            fi
	    echo "Applying process.cfg: $BASE_DIR $RUN $NODE:"
            read_cfg
            cd ..   
        done
        cd ..
    done 
else
    cd $ONE_RUN
    LOGS_DIR=$(pwd)/logs
    if [ ! -d results ]; then
        mkdir results
    fi
    echo "Applying process.cfg: $BASE_DIR $ONE_RUN no-node:"
    read_cfg
    cd ..   
fi
exit 0
