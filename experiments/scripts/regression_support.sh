#!/bin/sh

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

# WARNING: This document contains technology whose export or
# disclosure to non-U.S. persons, wherever located, is subject to the
# Export Administration Regulations (EAR) (15 C.F.R. Sections
# 730-774). Violations are subject to severe criminal penalties.


# This file contains functions, written for POSIX shell, that make
# working with results from the IRON experiment regression test
# framework easier.  In particular they help choose thresholds given a
# set of tests most of which are believed to be passing.

# To use, source the file with ". regression_support.sh" and then
# invoke the functions as needed.

# \todo Consider rewriting this in python.

# For all specified experiments and all their runs, re-run
# process_trpr.py.  Specfied experiments are those passed as
# arguments, or all directories starting with 201 (with apologies to
# 2020) if no arguments are given.  This is useful if the script is
# being changed (to fix bugs, or to set new thresholds), or to run a
# script from one point in history on experiments from another point.
reprocess () {
    if [ "$1" != "" ]; then
	all=$*
    else
	all=201*
    fi

    for d in $all; do
	exp=`ls ${d} | egrep -v "^bin$"`
	if [ -d ${d}/${exp}/run1 ]; then
	    for rundir in ${d}/${exp}/run*; do
		(cd "${rundir}" && python ~/IRON/experiments/scripts/process_trpr.py)
	    done
	fi
    done
}

# From a single stdin line with a summary.txt filename, optionally
# followed by other things (such as matches from egrep), extract the
# run directory to stdout.
extract_run () {
    sed -e 's;/summary.txt.*;;'
}

# Analyze experiment runs in the current directory.  The first
# argument is the experiment type.  The succeeding arguments are
# directories to include; if none, then all directories starting with
# 201 are included, with apologies to those working on IRON in 2020.
#
# Divide them in to pass (no microfailures) and fail (one or more
# microfailures).  Also produce a subcategory of failing as "badly
# failing", with an arbitrary threshold.
#
# In order to produce good thresholds, it is usually necessary to
# relax the tests to enable all runs that humans think are ok to pass,
# because excluding the ok-ish outliers unreasonably tightens the
# distributions.  (An earlier iteration of this function excluded only
# runs with 3 or more micro-failures as an attempt to avoid
# relaxation.)
passfail () {
    expname=$1; shift

    if [ "$expname" = "" ]; then
	echo "Missing experiment name."
	# We may not call exit, since we are running in the user's
	# shell.
	return 1
    fi

    # If any arguments remain, use them.  Otherwise guess at all.
    if [ "$1" != "" ]; then
	all=$*
    else
	all=201*
    fi

    # Produce a sorted list of all summary.txt files.
    # \todo Extend to handle quoting-required characters in directory names.
    # \todo Understand how sorting interacts before and after
    # extracting runs given that we have /run10/, but for now just
    # sort extra to conserve human time.
    (for exp in $all; do
	if [ -d $exp ]; then
	    find $exp -name summary.txt
	fi
	done) | sort > SUMMARY

    # Produce a list of all experiment runs.
    cat SUMMARY | extract_run | sort > ALL

    # Produce a list of passing and failing summary.txt files with
    # their conclusion line.
    cat SUMMARY | xargs egrep -H PASS > PASS.n
    cat SUMMARY | xargs egrep -H FAIL | sort -k5 -n > FAIL.n

    # Produce a list of passing and failing experiment runs.  Resort
    # (only needed on FAIL.n) to enable later use of comm).
    sort PASS.n | extract_run | sort > PASS
    sort FAIL.n | extract_run | sort > FAIL

    # Produce a list of summary.txt files with 3 or more failures.
    # This can be interesting when trying to find serious problems
    # when many results have a small number of microfailures
    # \todo Make the threshold configurable.
    cat SUMMARY | xargs egrep -H "FAIL.*fail ([3456789]|[1-9][0-9])" | extract_run > FAIL.3

    # Produce a list of microfailures over all runs.  They are not
    # sorted so that multiple microfailures in one experiment are
    # adjacent.
    cat SUMMARY | xargs egrep -H BAD > BAD-micro
    # Produce a list of runswith at least one microfailure.  This is
    # subtly different than failing runs because it excludes
    # experiment that have no microfailures but cannot be analyzed due
    # to insufficient data.
    cat BAD-micro | extract_run | sort | uniq > BAD-exp

    # Choose the set of runs to be evaluated.
    if [ "${BAD}" != "" ]; then
	# Include all (for coarse expected setting).
	cat ALL > OK-exp
    else
	# Find experiments without failures.  (This is equal to PASS,
	# but as written can easily be changed to FAIL.3.)
	comm -23 ALL FAIL > OK-exp
    fi

    echo -n "PASS:	"; wc -l PASS | awk '{print $1}'
    echo -n "FAIL:	"; wc -l FAIL | awk '{print $1}'
    echo -n "FAIL3:	"; wc -l FAIL.3 | awk '{print $1}'
    echo -n "BAD-micro:	"; wc -l BAD-micro | awk '{print $1}'
    echo -n "BAD-exp:	"; wc -l BAD-exp | awk '{print $1}'
    echo -n "OK-exp:	"; wc -l OK-exp | awk '{print $1}'

    iron_regress_rates $expname > RATES
    cat RATES
}

# Display text of failing tests.
iron_showtfail () {
    for i in `cat FAIL`; do
	clear;
	less $i/summary.txt;
    done
}

# Display text and xplots of failing tests.
iron_showxfail () {
    for i in `cat FAIL`; do
	clear;
	cat $i/summary.txt;
	xplot $i/summary-goodput.xplot;
    done
}

# Create a tarball of summary text and xplot files, for examination elsewhere.
iron_results_tar () {
    cd $HOME &&
    tar cf ~/iron_results/RESULTS.tgz `find RESULTS -name summary\* -o -name FAIL\* -o -name PASS -o -name SUMMARY`
}

## Compute expected values from experiments listed in OK-EXP

iron_regress_setup () {
    case "$1" in
	""|3-node-system)
	    EXP=3-node-system
	    FLOWS="1 2 3"
	    MEANLINES=11
	    # loop variables
	    sumavgf1z13=0
	    sumavgf1z2=0
	    sumavgf23z13=0
	    sumavgf23z2=0
	    ;;
	"3-node-system-lat")
	    EXP=3-node-system-lat
	    FLOWS="1 2"
	    MEANLINES=8
	    # loop variables
	    sumavg13=0
	    sumavg2=0
	    ;;
	"3-node-udp-perf")
	    EXP=3-node-udp-perf
	    FLOWS="1 2 3 4 5 6"
	    MEANLINES=8
	    ;;
	"y3_edge")
	    EXP=y3_edge
	    FLOWS="1 2 3"
	    MEANLINES=10
	    ;;
    esac

    INPUT=OK-exp
}

iron_regress_input2summary () {
    cat $INPUT | while read d; do
	# \todo The MEANLINES scheme is not robust.  Implement a
	# better parser, or make the output of process_trpr.py easier
	# to parse.
	head -${MEANLINES} $d/summary.txt
    done
}

# \todo Perhaps after converting to python, generalize over zones.
iron_regress_rates_aux () {
    for flow in ${FLOWS}; do
	for zone in 1 2 3; do
	    # Extract the first line (mean) matching the flow and zone, from each file.
	    # \todo Parse better, so the mean/dev is less confusing.
	    string="^flow $flow zone $zone"
	    avgavg=$(iron_regress_input2summary | \
		egrep "$string" | awk '{print $6}' | awk '{ tot += $1; n += 1} END { print tot / n}')
	    avgdev=$(iron_regress_input2summary | \
		egrep "$string" | awk '{print $8}' | awk '{ tot += $1; n += 1} END { print tot / n}')

	    echo "flow $flow zone $zone avgavg $avgavg avgdev $avgdev"

	    # expr only handles integer, and hence we use awk
	    case ${EXP} in
		3-node-system)
		    # In 3-node-system, we always have constrained
		    # bandwidth and the same sharing ratio, even
		    # though the link capacity is half in zone 2, so a
		    # single accumulation should be appropriate.
		    # However, the UDP flow is underserved, so we treat it separately.
		    case $flow in
			1)
			    case $zone in
				1|3)
				    sumavgf1z13=$(echo $sumavgf1z13 $avgavg | awk '{print $1 + $2}')
				    ;;
				2)
				    sumavgf1z2=$(echo $sumavgf1z2 $avgavg | awk '{print $1 + $2}')
				    ;;
			    esac
			    ;;
			2|3)
			    case $zone in
				1|3)
				    sumavgf23z13=$(echo $sumavgf23z13 $avgavg | awk '{print $1 + $2}')
				    ;;
				2)
				    sumavgf23z2=$(echo $sumavgf23z2 $avgavg | awk '{print $1 + $2}')
				    ;;
				esac
			    ;;
			esac
		    ;;
		3-node-system-lat)
		    # In 3-node-system-lat, we are not constrained in
		    # zones 1 and 3, and are constrained in 2. Thus in
		    # 1/3, we expect to achieve the full offered load
		    # (which we don't get).  In 2, we expect sharing
		    # by priority.  Therefore, sum theese separately
		    # for separate calculations of new expected
		    # values.
		    #
		    # \todo Consider making variable names reflect
		    # constrained vs not constrained zones, but it is
		    # not clear how much cross-experiment reusability
		    # there will be.
		    case $zone in
			1|3)
			    sumavg13=$(echo $sumavg13 $avgavg | awk '{print $1 + $2}')
			    ;;
			2)
			    sumavg2=$(echo $sumavg2 $avgavg | awk '{print $1 + $2}')
			    ;;
		    esac
		    ;;
	    esac
	done
    done

    case "${EXP}" in
	3-node-system)
	    # We expect in zones 1 and 3 to get double the results in
	    # zone 2.  Therefore we would divide the total sum of
	    # goodput by "1 + 0.5 + 1" to get the normalized result
	    # for zone 1 (and 3).  However, flow 1 is underserved and
	    # thus handled separately, and zone 2 is not necessarily
	    # half of zones 1/3, so we merely divide the sums for
	    # zones 1/3 in half.
	    normavgf1z13=$(echo $sumavgf1z13 | awk '{print $1 / 2}')
	    normavgf1z2=$(echo $sumavgf1z2 | awk '{print $1 / 1}')
	    normavgf23z13=$(echo $sumavgf23z13 | awk '{print $1 / 2}')
	    normavgf23z2=$(echo $sumavgf23z2 | awk '{print $1 / 1}')

	    # Within each zone, we expect flows 2 and 3 to have a 1/5
	    # split.  This happens almost exactly, so we actually use
	    # that ratio.
	    flow1z13=$(echo $normavgf1z13 | awk '{print $1 / 1}')
	    flow2z13=$(echo $normavgf23z13 | awk '{print $1 / 6}')
	    flow3z13=$(echo $normavgf23z13 | awk '{print 5 * $1 / 6}')
	    flow1z2=$(echo $normavgf1z2 | awk '{print $1 / 1}')
	    flow2z2=$(echo $normavgf23z2 | awk '{print $1 / 6}')
	    flow3z2=$(echo $normavgf23z2 | awk '{print 5 * $1 / 6}')

	    # Compute total goodput for zones 13, even though it is
	    # not used in setting thresholds.
	    normavg=$(echo $normavgf1z13 $normavgf23z13 | awk '{print $1 + $2}')

	    echo "goodput1,3: $normavg"
	    echo "zone 1,3:   $flow1z13 $flow2z13 $flow3z13"
	    echo "zone 2  :   $flow1z2 $flow2z2 $flow3z2"
	    ;;

	3-node-system-lat)
	    # Normalize the sums to single zones.  (The second line is
	    # computationally pointless, but is present for clarity and
	    # parallel structure.)
	    normavg13=$(echo $sumavg13 | awk '{print $1 / 2.0}')
	    normavg2=$(echo $sumavg2 | awk '{print $1 / 1.0}')

	    # In zones 1/3, we expect full rate, and 1/2 sharing.
	    # NB: The sharing is based on offered load, not priority.
	    flow1_z1=$(echo $normavg13 | awk '{print $1 / 3}')
	    flow2_z1=$(echo $normavg13 | awk '{print 2 * $1 / 3}')

	    # In zone 2, we expect sharing by priority.
	    flow1_z2=$(echo $normavg2 | awk '{print $1 / 6}')
	    flow2_z2=$(echo $normavg2 | awk '{print 5 * $1 / 6}')

	    echo "goodput1,3: $normavg13"
	    echo "goodput2:   $normavg2"
	    echo "zone 1,3:   $flow1_z1 $flow2_z1"
	    echo "zone 2  :   $flow1_z2 $flow2_z2"
	    ;;
    esac
}

iron_regress_rates () {
    iron_regress_setup $1
    iron_regress_rates_aux $1
}
