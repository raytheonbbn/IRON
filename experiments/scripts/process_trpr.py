#!/usr/bin/env python

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


# This script processes trpr files from an experiment in order to 1)
# make xplot input files that allow visualizing the data, 2) compute
# statistics on a per-flow per-region basis, and 3) determine
# pass/fail for various aspects of the experiment (and thus overall).

# For now, only the 3-node-system test is supported, and only goodput
# as received on node1 is examined.

# This must be invoked in $RESULTS/experiment/$RUN, with no arguments.
# It will exit gracefully if the experiment is not supported.  It
# produces summary.txt and summary-goodput.xplot; these are top-level
# files because they have experiment-wide scope.

# usage: python process_trpr.py

import math
import os
import re
import subprocess
import sys

# numpy is the standard approach for statistics.  However, it isn't
# installed on some machines where we want to run.  We make no attempt
# to be efficient; the point is to be as simple as possible to avoid
# bugs in code that would better not to reimplement.

# The / operator is python 2 is integer if both arguments are integer,
# and float otherwise.  In python 3 it is always float.  However,
# because all goodput, latency, and loss data are read as floats, we
# can be sure that / is always float in this program.

def handcoded_mean(vec):
    sum = 0
    count = 0
    for v in vec:
        sum += v
        count += 1
    avg = sum / count
    return avg

# \todo Note that numpy computes the standard deviation by dividing by
# the number of samples, treating the data as the entire population.
# We match that here, leaving open the question of whether a sample
# standard deviation calculation (N-1) would be more appropriate.
def handcoded_std(vec):
    mean = handcoded_mean(vec)
    sumsq = 0
    count = 0
    for v in vec:
        d = v - mean
        sumsq += d*d
        count += 1
    dev = math.sqrt(sumsq / count)
    return dev

def handcoded_convergence_time(xyvals, start_time, end_time):
    """
    This function tries to estimate the convergence time after an event occurs.
    It does this by examing the points from the end of the zone (end_time)
    back towards the start of the zone (start_time), looking for a sharp
    change in behavior.

    Specifically, this looks for the 10th outlier (cumulative) and returns the
    time before the most recent set of consecutive outliers. An outlier for
    this purpose is defined as a point more than 3 standard deviations away
    from the mean (not including this point or any consecutive outliers before
    this point).
    """
    # total values included so far in the computation, including most recent
    # outliers.
    count = 0
    # sum of y values included so far in the computation, including most
    # recent outliers.
    y_sum = 0
    # the upper bound for what we'll consider a non-outlier. This is equal to
    # the mean plus 3 standard deviations based on all values up to (but
    # excluding) the most recent consecutive set of outliers.
    upper_bound_good = None
    # the lower bound for what we'll consider a non-outlier.
    # like upper bound, but mean minus 3 standard deviations.
    lower_bound_good = None
    # how many outliers have we seen so far? When this hits 10, we're done.
    num_outliers = 0
    # the most recent point we've examine that was a non-outlier.
    most_recent_good = (0,0)
    zone_list = [(x,y) for (x,y) in xyvals if (x < end_time and x > start_time)]
    sortedvals = sorted(zone_list, key=lambda xy: xy[0], reverse=True)
    # Assume the convergence point is in the first half of the zone.
    # \todo It would be better to take hard-coded times from the
    # experiment-specific configuration and start with that, rather than
    # blindly assuming the second half is ok.
    start = len(zone_list) / 2
    for (x,y) in sortedvals:
        outlier = False
        if (count < start):
            # we're not looking for outliers yet. Just track this point as a
            # potential, so that if we see outliers right away we at least
            # return something in the right zone.
            most_recent_good = (x,y)
            count += 1
            y_sum += y
        else:
            # once we have a base mean and standard deviation, start
            # looking for outliers.
            if (upper_bound_good is not None and
                (y > upper_bound_good or y < lower_bound_good)):
                outlier = True
                num_outliers += 1
            if (num_outliers >= 10):
                return most_recent_good
            count += 1
            y_sum += y
            if (not outlier):
                # We only want to modify the upper and lower bounds if this
                # point was not an outlier. However, when we see a non-outlier,
                # include all previous outliers in the new value. This will
                # allow our mean and standard deviation to shift based on micro
                # changes in y value while still identifying (and returning
                # a point before a macro shift.
                # \todo We probably want a way to really/permanently ignore
                # significant outliers without preventing our mean from
                # adjusting once enough new points show up to legitimately
                # shift the value.
                most_recent_good = (x,y)
                avg = y_sum / count
                sumsq = 0
                # \todo (efficiency): This is recomputed every time because
                # we've changed the value of "avg" (which is included in every
                # term). There is probably an incremental way to compute
                # standard deviation that would be more efficient.
                for (x2, y2) in sortedvals:
                    if (x2 < x):
                        break
                    d = y2 - avg
                    sumsq += d*d
                stdev = math.sqrt(sumsq / count)
                upper_bound_good = avg + (3*stdev)
                lower_bound_good = avg - (3*stdev)
    return most_recent_good


## Define data structures for aggregating information about a
## particular analysis type (goodput, latency, loss).
class trpr_data:
    def __init__(this, name):
        this.name = name

        # For storing raw trpr data, a dictionary from flow to
        # (dictionary from x to y, where x is time and y is the
        # metric).
        this.data = dict()

        # For storing organized data, a dictionary from flow to
        # (dictionary from zone to (sequence of y)).
        this.results = dict()
        # Similarly, but sequence of x (times)
        this.resultsx = dict()

        # For storing statistics by flow and zone.
        this.avg = dict()
        this.dev = dict()
        this.count = dict()

        # For writing xplot data.
        this.plot = None

        # Zone boundary times, used for experiments that automatically
        # compute guard bands. This is a dictionary, keyed by flow, value
        # is a sorted list of (start_time, end_time) for the zones.
        this.zone_times = dict()

## Define globals, placed into classes to reduce namespace pollution
## and confusion.

# For storing experiment, run, and node information.
class g_meta:
    experiment_name = ""
    experiment_time = ""
    run_number = -1
    # While we only need to use class members, we need to instantiate
    # a member to be able to invoke a method.
    exp = None
    # Which destination node are we checking.
    # Depends on (and automatically computed based on) the experiment.
    node_name = ""

# Variables to store raw/processed input data.
class g_data:
    ## input data, raw and processed

    # For storing data, results, and stats about a type of data.
    d_gp = trpr_data("goodput")
    d_lat = trpr_data("latency")
    d_loss = trpr_data("loss")

    # For storing LinkEmClient timestamps, start/stop for two
    # commands, in boundary[0] to boundary[3].
    boundary = []

    # Absolute timeval of first received mgen packet.  This is believed to
    # be the origin of the trpr timescale.
    first_mgen = 0.0

    ## Evaluations of data.

    # Count of flow/zone combinations that do not have any or enough data.
    missing_zones = 0
    bad_zones = 0

    # Count of total tests and failed tests.
    tests = 0
    fail = 0

    ## Output
    summary = None

## Define a class for each supported experiment.

# Define a class to hold per-experiment procedures and data, to be
# subclassed for each experiment.  For each variable/function, define
# it so that if used by mistake we will notice.
class exp(object):
    name = "generic"

    # The base class has no flows and no zones, and expects zero
    # LinkEmClient events.
    flows = []
    zones = []
    expected_lec = 0
    # List of flow numbers where the start of each of these flows should be
    # considered a boundary between test zones.
    boundary_flows_starting = []
    # List of flow numbers where the end of each of these flows should be
    # considered a boundary between test zones.
    boundary_flows_ending = []
    # Ignore any packets arriving after this time. Used when computing zones.
    end_time = 0

    # We declare each experiment to have multiple zones.  Zone 0 is
    # points that are not evaluated.  Zones 1 and up are different
    # regions (by convention in time order) where we evaluate.
    # This takes a list of zone_times for experiments where
    # guardbands are different for different data types.
    def time2zone(this, time, zone_times):
        return 0

    # Convert port number to flow number, as defined by traffic.cfg.
    # \todo Parse traffic.cfg.
    # \todo Distinguish between UDP and TCP.
    def port2flow(this, port):
        return -1

    # Check if the data can be analyzed.  This will typically be about
    # whether we have adequate data for each flow and zone, and the
    # right number of LinkEmClient or boundary flow events.
    # (This can be extended in experiment classes.)
    def analyzable(this):
        ok = this.analyzable_zones()
        if (ok != True):
            return ok

        ok = this.analyzable_boundaries()
        if (ok != True):
            return ok

        return True

    # If there are zones with no or not-enough data, analysis is not
    # useful.
    def analyzable_zones(this):
        if (g_data.missing_zones > 0 or g_data.bad_zones > 0):
            return ("%d missing zones and %d bad zones" %
                    (g_data.missing_zones, g_data.bad_zones))
        else:
            return True

    # If LinkEmClient did not execute the number of commands we
    # expect, or we did not see the expected boundary flows start, we
    # cannot judge the system's behavior
    def analyzable_boundaries(this):
        num_boundaries = len(g_data.boundary)
        if (num_boundaries != this.expected_boundaries):
            return "Bad number of LinkEmClient events or boundary flows %d" % num_boundaries
        return True

    # Return the list of zone boundaries to be used when computing
    # convergence times for each zone. The default is the set of all
    # data boundaries, but this can be cut back in subclasses if we
    # end up with too many data boundaries (for instance if we have
    # multiple LinkEmClient commands for each zone start).
    def get_zone_boundaries(this):
        return g_data.boundary

    # average is a hash of hashes to map flow number (outer key) to
    # zone (inner key) to expected rate.  (See port2flow, above, for
    # how we map from port used to flow number; the plan is to match
    # the ordering in traffic.cfg.)
    expected_average = {}

    # hash of hashes to translate flow number (outer key) to zone (inner key)
    # to a 2-tuple of acceptable deviations from the expected average.
    average_thresh = {}

    # default value for the acceptable deviations from the expected average,
    # so that tests can opt not to define this.
    default_avg_thresh = (0.975, 1.02)

    # latency is a hash of hashes to map flow number (outer key) to
    # zone (inner key) to expected latency.  (See port2flow, above, for
    # how we map from port used to flow number; the plan is to match
    # the ordering in traffic.cfg.)
    expected_latency = {}

    # expected_ratios is a sequence of tuples giving a flow, a
    # reference flow, and and expected ratio.  Note that the expected
    # ratio is not per zone, so an experiment may need to override the
    # method. If any zones have expected rates of 0 for some flows, this
    # will simply skip computing the ratios for those zones.
    expected_ratios = []

    ## Multiple check functions follow.  They are separate so that
    ## specific experiment classes can override them separately,
    ## should that be necessary.

    # \todo Do CSE on BAD/ok and fail++.
    # \todo Generalize to latency and loss.
    # \todo Decide if summary should or shouldn't be passed in.

    # Check average rates in each zone.
    def check_average(this, summary):
        for flow in this.flows:
            for zone in this.zones:
                # This flow/zone might not have an expectation.
                if (this.expected_average[flow][zone] == None):
                    continue
                avg_thresh = this.default_avg_thresh
                if (flow in this.average_thresh and
                    zone in this.average_thresh[flow]):
                    avg_thresh = this.average_thresh[flow][zone]

                g_data.tests += 1
                if (this.expected_average[flow][zone] == 0):
                    actual_rate = 0
                    if (flow in g_data.d_gp.avg and
                        zone in g_data.d_gp.avg[flow] and
                        g_data.d_gp.avg[flow][zone] > 0):
                        bad = "BAD"
                        g_data.fail += 1
                        actual_rate = g_data.d_gp.avg[flow][zone]
                    else:
                        bad = " ok"
                    summary.write("%s flow %d zone %d avg-nonzero %f\n"
                                  % (bad, flow, zone, actual_rate))
                else:
                    ratio = (g_data.d_gp.avg[flow][zone] /
                             this.expected_average[flow][zone])
                    # \todo Consider making this a parameter.
                    # \todo The causes of variation and how to choose
                    # the allowed deviation are not well understood.
                    if (ratio < avg_thresh[0] or ratio > avg_thresh[1]):
                        bad = "BAD"
                        g_data.fail += 1
                    else:
                        bad = " ok"
                    summary.write("%s flow %d zone %d avg/exp %f\n"
                                  % (bad, flow, zone, ratio))

    # Check deviation/average ratio in each zone.  (This is a separate
    # function so that the human-oriented output is in a better order.)
    def check_deviation(this, summary):
        for flow in this.flows:
            for zone in this.zones:
                g_data.tests += 1
                # NOTE: we only add the zone to the avg[flow] dict is there
                # was data for which we could compute an average, even if that
                # data only included values of 0. Therefore, it's correct to
                # check for 0 (rather than None) once we know that the
                # (flow,zone) pair exists in the nested dict.
                if (flow not in g_data.d_gp.avg or
                    zone not in g_data.d_gp.avg[flow] or
                    g_data.d_gp.avg[flow][zone] == 0):
                    summary.write("N/A flow %d zone %d expects 0\n"
                                  % (flow, zone))
                else:
                    ratio = g_data.d_gp.dev[flow][zone] / g_data.d_gp.avg[flow][zone]
                    # \todo Consider making this a parameter.
                    if (ratio > 0.2):
                        bad = "BAD"
                        g_data.fail += 1
                    else:
                        bad = " ok"
                    summary.write("%s flow %d zone %d dev/avg %f\n"
                                  % (bad, flow, zone, ratio))

    def check_latency(this, summary):
        for flow in this.flows:
            for zone in this.zones:
                # This flow/zone might not have an expectation.
                if (flow not in this.expected_latency
                    or zone not in this.expected_latency[flow]
                    or flow not in g_data.d_lat.avg
                    or zone not in g_data.d_lat.avg[flow]
                    or this.expected_latency[flow][zone] == None):
                    continue

                g_data.tests += 1
                # \todo Get 95th percentile.
                lat = g_data.d_lat.avg[flow][zone]
                if (lat > this.expected_latency[flow][zone]):
                    g_data.fail += 1
                    bad = "BAD"
                else:
                    bad = " ok"
                summary.write("%s flow %d zone %d latency %f limit %f\n"
                              % (bad, flow, zone, lat,
                                 this.expected_latency[flow][zone]))

    def check_ratios_one(this, summary, flow, denom_flow, zone, ratio_e):
        g_data.tests += 1
        # Handle flows that only exist in some zones by simply not checking
        # the ratio if we don't have non-zero data for both flows.
        if (flow not in g_data.d_gp.avg or
            denom_flow not in g_data.d_gp.avg or
            zone not in g_data.d_gp.avg[flow] or
            zone not in g_data.d_gp.avg[denom_flow]):
            summary.write("N/A interflow ratio %d/%d zone %d Cannot compute.\n"
                          % (flow, denom_flow, zone))
        elif (g_data.d_gp.avg[flow][zone] == 0 or
            g_data.d_gp.avg[denom_flow][zone] == 0):
            summary.write("N/A interflow ratio %d/%d zone %d Cannot compute.\n"
                          % (flow, denom_flow, zone))
        else:
            ratio = g_data.d_gp.avg[flow][zone] / g_data.d_gp.avg[denom_flow][zone]
            # Normalize ratio to what is expected.
            ratio_n = ratio / ratio_e
            # \todo Consider making this a parameter.
            if (ratio_n < 0.985 or ratio_n > 1.035):
                bad = "BAD"
                g_data.fail += 1
            else:
                bad = " ok"
            summary.write("%s interflow ratio %d/%d zone %d %f\n"
                          % (bad, flow, denom_flow, zone, ratio))

    # Check interflow ratios, and log to summary file.
    def check_ratios(this, summary):
        # Compare ratios between pairs of flows.
        for flow, denom_flow, ratio_e in this.expected_ratios:
            # For the given pair, check all zones.
            for zone in this.zones:
                this.check_ratios_one(summary, flow, denom_flow, zone, ratio_e)

    # Check statistics that have been computed against expectations, and
    # output analysis to the provided file object.
    def check_stats(this, summary):
        this.check_average(summary)
        this.check_deviation(summary)
        this.check_ratios(summary)
        this.check_latency(summary)

        if (g_data.fail > 0):
            summary.write("FAIL")
            sys.stdout.write("FAIL")
        else:
            summary.write("PASS")
            sys.stdout.write("PASS")
        summary.write(" tests %d fail %d\n" % (g_data.tests, g_data.fail))
        # Include the overall summary line in stdout, so humans see it
        # when running an experiment.
        sys.stdout.write(" tests %d fail %d\n" % (g_data.tests, g_data.fail))

class exp_3_node_system(exp):
    name = "3-node-system"

    flows = [1, 2, 3]
    zones = [1, 2, 3]
    expected_boundaries = 8
    end_time = 39.5

    #  1: stable period before impairment
    #  2: stable period during impairment
    #  3: stable period after impairment
    #
    # Note that the size of the guard bands is arbitrary and is
    # currently tuned so that the test passes most of the time, for
    # experiments that do not have behavior that humans label as
    # troubled.
    def time2zone(this, time, zone_times=None):
        # 0.1-4 unstable, 0.5, 0.6 ok
        if (time >= 0.7 and time <= g_data.boundary[1]):
            return 1
        if (time >= g_data.boundary[1] + 2.5 and time <= g_data.boundary[5]):
            return 2
        if (time >= g_data.boundary[5] + 1.5 and time <= 39.5):
            return 3
        return 0

    def get_zone_boundaries(this):
        zone_boundaries = []
        zone_boundaries.append(g_data.boundary[1])
        zone_boundaries.append(g_data.boundary[5])
        return zone_boundaries

    def port2flow(this, port):
        # 1 is priority 1 UDP
        if (port == 30777):
            return 1
        # 2 is priority 1 TCP
        elif (port == 29778):
            return 2
        #3 is priority 5 TCP
        elif (port == 29779):
            return 3
        else:
            return -1

    # Ideally, the flows would have a 1:1:5 ratio, following their
    # priority definitions.  However, UDP is underserved for reasons
    # that are unclear.  Because we are trying to detect changes, we
    # can either force the expected values to be in this ratio and
    # widen the tolerances, or set the expected values to more closely
    # match what we are currently getting.  For flow 1, we deviate
    # from the nominal value of 1/7 of total goodput, but we use
    # nominal 1/6 5/6 values for the sum of 2 and 3.
    #
    # We force zone 1 and 3 to have the same values, because they have
    # the same long-term environment.  This does not seem problematic.
    #
    # We would like zone 2 to be half the rates for 1/3, because that
    # is the underlying link behavior.  However, known deviations from
    # ideal behavior are more pronounced at higher bandwidths.  Our
    # real goal is detecting changed behavior, so we not require a 1:2
    # ratio.
    expected_average = {
        1: { 1: 2407.76, 2: 1204.44, 3: 2402.42 },
        2: { 1: 2417.74, 2: 1198.46, 3: 2414.16 },
        3: { 1: 12106.9, 2: 5996.5, 3: 12089.4 }
    }

    expected_ratios = [
        (2, 1, 1),              # interflow 2/1 ratio 1
        (3, 1, 5),              # interflow 3/1 ratio 5
        (3, 2, 5) ]             # interflow 3/2 ratio 5

class exp_3_node_system_lat(exp):
    name = "3-node-system-lat"

    flows = [1, 2]
    zones = [1, 2, 3]
    expected_boundaries = 8
    end_time = 50

    #  1: stable period before impairment
    #  2: stable period during impairment
    #  3: stable period after impairment
    #
    # Note that the size of the guard bands is arbitrary and is
    # currently tuned so that the test passes most of the time, for
    # experiments that do not have behavior that humans label as
    # troubled.
    def time2zone(this, time, zone_times=None):
        if (time >= 3 and time <= g_data.boundary[1]):
            return 1
        if (time >= g_data.boundary[1] + 1.0 and time <= g_data.boundary[5]):
            return 2
        if (time >= g_data.boundary[5] + 5.0 and time <= 50):
            return 3
        return 0

    def get_zone_boundaries(this):
        zone_boundaries = []
        zone_boundaries.append(g_data.boundary[1])
        zone_boundaries.append(g_data.boundary[5])
        return zone_boundaries

    def port2flow(this, port):
        # 1 is priority 1 UDP, 5 Mbps, low latency
        if (port == 30777):
            return 1
        # 2 is priority 1 UDP, 10 Mbps
        elif (port == 30600):
            return 2
        else:
            return -1

    # In zone 1/3, there is adequate bandwidth, so we expect the
    # planned rates.  However, recent averages see 97.3% of planned.
    # In zone 2, there is 10 Mbps.  We expect 1/5 sharing, and
    # expected values are based on achieved rates at times we believe
    # the system is ok.
    expected_average = {
        1: { 1: 4861.6, 2: 1452.1, 3: 4815.19 },
        2: { 1: 9640.81, 2: 7264.58, 3: 9711.03 },
    }

    # Flow 1 has a specified 70ms latency requirement.
    expected_latency = {
        1: { 1: 0.06, 2: 0.06, 3: 0.06 }
    }

    def check_ratios(this, summary):
        # Compare flow 2 to 1 in zone 2, expecting 5.  (In the other
        # zones, there is adequate capacity, so we do not expect
        # sharing according to priorities.)
        this.check_ratios_one(summary, 2, 1, 2, 5)

class exp_3_node_udp_perf(exp):
    name = "3-node-udp_perf"

    flows = [1, 2, 3, 4, 5, 6]
    zones = [1]
    expected_boundaries = 0
    end_time = 220

    # Fairly arbitrary choice, intended to ignore the start and shutdown
    # periods.
    def time2zone(this, time, zone_times=None):
        if (time >= 11 and time <= 220):
            return 1
        return 0

    def port2flow(this, port):
        # 1 is priority 1 UDP from node 0
        if (port == 30102):
            return 1
        # 2 is priority 1 UDP from node 0
        elif (port == 30202):
            return 2
        # 3 is priority 5 UDP from node 0
        elif (port == 30302):
            return 3
        # 4 is priority 1 UDP from node 1
        elif (port == 30112):
            return 4
        # 5 is priority 1 UDP from node 1
        elif (port == 30212):
            return 5
        # 6 is priority 5 UDP from node 1
        elif (port == 30312):
            return 6
        else:
            return -1

    expected_average = {
        1: { 1: 1159.23 },
        2: { 1: 1159.16 },
        3: { 1: 5789.38 },
        4: { 1: 1161.67 },
        5: { 1: 1161.64 },
        6: { 1: 5799.57 }
    }

    # Expect latency to be fairly constant, since these are all UDP flows
    # and network conditions should be stable.
    expected_latency = {
        1: { 1: 0.06 },
        2: { 1: 0.06 },
        3: { 1: 0.06 },
        4: { 1: 0.06 },
        5: { 1: 0.06 },
        6: { 1: 0.06 }
    }

    expected_ratios = [
        (2, 1, 1),              # interflow 2/1 ratio 1
        (3, 1, 5),              # interflow 3/1 ratio 5
        (3, 2, 5),              # interflow 3/2 ratio 5
        (4, 1, 1),              # interflow 4/1 ratio 1
        (5, 1, 1),              # interflow 5/1 ratio 1
        (6, 1, 5) ]             # interflow 6/1 ratio 5

class exp_y3_edge(exp):
    name = "y3_edge"

    flows = [1, 2, 3]
    zones = [1, 2, 3]
    expected_boundaries = 2
    boundary_flows_starting = [3]
    boundary_flows_ending = [3]
    end_time = 120

    def time2zone(this, time, zone_times):
        # The zone start and end times are automatically computed for this
        # experiment based on the calculated convergence times. We leave
        # one second on each side to allow for errors in convergence time
        # calculation and boundary time calculation (which may be off because
        # we consider a flow starting/ending when the first/last packet
        # arrives at the destination, which doesn't accurately account for
        # traffic in the network.
        zone_num = 0
        prev_zone_time = -1
        for (start, end) in zone_times:
            zone_num += 1
            if (time > start + 1 and time < end - 1):
                return zone_num
        return 0

    def port2flow(this, port):
        # 1 is the UDP from node 1
        if (port == 30700):
            return 1
        # 2 is the first UDP from node 2
        elif (port == 30701):
            return 2
        # 3 is the late-start UDP from node 2
        elif (port == 30702):
            return 3
        else:
            return -1

    expected_average = {
        1: { 1: 4334.28, 2: 2927.71, 3: 4319.44 },
        2: { 1: 4336.94, 2: 2892.69, 3: 4334.72 },
        3: { 1: 0, 2: 2892.83, 3: 0 }
    }

    # Expect latency to be fairly constant, since these are all UDP flows
    # and network conditions should be stable.
    expected_latency = {
        1: { 1: 0.2, 2: 0.2, 3: 0.2 },
        2: { 1: 0.2, 2: 0.2, 3: 0.2 },
        3: { 1: 0, 2: 0.2, 3: 0 }
    }

    expected_ratios = [
        (2, 1, 1),          # interflow 2/1 ratio 1
        (3, 1, 1),          # interflow 3/1 ratio 1 (only examined for zone 2)
        (3, 2, 1) ]         # interflow 3/2 ratio 1 (only examined for zone 2)

## Read metadata.

class badDirectory(Exception):
    pass

# Process the current working directory.  Expect it to be a run
# directory.  Store components in variables for later use.
# Exit cleanly if the experiment is not supported.
def process_path():
    cwd = os.getcwd()
    # Expect something like */2017_11_06T16_41_42Z/3-node-system/run1
    # or */2017_11_16T06_33_42Z_3-node-system-debug/3-node-system/run1.
    # Note that the first regexp hunk is heading towards "[^/]".
    m = re.match(r'.*/([0-9_TZa-zA-Z\-]*)/([0-9a-zA-Z\-_]*)/run([0-9]*)$', cwd)
    if m:
        g_meta.experiment_time = m.group(1)
        g_meta.experiment_name = m.group(2)
        g_meta.run_number = int(m.group(3))
    else:
        raise badDirectory("cwd %s cannot parse as */date/exp/runN" % cwd)

    # Decide if this experiment is supported.
    g_meta.exp = None
    if (g_meta.experiment_name == "3-node-system"):
        g_meta.exp = exp_3_node_system()
        g_meta.node_name = "enclave2/app1"
    if (g_meta.experiment_name == "3-node-system-lat"):
        g_meta.exp = exp_3_node_system_lat()
        g_meta.node_name = "enclave2/app1"
    if (g_meta.experiment_name == "3-node-udp-perf"):
        g_meta.exp = exp_3_node_udp_perf()
        g_meta.node_name = "enclave3/app1"
    if (g_meta.experiment_name == "y3_edge"):
        g_meta.exp = exp_y3_edge()
        g_meta.node_name = "enclave6/app1"

    if (g_meta.exp == None):
        print "Experiment %s regression tests not supported." % g_meta.experiment_name
        sys.exit(0)

    print "process_trpr: Analyzing %s" % g_meta.experiment_name

## Read data

# Read a single trpr file, and store the data in a hash of hashes.
def read_trpr_one(nodename, fname, data):
    c = g_meta.exp

    trpr_fname = nodename + "/results/" + fname
    try:
        trpr = open(trpr_fname)
        lines = trpr.readlines()
        trpr.close()

        for line in lines:
            # Header for new flow?
            m = re.match(r'^# Flow: ([A-Z]*),([0-9.]*)/(\d*)->([0-9.]*)/(\d*)', line)
            if m:
                flow_type = m.group(1);
                src_addr = m.group(2);
                src_port = m.group(3);
                dst_addr = m.group(4);
                dst_port = m.group(5);
                flow = c.port2flow(int(dst_port))
                data[flow] = dict()
                continue

            # Data line?
            m = re.match(r'^(\d+\.\d+), (-?\d+\.\d+)$', line);
            if m:
                x = float(m.group(1))
                y = float(m.group(2))
                data[flow][x] = y
                continue
    # handle file not found.
    except (OSError, IOError):
        pass

# Read all trpr files
def read_trpr():
    # \todo Deal with some files existing and some not, cleanly.
    read_trpr_one(
        g_meta.node_name, "mgen_goodput_regress.trpr", g_data.d_gp.data)
    read_trpr_one(
        g_meta.node_name, "mgen_latency_regress.trpr", g_data.d_lat.data)
    read_trpr_one(
        g_meta.node_name, "mgen_loss_regress.trpr", g_data.d_loss.data)

# Read the LinkEmClient file, and store into boundary.
def read_lec():
    lec_fname = "LinkEmClient.log"
    lec = open(lec_fname)
    lines = lec.readlines()
    lec.close()

    which = 0
    for line in lines:
        # For now, assume that command/done comes in pairs, and simply
        # accumulate start/stop times.
        # \todo Check that command/done are pairs.
        m = re.match(r'^LinkEmClient (\w+) (\d+.\d+)',
                     line)
        if m:
            tv = float(m.group(2))
            g_data.boundary.append(tv)
            which += 1

class mgenBadTime(Exception):
    pass

# Read the mgen log file enough to determine the time of the first
# received packet, which is either TCP or non-multicast UDP.
# \todo Arguably we should construct a better filter from the flows
# from trpr.  We should also determine if the TCP open counts, or only
# the first data segment.
# \todo Address the problem of the experiment not having a single
# common timescale, which would allow avoiding this entire function.
def read_mgen():
    # Get the tcpdump line for the first packet that is TCP or
    # non-multicast UDP in the trace.  Avoid broken pipe errors by
    # using awk, which reads its entire input, instead of head.
    # \todo Deal with sbin-not-in-path more cleanly.
    cmd = ("cat {}/pcaps/* | /usr/sbin/tcpdump ".format(g_meta.node_name) +
           "-tt -n -r - tcp or udp and not multicast 2> /dev/null | " +
           "awk 'NR == 1 { print }'")
    tcpdump = subprocess.check_output(cmd, shell=True)

    m = re.match(r'^(\d+.\d+) ', tcpdump)
    if m:
        tv = float(m.group(1))
        g_data.first_mgen = tv
    else:
        raise mgenBadTime("Can't parse timeval of first mgen packet")

# Adjust boundary elements from absolute timeval to relative based on mgen.
def adjust_boundary():
    for i in range(len(g_data.boundary)):
        g_data.boundary[i] = g_data.boundary[i] - g_data.first_mgen

# Perform all input processing.  Read the data, and create a common
# timescale.
def read_all():
    read_trpr()
    read_lec()
    read_mgen()
    adjust_boundary()

## Process data and create output

# Create an xplot file, and emit the preamble.
def xplot_start_one(d_):
    xplotfile = "summary-" + d_.name + ".xplot"
    d_.plot = open(xplotfile, 'w')
    d_.plot.write("double double\n")
    d_.plot.write("title\n")
    d_.plot.write("%s %s %s\n" % (g_meta.experiment_time, g_meta.experiment_name, d_.name))

# Finish the xplot file.
def xplot_fini_one(d_):
    d_.plot.close()
    del d_.plot

def output_start():
    g_data.summary = open("summary.txt", 'w')
    xplot_start_one(g_data.d_gp)
    xplot_start_one(g_data.d_lat)
    xplot_start_one(g_data.d_loss)

def output_fini():
    g_data.summary.close()
    xplot_fini_one(g_data.d_gp)

def process_flow_boundaries(trpr):
    c = g_meta.exp
    for flow in c.boundary_flows_starting:
        # This assumes that TRPR won't include any 0 values for flows that
        # haven't yet started, but that should be a safe assumption, because
        # it would be bizarre for TRPR to predict not-yet-existing flows.

        # This also treats the first packet arriving at the destination as the
        # start time for a flow, rather than the time when the first packet
        # was sent. This is inaccurate, even though we're only looking at
        # values at the destination, because IRON may forward packets in such
        # a way that the first packets for a flow may be in the system and
        # affecting only flows (whose packets are already arriving) for a while
        # before we receive these first packets at the destination. To counter
        # this, we should add a small amount of guard band to the end of any
        # zone that ends because of flows starting or ending.
        if flow in trpr.data:
            tv = float(min(trpr.data[flow].keys()))
            g_data.boundary.append(tv)
    for flow in c.boundary_flows_ending:
        if flow in trpr.data:
            nonzero = {x:val for (x,val) in trpr.data[flow].items() if val != 0}
            tv = float(max(nonzero.keys()))
            g_data.boundary.append(tv)

def compute_zone_start_end_times(trpr):
    """
    This function computes the time at which the given trpr data converges
    after each zone-start boundary (definition of "convergence" for this
    purpose is explained in handcoded_convergence_time comments). It then
    stores a list of (start_time, end_time) tuples for each flow, consisting
    of the start (end of convergence) and end (end of zone) time for each
    zone. For zones for which the flow is expected to have no data, the
    stored start and end time are just the general zone boundary times, with
    no notion of convergence.

    These start and end times can be fed into the time2zone function for
    an experiment, or could just be used to compute and print convergence
    times. (This is experiment-dependent.)
    """
    c = g_meta.exp

    for flow in trpr.data:
        xyvals = []
        for x in trpr.data[flow].keys():
            xyvals.append((x, trpr.data[flow][x]))

        start_time = 0
        zone = 1
        boundaries = list(c.get_zone_boundaries())
        boundaries.append(c.end_time)
        trpr.zone_times[flow] = []
        for boundary in boundaries:
            end_time = boundary
            if c.expected_average[flow][zone] > 0:
                (cutoffx, cutoffy) = handcoded_convergence_time(
                    xyvals, start_time, end_time)
                trpr.start_time = start_time
                trpr.zone_times[flow].append((cutoffx, end_time))
            else:
                trpr.zone_times[flow].append((start_time, end_time))
            start_time = boundary
            zone += 1

def print_convergence_times(trpr):
    c = g_meta.exp

    g_data.summary.write("CONVERGENCE TIMES {}\n".format(trpr.name))
    for flow in trpr.zone_times:
        # we want a list of 0 + all the start-of-zone boundaries
        boundaries = list(c.get_zone_boundaries())
        boundaries.insert(0, 0.0)
        # generate a list of tuples (time zone starts, time flow converges)
        conv_time_input = zip(boundaries,
                              [times[0] for times in trpr.zone_times[flow]])
        zone = 1
        for (zone_start, conv_time) in conv_time_input:
            g_data.summary.write("flow {} zone {} converges: {}\n".format(
                flow, zone, conv_time - zone_start))
            zone += 1
    g_data.summary.write("\n")

# Organize y values by zone.  Emit an xplot line drawing each point.
# Emit a an xplot line drawing a line for LinkEmClient events.
def process_data(trpr):
    c = g_meta.exp

    # LinkEmClient events are simply times, but we draw them as
    # vertical lines.  Find the highest value in the plot, to scale
    # those lines, which also makes the highest value more obvious to
    # the viewer.
    ymax = 0

    for flow in c.flows:
        # Create dict from zone to sequence of y values
        trpr.results[flow] = dict()
        trpr.resultsx[flow] = dict()

        if flow in trpr.data:
            for x in trpr.data[flow].keys():
                zone = c.time2zone(x, trpr.zone_times[flow])
                y = trpr.data[flow][x]
                if (y > ymax):
                    ymax = y
                if zone == 0:
                    # Ignored data: do not accumulate.
                    # box means omitted, and is intentionally loud
                    trpr.plot.write("box %f %f %d\n" % (x, y, flow))
                    continue

                trpr.plot.write("x %f %f %d\n" % (x, y, flow))

                # Ensure sequence for this zone.
                if not zone in trpr.results[flow]:
                    trpr.results[flow][zone] = []
                if not zone in trpr.resultsx[flow]:
                    trpr.resultsx[flow][zone] = []

                trpr.results[flow][zone].append(y)
                trpr.resultsx[flow][zone].append(x)

    # Output lines for the linkem commands.
    for i in range(len(g_data.boundary)):
        if (i % 2 == 0):
            color = 1           # green for start
        else:
            color = 2           # red for stop
        trpr.plot.write("line %f %f %f %f %d\n" %
                             (g_data.boundary[i], 0, g_data.boundary[i], ymax, color))

# Compute and output per-zone statistics.  If possible, perform
# statistical tests.  If not possible, declare the results to fail.
def process_stats(trpr):
    c = g_meta.exp

    g_data.summary.write("BEGIN %s\n" % trpr.name)

    for flow in c.flows:
        # A missing flow counts for all zones.
        if not flow in trpr.results:
            g_data.summary.write("flow %d EMPTY\n" % flow)
            g_data.missing_zones += len(c.zones)
            continue

        # Create the per-flow dictionaries by zone.
        trpr.avg[flow] = dict()
        trpr.dev[flow] = dict()
        trpr.count[flow] = dict()

        for zone in c.zones:
            if not zone in trpr.results[flow]:
                if c.expected_average[flow][zone] > 0:
                    g_data.summary.write("flow %d zone %d EMPTY\n"
                                         % (flow, zone))
                    g_data.missing_zones += 1
                continue

            # Compute and print average, standard deviation and count
            # for this flow/zone.
            # NOTE: the zone is only added to the results[flow] dict when we
            # have a result to include. Therefore, it's safe to compute this
            # average without worrying about a divide-by-zero error.
            trpr.avg[flow][zone] = handcoded_mean(trpr.results[flow][zone])
            trpr.dev[flow][zone] = handcoded_std(trpr.results[flow][zone])
            trpr.count[flow][zone] = len(trpr.results[flow][zone])
            g_data.summary.write("flow %d zone %d mean %f std %f len %d\n"
                                 % (flow, zone, trpr.avg[flow][zone],
                                    trpr.dev[flow][zone], trpr.count[flow][zone]))

            # Require 5 seconds of data if we expected a non-zero average rate.
            if (c.expected_average[flow][zone] > 0 and
                trpr.count[flow][zone] < 50):
                g_data.summary.write("  not enough samples\n")
                g_data.bad_zones += 1

            # Compute first and last point, and print a line showing
            # the average.
            first = min(trpr.resultsx[flow][zone])
            last = max(trpr.resultsx[flow][zone])
            trpr.plot.write("line %f %f %f %f %d\n" %
                                 (first, trpr.avg[flow][zone],
                                  last, trpr.avg[flow][zone],
                                  flow))

    g_data.summary.write("END %s\n\n" % trpr.name)

# Check if all statistics have enough data to support analysis.
def check_stats_analyzeable():
    c = g_meta.exp

    why = c.analyzable()
    if (why != True):
        g_data.summary.write("FAIL NOT ANALYZABLE %s\n" % why)
        sys.stdout.write("FAIL NOT ANALYZABLE %s\n" % why)
    return why

# Check global statistics.  Calls each type's check function, as well
# as global checks, if any.
def check_stats_global():
    c = g_meta.exp

    c.check_stats(g_data.summary)

# Perform processing on data.
def process_all():
    output_start()
    process_flow_boundaries(g_data.d_gp)
    compute_zone_start_end_times(g_data.d_gp)
    compute_zone_start_end_times(g_data.d_lat)
    compute_zone_start_end_times(g_data.d_loss)

    process_data(g_data.d_gp)
    process_data(g_data.d_lat)
    process_data(g_data.d_loss)

    process_stats(g_data.d_gp)
    process_stats(g_data.d_lat)
    # The loss trpr file seems troubled.
    #process_stats(g_data.d_loss)

    print_convergence_times(g_data.d_gp)
    print_convergence_times(g_data.d_lat)

    if check_stats_analyzeable():
        check_stats_global()

    output_fini()

## Main control flow

process_path()
read_all()
process_all()
