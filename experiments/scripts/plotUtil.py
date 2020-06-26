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


"""
Script to plot the instantaneous send utility values,
as seen by the UDP proxy and/or the TCP proxy. It parses
the proxy logs for a line like the following:
..... FlowStats= <flow1>:{stats_dict}, <flow1>:{stats_dict}

usage: python plotUtil.py <path to udp proxy log> <path to tcp proxy log>
"""

from __future__ import print_function
from ast import literal_eval
from collections import namedtuple
import re
import sys

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

FlowPoint = namedtuple("FlowPoint", ["time", "util"])


def parse_flow_stats(log_file, start_time, flows):
    """
    Parse the log file for flow stats.

    :param file log_file: File to parse
    :param float start_time: Earliest time of a flow
    :param dict[str, list[FlowPoint]] flows: Data points for each flow
    :return float: Earliest time of a flow
    """
    for line in log_file:
        match = re.match(r'([0-9]*\.[0-9]+).*FlowStats=(.*)', line)
        if match:
            time = float(match.group(1))
            stats_dict = literal_eval('{' + match.group(2) + '}')
            if start_time == 0:
                start_time = time
            for flow, stats in stats_dict.items():
                if flow not in flows:
                    flows[flow] = []
                flows[flow].append(FlowPoint(time - start_time,
                                             float(stats['utility'])))
    return start_time


def main():
    if len(sys.argv) == 0:
        print("No log files were passed as arguments")
        exit(1)

    start_time = 0.0
    flows = {}

    with open(sys.argv[1]) as log_file:
        start_time = parse_flow_stats(log_file, start_time, flows)

    if len(sys.argv) > 2:
        with open(sys.argv[2]) as log_file:
            parse_flow_stats(log_file, start_time, flows)

    if len(flows) > 0:
        for flow, point in flows.items():
            plt.plot(point.time, point.util, label=flow)
        lgd = plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.1),
                         fancybox=True, shadow=True, ncol=1)
        plt.xlabel("Time/s")
        plt.ylabel("Utility")
        plt.title("Instantaneous Utility over Time")
        plt.savefig("util.png", bbox_extra_artists=(lgd,), bbox_inches='tight')
        plt.clf()

if __name__ == "__main__":
    main()
