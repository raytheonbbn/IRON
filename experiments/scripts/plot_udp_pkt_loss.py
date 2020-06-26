#!/usr/bin/env python
""" Script to plot packet loss in the UDP proxy """

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

# This script plots packet loss, as seen by the decoding state,
# in the UDP proxy. It is only valid for decoding states which does reordering.
# Packets that are late are counted as lost.

import matplotlib
matplotlib.use('Agg')

import argparse
import re
import os.path
import matplotlib.pyplot as plt
import sys
from subprocess import check_output, CalledProcessError

MAX_REASONABLE_LOSS = 10000 # 10,000 FECStates

############################################
def read_file(log_file):
    """ Find the log lines with packet loss information.

    Grep a specified log file for pktcount lines and returns
    just these lines for further processing.

    Args:
        log_file: The full path to the UDP proxy log file to be analysed.
    Returns:
        The  lines with pktcount information.
    """

    if os.path.isfile(log_file):
        try:
            grepped = check_output(["grep", "pktcount", log_file])
            start = check_output(["grep", "UDP Proxy configuration complete", log_file])
            for line in start.splitlines():
                match = re.match(r'([0-9]*)\.[0-9]+.*UDP', line)
                if match:
                  start_time = int(match.group(1))
                  return start_time, grepped.splitlines()
        except CalledProcessError:
            sys.exit(1)
        return 0, grepped.splitlines()
    else:
        print "Log file {0} not found".format(log_file)
        sys.exit(1)

############################################
def parse_log(log_file):
    """ Parse lines from log file for packet loss information.

    Args:
       The options passed in by the user.
    Returns:
       The flow identifers.
       The time of losses.
       The number of losses for each time period.
       Dictionary of losses per flow.
       The total number of packets on time.
       The maximum number of packets loss in any given period.
    """

    flows = []
    num_loss_per_sec = {}
    loss_array = {}
    times = {}
    start_time = 0.0
    max_loss = 0
    total_on_time = 0
    total_late = 0
    start_time, log_lines = read_file(log_file)

    for line in log_lines:
        match = re.match(\
           r'([0-9]*)\.[0-9]+.*Flow: (.*), Missing FECState group: ([0-9]*)', line)
        if match:
            if start_time == 0:
                start_time = int(match.group(1))
            if match.group(2) not in flows:
                flows.append(match.group(2))
                num_loss_per_sec[match.group(2)] = {}
                times[match.group(2)] = []
                loss_array[match.group(2)] = []
            loss_time = int(match.group(1)) - start_time
            if loss_time not in times[match.group(2)]:
                times[match.group(2)].append(loss_time)
                num_loss_per_sec[match.group(2)][loss_time] = 1
            else:
                num_loss_per_sec[match.group(2)][loss_time] += 1

            total_loss = num_loss_per_sec[match.group(2)][loss_time]

            if (total_loss > max_loss) and (total_loss < MAX_REASONABLE_LOSS):
                max_loss = total_loss
            if total_loss > MAX_REASONABLE_LOSS:
                print 'loss too large: line {0}'.format(line)

        match = re.match(r'([0-9]*)\.[0-9].*Late pkt group:', line)
        if match:
            total_late += 1

        match = re.match(r'([0-9]*)\.[0-9].*Total packets sent: ([0-9]*)', line)
        if match:
            total_on_time = int(match.group(2))

        match = re.match(r'([0-9]*)\.[0-9].*Total packets dropped: ([0-9]*)', line)
        if match:
            total_src_drop = int(match.group(2))

    print "UDP Proxy: total packets dropped at source: " + str(total_src_drop)
    print "UDP Proxy: total packets on time: " + str(total_on_time)
    print "UDP Proxy: total packets late   : " + str(total_late)

    return flows, times, num_loss_per_sec, loss_array, total_on_time, max_loss

############################################
def plot_packet_loss(options):
    """ Create a plot of packet loss over time.

    Args:
       The options passed in by the user.
    """
    marks = ['x', 'o', '>']
    cols = ['r', 'g', 'b']

    flows, times, num_loss_per_sec, loss_array, total_on_time, max_loss \
        = parse_log(options.log_file)

    total_pkts_loss = 0
    for flow in flows:
        for time in times[flow]:
            loss_array[flow].append(num_loss_per_sec[flow][time])
            total_pkts_loss += num_loss_per_sec[flow][time]

    print "UDP Proxy: total packets loss   : " + str(total_pkts_loss)

    title_str = "Packet loss Vs Time (total: " + str(total_pkts_loss) + \
          "/" + str(total_on_time + total_pkts_loss) + ")"

    if len(flows) < 4:
        for flow in flows:
            plt.scatter(times[flow], loss_array[flow],
                        marker=marks[flows.index(flow)],
                        c=cols[flows.index(flow)], label=flow)
    else:
        for flow in flows:
            plt.scatter(times[flow], loss_array[flow], label=flow)
    if max_loss > 0:
        plt.ylim(0, max_loss*1.1) # add 10% for white space
    else:
        plt.ylim(0)
    plt.xlim(0)
    plt.title(title_str)
    plt.xlabel("Time/s")
    plt.ylabel("Number of packets")
    plt.savefig("udp_decoder_pkt_loss.png")
    plt.clf()

############################################
def main():
    """ Parses argmuments and performs the requested operations. """
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--log', dest='log_file', default=None,
                        help='The UDP proxy log file with packet loss info. ')
    options = parser.parse_args()
    if options.log_file is None:
        parser.error(("Must specify UDP proxy log file"))

    plot_packet_loss(options)

############################################
if __name__ == "__main__":
    main()
