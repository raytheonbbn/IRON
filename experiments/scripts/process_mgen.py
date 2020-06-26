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

# Script to compute the total number of bytes received in an mgen log. 
# It disregards all traffic which has a destination port lower than a
# specified threshold.
# usage: python process_mgen.py <path to mgen log> <min port to consider> 

import matplotlib
matplotlib.use('Agg')

import numpy
import pylab
import matplotlib.pyplot as plt
import re
import sys
from subprocess import check_output, CalledProcessError

# Map of port:on_time
on_time = {}
# Map of port:setup_time
setup_time = {}
# Map of port:transfer_time
transfer_time = {}
# Map of port:transfer_send_time
transfer_send_time = {}

def ParseLog(filename, min_port):
    ref_time = 0.0
    try:
        grepped = check_output(["grep", "ON flow", filename])
        lines = grepped.splitlines()

        for line in lines:
            m = re.match(r'([0-9]*):([0-9]*):([0-9]*\.[0-9]*) '
                          'ON.*dst>.*/([0-9]*).*', line)
            if m:
                time = float(m.group(3)) + 60*float(m.group(2)) \
                       + 3600*float(m.group(1))
                if ref_time == 0:
                    ref_time = time
                port = int(m.group(4))
                if port < min_port:
                    continue
                if port not in on_time:
                    on_time[port] = time 
                else:
                    print "Port %s used for multiple flows. Skipping" % port
                    continue

    except:
        print "No ON commands in this log"

    try:
        grepped = check_output(["grep", "CONNECT flow", filename])
        lines = grepped.splitlines()

        for line in lines:
            m = re.match(r'([0-9]*):([0-9]*):([0-9]*\.[0-9]*) '
                          'CONNECT .*dst>.*/([0-9]*).*', line)
            if m:
                time = float(m.group(3)) + 60*float(m.group(2)) \
                       + 3600*float(m.group(1))
                if ref_time == 0:
                    ref_time = time
                port = int(m.group(4))
                if port < min_port:
                    continue
                if port not in on_time:
                    print "CONNECT without prior ON. Skipping"
                    continue
                setup_time[port] = time - on_time[port]
                print "Setup time is: %s" % setup_time[port]

    except:
        print "No CONNECT commands in this log"

    try:
        grepped = check_output(["grep", "RECV proto>TCP", filename])
        lines = grepped.splitlines()

        for line in lines:
            m = re.match(r'([0-9]*):([0-9]*):([0-9]*\.[0-9]*) '
                          'RECV proto>TCP.*dst>.*/([0-9]*) sent>'
                          '([0-9]*):([0-9]*):([0-9]*\.[0-9]*).*', line)
            if m:
                recv_time = float(m.group(3)) + 60*float(m.group(2)) \
                            + 3600*float(m.group(1))
                send_time = float(m.group(7)) + 60*float(m.group(6)) \
                            + 3600*float(m.group(5))
                if ref_time == 0:
                    ref_time = send_time
                port = int(m.group(4))
                if port < min_port:
                    continue
                if port not in transfer_time:
                    transfer_time[port] = recv_time - send_time
                    transfer_send_time[port] = send_time
                    print "Transfer time for port %s is: %s" % \
                          (port, transfer_time[port])
                else:
                    # If the transfer is broken up into multiple "SEND", then
                    # the transfer time is the time difference between the
                    # reception of the last packet and the transmission of the
                    # first packet.
                    transfer_time[port] = recv_time - transfer_send_time[port]
                    print "Warning: Multiple RECVs for flow %s" % port
                    continue

    except:
        print "No RECV commands in this log"
    return ref_time

def PlotSetupTimes(ref_time):
    start_times = []
    setup_times = []
    xfer_send_times = []
    xfer_times = []
    max_delay = 0
    for port in on_time.keys():
        if port in setup_time:
            start_times.append(on_time[port] - ref_time)
            setup_times.append(setup_time[port])
            if setup_time[port] > max_delay:
                max_delay = setup_time[port]
    for port in transfer_send_time.keys():
        xfer_send_times.append(transfer_send_time[port] - ref_time)
        xfer_times.append(transfer_time[port])
        if transfer_time[port] > max_delay:
            max_delay = transfer_time[port]
    if len(start_times) > 0:
        print "Average setup time: %s seconds" % numpy.mean(setup_times) 
        plt.scatter(start_times, setup_times, marker='x', \
                    c='r', label='setup times')
    if len(xfer_times) > 0:
        print "Average transfer time: %s seconds" % numpy.mean(xfer_times)
        plt.scatter(xfer_send_times, xfer_times, marker='o', \
                    c='b', label='transfer times')
    if len(start_times) + len(xfer_times) > 0:
        plt.ylim(0, max_delay*1.1) # add 10% for white space
        plt.xlim(0)
        plt.legend(loc='lower right',
                         fancybox=True, shadow=True, ncol=1)
        plt.xlabel("Experiment Time/s")
        plt.ylabel("Latency/s")
        plt.title("Setup and transfer time for TCP flows")
        plt.savefig("setup_times.png")
        plt.clf()

def main():
    if len(sys.argv) < 3:
        print "Usage: python process_mgen.py <min_port> <path_to_mgen_log> <path_to_mgen_log> ..." 
        print "Result will include flows from all included mgen files."
        exit(1)

    min_port = int(sys.argv[1])
    for i in range(2,len(sys.argv)):
        filename = sys.argv[i]
        ref_time = ParseLog(filename, min_port)
    PlotSetupTimes(ref_time)

if __name__ == "__main__":
    main()
