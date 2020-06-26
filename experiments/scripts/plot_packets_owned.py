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

# Script to plot the number of packets owned over time by the BPF, TCP
# proxy, and UDP proxy.
# This parses the component log files for a line like the following:
# ..... Packets owned = 0
# It generates a plot called packets_owned.png.
# usage: python plot_packets_owned.py <path to bpf log> <path to udp proxy
#        log> <path to tcp proxy log>

import matplotlib
matplotlib.use('Agg')

import re
import pylab
import matplotlib.pyplot as plt
import sys
from subprocess import check_output, CalledProcessError

filename = []
labels = []
filename.append(sys.argv[1])
labels.append("BPF")
filename.append(sys.argv[2])
labels.append("UDP")
filename.append(sys.argv[3])
labels.append("TCP")
plots = []

marks = ['x','o','>']
cols = ['r','g','b']

anyFound = False
start_time = 0.0
for i in xrange(0,3):
  try:
    grepped = check_output(["grep", "Packets owned", filename[i]])
    lines = grepped.splitlines()
  except CalledProcessError:
    print('pktsowned: Error grepping log file {0}'.format(filename[i]))
    sys.exit(1)

  times = []
  pkts = []
  found = False
  for line in lines:
    m = re.match(r'([0-9]*\.[0-9]+).*Packets owned = (.*)',line)
    if m:
      try:
        if start_time == 0:
          start_time = float(m.group(1))
        times.append(float(m.group(1)) - start_time)
        pkts.append(m.group(2))
        found = True
        anyFound = True
      except LookupError:
        print 'Error processing line: {0}'.format(line)
        sys.exit(1)
  if found:
    plots.append(plt.scatter(times,
                             pkts,
                             marker=marks[i],
                             c=cols[i],
                             label=labels[i]))

if not anyFound:
    sys.exit()
try:
  plt.legend()
  plt.title("Packets owned")
  plt.savefig("packets_owned.png")
  plt.clf()
except LookupError:
  print 'Lookup error printing packets owned graph.'
