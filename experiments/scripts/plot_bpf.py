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

# Script to plot the weights and queue depths as computed by the BPF,
# when queue depth managers such as heavy ball and EWMA are used.
# This parses the BPF log for a line like the following:
# ..... Bin: 2, Weight: 0.000000, Queue: 0.000000
# It generates two plots: bpf_queues.png and bpf_weights.png
# usage: python plotSR.py <path to bpf log>

# You may have to edit the limits below to the desired range.

import matplotlib
matplotlib.use('Agg')

import re
import pylab
import matplotlib.pyplot as plt
import sys
from subprocess import check_output, CalledProcessError

MAX_REASONABLE_Q = 10000000 # 10 mil Bytes
MAX_REASONABLE_WEIGHT = 10000000 # 10 mil Bytes

filename = sys.argv[1]
try:
  grepped = check_output(["grep", "Weight", filename])
  lines = grepped.splitlines()
except CalledProcessError:
  print('plot_bpf: Error grepping log file {0}'.format(filename))
  sys.exit(1)

marks = ['x','o','>']
cols = ['r','g','b']
flows = []
weights = {}
queues = {}
times = {}
start_time = 0.0
max_q = 0
max_weight = 0
found = False
for line in lines:
  m = re.match(r'([0-9]*\.[0-9]+).*Bin: (.*), Weight: ([0-9]+) B, ' \
               'Queue: ([0-9]+) B',line)
  if m:
    try:
      bin = m.group(2)
      found = True
      if start_time == 0:
        start_time = float(m.group(1))
      if bin not in flows:
        flows.append(bin)
        weights[bin] = []
        queues[bin] = []
        times[bin] = []
      weight = float(m.group(3))
      queue = float(m.group(4))
      times[bin].append(float(m.group(1)) - start_time)
      weights[bin].append(weight)
      queues[bin].append(queue)
      if (weight > max_weight and weight < MAX_REASONABLE_WEIGHT):
        max_weight = weight
      if (queue > max_q and queue < MAX_REASONABLE_Q):
        max_q = queue
      if weight > MAX_REASONABLE_WEIGHT:
        print 'weight too large at time {0}: {1}'.format(bin, weight)
        print 'line {0}'.format(line)
      if queue > MAX_REASONABLE_Q:
        print 'queue length too large at time {0}: {1}'.format(bin, queue)
        print 'line {0}'.format(line)
    except LookupError:
      print 'Error processing line: {0}'.format(line)
      # the indexes may be off, so just exit rather than generating potentially
      # invalid graphs.
      sys.exit(1)

if not found:
    sys.exit()
try:
  if len(flows) < 4:
      for f in flows:
          plt.scatter(times[f],
                      weights[f],
                      marker=marks[flows.index(f)],
                      c=cols[flows.index(f)],
                      label=f)
  else:
      for f in flows:
          plt.scatter(times[f],weights[f],label=f)
  plt.ylim(0,max_weight*1.1) # add 10% for white space
  #plt.legend(loc=4)
  plt.title("Weights (Bytes)")
  plt.savefig("bpf_weights.png")
  plt.clf()
except LookupError:
  print 'Lookup error printing weights graph.'

try:
  if len(flows) < 4:
      for f in flows:
          #plt.scatter(times[f],queues[f],label=f)
          plt.scatter(times[f],
                      queues[f],
                      marker=marks[flows.index(f)],
                      c=cols[flows.index(f)],
                      label=f)
  else:
      for f in flows:
          plt.scatter(times[f],queues[f],label=f)
  plt.ylim(0,max_q*1.1) # add 10% for white space

  #plt.legend(loc=4)
  plt.title("Queue Lengths (Bytes)")
  plt.savefig("bpf_queues.png")
  plt.clf()
except LookupError:
  print 'Lookup error printing queue length graph.'
