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

# Script to plot the instantaneous send rate and queue depths 
# as seen by the UDP proxy. It parses the proxy log for a line like the following:
# ..... label: mgen_flow_2, queue: 0.000000, rate: 1000000.000000
# It generates two plots: queues.png and rates.png 
# usage: python plotSR.py <path to udp proxy log>  

# You may have to edit the limits below to the desired range. 

import matplotlib
matplotlib.use('Agg')

import re
import pylab
import matplotlib.pyplot as plt
import sys
from subprocess import check_output, CalledProcessError

MAX_REASONABLE_Q = 100000000 # 100 million Bytes
MAX_REASONABLE_RATE = 1000000000 # 1 billion bps (1 Gbps)

filename = sys.argv[1]

try:
  start = check_output(["grep", "UDP Proxy configuration complete", filename])
  for line in start.splitlines():
    match = re.match(r'([0-9]*)\.[0-9]+.*UDP', line)
    if match:
      start_time = int(match.group(1))
    else:
      start_time = 0
  grepped = check_output(["grep", "rate", filename])
  lines = grepped.splitlines()
except CalledProcessError:
  sys.exit(1)


marks = ['x','o','>']
cols = ['r','g','b']
flows = []
rates = {}
queues = {}
times = {}
hold_times = {}
hold_times_ts = {}
max_q = 0
max_rate = 0
for line in lines:
  m = re.match(r'([0-9]*\.[0-9]+).*f_id: (.*), queue: ([0-9]*).*b, rate: ([0-9]*\.[0-9]+)bps',line)
  if m:
    if start_time == 0:
      start_time = float(m.group(1))
    if m.group(2) not in flows:
      flows.append(m.group(2))
      rates[m.group(2)] = []
      queues[m.group(2)] = []
      times[m.group(2)] = []
      hold_times[m.group(2)] = []
      hold_times_ts[m.group(2)] = [] 
    queue = float(m.group(3))
    rate = float(m.group(4))
    times[m.group(2)].append(float(m.group(1)) - start_time)
    queues[m.group(2)].append(queue)
    rates[m.group(2)].append(rate)
    if (queue > max_q and queue < MAX_REASONABLE_Q):
      max_q = queue
    if (rate > max_rate and rate < MAX_REASONABLE_RATE):
      max_rate = rate
    if queue > MAX_REASONABLE_Q:
      print 'queue length too large at time {0}: {1}'.format(m.group(2), queue)
      print 'line {0}'.format(line)

if len(flows) < 4:
    for f in flows:
        plt.scatter(times[f],rates[f],marker=marks[flows.index(f)],c=cols[flows.index(f)],label=f)
else:
    for f in flows:
        plt.scatter(times[f],rates[f],label=f)
if max_rate > 0:
    plt.ylim(0,max_rate*1.1) # add 10% for white space
#plt.legend(loc=4)
plt.title("Admission rate (bps)")
plt.savefig("rates.png")
plt.clf()

if len(flows) < 4:
    for f in flows:
        plt.scatter(times[f],queues[f],marker=marks[flows.index(f)],c=cols[flows.index(f)],label=f)
else:
    for f in flows:
        plt.scatter(times[f],queues[f],label=f)
if max_q > 0:
    plt.ylim(0,max_q*1.1) # add 10% for white space

#plt.legend(loc=4)
plt.title("Queue Lengths (bits)")
plt.savefig("queues.png")
plt.clf()

try:
  grepped_hold = check_output(["grep", "packet hold time", filename])
  lines_hold = grepped_hold.split_lines()
except CalledProcessError:
  sys.exit(1)

for line in lines_hold:
  m = re.match(r'([0-9]*\.[0-9]+).*tag: (.*), packet hold time: (.*) microseconds',line)
  if m:
    if start_time == 0:
      start_time = float(m.group(1))
    if m.group(2) not in flows:
      flows.append(m.group(2))
      rates[m.group(2)] = []
      queues[m.group(2)] = []
      times[m.group(2)] = []
      hold_times[m.group(2)] = [] 
      hold_times_ts[m.group(2)] = [] 
    hold_times_ts[m.group(2)].append(float(m.group(1)) - start_time)
    hold_times[m.group(2)].append(float(m.group(3)))

if len(flows) < 4:
    for f in flows:
        plt.scatter(hold_times_ts[f],hold_times[f],marker=marks[flows.index(f)],c=cols[flows.index(f)],label=f)
else:
    for f in flows:
        plt.scatter(hold_times_ts[f],hold_times[f],label=f)


plt.title("Hold Times")
plt.savefig("hold_times.png")
plt.clf()
