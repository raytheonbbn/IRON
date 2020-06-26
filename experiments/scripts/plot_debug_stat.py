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

# Script to plot the value of an arbitrary debugging statistic.
# This parses the passed-in log for a line like the following:
# ..... <stat name>, <time>, avg: <avg>, min: <min>, max: max.
# It generates one plot called <statname>.png
#
# usage: python plot_debug_stat.py <path to log file> <stat name> <output name>
#
# output name is optional. If not provided, stat name is used.

import matplotlib
matplotlib.use('Agg')

import argparse
import re
import pylab
import matplotlib.pyplot as plt
import sys
from subprocess import check_output, CalledProcessError

parser = argparse.ArgumentParser()
parser.add_argument('filename')
parser.add_argument('statname')
parser.add_argument('outputname', nargs='?')
options = parser.parse_args()

filename = options.filename
statname = options.statname
if not options.outputname:
  outputname = statname
else:
  outputname = options.outputname
start_time = 0.0
# Use the constructor of DebuggignStats as the start time, to help align
# graphs that start at different points in the test run.
try:
  grepped = check_output(
    'grep "DebuggingStats::DebuggingStats\] STARTTIME" {}'.format(
      filename), shell=True)
  lines = grepped.splitlines()
  for line in lines:
    m = re.search(r'STARTTIME = ([0-9]+)', line)
    if m:
      try:
        start_time = int(m.group(1))
      except LookupError:
        print 'Error processing firstline: {0}'.format(line)
except CalledProcessError:
  print('No STARTTIME found for DebuggingStats in file {}'.format(filename))

try:
  grepped = check_output(
    'grep "{}," {}'.format(statname, filename), shell=True)
  lines = grepped.splitlines()
except CalledProcessError:
  print('No log statements found for stat {} in file {}'.format(
    statname, filename))
  sys.exit(1)

times = []
avgvals = []
minvals = []
maxvals = []
found = False
for line in lines:
  m = re.search(
    r'{}, ([0-9]+), avg: ([0-9]+\.?[0-9]*), min: ([0-9]+), max: ([0-9]+)'.format(
      statname), line)
  if m:
    try:
      time = int(m.group(1))
      avg = m.group(2)
      minval = m.group(3)
      maxval = m.group(4)
      found = True
      if start_time == 0:
        start_time = time
      times.append((time - start_time)/1000000)
      avgvals.append(avg)
      minvals.append(minval)
      maxvals.append(maxval)
    except LookupError:
      print 'Error processing line: {0}'.format(line)

if not found:
  print('No amortized results.')
else:
  try:
    plt.scatter(times, avgvals, c='r', label='avg')
    plt.scatter(times, minvals, c='g', label='min')
    plt.scatter(times, maxvals, c='b', label='max')
    plt.title("{} over time".format(statname))
    plt.savefig("{}.png".format(outputname))
    plt.clf()
  except LookupError:
    print('Lookup error printing {} graph.'.format(statname))
  # We won't have both amortized and instant results for the same stat.
  sys.exit()

raw_time_val = [] # 2-tuples: time, val
found = False
for line in lines:
  m = re.search(
    r'{}, ([0-9]+), val: (\-?[0-9]+\.?[0-9]*)'.format(statname), line)
  if m:
    try:
      time = int(m.group(1))
      val = m.group(2)
      found = True
      raw_time_val.append((time, val))
    except LookupError:
      print 'Error processing line: {0}'.format(line)
      sys.exit(1)
raw_time_val = sorted(raw_time_val, key=lambda (t,v): t)
times = [(time - start_time)/1000 for (time, val) in raw_time_val]
vals = [val for (time,val) in raw_time_val]

if not found:
  print('No full results.')
else:
  try:
    plt.scatter(times, vals, c='r', label='val')
    plt.title("{} over time".format(statname))
    plt.savefig("{}.png".format(outputname))
    plt.clf()
  except LookupError:
    print('Lookup error printing {} graph.'.format(statname))
