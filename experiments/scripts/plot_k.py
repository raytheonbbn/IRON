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

# Script to plot the value of K when using adaptive K.
# This parses the BPF log for a line like the following:
# ..... k val changed to xxx.
# It generates one plot called k_changes.png
# usage: python plot_k.py <path to bpf log>

import matplotlib
matplotlib.use('Agg')

import re
import pylab
import matplotlib.pyplot as plt
import sys
from subprocess import check_output, CalledProcessError

filename = sys.argv[1]
try:
  grepped = check_output('grep "K val changed" {}'.format(filename), shell=True)
  lines = grepped.splitlines()
except CalledProcessError:
  print('No adaptive k LogA statements found in file {0}'.format(filename))
  sys.exit(1)

marks = ['x','o','>']
cols = ['r','g','b']
times = []
kvals = []
start_time = 0.0
found = False
for line in lines:
  m = re.match(r'([0-9]*\.[0-9]+).*K val changed to ([0-9]+)',line)
  if m:
    try:
      k_val = m.group(2)
      found = True
      log_time = float(m.group(1))
      if start_time == 0:
        start_time = log_time
      times.append(log_time - start_time)
      kvals.append(k_val)
    except LookupError:
      print 'Error processing line: {0}'.format(line)
      # the indexes may be off, so just exit rather than generating potentially
      # invalid graphs.
      sys.exit(1)

if not found:
    sys.exit()
try:
  plt.scatter(times,
              kvals)
  plt.title("K values")
  plt.savefig("k_changes.png")
  plt.clf()
except LookupError:
  print 'Lookup error printing k changes graph.'
