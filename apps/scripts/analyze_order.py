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
#
# A script to analyze mgen logs for delay and ordering properties.
#
# Usage:
#   python analyze_order.py mgen_file_name
#
# where,
#
# mgen_file_name  : Name of the mgen file
#

from os.path import exists
from matplotlib import pyplot as plt
import sys
import operator

if len(sys.argv) == 2:
  script, mgen_file_name = sys.argv
else:
  print "Usage: python %s <mgen_file>" % (sys.argv[0])
  sys.stdout.flush()
  exit(1)


if not exists(mgen_file_name):
  print "Mgen file not found, cannot run"
  sys.stdout.flush()
  exit(1)

print "Extracting information from mgen file...%s" % mgen_file_name
sys.stdout.flush()

f = open(mgen_file_name, 'r')

result_map = {}

# Read the lines for the file provided
for line in f.readlines():
  if not line.startswith("#") and not line == "\n":
    values = line.split(" ")
# Parse out the RECV line, remove trailers
    if "RECV" in line:
      rx_time = values[0]
      flow = values[3]
      flow = flow.strip("flow>")
      seqn = values[4]
      seqn = seqn.strip("seq>")
      src = values[5]
      addr, port = src.rsplit("/", 1);
      tx_time = values[7]
      tx_time = tx_time.strip("sent>")
      size = values[9]
      size = size.strip("size>")

# Add to the result_map if there
      if flow not in result_map:
        tempd = {}
        tempd['rx_times'] = []
        tempd['delay'] = []
        tempd['seqns'] = []
        [hours, minutes, secs] = [float(x) for x in tx_time.split(':')]
        tx_time_float = hours*24.*60. + minutes*60. + secs
        tempd['ortime'] = tx_time_float
        result_map[flow] = tempd

# Compute the absolute time as a float
      [hours, minutes, secs] = [float(x) for x in rx_time.split(':')]
      rx_time_float = hours*24.*60. + minutes*60. + secs
      result_map[flow]['rx_times'].append(rx_time_float - result_map[flow]['ortime'])
      [hours, minutes, secs] = [float(x) for x in tx_time.split(':')]
      tx_time_float = hours*24.*60. + minutes*60. + secs
      result_map[flow]['delay'].append(rx_time_float - tx_time_float)
      result_map[flow]['seqns'].append(seqn)

f.close()

exp_name = ''
node_name = ''
if "results_" in mgen_file_name:
  exp_name = 'results_' + mgen_file_name.split('/results_', 1)[1]
  exp_name = exp_name.split('/logs', 1)[0]
  exp_name, node_name = exp_name.split('/node', 1)
  node_name = 'node' + node_name

figure_num = 1
for subplot_index in range(1, 11):
  plt.figure(figure_num)
  plt.suptitle('Tx-Rx delay as a function of sequence number for %s %s, flow %d'%(exp_name, node_name, subplot_index))
  plt.subplot(1, 2, 1)
  plt.xlabel('Seq Num')
  plt.ylabel('Time (s)')
  plt.plot(result_map[str(subplot_index)]['seqns'], result_map[str(subplot_index)]['rx_times'], 'o', color=[0.5, 0.5, 1.])

  plt.subplot(1, 2, 2)
  plt.xlabel('Seq Num')
  plt.ylabel('Delay (s)')
  plt.plot(result_map[str(subplot_index)]['seqns'], result_map[str(subplot_index)]['delay'], 'o', color=[0.5, 0.5, 1.])
  figure_num += 1


subplot_index = 1
plt.figure(figure_num)
plt.suptitle('Time from 1st packet tx time for all flows for %s'%node_name)
for subplot_index in range(1, 11):
  plt.subplot(len(result_map)/2, 2, subplot_index)
  plt.plot(result_map[str(subplot_index)]['seqns'], result_map[str(subplot_index)]['rx_times'], 'o', color=[0.5, 0.5, subplot_index/10.])
figure_num += 1

subplot_index = 1
plt.figure(figure_num)
plt.suptitle('Delay for all flows for %s'%node_name)
for subplot_index in range(1, 11):
  plt.subplot(len(result_map)/2, 2, subplot_index)
  plt.plot(result_map[str(subplot_index)]['seqns'], result_map[str(subplot_index)]['delay'], 'o', color=[0.5, 0.5, subplot_index/10.])
figure_num += 1


plt.show()
