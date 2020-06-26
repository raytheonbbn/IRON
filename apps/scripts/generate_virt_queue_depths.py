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
A script to analyze testbed and bpf config files in order to generate virtual
queue depths.

The script computes the number of hops to destination nodes servicing the bin
ids and multiplies that number to obtain a queue depth.  The number of hops are
obtained from a Dijkstra implementation, run on a graph that represents the
network and its connections.  The graph is derived from looking at the
experiment file (to keep only iron node information), the testbed file to
establish which nodes are neighbors, and the bin map file to map the bin id to
a particular node / address.

Then, once the number of hops to destinations is obtained, the output file is
written with strings indicating virtual queue depths for every bin.

This program relies on mappings which is a dictionary to help find e.g., the ip
address of a node, the node servicing a bin id, etc.
"""

from os.path import exists
import sys
import operator
import numpy as np
import optparse
from shortest_path import ShortestPath


usage = ('Usage: %prog [options] -e EXP_FILE -t TESTBED -b BINMAP\n\n'    +
          '   EXP_FILE    Full path and name of experiment config file\n' +
          '   TESTBED     Full path and name of testbed config file\n'    +
          '   BINMAP      Name of bin map configuration file (no path)\n')

parser = optparse.OptionParser(usage=usage, version='%prog 0.1')

parser.add_option('-e', '--exp_cfg', dest='exp_filename', default=None,
                      help='Full path and name of experiment config file',
                      metavar='FILE')
parser.add_option('-t', '--testbed', dest='testbed_filename', default=None,
                      help='Full path and name of testbed config file',
                      metavar='FILE')
parser.add_option('-b', '--binmap', dest='binmap_filename', default=None,
                      help='Name of bin map config file (do not specify path)',
                      metavar='FILE')
parser.add_option('-d', '--debug', action='store_true', dest='debug',
                      default=False, help='Enable debug logging')
parser.add_option('-f', '--out', dest='output_filename',
                      default='vq_set_cmd.bfc',
                      help='Name of output command file (do not specify path)',
                      metavar='FILE')
parser.add_option('-m', '--multiplier', dest='multiplier',
                      default=5,
                      help='Multiplier to apply to num hops',
                      metavar='INT')
parser.add_option('-s', dest='av_packet_size_bytes',
                      default=1500,
                      help='Average packet size in bytes',
                      metavar='INT')

(opts, args) = parser.parse_args()

# Sanity check command line
if (not opts.exp_filename or not opts.testbed_filename 
      or not opts.binmap_filename):
  print usage
  sys.stdout.flush()
  exit(1)


# Extract command line vars:
exp_filename      = opts.exp_filename
testbed_filename  = opts.testbed_filename
binmap_filename   = opts.binmap_filename
multiplier        = int(opts.multiplier) * int(opts.av_packet_size_bytes)


# Check if we have all the required files
if not exists(exp_filename):
  print "Experiment filename %s not found" % exp_filename
  sys.stdout.flush()
  exit(1)

# Find experiment name and path
exp_name = exp_filename.rsplit('/', 1)[0]

if not exists(testbed_filename):
  print "Testbed filename %s not found" % testbed_filename
  sys.stdout.flush()
  exit(1)

binmap_filename = exp_name + '/cfgs/' + binmap_filename
if not exists(binmap_filename):
  print "Bin_map filename %s not found" % binmap_filename
  sys.stdout.flush()
  exit(1)



if opts.debug:
  print "Extracting information from the experiment file %s" % exp_filename
  sys.stdout.flush()


# Look into exp.cfg file to find iron nodes
f = open(exp_filename, 'r')

iron_nodes = []

for line in f.readlines():
  if "IRON_NODES" in line:
    iron_nodes_str  = line[line.find('(') + 1 : line.find(')')]
    iron_nodes      = iron_nodes_str.split()

f.close()
if opts.debug:
  print "Iron nodes are: ", iron_nodes


# Look into binmap file to find mapping of bin Id to iron nodes
if opts.debug:
  print "\nExtracting information from the binmap file", binmap_filename
f = open(binmap_filename, 'r')

# We will need to map bin ids to the address of the node that services it
addr_binid_mapping = {}

for line in f.readlines():
  if line.startswith('#') or line == '\n':
    continue

  line = line.strip('\n')

  # Find the address of iron node that services bin id
  if '.IronNodeAddr' in line:
    bin_str, addr = line.split('.IronNodeAddr', 1)
    bin_id  = bin_str.split('.')[-1]
    addr    = addr.strip()

    addr_binid_mapping[addr] = bin_id

f.close()

if len(addr_binid_mapping) == 0:
  print "No binids defined, nothing to do"
  exit(0)

if opts.debug:
  print "Bin ids are mapping to addresses as follows: ", addr_binid_mapping


# Look into testbed file to find links and addresses between iron nodes
if opts.debug:
  print ("\nExtracting information from the testbed filename... %s"
                                                            % testbed_filename)

f = open(testbed_filename, 'r')

iron_links = []
node_lines = []
binid_node_mapping = {}

for line in f.readlines():
  if line.startswith('#') or line == '\n':
    continue
  
  line = line.strip('\n')

  # Find links between two iron nodes (other links are of no interest)
  if line.startswith('link'):
    values = line.split()
    if len(values) == 3:
      if (values[1] in iron_nodes) and (values[2] in iron_nodes):
        iron_links.append(values[0])
    elif len(values) == 2:
      if values[1] in iron_nodes:
        iron_links.append(values[0])

  # In doubt, temporarily store the lines starting with 'nodeX appX etc. in 
  # case they are out of order with the link lines
  if line.startswith('node'):
    if line.split()[0] in iron_nodes:
      node_lines.append(line)

if opts.debug:
  print "Iron links are: ", iron_links

f.close()

# Continue processing the other part of testbed config file:
# Find node-address pairs
addr_node_pairs = {}

for line in node_lines:
  values = line.split()
  node = values[0]
  associated_links = values[2].split(',')

  incoming_addresses = []
  for link in associated_links:
    link_number, addr = link.split('=')
    if link_number in iron_links:
      incoming_addresses.append(addr)
      addr_node_pairs[addr] = node

    # Find mapping from bin id to node
    if addr in addr_binid_mapping:
      bin_id = addr_binid_mapping[addr]
      binid_node_mapping[bin_id] = node


if opts.debug:
  print "Nodes have the following addresses: ", addr_node_pairs
  print "BinIds tie to the following nodes : ", binid_node_mapping


num_iron_nodes  = len(iron_nodes)
connectivity    = np.zeros(shape=(num_iron_nodes, num_iron_nodes))
node_index_mapping = {}
index_node_mapping = {}


# Look into all bpf_nodeX.cfg files
node_ipaddr_mapping = {}
for node in iron_nodes:
  bpfcfg_filename = exp_name + '/cfgs/bpf_' + node + '.cfg'

  if not exists(bpfcfg_filename):
    print "Config file %s not found!" % bpfcfg_filename
    continue

  if opts.debug:
    print "\nExtracting information from bpf_" + node + ".cfg"

  f = open(bpfcfg_filename, 'r')
  
  for line in f.readlines():
    if line.startswith('#') or line == '\n':
      continue

    # Find the ip address of a node
    if 'bpf.ipaddr' in line.lower():
      node_ipaddr_mapping[node] = line.split(None, 1)[1].strip()


    # Find the ip address of remote side for all PathControllers
    if 'dstaddr' in line.lower() and 'pathcontroller' in line.lower():
      # Find destination address, which can be mapped to dest node
      dst_addr = line.split(None, 1)[1].strip()
      dst_node = addr_node_pairs[dst_addr]
      if opts.debug:
        print "%s has link to address %s / %s" % (node, dst_addr, dst_node)

      # Enter into connectivity matrix, but first, use proper indexing
      if node not in node_index_mapping:
        num_nodes_in_mapping = len(node_index_mapping)
        node_index_mapping[node] = len(node_index_mapping)
        index_node_mapping[len(index_node_mapping)] = node

      if dst_node not in node_index_mapping:
        num_nodes_in_mapping = len(node_index_mapping)
        node_index_mapping[dst_node] = len(node_index_mapping)
        index_node_mapping[len(index_node_mapping)] = dst_node

      node_index = node_index_mapping[node]
      dst_node_index = node_index_mapping[dst_node]
      connectivity[node_index, dst_node_index] = 1
      connectivity[dst_node_index, node_index] = 1

  f.close()

if opts.debug:
  print ("\nNodes have the following indices in the matrix below:",
          node_index_mapping)
  print "Connectivity matrix:\n", connectivity

if connectivity.sum() == 0:
  print "Found no neigbhors for any node, abort"
  exit(1)

# Get shortest path
sp    = ShortestPath()
graph = sp.ConvertConnectivityToGraph(connectivity, index_node_mapping)


# Parse the results from shortest path
results = {}

for node in iron_nodes:
  path, distances, next_hops = sp.ComputeShortestPath(graph, node)
  if opts.debug:
    print node, "has following distances to other nodes:", distances

  # Fill results as:
  # {Node7: {'binids': {1: length 20}, {3: length 30}}, {'ipaddr': 32.2}}
  if node not in results:
    results[node]           = {}
    results[node]['ipaddr'] = node_ipaddr_mapping[node]
    results[node]['binids'] = {}

  for bin_id in binid_node_mapping:
    # Get dest node for the current bin id, because we have a node mapping, not
    # bin id mapping
    bin_dst_node = binid_node_mapping[bin_id]
    num_hops = distances[bin_dst_node]

    if opts.debug:
      print ("%s (%s) has a bin id %s (%s) distance of %d" %
             (node, node_ipaddr_mapping[node], bin_id, bin_dst_node, num_hops))

    # Ignore distance of 0 (0 is the virtual queue default)
    if num_hops == 0:
      continue


    if bin_id not in results[node]['binids']:
      results[node]['binids'][bin_id] = num_hops

print ""

boilerplate_str = ('#\n'                                                      +
'# This bpfctl script is to be fed into the "bpfctl" program using the "-f"\n'+
'# command line option in order to dynamically control backpressure\n'        +
'# forwarders during an experiment or test.  A single script is capable of\n' +
'# controlling multiple backpressure forwarders, which simplifies event\n'    +
'# timings.  This should be modified to support the desired system\n'         +
'# configuration and experiment parameters.\n'                                +
'#\n'                                                                         +
'# Using a "sleep" command will pause the processing of this script before\n' +
'# continuing with the next command.  Sleep times must be specified in\n'     +
'# seconds, and may be fractional.\n'                                         +
'#\n'                                                                         +
'# Transactional command lines are listed one per line, with the format:\n'   +
'#\n'                                                                         +
'#   <host>  <command>  <target>  [<command_arguments>]\n'                    +
'#\n'                                                                         +
'# Hosts may be specified by hostname or IP address.  If the bpfctl "-H"\n'   +
'# command line option is used, then the host variable specified in the\n'    +
'# "-H" option replaces each occurrence of "[H]" within each command\'s\n'    +
'# hostname.\n'                                                               +
'# For example, if the hostname variable is specified as "-H 7" in the\n'     +
'# bpfctl command, and a command has a hostname of "iron[H]3.bbn.com", then\n'+
'# the hostname used for the command will be "iron73.bbn.com".\n'             +
'#\n'                                                                         +
'# The command may be any of the supported commands, such as "set".\n'        +
'#\n'                                                                         +
'# The target specifies the target of the command, which may be either\n'     +
'# "bpf" for the backpressure forwarder, or "PathCtrl" for a Sond or CAT.\n'  +
'# When specifying a PathCtrl, a PathCtrl number must be specified in the\n'  +
'# target string with the format "PathCtrl:N" in order to access the\n'       +
'# correct PathCtrl instance.  The PathCtrl numbers must be the integer\n'    +
'# numbers assigned in the backpressure forwarder configuration files.\n'     +
'#\n'                                                                         +
'# For commands that require configuration parameter names (i.e. "keys"),\n'  +
'# these keys must be valid strings understood by the target component.\n'    +
'# For set commands, the value specified must be appropriate for the key.\n'  +
'#\n'                                                                         +
'# Note that for PathCtrl "maxLineRate" parameters, the specified rates\n'    +
'# must be in kbps (kilobits per second, 1 kbps = 1000 bps), and may be\n'    +
'# fractional.\n'                                                             +
'#\n\n\n')


outfile = exp_name + '/cfgs/' + opts.output_filename
f       = open(outfile, 'w')
f.write(boilerplate_str)

# Build the strings to write to file:
for node in results:
  for bin_id in results[node]['binids']:
    # Add self to this bin id
    str = ('%s set bpf VirtualQueueDepthsBytes bid:%s;%s:%d'
          % (results[node]['ipaddr'], bin_id, results[node]['ipaddr'],
              results[node]['binids'][bin_id] * multiplier))

    # Add the node's neighbors
    node_index = node_index_mapping[node]
    for i in range(0, len(connectivity)):
      if connectivity[node_index, i] > 0:
        dst_node = index_node_mapping[i]
        if bin_id in results[dst_node]['binids']:
          str += (",%s:%d" % (results[dst_node]['ipaddr'],
                  results[dst_node]['binids'][bin_id] * multiplier))
    if opts.debug:
      print str

    f.write(str + '\n')

f.write('\n\n')
f.close()

