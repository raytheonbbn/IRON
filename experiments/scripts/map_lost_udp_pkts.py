#!/usr/bin/env python

""" Script to map lost FEC group/slot IDs to packet IDs"""

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

# This script parses UDP proxy logs to identify lost packets by FEC Group
# and Slot ID and looks at the BPF logs to find the corresponding packet
# IDs, which can then be used in the packet tracing tool.
# Note that there can be multiple packets with the same FEC group ID.
# The timestamps can be used as a hint as to which corresponds to the
# dropped packets.

import argparse
import re
import os.path
import sys
from subprocess import check_output, CalledProcessError

############################################
def map_lost_packets(exp_dir):
    """ Parse UDP proxy logs and create a mapping of FECState to packet ID. 
    Args:
        exp_dir: Path to the directory of the experiment to be analysed.
    """

    outfile = open('lost_pkts_map.txt', 'w')
    late_packets = {}
    command_str = 'grep -r "pktcount: Late pkt group:" {}'.format(exp_dir)
    try:
        grepped = check_output(command_str, shell=True)
    except CalledProcessError:
        pass
    else:
        lines = grepped.splitlines()
        for line in lines:
            match = re.search(
                r'(node[0-9]+)/logs/.*\.log:([0-9]+\.[0-9]+).*Late pkt group: '
                r'([0-9]+), slot: ([0-9]+).*PacketId: <([0-9]+)>', line)
            if match:
                node = match.group(1)
                time = match.group(2)
                group = match.group(3)
                slot = match.group(4)
                packet_id = match.group(5)
                outfile.write('{} {} Late packet FEC {}/{} -> PacketId {}.\n'.format(
                  time, node, group, slot, packet_id))
                late_packets[group + ':' + slot] = packet_id
    cmd_str = 'grep -r "pktcount:.*Missing FECState group" {}'.format(exp_dir)
    try:
        grepped = check_output(cmd_str, shell=True)
    except CalledProcessError:
        outfile.close()
        sys.exit(1)
    else:
        lines = grepped.splitlines()
    for line in lines:
        match = re.search(
                r'(node[0-9]+)/logs/(...).*\.log:([0-9]+\.[0-9]+)'
                r'.*Missing FECState group: ([0-9]+), slot: ([0-9]+)', line)
        grep_bpf_cmd = ''
        slot = 0
        if match:
            node = match.group(1)
            comp = match.group(2)
            time = match.group(3)
            group = match.group(4)
            slot = match.group(5)
            grep_bpf_cmd = 'grep -r "FECMap: Group <{}> Slot <{}>" {}'.format(
              group, slot, exp_dir)
        else:
            match = re.search(
                r'(node[0-9]+)/logs/(...).*\.log:([0-9]+\.[0-9]+)'
                r'.*Missing FECState group: ([0-9]+)', line)
            if match:
                node = match.group(1)
                comp = match.group(2)
                time = match.group(3)
                group = match.group(4)
                grep_bpf_cmd = 'grep -r "FECMap: Group <{}>" {}'.format(
                  group, exp_dir)
            else:
                continue

            try:
                bpf_grepped = check_output(grep_bpf_cmd, shell=True)
            except CalledProcessError:
                if group + ':' + str(slot) in late_packets.keys():
                    outfile.write('{} {} Missing packet (was late): '\
                      'FEC {}/{} -> PacketId {}\n'.format(time, node, 
                       group, slot,late_packets[group + ':' + str(slot)]))
                else:
                    outfile.write('{} {} Missing packet: FEC {}/{} -> PacketId' \
                      '<No Match>\n'.format(time, node, group, slot))
                continue
            else:
                bpf_log_lines = bpf_grepped.splitlines()
            for bpf_line in bpf_log_lines:
                bpf_match = re.search(
                    r'(node[0-9]+)/logs.*log:([0-9]+\.[0-9]+).*FECMap:'
                    r'.*PacketId: <([0-9]+)>', bpf_line)
                if bpf_match:
                    bpf_node = bpf_match.group(1)
                    bpf_time = bpf_match.group(2)
                    packet_id = bpf_match.group(3)
                    outfile.write('{} {} Missing packet: FEC {}/{} -> PacketId {}.' \
                        ' Dropped {} at {}\n'.format(
                        time, node, group, slot, packet_id, bpf_time, bpf_node))
    outfile.close()

############################################
def find_test_dir():
    """ Reads last_run_experiment.txt to get the experiment directory.

    Return:
        The path to the test directory. If this fails, calls sys.exit().
    """
    try:

        directory = os.path.join(os.path.expanduser('~'), "iron_results")
        results_dir = []
        for d in os.listdir(directory):
            if not os.path.isfile(os.path.join(directory, d)):
                results_dir.append(os.path.join(directory, d))

        results = max(results_dir, key=os.path.getmtime)
        print 'Using results dir: {}'.format(results)
        return results
    except IOError:
        print 'Failed to read {}. Use -d to indicate test results ' \
              'directory'.format(directory)
        sys.exit()


############################################
def main():
    """ Parses argmuments and performs the requested operations. """
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dir', dest='exp_dir', default=None,
      help='The full path to the experiment directory to analyse')
    options = parser.parse_args()
    if options.exp_dir is None:
        map_lost_packets(find_test_dir())
    else:
        map_lost_packets(options.exp_dir)

############################################
if __name__ == "__main__":
    main()

