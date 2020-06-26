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
# A script to create an experiment configuration file from a testbed
# topology file. The testbed topology file contains the suffix to use
# to construct the fully qualified host names, the directory to use to
# stage the experiment, optionally the name of the node that is the
# target of the experiment results, the directory to place the
# experiment results, a definition of the links, and the definition of
# the nodes in the experiment (including the node name and the links
# associated with the node).
#
# Usage:
#
#   python generate_testbed_exp_cfg.py user_name testbed_file_name
#        exp_file_name [exp_name]
#
# where,
#
# user_name         : Name of the user to run experiment as
# testbed_file_name : Name of the testbed topology file
# exp_file_name     : Name of the experiment configuration file
# exp_name          : Name of the experiment. This is only used for DETER
#                     experiments and this must match the name of the
#                     experiment provided when beginning a DETER
#                     experiment.
#

from __future__ import print_function
import argparse
from os import path
import os
import socket
import subprocess
import sys

def print_debug(msg, *format_args):
    """Print when not in quiet mode. Supports string formatting."""
    if not args.quiet:
        print(msg.format(*format_args))

parser = argparse.ArgumentParser()
parser.add_argument("-q", "--quiet", action="store_true", dest="quiet",
                    default=False, help="Only output text if there is an issue.")
parser.add_argument("user_name", metavar="USER_NAME",
                    help="Name of the user to run experiment as.")
parser.add_argument("testbed_file_name", metavar="TESTBED_FILENAME",
                    help="Name of the testbed topology file.")
parser.add_argument("exp_file_name", metavar="EXP_FILENAME",
                    help="Name of the experiment configuration file.")
parser.add_argument("exp_name", metavar="EXP_NAME", nargs="?", default="",
                    help="Name of the experiment. Only used for DETER "
                         "experiments. must match the name of the experiment "
                         "provided when beginning a DETER experiment")

args = parser.parse_args()

node_map = {}
linkem_map = {}
results_location = ""
results_host = ""

# Extract the information from the testbed topology file.
#
if (not path.exists(args.testbed_file_name)):
    print("Testbed file {} does not exist, "
          "cannot run".format(args.testbed_file_name))
    exit(1)

print_debug("Extracting information from Testbed file {}...",
            args.testbed_file_name)

f = open(args.testbed_file_name, 'r')

for line in f.readlines():

    #
    # We will skip comments and blank lines.
    #

    if not line.startswith("#") and not line == "\n":
        if line.startswith("suffix"):
            suffix = line.split(" ")[1].strip()
            suffix = suffix.replace('EXP_NAME', args.exp_name)
        elif line.startswith("link"):
            #
            # For now, we don't do anything with the linkX lines in
            # the testbed topology file. In the future these can be
            # used to generate the DETER configuration file.
            #
            continue
        elif line.startswith("node"):
            (key, value) = line.split(" ", 1)
            (host, links) = value.strip().split(" ")
            node_map[key] = {'host' : host, 'links' : links}
        elif line.startswith("exp_base_dir"):
            exp_base_dir = line.split(" ")[1].strip()
        elif line.startswith("results_location"):
            results_location = line.split(" ")[1].strip()
        elif line.startswith("results_host"):
            results_host = line.split(" ")[1].strip()

# Close the file.
f.close()

#
# Create the directory for the generated file. It will be placed in
# ~/iron_exp_staging
#
home = path.expanduser("~")
if not path.exists("%s/iron_exp_staging" % (home)):
    os.makedirs("%s/iron_exp_staging" % (home))

#
# Read in the lines in the experiment configuration file and generate
# a configuration file that substitutes the information extracted from
# the testbed topology file.
#

output_file_name = "%s/iron_exp_staging/%s" % (home, args.exp_file_name.rsplit("/", 1)[1])
hosts = "%s/iron_exp_staging/hosts.txt" % (home)

of = open(output_file_name, 'w')
of2 = open(hosts,'w')

of.write("USER_NAME=%s\n" % args.user_name)
of2.write("USER_NAME=%s\n" % args.user_name)
of.write("EXP_BASE_DIR=%s\n" % exp_base_dir)
of.write("TESTBED_TOPO_FILE=%s\n" % path.basename(args.testbed_file_name))

if (results_location != ""):
    of.write("RES_LOC=%s\n" % results_location)


if (results_host != ""):
    of.write("RES_HOST=%s\n" % results_host)
else:
    of.write("RES_HOST=%s\n" % socket.gethostname())

f = open(args.exp_file_name, 'r')

print_debug("Processing experiment file {}...", args.exp_file_name)

for line in f.readlines():
    if line.startswith("NODE_LIST"):
        #
        # The NODE_LIST line from the experiment configuration file
        # is changed as follows:
        #
        # - Generic nodeX is changed to "nodeX:fully qualified node
        #   name" for each node. The generic nodeX is utilized to
        #   construct the names of the directories for the experiment
        #   results and the fully qualified name is used to get to the
        #   machine to collect the experiment results.
        #
        print_debug("Generating fully qualified names for NODE_LIST...")

        tmp_exp_node_list = []
        exp_nodes = line.rsplit("=")[1].strip('()\n').split(" ")
        host_list = "exp_hosts=("
        for exp_node in exp_nodes:
            if exp_node in node_map:
                node_map[exp_node]['host'] = "%s.%s" % (node_map[exp_node]['host'],suffix)
                tmp_exp_node_list.append(exp_node + ":" + node_map[exp_node]['host'])
                host_list += " " +  node_map[exp_node]['host']
            else:
                print("Node {} not in node_map".format(exp_node))
        of.write("NODE_LIST=(")
        of.write(' '.join(tmp_exp_node_list))
        host_list += " )"
        of2.write(host_list)
        of.write(")\n")
    elif line.startswith("IRON_NODES"):
        #
        # The IRON_NODES line from the experiment configuration file
        # is changed as follows:
        #
        # - Generic nodeX is changed to "nodeX:fully qualified node
        #   name" for each node. The generic nodeX is utilized to
        #   construct the names of the UDP Proxy and Backpressure
        #   Forwarder configuration files to use at run-time and the
        #   fully qualified name is used to get to the machine to run
        #   the udp_proxy and bpf on.
        #
        print_debug("Generating fully qualified names for IRON_NODES...")
        tmp_iron_node_list = []
        iron_nodes = line.rsplit("=")[1].strip('()\n').split(" ")
        for n in iron_nodes:
            tmp_iron_node_list.append(n + ":" + node_map[n]['host'])
        of.write("IRON_NODES=(")
        of.write(' '.join(tmp_iron_node_list))
        of.write(")\n")
    elif line.startswith("PROXY_INBOUND_IFS"):
        #
        # The PROXY_INBOUND_IFS line from the experiment configuration
        # file is changed as follows:
        #
        # - Generic nodeX is changed to fully qualified node name
        # - Generic linkX is changed to interface name. This is
        #   determined by interacting with the node and is required
        #   because the interface names can change from reboot to
        #   reboot (especially on the DETER nodes).
        #
        print_debug("Determining proxy inbound interface names...")
        proxy_inbound_if_list = []
        proxy_inbound_ifs = line.rsplit("=")[1].strip('()\n').split(" ")
        for proxy_inbound_if in proxy_inbound_ifs:
            (node, link) = proxy_inbound_if.split(":")
            links = node_map[node]['links']
            link_values = links.split(",")
            for link_value in link_values:
                (link_id, ip_address) = link_value.split("=")
                if (link == link_id):
                    host = node_map[node]['host'].strip('\n')
                    cmd = ("ssh -oStrictHostKeyChecking=no -oLogLevel=quiet %s netstat -ie | "
                           "grep -B1 \"%s\" | head -n1 | awk '{print $1}'" %
                           (host, ip_address))
                    ps = subprocess.Popen(cmd, shell=True,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT)
                    intf = ps.communicate()[0].strip()
                    if intf == "" or "Connection closed" in intf:
                        print("inbound device interface not found for {}.".format(host))
                    else:
                        proxy_inbound_if_list.append("%s:%s" % (node, intf))
        of.write("PROXY_INBOUND_IFS=(")
        of.write(' '.join(proxy_inbound_if_list))
        of.write(")\n")
    elif line.startswith("MGEN_NODES"):
        #
        # The MGEN_NODES line from the experiment configuration file
        # is changed as follows:
        #
        # - Generic nodeX is changed to "nodeX:fully qualified node
        #   name" for each node. The generic nodeX is utilized to
        #   construct the mgen configuration file to use at run-time
        #   and the fully qualified name is used to get to the machine
        #   to run mgen on.
        #
        print_debug("Generating fully qualified names for MGEN_NODES...")
        tmp_mgen_node_list = []
        mgen_nodes = line.rsplit("=")[1].strip('()\n').split(" ")
        for n in mgen_nodes:
            tmp_mgen_node_list.append(n + ":" + node_map[n]['host'])
        of.write("MGEN_NODES=(")
        of.write(' '.join(tmp_mgen_node_list))
        of.write(")\n")
    elif line.startswith("LINKEM_NODES"):
        #
        # The LINKEM_NODES line from the experiment configuration file
        # is changed as follows:
        #
        # - Generic nodeX:nodeY:linkZ is changed to "nodeX:fully
        #   qualified node name for nodeX".
        # - A LINKEM_REF_ADDRS line is created with entries containing
        #   "nodeX:nodeY linkZ IP Address" for each node. The "nodeY
        #   linkZ IP Address" is the reference address for configuring
        #   the LinkEm running on nodeX.
        #
        print_debug("Generating fully qualified names for LINKEM_NODES...")
        tmp_linkem_node_list = []
        tmp_linkem_ref_addrs = []
        linkem_nodes = line.rsplit("=")[1].strip('()\n').split(" ")
        linkem_port=3450
        for n in linkem_nodes:
            linkem_port += 1
            (linkem_node, ref_addr_node, ref_addr_link) = n.split(":")
            ref_addr_node_links = node_map[ref_addr_node]['links']
            ref_addr_node_link_values = ref_addr_node_links.split(",")
            for ref_addr_node_link_value in ref_addr_node_link_values:
                (link_id, ip_address) = ref_addr_node_link_value.split("=")
                if (ref_addr_link == link_id):
                    try:
                        tmp_linkem_node_list.append(linkem_node + ":" +
                        node_map[linkem_node]['host'] + ":" + str(linkem_port) + ":" + ip_address)
                    except KeyError, e:
                        print("Error: %s.  Verify your configuration files."
                              % str(e))
                        exit(1)
        of.write("LINKEM_NODES=(")
        of.write(' '.join(tmp_linkem_node_list))
        of.write(")\n")
    elif line.startswith("PCAPS"):
        #
        # The PCAPS line from the experiment configuration file is
        # changed as follows:
        #
        # - Generic nodeX is changed to fully qualified node name
        # - Generic linkX is changed to interface name. This is
        #   determined by interacting with the node and is required
        #   because the interface names can change from reboot to
        #   reboot (especially on the DETER nodes).
        #
        print_debug("Determining tcpdump interface names...")
        pcap_cmd_list = []
        pcap_cmds = line.rsplit("=")[1].strip('()\n').split(" ")
        for pcap_cmd in pcap_cmds:
            (node, link) = pcap_cmd.split(":")
            try:
                links = node_map[node]['links']
            except KeyError, e:
                print("Error: %s.  Verify your configuration files." % str(e))
                exit(1)
            link_values = links.split(",")
            for link_value in link_values:
                (link_id, ip_address) = link_value.split("=")
                if (link == link_id):
                    cmd = ("ssh -oStrictHostKeyChecking=no -oLogLevel=quiet %s netstat -ie | grep -B1 \"%s\" | head -n1 | awk '{print $1}'" %
                           (node_map[node]['host'].strip('\n'), ip_address))
                    ps = subprocess.Popen(cmd, shell=True,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT)
                    intf = ps.communicate()[0].strip()
                    if not "Connection closed" in intf:
                        pcap_cmd_list.append("%s:%s:%s" % (node_map[node]['host'], intf, link))
        of.write("PCAPS=(")
        of.write(' '.join(pcap_cmd_list))
        of.write(")\n")
    elif line.startswith("DECAP"):
        #
        # The DECAP line from the experiment configuration file is
        # changed as follows:
        #
        # - Generic nodeX is changed to fully qualified node name
        #

        print_debug("Generating fully qualified names for decapsulating...")
        tmp_decap_list = []
        decap_list = line.rsplit("=")[1].strip('()\n').split(" ")
        for decap_cmd in decap_list:
            (node, link, app) = decap_cmd.split(":")
            tmp_decap_list.append(node_map[node]['host'] + ":" + link + ":" + app)
        of.write("DECAP=(")
        of.write(' '.join(tmp_decap_list))
        of.write(")\n")

    else:
        #
        # Preserve any comments in the original file.
        #
        of.write(line)
of.write("\n")

#
# Close the open files.
#
f.close()
of.close()
of2.close()

exit (0)
