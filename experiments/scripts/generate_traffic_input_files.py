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
# Generate an mgen input file. The inputs to this script include the
# location of the txt file that captures the characteristics of the
# desired UDP flows. The format of the input data for a src is:
#
#  protocol src dest src_port dst_port start_time end_time packet_size data_rate
#
# The protocol can be: udp, tcp or video.
# The source and destination are the generic node names.
#
# Usage: generate_traffic_input_files.py experiment_name testbed_topo_file
#  e.g. generate_traffic_input_files.py 3-node-system example_testbed.cfg
#
# This script is called by configure.sh to set up experiments.
#

from sys import argv
from sys import exit
from decimal import *
from os.path import exists
from glob import glob
from os import remove
from random import random,uniform
from socket import inet_aton
import subprocess
import sys

exp_dir = argv[1]
tb_file = argv[2]
flow_id = {}
node_map = {}
intf_map = {}
used_ports = {}
video_id = 0
suffix = ""

# Define the maximum amount of accomodated latency, in seconds.
# Receivers will wait this many seconds after the senders finish.
# This time is on top of start_skew.
max_latency = 10

# Short flows have a hard-coded lifetime.
short_length = 2

def abort(error_msg):
    # Remove any existing mgen, gst input files
    files = glob(exp_dir + '/cfgs/mgen_input*')
    for fl in files:
        remove(fl)

    files = glob(exp_dir + '/cfgs/gst_input*')
    for fl in files:
        remove(fl)

    print "ERROR: %s" % error_msg
    exit(1)

# Build node_map from testbed
try:
    with open(tb_file) as f:
        lines = f.readlines()
except IOError:
    abort('Unable to open testbed file: %s' %tb_file)

# Remove any existing mgen, gst input files
files = glob(exp_dir + '/cfgs/mgen_input*')
for fl in files:
    remove(fl)

files = glob(exp_dir + '/cfgs/gst_input*')
for fl in files:
    remove(fl)

for line in lines:
    # Ignore empty or comment lines.
    if len(line.strip()) == 0 or line.lstrip()[0] == '#':
        continue

    elif line.startswith("suffix"):
        suffix = line.split(" ")[1].strip()

    elif line.startswith("node"):
        (key, value) = line.split(" ", 1)
        (host, links) = value.strip().split(" ")
        link_values = links.split(",")
        (link_id, ip_address) = link_values[0].split("=")
        node_map[key] = {'host' : host, 'ip' : ip_address}


#
# Open the traffic input file.
#
if not exists(exp_dir + '/cfgs/traffic.cfg'):
    abort("Filename " + exp_dir + "/cfgs/traffic.cfg does not exist")

f = open(exp_dir + '/cfgs/traffic.cfg', 'r')

file_no = 0
for line in f.readlines():

    #
    # Skip comments and blank lines.
    #

    if not line.startswith("#") and not line == "\n":
        #
        #  traffic directives have the following format:
        #
        #  For tcp/udp/video:
        #  protocol src dest num_flows src_port dst_port start_time end_time packet_size data_rate
        #  Where the parameters are defined as follows:
        #  protocol - "tcp" or "udp" or "video" (with no quotation marks).
        #  src      - The generic name of the source node (e.g. node0).
        #  dest     - The generic name of the destination node (e.g. node1).
        #  num_flows- The number of flows with this specification.
        #  src_port - The source port for the flow. If num_flows > 1,
        #             then the source port is incremented for each flow.
        #  dst_port - The destination port for the flow. If num_flows > 1,
        #             then the source port is incremented for each flow.
        #  start_time - The start time for the flow.
        #  end_time   - The end time for the flow.
        #  packet_size - The size of data packets.
        #  data_rate   - The average rate for sourcing data.
        #
        #  For mcast:
        #  protocol node group num_flows src_port dst_port start_time end_time packet_size data_rate
        #  Where the parameters are defined as follows:
        #  protocol - "mcast" (with no quotation marks).
        #  src      - The generic name of the node which can be a receiver, sender or both
        #             (e.g. node0).
        #  dest     - The multicast group address, e.g. 224.10.20.30.
        #  num_flows- The number of flows with this specification.
        #  src_port - The source port for the flow. If num_flows > 1,
        #             then the source port is incremented for each flow.
        #  dst_port - The destination port for the flow. If num_flows > 1,
        #             then the source port is incremented for each flow.
        #  start_time - The start time for the flow.
        #  end_time   - The end time for the flow.
        #  packet_size - The size of data packets.
        #  data_rate   - The average rate for sourcing data. If the rate is 0, then the node
        #                is only a receiver.
        #  Note: application nodes will automatically join the group at the start of a flow and
        #  leave the multicast group after the duration of the flow.
        #
        #  For short_tcp:
        #  protocol src dest num_flows lo_port hi_port start_time end_time flow_size_bytes interflow_duration
        #
        #  A "short_tcp" flow is a series of short tcp flows. The port numbers
        #  chosen the lo_port and hi_port interval. For these flows, the source
        #  port is always set to the destination port. If there are not enough
        #  ports in the range, then script will fail and return an error. Each
        #  flow will run for the duration, or time taken the transmit 3KB of
        #  data, whichever comes first.
        #
        #  The parameters are defined as follows:
        #  protocol   - "short_tcp" (with no quotation marks).
        #  src        - The generic name of the source node (e.g. node0).
        #  dest       - The generic name of the destination node (e.g. node1).
        #  num_flows  - The number of flows with this specification.
        #  lo_port    - The lower bound for source port number for this flow.
        #  hi_port    - The upper bound for source port number for this flow.
        #  start_time - The start time for the series of short flows.
        #  end_time   - The end time for the series of short flows.
        #  flow_size_bytes - The amount of data, in bytes, that should be transferred in
        #               a single short flow.
        #  interflow_duration - The average time between successive short
        #               flows. This is randomly incremented or decremented by
        #               up to 10%.
        #
        #  For filetransfer:
        #  protocol src dest num_flows src_port dst_port start_time end_time flow_size_bytes hard_deadline
        #
        #  A 'filetransfer' is a single TCP flow that will deliver a specified maximum
        #  number of bytes. If there is a hard deadline, the flow will terminate after
        #  this much time, even if the specified number of bytes are not sent.
        #
        #  The parameters are defined as follows:
        #  protocol   - "filetransfer" (with no quotation marks).
        #  src        - The generic name of the source node (e.g. node0).
        #  dest       - The generic name of the destination node (e.g. node1).
        #  num_flows  - The number of flows with this specification.
        #  src_port   - The lower bound for source port number for this flow.
        #  dst_port   - The destination port for the flow. If num_flows > 1,
        #               then the source port is incremented for each flow.
        #  start_time - The start time for the filetransfer.
        #  end_time   - The end time for the filetransfer.
        #  flow_size_bytes - The amount of data, in bytes, that should be transferred in
        #               a single filetransfer.
        #  hard_deadline - If this is set to '1', the flow will terminate after end_time,
        #               if the filetransfer is not yet complete.
        #
        values = line.split(" ")

        if len(values) < 2:
            abort("Incorrect number of values provided for mgen src: %s" % line)

        if len(values) != 10:
            abort("Incorrect number of values provided for mgen src: %s" % line)

        protocol    = values[0]
        source      = values[1]
        destination = values[2]
        num_flows   = int(values[3])
        start_time  = values[6]
        end_time    = values[7]
        mapped_dest = ""
        mapped_src  = ""
        if ((protocol == "udp") or (protocol == "tcp") or (protocol == "video") or
            (protocol == "mcast")):
            dst_port    = int(values[4])
            src_port    = int(values[5])
            packet_size = values[8]
            data_rate   = values[9].strip('\n')
            multiplier = 0
            if (data_rate.find("Kbps") != -1):
                multiplier = 1e3
                mgen_data_rate = float(data_rate[:data_rate.rfind("Kbps")])
                pps = round(Decimal(mgen_data_rate * 1000) / 8 / int(packet_size), 2)
            elif (data_rate.find("Mbps") != -1):
                multiplier = 1e6
                mgen_data_rate = float(data_rate[:data_rate.rfind("Mbps")])
                pps = mgen_data_rate * 1000000 / 8 / int(packet_size)
            elif (data_rate.find("Gbps") != -1):
                multiplier = 1e9
                mgen_data_rate = float(data_rate[:data_rate.rfind("Gbps")])
                pps = mgen_data_rate * 1000000000 / 8 / int(packet_size)
            elif data_rate.find("bps") != -1:
                multiplier = 1
                mgen_data_rate = float(data_rate[:data_rate.rfind("bps")])
            else:
                f.close()
                abort("Data rate unit improperly set, aborting")
            mgen_data_rate *= multiplier
            pps = round(mgen_data_rate / (8. * int(packet_size)), 2)

        elif (protocol == "short_tcp"):
            lo_port     = int(values[4])
            hi_port     = int(values[5])
            flow_size_bytes = int(values[8])
            interflow_duration = int(values[9].strip("\n"))
        elif (protocol == "filetransfer"):
            src_port    = int(values[4])
            dst_port    = int(values[5])
            flow_size_bytes = int(values[8])
            hard_deadline = int(values[9].strip("\n"))
        else:
            f.close()
            abort("Unsupported protocol: %s" % protocol)

        # validate/expand the destination node
        if protocol != "mcast":
            if destination not in node_map:
                try:
                    (destination, destination_ip) = destination.strip().split(":")
                    inet_aton(destination_ip)
                    mapped_dest = destination_ip
                except:
                    f.close()
                    abort("Invalid destination: %s" % destination)
            else:
                mapped_dest = node_map[destination]['ip']

        # validate/expand the source node
        if source not in node_map:
            f.close()
            abort("Invalid source: %s" % source)
        else:
            mapped_src = node_map[source]['ip']
 
        if destination not in used_ports:
            used_ports[destination] = []
            used_ports[source] = []

        if protocol == 'video':
          src_gst = open(exp_dir + "/cfgs/gst_input_" + source + ".cfg", 'a')
          dst_gst = open(exp_dir + "/cfgs/gst_input_" + destination +
                         ".cfg", 'a')
           # Check that multiple flows do not have the same destination port
          for flow in range(0, num_flows):
              if dst_port in used_ports[destination]:
                  src_gst.close()
                  dst_gst.close()
                  f.close()
                  abort("Error: port %d used twice on dest %s" %
                                     (dst_port, destination))
              else:
                  used_ports[destination].append(dst_port)

              src_gst.write('screen -d -m -L gst-launch-1.0 -v filesrc ' +
                  ' location=~/videos/NEW.ts ! decodebin ! x264enc ' +
                  ' bitrate=%d ! rtph264pay  ! udpsink host=%s port=%s\n' % (
                   mgen_data_rate/1000, mapped_dest, dst_port))
              dst_gst.write('screen -d -m -L gst-launch-1.0 -e -v' +
                   ' udpsrc port=' + str(src_port) +' caps = "application/x-rtp,' +
                   ' media=(string)video, clock-rate=(int)90000,' +
                   ' encoding-name=(string)H264,' + ' payload=(int)96" !' +
                   ' rtpjitterbuffer ! rtph264depay ! h264parse ! mp4mux !' +
                   ' filesink ' + 'location=/tmp/vid-%d-recvd.mp4\n' % (video_id))

              video_id += 1
              dst_port += 2
          src_gst.close()
          dst_gst.close()
          continue

        # We get here if its not a video flow
        src_mgn = open(exp_dir + "/cfgs/mgen_input_" + source + "_" +
                       str(file_no) + ".mgn", 'w')
        file_no = file_no + 1
        if (protocol != "mcast"):
            dst_mgn = open(exp_dir + "/cfgs/mgen_input_" + destination + "_" +
                           str(file_no) + ".mgn", 'w')
            file_no = file_no + 1

        if source not in flow_id:
            flow_id[source] = 1

        if protocol == 'short_tcp':
            port = lo_port
            for flow in range(0, num_flows):
                time = float(start_time) + float(interflow_duration*uniform(1.0, 1.25))
                while (time < float(end_time)):
                    while (port in used_ports[source]) or (port in used_ports[destination]):
                        port += 1
                    if port > hi_port:
                        src_mgn.close()
                        dst_mgn.close()
                        f.close()
                        abort("Insufficient number of ports")
                    src_mgn.write("%s ON %s tcp dst %s/%d src %d PERIODIC [1000 %s] COUNT 1\n" % (
                    str(time), flow_id[source], mapped_dest,
                    port, port, flow_size_bytes))
                    dst_start_time = 0
                    dst_stop_time = time + short_length + max_latency
                    dst_mgn.write("%s listen tcp %s\n" % (dst_start_time, port))
                    src_mgn.write("%s OFF %s\n" % (time+short_length, flow_id[source]))
                    dst_mgn.write("%s ignore tcp %s\n" % (dst_stop_time, port))
                    flow_id[source] += 1
                    time += interflow_duration*uniform(0.90, 1.10)
                    port += 1
            continue

        if protocol == 'filetransfer':
            flow_cnt = 0
            for flow in range(0, num_flows):
                # Currently, there is a hard coded constant that ensures
                # that there is an mgen process for each flow.
                if (flow_cnt >= 1):
                    src_mgn.close()
                    dst_mgn.close()
                    src_mgn = open(exp_dir + "/cfgs/mgen_input_" + source + "_" +
                                   str(file_no) + ".mgn", 'w')
                    file_no = file_no + 1
                    dst_mgn = open(exp_dir + "/cfgs/mgen_input_" + destination +
                                   "_" + str(file_no) + ".mgn", 'w')
                    file_no = file_no + 1

                # Check that multiple flows do not have the same destination port
                if dst_port in used_ports[destination]:
                    f.close()
                    abort("Error: port %d used twice on dest %s" %
                          (dst_port, destination))
                else:
                    used_ports[destination].append(dst_port)

                flow_start_time = float(start_time)
                src_mgn.write("%s ON %s tcp dst %s/%d src %d PERIODIC [1000 %s] COUNT 1\n" % (
                str(flow_start_time), flow_id[source], mapped_dest,
                dst_port, src_port, flow_size_bytes))
                dst_start_time = 0
                dst_stop_time = float(end_time) + max_latency
                dst_mgn.write("%s listen tcp %s\n" % (dst_start_time, dst_port))
                if hard_deadline == 1:
                    src_mgn.write("%s OFF %s\n" % (end_time, flow_id[source]))
                    dst_mgn.write("%s ignore tcp %s\n" % (dst_stop_time, dst_port))
                dst_port += 1
                src_port += 1
                flow_id[source] += 1
                flow_cnt += 1
            continue


        # It's either a TCP or UDP flow.
        flow_cnt = 0
        for flow in range(0, num_flows):
            # Currently, there is a hard coded constant that ensures
            # that there is an mgen process for each flow.
            if (flow_cnt >= 1):
                src_mgn.close()
                if protocol != "mcast":
                    dst_mgn.close()
                src_mgn = open(exp_dir + "/cfgs/mgen_input_" + source + "_" +
                               str(file_no) + ".mgn", 'w')
                file_no = file_no + 1
                if protocol != "mcast":
                    dst_mgn = open(exp_dir + "/cfgs/mgen_input_" + destination +
                                   "_" + str(file_no) + ".mgn", 'w')
                    file_no = file_no + 1
                flow_cnt = 0

            # Check that multiple flows do not have the same destination port
            if (dst_port in used_ports[destination]) and (protocol != "mcast"):
                f.close()
                abort("Error: port %d used twice on dest %s" %
                      (dst_port, destination))
            else:
                used_ports[destination].append(dst_port)

            flow_start_time = float(start_time)
            if pps > 0:
                flow_start_time = float(start_time)+random()/pps
            dst_start_time = 0
            dst_stop_time = float(end_time) + max_latency

            if protocol == "mcast":
                # Get the interface to be used by multicast traffic.
                # Look in the cache first
                if source not in intf_map:
                    cmd = ("ssh -oStrictHostKeyChecking=no -oLogLevel=quiet %s.%s netstat -ie | "
                           "grep -B1 \"%s\" | head -n1 | awk '{print $1}'" %
                           (node_map[source]['host'].strip('\n'), suffix,  mapped_src))
                    ps = subprocess.Popen(cmd, shell=True,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT)
                    intf = ps.communicate()[0].strip()
                    if intf == "" or "Connection closed" in intf:
                        abort("Unable to find suitable interface for multicast traffic")
                    intf_map[source] = {'intf' : intf}
                else:
                    intf = intf_map[source]['intf']
                    
                # print ("Multicast interface is: %s\n" % intf)

                if (pps == 0):
                    src_mgn.write("%s JOIN %s INTERFACE %s\n" % (flow_start_time, destination, intf))
                    src_mgn.write("%s LISTEN UDP %s\n" % (flow_start_time, dst_port))
                if (pps > 0):
                    src_mgn.write("%s on %s udp dst %s/%d SRC %d JITTER [%s %s 0.1] INTERFACE %s TTL 10\n" % (
                        flow_start_time, flow_id[source],
                        destination, dst_port, src_port, pps, (int(packet_size)-28), intf))
                    src_mgn.write("%s off %s\n" % (end_time, flow_id[source]))
                if (pps == 0):
                    src_mgn.write("%s ignore udp %s\n" % (dst_stop_time, dst_port))
                    src_mgn.write("%s LEAVE %s INTERFACE %s\n" % (dst_stop_time, destination, intf))
            else:
                src_mgn.write("%s on %s %s dst %s/%d src %d JITTER [%s %s 0.1]\n" % (
                    flow_start_time, flow_id[source], protocol,
                    mapped_dest, dst_port, src_port, pps, (int(packet_size)-28)))
                dst_mgn.write("%s listen %s %s\n" % (dst_start_time,
                                                     protocol, dst_port))
                dst_mgn.write("%s ignore %s %s\n" % (dst_stop_time, protocol, dst_port))
                src_mgn.write("%s off %s\n" % (end_time, flow_id[source]))


            dst_port += 1
            src_port += 1
            flow_id[source] += 1
            flow_cnt += 1
        if (protocol != "mcast"):
            dst_mgn.close()
        src_mgn.close()

#
# Close the input file.
#
f.close()
