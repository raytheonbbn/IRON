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
Script to listen on a specified interface for IGMPv3 packets
and determine if the host is joining/leaving multicast groups.
These changes are then reported to IRON. 

usage: sudo python sniff_igmp.py iface amp_addr
"""

from scapy.all import sniff,IP
from scapy.contrib.igmpv3 import IGMPv3,IGMPv3mr,IGMPv3gr
import sys
import os

amp_addr = ""
mcast_exclude = ["224.0.0.2", "224.0.0.13", "224.0.0.22"]

def pkt_callback(pkt):
#    pkt.show() # debug statement
    if pkt.haslayer(IP):
      ip = pkt.getlayer(IP)
    else:
      return

    if pkt.haslayer(IGMPv3):
      igmp = pkt.getlayer(IGMPv3)
    else:
      return

    if pkt.haslayer(IGMPv3mr):
      mem_rpt = pkt.getlayer(IGMPv3mr)
#      print "num grps: " + str(mem_rpt.numgrp)
    else:
      return

#    print mem_rpt.records

    for record in mem_rpt.records:
      if record.haslayer(IGMPv3gr):
        grp_rpt = record.getlayer(IGMPv3gr)
#        print "Report type: %d" % (grp_rpt.rtype)
        if grp_rpt.rtype == 4:
          print "%s Joined group: %s\n" % (ip.src, grp_rpt.maddr)
          cmd = "/home/iron/iron_exps/bin/gmu join %s %s" % (grp_rpt.maddr, amp_addr)
          print cmd
          os.system(cmd)

        elif grp_rpt.rtype == 3:
          print "%s Leave group: %s\n" % (ip.src, grp_rpt.maddr)
          cmd = "/home/iron/iron_exps/bin/gmu leave %s %s" % (grp_rpt.maddr, amp_addr)
          print cmd
          os.system(cmd)

        elif (grp_rpt.rtype == 2) and (grp_rpt.maddr not in mcast_exclude):
          print "%s report group: %s\n" % (ip.src, grp_rpt.maddr)
          cmd = "/home/iron/iron_exps/bin/gmu join %s %s" % (grp_rpt.maddr, amp_addr)
          print cmd
          os.system(cmd)



def main():
    if len(sys.argv) != 3:
        print("Must specify interface name and amp address.\n")
        print("Usage: sudo python sniff_igmp.py iface_name amp_addr\n")
        exit(1)

    iface_name = sys.argv[1]
    global amp_addr
    amp_addr = sys.argv[2]
    sniff(iface=iface_name, prn=pkt_callback, filter="igmp", store=0)

if __name__ == "__main__":
    main()


