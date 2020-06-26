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

This codebase provides:

---

1) Creation of persistent virtual interfaces (VIFs that remain accessible 
after the creating process completes)

The persistent vif creation tool is "addvif". Its usage syntax is:

addvif [device_name]

if the optional device_name argument is not supplied, the default 
device name "vif0" is used

---

2) Deletion of persistent virtual interfaces

The persistent vif deletion tool is "delvif". Its usage syntax is:

delvif [device_name]

if the optional device_name argument is not supplied, the default 
device name "vif0" is used

--- 

3) Example configuration file to be placed in /etc/sysconfig/network-scripts.
This configuration file shows how to set various parameters to be used in 
configuraing the VIF, and allows using the network control scripts "ifup" 
and "ifdown" in the same manner used with physical interfaces.

The example file name is "ifcfg-vif0". The actual name of the configuration 
file and the parameters contained within it must of course match the device 
name and parameters you want to use on your host conifguration. If you want 
to create a VIF named "foo" that has an IP address of 200.199.198.197, then 
copy the file ifcfg-vif0 to a new file named ifcfg-foo, edit the IPADDR 
and DEVICE values within the file to be "200.199.198.197" and "foo" 
respectively, then copy the file to /etc/sysconfig/network-scripts. Then all 
you need to do is issue the command

ifup foo

and you should be able to see an interface named foo with your assigned 
parameters using ifconfig

Alternatively, you can configure the VIF with ifconfig:

ifconfig device_name ip_address/prefix up

For example,

ifconfig vif0 172.24.200.1/24 up

---

4) In case you prefer a more local, personal approach to VIF configuration, 
two scripts are provided -- "vifup" and "vifdown" -- which alternately perform 
the VIF creation and parameter assignment directly. Use as you see fit.

--- 

5) A "dummy" receiver to read and discard packets sent to a given VIF by the
host as a result of the routing process (keeps the device queues from backing 
up). Use this on VIFs that may receive packets as part of the normal host 
forwarding operations, but for which no vreplay application (see #6 below) is 
directly attached and feeding data (vreplay takes care of read-n-discard 
operations for the VIF is is using)

This VIF read-n-discard application is "vrcvr". Its usage syntax is:

vrcvr [device_name]

if the optional device_name argument is not supplied, the default 
device name "vif0" is used

---

6) A VIF-based replay tool that takes a tcpdump file and sends it through a 
VIF into the host routing path. 

The VIF replay tool is named "vreplay". Its usage syntax is:

vreplay tcpdump_file [device_name]

if the optional device_name argument is not supplied, the default 
device name "vif0" is used

***Note that the replay tool takes care of the "vrcvr" function (see #5
above) for the interface it is using. Hence if there is only one VIF 
configured on a host and it is being used by vreplay to feed data into the 
kernel, you do not need to run the vrcvr application.***
