#!/usr/bin/env bash
#
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


# Create the experiment disk on the remote execution node. This script
# expects 1 command line argument, the user name.

# The script's name for error messages.
this="${0##*/}"

# Make sure we have the correct number of command line arguments.
if [ "$#" -ne 1 ]; then
    echo "Usage:"
    echo "  ${this} user_name"
    exit 1
fi

GROUP=edg-iron
BASE=/iron
USER=$1

# Make sure that the /iron directory exists.
if [ ! -e ${BASE} ]; then
    sudo mkdir ${BASE} &> /dev/null
fi

# Mount /dev/sda4 to /iron, if necessary.
if [ "`grep /dev/sda4 /proc/mounts`" == "" ]; then
    echo "Creating experiment disk on ${HOSTNAME}..."
    sudo mkfs.ext4 /dev/sda4 &> /dev/null
    sudo mount /dev/sda4 ${BASE}
fi

# Create the user directory in /iron, if necessary.
if [ ! -e ${BASE}/${USER} ]; then
    echo "Creating ${BASE}/${USER} directory on ${HOSTNAME}..."
    sudo mkdir ${BASE}/${USER} &> /dev/null
    sudo chown ${USER}:${GROUP} ${BASE}/${USER} &> /dev/null
fi

# Also, make sure that the zfs dir is mounted. This will create
# /zfs/iron on all experiment nodes.
if [ "`grep /zfs/edgect /proc/mounts`" == "" ]; then
    echo "Mounting /zfs/edgect on ${HOSTNAME}..."
    sudo mkdir /zfs &> /dev/null
    sudo mount zfs:/zfs/edgect /zfs &> /dev/null
fi

# Exit script successfully.
exit 0
