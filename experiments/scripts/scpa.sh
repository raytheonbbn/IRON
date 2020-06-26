#!/bin/bash

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


if [ "$#" -lt 4 ]; then 
    echo "usage: scpa.sh [-12346BCpqrv] [-c cipher] [-F ssh_config] [-i identity_file]"
    echo "[-l limit] [-o ssh_option] [-P port] [-S program]"
    echo "[[user@]host1:]file1 ... [[user@]host2:]file2 deadline priority AMP_addr"
    exit 1
fi

# The AMP address is the last argument passed in.
AMP_ADDR="${@: -1}"
echo $AMP_ADDR

# Remove the address from the argument list before calling scp.
set -- "${@:1:$#-1}"

# The priority is now the last argument in the list.
PRIORITY="${@: -1}"
echo "priority is $PRIORITY"

# Remove the priority from the argument list before calling scp.
set -- "${@:1:$#-1}"

# The deadline is now the last argument in the list.
DEADLINE="${@: -1}"
echo "deadline is $DEADLINE"

# Remove the deadline from the argument list before calling scp.
set -- "${@:1:$#-1}"


echo "$@"
# Get the file size.
FILENAME=$(echo "${@:(-2):1}" | awk -F':' '{print $(NF)}')
FILESIZE=$(stat -c%s "$FILENAME")
echo "size is $FILESIZE"

# Start the transfer in a detached screen so it will continue
# after this script ends.
screen -Dm scp "$@" &
sleep 1
pid=$!

echo "Pid is $pid"
SCPPID=`pgrep -P $pid`
SSHPID=`pgrep -P $SCPPID`
echo "SSHPID is $SSHPID"

sleep 1
LSTR=$(sudo lsof -aPi -p $SSHPID 2>/dev/null)
echo "LSTR is $LSTR"
TUPLE=$(echo $LSTR | awk -F' ' '{print $(NF-1)}')
echo $TUPLE

SNAME=$(echo $TUPLE | awk -F'->' '{print $(1)}' | awk -F':' '{print $(1)}')
SADDR=$(getent hosts $SNAME | awk '{ print $1 }')
if [ -z "$SADDR" ]; then
  SADDR=$SNAME
fi
SPORT=$(echo $TUPLE | awk -F'->' '{print $(1)}' | awk -F':' '{print $(2)}')
DNAME=$(echo $TUPLE | awk -F'->' '{print $(2)}' | awk -F':' '{print $(1)}')
DADDR=$(getent hosts $DNAME | awk '{ print $1 }')
if [ -z "$DADDR" ]; then
  DADDR=$DNAME
fi
DPORT=$(echo $TUPLE | awk -F'->' '{print $(2)}' | awk -F':' '{print $(2)}')
echo "$SADDR:$SPORT -> $DADDR:$DPORT"
sleep 2
echo "$SADDR:$SPORT $DADDR:$DPORT $FILESIZE $DEADLINE $AMP_ADDR $PRIORITY"
echo `../bin/ftc $SADDR:$SPORT $DADDR:$DPORT $FILESIZE $DEADLINE $AMP_ADDR $PRIORITY`

