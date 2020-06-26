#!/bin/sh

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

# Parse the command line arguments.
if [ $# -ne 6 ]; then
    echo "Usage:  show_plots.sh <sc1> <ce1> <path1/bpf.log> <sc1> <ce1> <path1/bpf.log>"
    exit 1
fi

SC1=$1
CE1=$2
LOG1=$3

SC2=$4
CE2=$5
LOG2=$6

# Clean up any old data files.
/bin/rm -f node*_snd.txt node*_rcv.txt input_*.dat

# Generate the 1->2 plot.
grep "Conn ${CE1}:" ${LOG1} | grep "PLT_SND" > node1_snd.txt

grep -E "(Conn ${CE2}:.*PLT_RCV)|(SliqCat ${SC2}:.*PLT_OWD)" ${LOG2} > node2_rcv.txt

python process_delay.py node1_snd.txt node2_rcv.txt input_act_owd.dat

grep "PLT_SND" node1_snd.txt | awk '{print $1 " " $8 " " $9}' > input_hold.dat

grep "PLT_OWD" node2_rcv.txt | awk '{print $1 " " $7}' > input_est_owd.dat

echo "Showing results for 1->2"
gnuplot -persist plot_ttg.p

# Wait for the user to close gnuplot and press any key.
read -p "Close gnuplot and press any key..." ans

# Generate the 1->2 plot.
grep "Conn ${CE2}:" ${LOG2} | grep "PLT_SND" > node2_snd.txt

grep -E "(Conn ${CE1}:.*PLT_RCV)|(SliqCat ${SC1}:.*PLT_OWD)" ${LOG1} > node1_rcv.txt

python process_delay.py node2_snd.txt node1_rcv.txt input_act_owd.dat

grep "PLT_SND" node2_snd.txt | awk '{print $1 " " $8 " " $9}' > input_hold.dat

grep "PLT_OWD" node1_rcv.txt | awk '{print $1 " " $7}' > input_est_owd.dat

echo "Showing results for 2->1"
gnuplot -persist plot_ttg.p

# Wait for the user to close gnuplot and press any key.
read -p "Close gnuplot and press any key..." ans

# Clean up the data files.
/bin/rm -f node*_snd.txt node*_rcv.txt input_*.dat

exit 0
