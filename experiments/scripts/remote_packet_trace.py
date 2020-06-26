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

""" Script to trace a packet on a remote testbed """

from __future__ import print_function
import argparse
import os
import re
import sys
from subprocess import CalledProcessError

from iron.util.subprocess_compat import check_output


############################################
def get_experiment_info(deter, zfs_user):
    """ Parses files (on zfs) to get experiment name, user, and hosts

    Args:
        deter: True if we are gathering results from deter (False for local
            testbed.)
        zfs_user: username to use on zfs for a deter experiment. If none, ssh
            won't specify a user name.

    Return:
        Tuple (exp, user, host_list):
            exp: experiment name (e.g. 3-node-system)
            user: user name who ran the experiment
            host_list: list of hostnames for the testbed
    """
    if deter:
        staging = ''
    else:
        staging = '{}/'.format(os.path.expanduser('~'))
    command_str = "cat {}iron_exp_staging/current_exp.txt".format(staging)
    if deter:
        if zfs_user:
            zfs_user = '{}@'.format(zfs_user)
        else:
            zfs_user = ''
        command_str = 'ssh {}zfs.isi.deterlab.net "{}"'.format(
            zfs_user, command_str)
    try:
        exp = check_output(command_str, shell=True)
        exp = exp.strip()
        print('Searching pcaps from experiment {}'.format(exp))
    except CalledProcessError:
        print('Error executing: {} to get experiment name'.format(
            command_str))
        sys.exit()

    # Now get the list of hosts.
    command_str = "cat {}iron_exp_staging/{}/hosts.txt".format(staging, exp)
    if deter:
        command_str = 'ssh {}zfs.isi.deterlab.net "{}"'.format(
            zfs_user, command_str)
    try:
        hosts_lines = check_output(command_str, shell=True)
    except CalledProcessError:
        print('Error executing: {} to get hosts list'.format(command_str))
        sys.exit()
    hosts_lines = hosts_lines.splitlines()
    user = hosts_lines[0].split('=')[1].strip()
    hosts_list = hosts_lines[1].strip().split("=(")[1].split(")")[0].split()
    return exp, user, hosts_list

############################################
def search_pcaps_on_host(exp, user, host, remote_home, options, ipid, stage):
    """ Searches for the packet on the given host

    Args:
        exp: The experiment name
        user: The user name
        host: The hostname
        remote_home: The home directory on the host
        options: The options passed in by the user.
        ipid: The IPID to search for (may be different from the options if
            this is stage 3)
        stage: To be passed into the remote packet_trace script.

    Return:
        The name of the generated output file if we had valid results,
        or None if there were no results.
    """
    outfile = None
    print('***************')
    print('Searching pcaps on host {}'.format(host))
    command_str = ('python {home}/iron_exps/scripts/packet_trace.py '
                   '-s -d {home}/iron_exps/{exp} -n {host}').format(
                       home=remote_home, exp=exp, host=host)
    if options.binid is not None:
        command_str += ' -b {}'.format(options.binid)
    if options.pid is not None:
        command_str += ' -p {}'.format(options.pid)
    if ipid is not None:
        command_str += ' -i {}'.format(ipid)
    if options.verbose:
        command_str += ' -v'
    if options.logs:
        command_str += ' -l'
    if stage == 1 or stage == 3:
        command_str += ' -x {}'.format(stage)
    ssh_str = 'ssh {}@{} "{}"'.format(user, host, command_str)
    try:
        results = check_output(ssh_str, shell=True)
        # check whether we have valid results.
        match = re.search('IPID=([0-9]+)', results)
        if match:
            outfile = 'out-{}'.format(host)
            with open(outfile, "w") as result_file:
                result_file.write(results)
        print('***************')
        print('Ran command:\n{}'.format(ssh_str))
        print('Remote execution results:\n{}'.format(results))
    except IOError:
        print('Unable to open file {}.'.format(outfile))
    except CalledProcessError:
        print('Error executing: {}'.format(ssh_str))
    return outfile

############################################
def run_stage_2(ipid_file):
    """ Parses a result file to get the new IP ID

    Assumes we've already run phase 1 to get a single result. Parses that
    result to get an IPID to use for further remote searching by running
    packet_trace.py at stage 2.

    Args:
        ipid_file: the file to use to get the IPID
    Return:
        the IPID if one is found, or None. (If None, then we'll just keep
        searching by PID.)
    """
    print('***************')
    command_str = 'python packet_trace.py -x 2 {}'.format(ipid_file)
    print('Parsing results to get new filter with command:\n{}'.format(
        command_str))
    try:
        results = check_output(command_str, shell=True)
        print('Results:\n{}'.format(results))
        match = re.search('IPID=([0-9]+)', results)
        if match:
            return match.group(1)
    except CalledProcessError:
        print('Error executing: {}'.format(command_str))

############################################
def run_packet_trace(options):
    """ Searches pcap files and (if required) log files for the given packet.

    Args:
        options: The options passed in by the user.
    """
    ipid = options.ipid
    # First get the current experiment information from zfs.
    exp, user, hosts_list = get_experiment_info(options.deter, options.zfs_user)

    # Remotely run packet_trace.py to get the necessary results. This is done
    # in 4 phases.
    # Phase 1: Run packet_trace.py -x 1 remotely on each host name until we
    #     find the requested PID.
    # Phase 2: Parse the results of phase 1 to get the IP ID. (Done by running
    #     packet_trace.py -x 2 locally.)
    # Phase 3: Run packet_trace.py -x 3 remotely on each host, passing in the
    #     IP ID.
    # Phase 4: Run packet_trace.py -m locally to merge the results from
    #     Phase 3.
    outfiles = set()
    remote_home = '/home/{}'.format(user)
    if options.deter:
        remote_home = '/iron/{}'.format(user)
    stage = 0
    if options.pid is not None:
        stage = 1
    while stage < 4:
        for host in hosts_list:
            if stage == 1 and outfiles:
                # We've already found a result. No need to look at the rest
                # of the hosts.
                break
            outfile = search_pcaps_on_host(
                exp, user, host, remote_home, options, ipid, stage)
            if outfile:
                outfiles.add(outfile)
                if stage == 1:
                    # In stage 1, we want to stop after we have any
                    # results.
                    break
        if stage == 0 or stage == 3:
            # We're done. Go on to merging.
            stage = 4
        elif stage == 1:
            # Perform stage 2 outside the "for each host" loop, since this
            # command is run locally.
            if not outfiles:
                print('No results found for pid {}'.format(options.pid))
                sys.exit()
            # ok to pop the file, since we'll find it again in a later stage.
            ipid = run_stage_2(outfiles.pop())
            stage = 3

    print('***************')
    command_str = 'python packet_trace.py -m {}'.format(" ".join(outfiles))
    print('Merging results with command:\n{}'.format(command_str))
    try:
        results = check_output(command_str, shell=True)
        print(results)
    except CalledProcessError:
        print('Error executing: {}'.format(command_str))

############################################
def main():
    """ Parses argmuments and performs the requested operations. """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--pid', dest='pid', default=None,
                        help='specify IRON packet id to find. pid or ipid ' +
                        'is required')
    parser.add_argument('-b', '--binid', dest='binid', default=None,
                        help='specify IRON bin id to find. Ignored unless ' +
                        'pid is specified.')
    parser.add_argument('-i', '--ipid', dest='ipid', default=None,
                        help='specify IP packet ID to find. pid or ipid is ' +
                        'required. This is ignored if pid is specified.')
    parser.add_argument('-l', '--logs', dest='logs', default=False,
                        action="store_true",
                        help='whether or not to grep logs for the packet id. '
                        'Ignored unless pid is specified. If this option is '
                        'enabled, greps for log statements generated using '
                        'Packet::GetPacketMetadataString()')
    parser.add_argument('-v', '--verbose', dest='verbose', default=False,
                        action="store_true",
                        help='prints the entire pcap parse for each packet. '
                        'Verbose output will be stored in individual output '
                        'files from the remote machines, but will not be '
                        'merged.')
    parser.add_argument('-d', '--deter', dest='deter', default=False,
                        action="store_true",
                        help='Flag to indicate this was a deter test.')
    parser.add_argument('-u', '--zfsuser', dest='zfs_user', default=None,
                        help='Provide a username on zfs, if different from '
                        'local.')
    options = parser.parse_args()
    if options.pid is None and not options.ipid is None:
        parser.error(("Must specify one of -p (--pid) or -i (--ipid)"))
    if options.pid is not None and options.binid is not None:
        print('searching for binid {}, pid {}'.format(
            options.binid, options.pid))
    elif options.pid is not None:
        print('searching for pid {}'.format(options.pid))
    else:
        print('searching for IP ID {}'.format(options.ipid))

    run_packet_trace(options)

############################################
if __name__ == "__main__":
    main()
