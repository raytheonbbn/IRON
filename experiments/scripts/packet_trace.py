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


""" Script to trace a packet using wireshark and log files. """

from __future__ import print_function
import argparse
import os
import sys
import re
from datetime import datetime
from subprocess import check_output, CalledProcessError

import pyshark

############################################
class PacketInfo(object):
    """ Contains information parsed from a pyshark packet.

    Attributes:
        filepath: Which pcap file this came from (full path)
        node: Node name, parsed from file name
        link: Link name, parsed from file name
        pkt: The full pyshark packet object
        timestamp: sniff timestamp from pyshark, as a float
        str_ts: sniff timestamp from pyshark, as a string
        sniff_time: sniff time (formatted) from pyshark
        pid: the packet id
        binid: the bin id
        ipid: the IP id field from innermost IP header
        protocol: UDP or TCP, based on innermost header
        srcaddr: source IP address from innermost IP header
        srcport: source port from innermost transport layer header
        dstaddr: destination IP address from innermost IP header
        dstport: destination port from innermost transport layer header
        ttg: time to go from SLIQ latency info header
        ttg_valid: ttg valid field from SLIQ latency info header
        ws_filter: assembled wireshark filter to get potential instances of
                this packet
        time_diff: the difference between this timestamp and the previous
                timestamp in the list of sorted results.
    """
    ############################################
    def __init__(self, filepath, packet=None):
        """ Initializes variables (without parsing packet).

        This does set the time and timestamp based on values from the packet.

        Args:
            filepath: The full path to the pcap file where this packet was found.
            packet: The pyshark packet object. Used to fill in timestamps.
                If this is None (the default), then timestamps will remain
                as None until explicitly set.
          """
        self.filepath = filepath
        self.node = None
        self.link = None
        self.pkt = packet
        if packet:
            self.timestamp = float(packet.sniff_timestamp)
            self.str_ts = packet.sniff_timestamp
            self.sniff_time = packet.sniff_time
        else:
            self.timestamp = None
            self.str_ts = None
            self.sniff_time = None
        self.pid = None
        self.binid = None
        self.ipid = None
        self.protocol = None
        self.srcaddr = None
        self.srcport = None
        self.dstaddr = None
        self.dstport = None
        self.ttg = None
        self.ttg_valid = None
        self.ws_filter = None
        self.time_diff = None

    ############################################
    def __repr__(self):
        """ Returns a string representation of the PacketInfo

        Returns:
            A string representation of the PacketInfo
        """
        return '{filepath} at {ts}: bin={bin}, pid={pid}, ip id={ipid}'.format(
            filepath=self.filepath,
            ts=self.str_ts,
            bin=self.binid,
            pid=self.pid,
            ipid=self.ipid)

    ############################################
    def __eq__(self, other):
        """ Tests equivalence of PacketInfo objects

        Notional equivalence tries to ensure they are the same packet. Used
        to remove duplicates that we might get from merging to pcap parses of
        the same pcap.

        Args:
            other: The other instance to which we are comparing this instance.

        Returns:
            True if they match, False if they don't.
        """
        if isinstance(other, PacketInfo):
            # Note: this doesn't compare values that were automatically
            # computed within this class based on other values, since that
            # would just be added ineffiency. It also doesn't include
            # comparing the packet object, since we've already parsed out
            # all of the information we care about, and checking packet
            # equivalence on a pyshark packet is likely a big job.
            return ((self.filepath == other.filepath) and
                    (self.str_ts == other.str_ts) and
                    (self.binid == other.binid) and
                    (self.pid == other.pid) and
                    (self.protocol == other.protocol) and
                    (self.srcaddr == other.srcaddr) and
                    (self.dstaddr == other.dstaddr) and
                    (self.srcport == other.srcport) and
                    (self.dstport == other.dstport) and
                    (self.ipid == other.ipid) and
                    (self.ttg == other.ttg) and
                    (self.ttg_valid == other.ttg_valid))

        else:
            return False

    ############################################
    def __ne__(self, other):
        """ The opposite of __eq__

        Args:
            other: The other instance to which we are comparing this instance.

        Returns:
            False if they match, True if they don't.
        """
        return not self.__eq__(other)

    ############################################
    def __hash__(self):
        """ Generates a hash to be used when checking for duplicates.

        Returns:
            A has of the string representation of the PacketInfo
        """
        return hash(self.__repr__())

    ############################################
    def append_to_filter(self, to_append):
        """ Adds to_append to the internal pyshark filter

        Used to assemble the pyshark filter gradually while parsing the
        packet. This will handle adding the && when needed.

        Args:
            to_append: The new string representing the quality to append to
                the filter.
        """
        if self.ws_filter is None:
            self.ws_filter = ''
        else:
            self.ws_filter += ' && '
        self.ws_filter += to_append

    ############################################
    def print_info(self, timediff=True):
        """ Pretty prints the PacketInfo

        Args:
            timediff: True if this should print the time as a string and the
                time difference in ms. False to print just the timestamp (for
                instance, for raw unsorted results). Defaults to True.
        """
        print_time = self.sniff_time
        if not timediff:
            print_time = self.str_ts
        info = ('{node}/{link}: '
                '{time}: '
                '{proto}/{port:<6}: '
                'IPID={ipid:<6}: '
                'binid={binid:<4}: '
                'pid={pid:<8}: '
                'ttg={ttg}').format(
                    node=self.node, link=self.link,
                    time=print_time,
                    proto=self.protocol, port=self.srcport,
                    ipid=self.ipid,
                    binid=self.binid,
                    pid=self.pid,
                    ttg=self.ttg)
        if timediff:
            if self.time_diff is not None:
                print('{timediff:12.8} ms: {info}'.format(
                    timediff=self.time_diff, info=info))
            else:
                print('               : {}'.format(info))
        else:
            print(info)

    ############################################
    def print_verbose(self):
        """ Prints all of the packet information (including the packet) """
        print('filepath = {}'.format(self.filepath))
        print('node/link = {}/{}'.format(self.node, self.link))
        print('timestamp = {}'.format(self.str_ts))
        print('sniff_time = {}'.format(self.sniff_time))
        print('time diff from previous = {}'.format(self.time_diff))
        print('--------- packet --------------')
        print(self.pkt)

############################################
class LogInfo(object):
    """ Contains information parsed from a log message generated using
        Packet::GetPacketMetadataString.

    Attributes:
      node: Node name, parsed from file directory
      component: Component that generated the log, parsed from file name
      timestamp: timestamp from log message, as a float
      str_ts: timestamp from the log message, as a string
      log_msg: the contents of the log message, starting with log level
                 indicator
      line: the full grepped log line, including path/file
      time_diff: the difference between this timestamp and the previous
                 timestamp in the list of sorted results.
      time: timestamp formatted to match pyshark time
    """
    ############################################
    def __init__(self, node, component, timestamp, log_msg, line):
        """ Initializes variables

        Args:
            node: The node name where the log was found.
            component: The component the logged the message.
            timestamp: The timestamp (as a string) from the log message.
                       Will be converted to a float.
            log_msg: The message logged, starting with log level.
            line: The full line from the grep.
        """
        self.node = node
        self.component = component
        self.str_ts = timestamp
        self.timestamp = float(timestamp)
        self.log_msg = log_msg
        self.line = line
        self.time_diff = None
        self.time = datetime.fromtimestamp(self.timestamp).strftime(
            '%Y-%m-%d %H:%M:%S.%f')

    ############################################
    def print_info(self, timediff=True):
        """Pretty prints the LogInfo

        Args:
            timediff: True if this should print the time as a string and the
                time difference in ms. False to print just the timestamp (for
                instance, for raw unsorted results). Defaults to True.
        """
        print_time = self.time
        if not timediff:
            print_time = self.str_ts
        info = ('{node}/{component:<5}: '
                '{time}: '
                '{logmsg}').format(
                    node=self.node, component=self.component,
                    time=print_time,
                    logmsg=self.log_msg)
        if timediff:
            if self.time_diff is not None:
                print('{timediff:12.8} ms: {info}'.format(
                    timediff=self.time_diff, info=info))
            else:
                print('               : {}'.format(info))
        else:
            print(info)

############################################
def search_pcaps(test_dir, ws_filter, max_results=None):
    """ Uses the given wireshark filter to search all pcaps in test_dir

    Args:
        test_dir: The directory from which we want to search all pcaps
            (recursively)
        ws_filter: The wireshark filter to use for the search
        max_results: How many results to return, in case there are many?
            If 0 or None (the default), then this will return all results.

    Returns:
        A list of tuples of the form (filename, packet), where filename is
        the full path to the pcap file in which the packet was found, and
        packet is the pyshark packet object representing the pcap line.
    """
    num_results = 0
    found_enough = False
    packets = []
    for root, _, files in os.walk(test_dir):
        if found_enough:
            break
        if root.endswith("pcaps"):
            for pcap_file in files:
                if found_enough:
                    break
                filename = os.path.join(root, pcap_file)
                try:
                  cap = pyshark.FileCapture(filename, display_filter=ws_filter)
                  try:
                      while True:
                          pkt = cap.next()
                          num_results += 1
                          packets.append((filename, pkt))
                          # max_results = 0 is treated as unlimited.
                          if max_results and num_results >= max_results:
                              found_enough = True
                              break
                  except StopIteration:
                      pass
                except pyshark.capture.capture.TSharkCrashException as err:
                  print("Exception:", err)
                  pass
    return packets

############################################
def parse_packet((filepath, pkt), nodename=None):
    """ Generates a PacketInfo object from the given pyshark Packet

    This will gather IP and transport fields from the innermost headers, as
    as sliq fields of interest. Fields are gathered together into a PacketInfo
    object.

    Args:
        tuple (filepath, pkt):
            filepath: the full path to the pcap file where this packet was found.
                  This will be parsed to get the node and link names.
            pkt:  the tshark packet object.
        nodename:
            Used as the "node" in the PacketInfo object whenever the filename
            passed in doesn't include a node. Ignored if the filename does
            include a node. If None (the default) AND if the filename does
            not include a node, the node recorded in the packet will remain
            None.

    Returns:
        A PacketInfo object with the information parsed from the packet.
    """
    info = PacketInfo(filepath, pkt)
    match = re.search('(node[0-9]+).+(link[0-9]+)', filepath)
    if match:
        info.node = match.group(1)
        info.link = match.group(2)
    else:
        match = re.search('(link[0-9]+)', filepath)
        if match:
            info.node = nodename
            info.link = match.group(1)
    have_transport = False
    have_ip = False
    # search in reversed order so that we get the inner-most IP/UDP/TCP
    for layer in reversed(pkt.layers):
        if layer.layer_name == 'udp' and not have_transport:
            info.protocol = "UDP"
            info.srcport = layer.srcport
            info.dstport = layer.dstport
            info.append_to_filter(
                'udp.srcport=={} && udp.dstport=={}'.format(
                    info.srcport, info.dstport))
            have_transport = True
        elif layer.layer_name == 'tcp' and not have_transport:
            info.protocol = "TCP"
            info.srcport = layer.srcport
            info.dstport = layer.dstport
            info.append_to_filter(
                'tcp.srcport=={} && tcp.dstport=={}'.format(
                    info.srcport, info.dstport))
            have_transport = True
        elif layer.layer_name == 'ip' and not have_ip:
            info.srcaddr = layer.src
            info.dstaddr = layer.dst
            info.ipid = int(layer.id, 16)
            info.append_to_filter(
                'ip.src=={} && ip.dst=={} && ip.id=={}'.format(
                    info.srcaddr, info.dstaddr, info.ipid))
            have_ip = True
        elif layer.layer_name == 'sliq':
            try:
                info.pid = layer.pid
                info.binid = layer.bid
            except AttributeError:
                # all the sliq headers have layer name 'sliq', so we don't
                # know whether this was metadata or something else.
                pass
            try:
                # separate try, because ttg is in a different sliq header.
                ttg = layer.ttg
            except AttributeError:
                pass
            else:
                ttg = int(ttg)
                # interepret the field as a 2s complement signed integer
                if (ttg >> 31) > 0:
                    ttg = (-0x80000000 + (ttg & 0x7fffffff))
                info.ttg = ttg
                info.ttg_valid = layer.ttg_valid
    return info

############################################
def search_logs(test_dir, pid=None, nodename=None):
    """ Greps the logs in test_dir (recursively) to find the given packet id.

    This greps the logs and parses the results into LogInfo objects.

    Args:
        test_dir: The directory from which we want to grep all log files
                  (recursively)
        pid: The packet id to search for
        nodename: Used as the "node" in the LogInfo object whenever the
            test_dir passed in doesn't include a node. Ignored if the filename
            does include a node. If None (the default) AND if the filename
            does not include a node, the node recorded in the packet will
            remain None.

    Returns:
        A list of LogInfo objects representing the findings (may be empty)
    """
    if pid is None:
        return []
    log_results = []
    command_str = 'grep -r "PacketId: <{}>" {}'.format(pid, test_dir)
    try:
        grepped = check_output(command_str, shell=True)
    except CalledProcessError:
        pass # there may be no log message matches, and that's ok
    else:
        lines = grepped.splitlines()
        for line in lines:
            match = re.search(
                r'(node[0-9]+)/logs/(...).*\.log:([0-9]+\.[0-9]+) (.+)', line)
            if match:
                info = LogInfo(node=match.group(1),
                               component=match.group(2),
                               timestamp=match.group(3),
                               log_msg=match.group(4),
                               line=line)
                log_results.append(info)
            else:
                match = re.search(
                    r'logs/(...).*\.log:([0-9]+\.[0-9]+) (.+)', line)
                if match:
                    info = LogInfo(node=nodename,
                                   component=match.group(1),
                                   timestamp=match.group(2),
                                   log_msg=match.group(3),
                                   line=line)
                    log_results.append(info)
    return log_results

def parse_results(results_file):
    """ Parses the results from the given file

    This is used to read and merge previously-generated results.
    This function parses a single file consisting of the output
    from running this program. It assumes the output was
    generated with the skipsort (-s) option. It parses the results
    into a list of PacketInfo objects and a list of LogInfo objects.

    Args:
        results_file: file from which to read results.

    Return:
        A 2-tuple: (pkt_info_list, log_info_list), where pkt_info_list is
        a list of the PacketInfo objects from the file, and log_info_list
        is a list of the LogInfo objects from the file.
    """
    pkt_info_list = []
    log_info_list = []
    try:
        with open(results_file) as file_ptr:
            results = file_ptr.readlines()
    except IOError as ioe:
        print('Unable to open file {}. Error {}: {}'.format(
            results_file, ioe.errno, ioe.strerror))
        return pkt_info_list, log_info_list
    results = [line.strip() for line in results]
    pcap_matcher = re.compile((r'([\w\.]+)/(link[0-9]+).*?'
                               r'([0-9]+\.[0-9]+).*?'
                               r'(\w+)/([0-9]+).*?'
                               r'IPID=([0-9]+).*?'
                               r'binid=([0-9]+|None).*?'
                               r'pid=([0-9]+|None).*?'
                               r'ttg=([0-9]+|None)'))
    log_matcher = re.compile((r'([\w\.]+)/(\w+).*?'
                              r'([0-9]+\.[0-9]+).*?'
                              r'(.*)'))
    for line in results:
        match = pcap_matcher.match(line)
        if match:
            pkt = PacketInfo(results_file)
            pkt.node = match.group(1)
            pkt.link = match.group(2)
            pkt.str_ts = match.group(3)
            pkt.timestamp = float(pkt.str_ts)
            pkt.sniff_time = datetime.fromtimestamp(
                pkt.timestamp).strftime(
                    '%Y-%m-%d %H:%M:%S.%f')
            pkt.protocol = match.group(4)
            pkt.srcport = match.group(5)
            pkt.ipid = match.group(6)
            pkt.binid = match.group(7)
            pkt.pid = match.group(8)
            pkt.ttg = match.group(9)
            pkt_info_list.append(pkt)
        else:
            match = log_matcher.match(line)
            if match:
                node = match.group(1)
                component = match.group(2)
                str_ts = match.group(3)
                log_msg = match.group(4)
                log_info_list.append(
                    LogInfo(node, component, str_ts, log_msg, line))

    return pkt_info_list, log_info_list

############################################
def difftime_and_print(to_print, label):
    """ Compute the line to line time diffs and print results

    Args:
        to_print: list of PacketInfo and LogInfo objects
        label: String to print as part of the pre-print separator
    """
    prev_time = None
    for info in to_print:
        if prev_time:
            info.time_diff = (info.timestamp - prev_time) * 1000
        prev_time = info.timestamp
    print('\n------------------- {} -----------------------'.format(label))
    for info in to_print:
        if info.time_diff > 1000:
            # just print a hint that this may be an IP id rollover.
            print('--------------------------------------------------')
        info.print_info()

############################################
def merge(file_list):
    """ Merge results from the files in file_list

    Each file should contain the results of running this script with
    the -s option. This will parse the files, merge the results and
    sort by timestamp, compute time diffs, and pretty print the
    results.

    Args:
        file_list: A list of filenames to merge.
    """
    pkt_info = []
    log_info = []
    for filename in file_list:
        pkt_info_list, log_info_list = parse_results(filename)
        pkt_info += pkt_info_list
        log_info += log_info_list
    print_results(True, pkt_info, log_info)

############################################
def parse_for_ipid(filename):
    """ Reads one result from the given file and uses it to search by ipid

    This is called when running packet_trace.py as part of
    remote_packet_trace.py. This is "stage 2" - where we read the results from
    a single finding of the PID and use these results to get the IPID to
    search for on all test nodes.

    Args:
        filename: A list containing a single result by PID
    """
    pkt_info_list = parse_results(filename)[0]
    if pkt_info_list:
        pkt_info = pkt_info_list[0]
        if pkt_info.ipid is None:
            print('No Results')
        else:
            print('IPID={}'.format(pkt_info.ipid))
    else:
        print('No Results')

############################################
def find_one_by_pid(pid, binid, test_dir, nodename, print_and_exit):
    """ Find at most one packet by PID (and binid, if specified)

    This sets up the wireshark filter, calls search_pcaps, checks the
    results (exits if there aren't any), and returns the one result.

    Args:
        pid: The packet id to find (must be non-None)
        binid: The bin id to find (if None, will search just by PID)
        test_dir: Directory containing the pcap files to search
        nodename: Name of the node to be used when running remotely when
            test_dir doesn't contain the node name.
        print_and_exit: If true, this will just print the one result and
            then sys.exit. If false, this will return the resulting
            PacketInfo.

    Return:
        PacketInfo representing the one result. If there is no result,
        this calls sys.exit() since we cannot continue.
    """
    ws_filter = 'sliq.pid && sliq.pid == {}'.format(pid)
    if binid is not None:
        ws_filter += ' && sliq.bid == {}'.format(binid)
    packets = search_pcaps(test_dir, ws_filter, max_results=1)

    if not packets:
        print('binid {}, pid {} not found.'.format(binid, pid))
        sys.exit()

    info = parse_packet(packets[0], nodename)
    if not info.ws_filter:
        print('Unable to parse packet.')
        sys.exit()
    if print_and_exit:
        info.print_info(timediff=False)
        sys.exit()
    return info

############################################
def print_results(sort, packet_info_list, log_info_list):
    """ Prints the given info list

    Args:
        sort: If True, the list is sorted before printing and time diffs
            are included in the output
        packet_info_list: The PacketInfo objects to print
        log_info_list: The LogInfo objects to print
    """
    if sort:
        info_list = []
        if packet_info_list:
            info_list = sorted(packet_info_list,
                               key=lambda info: info.timestamp)
            difftime_and_print(info_list, "PCAP")
        if log_info_list:
            info_list = sorted(info_list + log_info_list,
                               key=lambda info: info.timestamp)
            difftime_and_print(info_list, "PCAP AND LOG")
    else:
        if packet_info_list:
            for info in packet_info_list:
                info.print_info(timediff=False)
        if log_info_list:
            for info in log_info_list:
                info.print_info(timediff=False)

############################################
def perform_trace(test_dir,
                  binid=None,
                  pid=None,
                  ipid=None,
                  verbose=False,
                  parse_logs=False,
                  sort=True,
                  stage=0,
                  nodename=None):
    """ Searches pcap files and (if required) log files for the given packet.

    This function does the following steps when run normally (not via
    remote_packet_trace.py).
    1. If PID is specified, runs pyshark on pcaps under test_dir to get one
       matching packet. Uses this to get a filter that will work on non-IRON
       packets as well as IRON packets.
    2. If PID is not specified, instead of generating a filter, this will
       just filter on IP ID.
    3. Uses the computed filter to get all packet matches in pcap files under
       test_dir. Parses these into a list of PacketInfo objects.
    4. Sorts the results by time and pretty prints them.
    5. If parse_logs is true and a pid was specified, parses all log files
       under test_dir to look for lines matching the string generated by
       Packet::GetPacketMetadataString.
       Parses these into LogInfo objects, combines with the list of PacketInfo
       objects, sorts, and pretty prints.
    6. If verbose is true, prints all of the details of all pcap results.

    If using the extra parameters from remote_packet_trace.py, this may stop
    after step 1 ("stage 1" from remote_packet_trace), so that the IP ID can
    be passed around to all remote nodes to re-run the next step. Stage 3
    then starts where step 1 left off.

    Args:
        test_dir: Where we want to get the pcaps and logs to search.
        binid: If binid and pid are specified, we will only look for packets
            that match this binid as well as matching the given pid. If this
            is None (the default), then we will match only on PID (if
            specified) or IP ID. If no PID is specified, this is ignored.
        pid: The packet id we want to match. (May be None, the deault, to
            match on ip id instead, but pid OR ipid must be specified).
        ipid: The IP ID to match. If pid is specified, ipid will not be used.
            None is the default. IP ID or PID MUST be specified.
        verbose: True to print all information from pcap matches. Defaults
            to False.
        parse_logs: True to parse log files in addition to searching pcaps.
            Defaults to False.
        sort: If True (the default), this will merge and sort the results
            before printing. If False, this just prints all PCAP results
            followed by all LOG results (unsorted)
        stage: If 1, only runs until a single result by PID is found. If 3,
            only runs the search by IPID (ignoring the PID argument except for
            pruning results). If 0 (the default), does both.
        nodename: If this is passed in, this name is used whenever we have a
            pcap or log file that doesn't include a node name in the file
            path. If None (the default), and if file names don't incldue
            node names, then the node names will remain "None" in the output.
    """

    ws_filter = 'ip.id=={}'.format(ipid)
    if pid is not None and (stage != 3):
        info = find_one_by_pid(pid, binid, test_dir, nodename, (stage == 1))
        ws_filter = info.ws_filter
        ipid = info.ipid

    print('wireshark filter: {}'.format(ws_filter))

    packet_info = set()
    for pcap_pkt in search_pcaps(test_dir, ws_filter):
        pkt = parse_packet(pcap_pkt, nodename)
        if (int(pkt.ipid) == int(ipid) and
                (pid is None or pkt.pid is None or int(pkt.pid) == int(pid))):
            packet_info.add(pkt)

    log_results = None
    if pid is not None and parse_logs:
        log_results = search_logs(test_dir, pid, nodename)
    print_results(sort,
                  list(packet_info),
                  log_results)

    if verbose:
        for info in sorted(packet_info, key=lambda pi: pi.timestamp):
            print('\n----------------- VERBOSE PCAP ------------------------')
            info.print_verbose()

def find_test_dir():
    """ Reads last_run_experiment.txt to get the experiment directory.

    Return:
        The path to the test directory. If this fails, calls sys.exit().
    """
    try:
        last_run_file = os.path.join(os.path.expanduser('~'),
                                     "iron_results",
                                     "last_run_experiment.txt")
        with open(last_run_file, "r") as file_stream:
            return file_stream.read().strip()
    except IOError:
        print('Failed to read {}. Use -d to indicate test results '
              'directory'.format(last_run_file))
        sys.exit()

############################################
def main():
    """ Parses argmuments and performs the requested operations. """
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--binid', dest='binid', default=None,
                        help='specify IRON bin id to find. Ignored unless ' +
                        'pid is specified.')
    parser.add_argument('-d', '--testdir', dest='testdir', default=None,
                        help='specify the test directory. Default is the ' +
                        'value in ~/iron_results/last_run_experiment.txt')
    parser.add_argument('-i', '--ipid', dest='ipid', default=None,
                        help='specify IP packet ID to find. pid or ipid is ' +
                        'required. This is ignored if pid is specified.')
    parser.add_argument('-l', '--logs', dest='logs', default=False,
                        action="store_true",
                        help='whether or not to grep logs for the packet id. '
                        'Ignored unless pid is specified. If this option is '
                        'enabled, greps for log statements generated using '
                        'Packet::GetPacketMetadataString()')
    parser.add_argument('-p', '--pid', dest='pid', default=None,
                        help='specify IRON packet id to find. pid or ipid ' +
                        'is required')
    parser.add_argument('-v', '--verbose', dest='verbose', default=False,
                        action="store_true",
                        help='prints the entire pcap parse for each packet')

    group = parser.add_argument_group("Remote Tracing Options",
                                      "This script can be called from "
                                      "remote_packet_trace.py to trace "
                                      "packets right on the test machines "
                                      "instead of locally. These should not "
                                      "be necessary when running manually.")
    group.add_argument('-m', '--merge', dest='merge', default=False,
                       action="store_true",
                       help='Ignore other parameters. Instead, merge the '
                       'list of files presented after the optional '
                       'arguments.')
    group.add_argument('-n', '--nodename', dest='nodename', default=None,
                       help='specify the name of the node where the script '
                       'is running. Should be used only from '
                       'remote_packet_trace.')
    group.add_argument('-s', '--skipsort', dest='skip_sort', default=False,
                       action="store_true",
                       help='If true, skip sorting results, merging log '
                       'results into pcap results, and computing time diffs.'
                       ' Helpful for running remotely and merging after the '
                       'fact.')
    group.add_argument('-x', '--stage', dest='stage', default=0, type=int,
                       choices=[0, 1, 2, 3],
                       help='When -x 1, if there is a -p option then this '
                       'script will find at most one result based on the PID. '
                       'When -x 2, this also requires an argument specifying '
                       'the file containing the results from the previous '
                       '-x 1 run. All other arguments are ignored for -x 2. '
                       'When -x 3, this will not search for the given -p PID. '
                       'It will search only by IPID, and use the PID only to '
                       'prune the results.')
    group.add_argument('files', metavar='FILE', nargs='*',
                       help='When using -x 2, specify one file which will be '
                       'parsed to get the IP ID. When using -m, specify any '
                       'number of files to be merged. These are ignored '
                       'unless stage is 2 or merge is enabled.')

    parser.add_argument_group(group)
    options = parser.parse_args()
    if (options.pid is None
            and options.ipid is None
            and not options.merge
            and options.stage != 2):
        parser.error(("Must specify one of -p (--pid) or -i (--ipid)."))
    if options.merge:
        if not options.files:
            parser.error(("Must specify at least one filename to be merged."))
            sys.exit()
        merge(options.files)
        sys.exit()

    if options.stage == 2:
        if not options.files:
            parser.error(("Must specify a filename to parse to get the "
                          "IPID when stage is 2."))
            sys.exit()
        parse_for_ipid(options.files[0])
        sys.exit()

    if not options.testdir:
        options.testdir = find_test_dir()

    if not options.skip_sort:
        if options.pid is not None and options.binid is not None:
            print(
                'searching for binid {}, pid {} in test dir = {}'.format(
                    options.binid, options.pid, options.testdir))
        elif options.pid is not None:
            print('searching for pid {} in test dir = {}'.format(
                options.pid, options.testdir))
        else:
            print('searching for IP ID {} in test dir = {}'.format(
                options.ipid, options.testdir))

    perform_trace(test_dir=options.testdir,
                  binid=options.binid,
                  pid=options.pid,
                  ipid=options.ipid,
                  verbose=options.verbose,
                  parse_logs=options.logs,
                  sort=not options.skip_sort,
                  stage=options.stage,
                  nodename=options.nodename)

############################################
if __name__ == "__main__":
    main()
