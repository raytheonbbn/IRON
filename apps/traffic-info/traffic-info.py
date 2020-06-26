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

from __future__ import print_function, division
import argparse
import csv
from collections import namedtuple, defaultdict
from math import floor
import socket
import sys
from time import time
from threading import Thread, Event

import matplotlib
import pcapy
from six.moves import queue
from six.moves import tkinter as tk

from iron.gui.plot import Plot, CurveUpdate, AutoScaleY, ScrollSupport
from iron.gui.tk_util import ttk

matplotlib.use('TkAgg', warn=True)

# pcap reader settings
PACKET_MAX_CAPTURE_LEN = 1024
PACKET_PROMISCUOUS_READ = False
PACKET_READ_TIMEOUT_MS = 1000

MICRO_SECONDS_PER_SEC = 1000000

MAX_DISPLAY_KBITS = 15000
BYTES_PER_KBYTE = 1024

DEFAULT_TITLE = "IRON"

FilterQueue = namedtuple("FilterQueue", ["name", "iface", "filter", "queue"])
PacketData = namedtuple("PacketData", ["read_time", "len"])

TOTAL_NAME = "Total Throughput"
# Colors
TOTAL_COLOR = '#000000'  # black
COLORS = ['#ff0000',  # red
          '#00ff00',  # green
          '#0000ff',  # blue
          '#ff9933',  # orange
          '#9966cc',  # purple
          '#999999',  # grey
          '#ff66ff']  # pink

_START_TIME = time()


def _to_relative(timestamp):
    return timestamp - _START_TIME


def packet_time_to_relative(packet_timestamp):
    return _to_relative(packet_timestamp[0] +
                        packet_timestamp[1]/MICRO_SECONDS_PER_SEC)


def _now():
    return _to_relative(time())


def bytes_to_kbits(value):
    return value / BYTES_PER_KBYTE * 8


def kbits_to_bytes(value):
    return value * BYTES_PER_KBYTE / 8


class PcapReader(object):
    def __init__(self, iface, data_queue, pcap_filter=None):
        self._data_queue = data_queue
        self._reader = pcapy.open_live(iface, PACKET_MAX_CAPTURE_LEN,
                                       PACKET_PROMISCUOUS_READ,
                                       PACKET_READ_TIMEOUT_MS)
        if pcap_filter is not None:
            self._reader.setfilter(pcap_filter)
        self._stopped = Event()

    def stop(self):
        self._stopped.set()

    def read_packets(self):
        while not self._stopped.is_set():
            try:
                header, _ = self._reader.next()
                if header is None:
                    continue
                timestamp = packet_time_to_relative(header.getts())
                self._data_queue.put(PacketData(timestamp, header.getlen()))
            except socket.timeout:
                # There wasn't a packet that could be read. Since we don't care
                # about what the packets are or when they show up, try again.
                pass


class TrafficViz(object):
    """
    The traffic stats visualizer.
    """
    NO_SEC = -1

    def __init__(self, root, title, filter_queues, init_scroll_slider_width,
                 plot_total, y_lim, debug=False):
        self._root = root
        self._title = title
        self._filter_queues = filter_queues
        self._in = {}
        self._debug = debug
        self._refresh_ms = 100
        self._graph_hist_secs = 60
        self._prev_bytes = {}
        self._latest_plotted_sec = 0
        self._plot_total = plot_total

        self._create_widgets(init_scroll_slider_width, y_lim)

    def _create_widgets(self, init_scroll_slider_width, y_lim):
        """
        Create the various layout widgets for this UDP GUI frame.
        """
        self._root.title(self._title)

        # Use the 'default' theme.
        self._style = ttk.Style()
        self._style.theme_use('default')

        title = 'Traffic Rates Over the Last {}s'.format(self._graph_hist_secs)
        self._plot = Plot(self._root, title=title,
                          x_label='Time (s)', y_label='Throughput (kbits)',
                          max_display=self._graph_hist_secs, legend=True,
                          legend_position="upper left",
                          font_size=40,tick_font_size=40,
                          auto_scale_y=AutoScaleY(0, y_lim),
                          scroll=True,
                          init_scroll_slider_width=init_scroll_slider_width)

        # initial values
        x_data = [0]
        y_data = [0]
        # add curve to be total of all named curves
        if self._plot_total:
            self._plot.add_curve(TOTAL_NAME, x_data, y_data,
                                 color=TOTAL_COLOR)
        for f_queue, color in zip(self._filter_queues, COLORS):
            self._plot.add_curve(f_queue.name, x_data, y_data, color=color)

    def _update_ui(self):
        """
        Update the UI with values form the queues
        """
        # Read all of the received messages.  Loop until all of the queues
        # are empty.

        # mapping of seconds to mappings of filter names to total bytes.
        # defaultdict allows for setting the initial value on first access
        filter_bytes_read = defaultdict(lambda: defaultdict(int))

        update_plot = False
        largest_sec = TrafficViz.NO_SEC
        while True:
            break_flag = True

            for f_queue in self._filter_queues:
                try:
                    value = f_queue.queue.get_nowait()
                    update_plot = True
                    sec = floor(value.read_time)
                    largest_sec = max(largest_sec, sec)
                    filter_bytes = filter_bytes_read[sec]
                    filter_bytes[f_queue.name] += value.len
                    break_flag = False
                except queue.Empty:
                    pass

            if break_flag:
                break

        # inject 0 values if no data has been plotted for this second
        now = floor(_now())
        if (largest_sec == TrafficViz.NO_SEC and
                self._latest_plotted_sec < now):
            update_plot = True
            for f_queue in self._filter_queues:
                filter_bytes_read[now][f_queue.name] = 0
            largest_sec = now

        if update_plot:
            self._latest_plotted_sec = largest_sec
            self._plot_bytes(filter_bytes_read)

        self._schedule_update_ui()

    def _plot_bytes(self, filter_bytes_read):
        """
        Update the plot with new data that has been read.

        filter_bytes_read: Mapping of seconds to mappings of filter names to
        total bytes.
        """
        total_update = CurveUpdate([], [])
        updates = {q.name: CurveUpdate([], []) for q in self._filter_queues}
        for second in sorted(filter_bytes_read):
            total_bytes = 0
            for f_queue in self._filter_queues:
                name = f_queue.name
                bytes_read = filter_bytes_read[second].get(name, 0)

                # Get the previously plotted value incase all of the packets
                # for a given second were not read in one pass
                plotted_value = self._plot.get_y_value(name, second, default=0)
                # Because of the conversion to a  decimal number and back, there
                # may be rounding errors. Since this is used for a scrolling
                # display, not real data analysis, this should not be an issue.
                plotted_bytes = kbits_to_bytes(plotted_value)

                total_filter_bytes = bytes_read + plotted_bytes

                updates[name].x_data.append(second)
                updates[name].y_data.append(bytes_to_kbits(total_filter_bytes))

                total_bytes += total_filter_bytes

            total_update.x_data.append(second)
            total_update.y_data.append(bytes_to_kbits(total_bytes))
        if self._plot_total:
            updates[TOTAL_NAME] = total_update
        self._plot.update_all(updates, replace=True)

    def _schedule_update_ui(self):
        self._root.after(self._refresh_ms, self._update_ui)

    def run(self):
        """
        Run the application. This method will not return.
        """
        self._schedule_update_ui()
        self._root.mainloop()


def from_file(filter_file):
    reader = csv.reader(filter_file)
    filter_queues = []
    pcap_readers = []

    for i, row in enumerate(reader):
        try:
            name, iface, pcap_filter = row
        except ValueError:
            print("Line {} does not have 3 values".format(i + 1))
            sys.exit(1)

        f_queue = FilterQueue(name, iface, pcap_filter, queue.Queue())
        filter_queues.append(f_queue)
        pcap_readers.append(PcapReader(iface, f_queue.queue, pcap_filter))

    if len(filter_queues) > len(COLORS):
        print("More than {} filters is not supported".format(len(COLORS)))
        sys.exit(2)

    return filter_queues, pcap_readers


def from_args(filters):
    if len(filters) > len(COLORS):
        print("More than {} filters is not supported".format(len(COLORS)))
        sys.exit(2)

    filter_queues = []
    pcap_readers = []
    for name, iface, pcap_filter in filters:
        f_queue = FilterQueue(name, iface, pcap_filter, queue.Queue())
        filter_queues.append(f_queue)
        pcap_readers.append(PcapReader(iface, f_queue.queue, pcap_filter))
    return filter_queues, pcap_readers


def main():
    """
    Main function for the IRON demonstration statistics visualization tool.
    """
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--filter', dest='filters', action="append",
                       default=[], nargs=3, metavar=("NAME", "IFACE", "FILTER"),
                       help='Identifier name for the data being filtered,'
                            ' followed by the network interface to listen on,'
                            ' followed by pcap filter itself')
    group.add_argument('-ff', '--filter-file', dest='filter_file', default=None,
                       metavar="FILTER_FILE", type=argparse.FileType("rb"),
                       help='CSV file containing one filter per line. Each '
                            'line has the format of: NAME", IFACE, FILTER')

    parser.add_argument("--title-prefix", default=DEFAULT_TITLE,
                        help="Text prepended to title displayed in UI.")
    parser.add_argument('-g', '--geometry', dest='geometry', default=None,
                        help='the size and position of the window as '
                             'WIDTHxHEIGHT+XOFF+YOFF, see X(7)', metavar='GEOM')
    parser.add_argument('-t', '--test', action='store_true',
                        dest='test_mode_flag',
                        default=False,
                        help='allow test mode')
    parser.add_argument('-d', '--debug', action='store_true', dest='debug_flag',
                        default=False, help='enable debug logging')
    parser.add_argument('-s', '--plot-total', action='store_true', dest='plot_total',
                        default=False, help='plot the total of all flows specified')
    parser.add_argument('-y', '--y-lim', dest='y_lim',
                        default=MAX_DISPLAY_KBITS, type=int, help='The maximum value on the Y-axis to plot')

    args = parser.parse_args()

    if args.filter_file is None:
        filter_queues, pcap_readers = from_args(args.filters)
    else:
        with args.filter_file:
            filter_queues, pcap_readers = from_file(args.filter_file)

    # Create the GUI.
    root = tk.Tk()
    # Set any specified window geometry.
    if args.geometry is not None:
        try:
            root.geometry(args.geometry)
        except tk.TclError:
            print('Invalid geometry specification: ' + args.geometry)
            sys.exit(2)

    traffic_viz = TrafficViz(root, args.title_prefix + ' Traffic Throughput',
                             filter_queues,
                             ScrollSupport.slider_width(args.geometry),
                             args.plot_total,
                             args.y_lim,
                             args.debug_flag)

    # Start all pcap reader
    for reader in pcap_readers:
        Thread(target=reader.read_packets).start()

    # Enter the GUI main processing loop. Only returns when the GUI closes.
    traffic_viz.run()

    # Stop all pcap reader
    print("Shutting down")
    for reader in pcap_readers:
        reader.stop()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("keyboard")
        sys.exit(0)
