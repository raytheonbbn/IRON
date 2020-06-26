// IRON: iron_headers
/*
 * Distribution A
 *
 * Approved for Public Release, Distribution Unlimited
 *
 * EdgeCT (IRON) Software Contract No.: HR0011-15-C-0097
 * DCOMP (GNAT)  Software Contract No.: HR0011-17-C-0050
 * Copyright (c) 2015-20 Raytheon BBN Technologies Corp.
 *
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contracts No. HR0011-15-C-0097 and
 * HR0011-17-C-0050. Any opinions, findings and conclusions or
 * recommendations expressed in this material are those of the author(s)
 * and do not necessarily reflect the views of the Defense Advanced
 * Research Project Agency.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/* IRON: end */

#ifndef IRON_BPF_PATH_CONTROLLER_INFO_H
#define IRON_BPF_PATH_CONTROLLER_INFO_H

#include "itime.h"
#include "flow_stats.h"
#include "timer.h"


namespace iron
{
  class PathController;

  /// Path controller information structure.
  struct PathCtrlInfo
  {
    PathCtrlInfo()
        : path_ctrl(NULL), in_timer_callback(false), timer_handle(),
          bucket_depth_bits(0.0), link_capacity_bps(0.0),
          last_qlam_tx_time(), last_capacity_update_time(), pdd_mean_sec(0.0),
          pdd_variance_secsq(0.0), pdd_std_dev_sec(0.0), flow_stats()
    {}

    virtual ~PathCtrlInfo()
    {}

    /// The path controller pointer.
    PathController*      path_ctrl;

    /// A flag recording if currently in the QLAM timer callback.
    bool                 in_timer_callback;

    /// The QLAM timer handle.
    iron::Timer::Handle  timer_handle;

    /// Token bucket depth, in bits, for sending QLAM packets.
    double               bucket_depth_bits;

    /// The usable link capacity deduced from the path controller.
    double               link_capacity_bps;

    /// Time when the last QLAM was sent on this path controller.
    iron::Time           last_qlam_tx_time;

    /// Time when the path controller last updated its capacity.
    iron::Time           last_capacity_update_time;

    /// The low-latency packet delivery delay (PDD) mean in seconds.
    double               pdd_mean_sec;

    /// The low-latency packet delivery delay (PDD) variance in seconds
    /// squared.
    double               pdd_variance_secsq;

    /// The low-latency packet delivery delay (PDD) standard deviation in
    /// seconds.
    double               pdd_std_dev_sec;

    /// Accumulates flow statistics.
    FlowStats            flow_stats;

  }; // end struct PathCtrlInfo

} // namespace iron

#endif // IRON_BPF_PATH_CONTROLLER_INFO_H
