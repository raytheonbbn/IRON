
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

#ifndef IRON_BPF_NPLB_BIN_QUEUE_MGR_H
#define IRON_BPF_NPLB_BIN_QUEUE_MGR_H

/// \file nplb_bin_queue_mgr.h

#include "bin_indexable_array.h"
#include "bin_queue_mgr.h"

namespace iron
{
  /// \brief NPLBBinQueueMgr class to implement the No Packet Left Behind
  ///        algorithm for avoiding starvation.
  ///
  class NPLBBinQueueMgr : public BinQueueMgr
  {
    public:

    ///
    /// \brief Constructor.
    ///
    /// \param  bin_idx      Bin index of the unicast destination or mcast group.
    /// \param  packet_pool  Pool containing packet to use.
    /// \param  bin_map      Mapping of IRON bins.
    NPLBBinQueueMgr(BinIndex bin_idx, PacketPool& packet_pool, BinMap& bin_map);

    ///
    /// \brief Destructor.
    ///
    virtual ~NPLBBinQueueMgr();

    /// \brief Set up NPLBBinQueueMgr and log configuration information.
    ///
    /// \param  config_info   The reference to the config info object used to
    ///                       initialize values.
    /// \param  node_bin_idx  The node's bin index.
    ///
    /// \return true if initialization succeeded.
    virtual bool Initialize(const ConfigInfo& config_info,
                            BinIndex node_bin_idx);

    ///
    /// \brief  Get the logical queue depths to be used for BPF decision
    ///         making, in bytes. In this case, the depths + delay term.
    /// Memory ownership is transferred to the calling object.  However, that
    /// object shall NOT destroy / free the returned QueueDepth object.  It is
    /// however free to modify it by adding and removing elements to it.
    ///
    /// \return The pointer to the queue depths object for the modified depth
    /// + delay.
    ///
    virtual QueueDepths* GetQueueDepthsForBpf();

    ///
    /// \brief  Get the logical queue depths to be used for QLAMs to neighbors.
    ///         In this case, the depths + delay term.
    /// Memory ownership is transferred to the calling object.  However, that
    /// object shall NOT destroy / free the returned QueueDepth object.  It is
    /// however free to modify it by adding and removing elements to it.
    ///
    /// \return The pointer to the queue depths object to be used in QLAM.
    ///
    virtual QueueDepths* GetDepthsForBpfQlam();

    ///
    /// \brief  Get the single queue depth for this bin to be shared with the
    /// proxies for admission control.
    ///
    /// \return The value to be passed to the proxies for admission control.
    ///
    virtual uint32_t GetQueueDepthForProxies();

    protected:

    /// \brief Performs any necessary cleanup and logging after a dequeue.
    ///
    /// This function is useful because we have several dequeue functions that
    /// all need the same follow-on work after successfully finding a packet,
    /// and because subclasses have algorithm-specific actions after a
    /// dequeue.
    ///
    /// \param   dq_info    Information about the packet (or bytes) that was
    ///                     dequeued.
    /// \param   cloned     True if the "dequeue" was a packet clone, leaving
    ///                     the original packet behind in the queue to send to
    ///                     other destinations. False if we removed the entire
    ///                     packet.
    virtual void OnDequeue(const DequeuedInfo& dq_info, bool cloned);

    private:

    ///
    /// Disallow the copy constructor.
    ///
    NPLBBinQueueMgr(const NPLBBinQueueMgr& other);

    ///
    /// Disallow the copy operator.
    ///
    NPLBBinQueueMgr& operator= (const NPLBBinQueueMgr& other);

    /// Figures out whether and how many zombies to add for long queue delays.
    ///
    /// The bin_id MUST be valid.
    ///
    /// \param   bin_idx  The index for the bin from which we just
    ///                   dequeued a packet. The stickiness for this bin may
    ///                   be affected. Must be a valid bin index.
    /// \param   dequeued_pkt_recv_time   What time was the newly-dequeued
    ///                   packet received? The stickiness is based on the
    ///                   difference between how long this packet sat in the
    ///                   queue and how long the following packet sat in the
    ///                   queue so far.
    void IncrementDelayStickiness(
      BinIndex bin_idx, Time dequeued_pkt_recv_time);

    /// \brief Adjusts the queue depths to include a NPLB delay term.
    ///
    /// \return The bin-indexed QueueDepths array containing the
    ///         backpressure local values to be used when computing
    ///         gradients. The same values will be distributed via QLAMs so
    ///         that neighbors can accurately compute gradients.  This
    ///         is shared with the proxies for admission control.
    QueueDepths* ComputeNPLB();

    /// The backpressure gradient queue-delay weight.
    ///
    /// This is how much weight to place on the queue-delay term in the
    /// backpressure gradients. This will be equally weighted to the queue
    /// depth term when set to [drain-rate / 1x10^6], since the delay term
    /// reflects how long a packet has been sitting first in the queue in
    /// micro seconds, and the queue depths are in bytes.
    double                            delay_weight_;

    /// This is parameter d_{max} in the paper "No Packet Left Behind". (In
    /// usec rather than time slots, since we are essentially using a usec as
    /// a time slot). If the difference between the queue delay on the first
    /// packet dequeued and the first packet remaining in the queue is greater
    /// than this value, then zombies will be added so that later packets will
    /// sit in the queue for less time. Increasing this means we get less
    /// stickiness, so higher latency for packets facing potential
    /// starvation. Decreasing this will decrease latency for these
    /// packets at the expense of latency for packets for more heavily
    /// utilized bins.
    Time                              delay_stickiness_threshold_;

    /// Used for storing NPLB queue depths adjusted with delay terms.
    /// This QueueDepths object is adjusted and then returned by the dynamic
    /// ComputeNPLB function. If that function is not called when accessing
    /// queue depths (for any purpose), these values are not used.
    QueueDepths                       nplb_values_;

    /// Pointers to classes for adding to the ongoing xplot graphs of queue
    /// depths and delay terms, one for each destination bin. May be NULL.
    BinIndexableArray<GenXplot*>      nplb_xplot_;
  };      // End NPLBBinQueueMgr
}         // End namespace.
#endif    // IRON_BPF_NPLB_BIN_QUEUE_MGR_H
