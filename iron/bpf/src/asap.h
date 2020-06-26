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

///  \brief ASAP header file
///
/// This class contains the state and logic for implementing the ASAP
/// (Anti-Starvation with Artificial Packets) algorithm to counter starvation
/// of small flows.

#ifndef IRON_BPF_ASAP_H
#define IRON_BPF_ASAP_H

#include "bin_indexable_array.h"
#include "bin_map.h"
#include "itime.h"
#include "gradient.h"
#include "ordered_list.h"

#include <stdint.h>


namespace iron
{
  class BinQueueMgr;
  class Packet;
  class PacketPool;
  struct DequeuedInfo;

  /// \brief The ASAP class contains the state and logic for the ASAP algorithm.
  ///
  /// ASAP (Anti-Starvation with Artificial Packets) proactively adds zombies
  /// for a group,destination that is being starved due to insufficient
  /// packets entering the node.
  class ASAP
  {
  public:

    /// \brief Default constructor.
    ///
    /// \param  packet_pool  Pool containing packet to use.
    /// \param  bin_map      Mapping of IRON bins.
    /// \param  q_mgr        The queues ASAP acts on.
    /// \param  my_bin_index ASAP is managing queues for this bin.
    /// \param  node_bin_index ASAP is running on this node
    ASAP(PacketPool& packet_pool, BinMap& bin_map, BinQueueMgr& q_mgr,
         BinIndex my_bin_index, BinIndex node_bin_index);

    /// \brief Destructor.
    virtual ~ASAP();

    /// \brief Adjust the queue depths for anti-starvation.
    ///
    /// This will add zombies to the queue to account for packet
    /// delay, with the goal of preventing starvation by adding
    /// more and more zombies as the delay grows.
   void AdjustQueueValuesForAntiStarvation();

    /// \brief Updates internal state after a packet is dequeued.
    ///
    /// \param   dq_info    Information from the packet that was dequeued.
    void OnDequeue(const DequeuedInfo& dq_info);

    /// \brief Process a capacity update from the bpf
    ///
    /// \param pc_num The path controller number
    ///
    /// \param capacity_bps The current capacity estimate in bps
    void ProcessCapacityUpdate(uint32_t pc_num, double capacity_bps);

    /// \brief Update the zombie cap for this bin.
    ///
    /// \param new_cap  The updated cap on ASAP zombies for this bin.
    /// \param is_ls    True if this is for latency sensitive traffic.
    void SetASAPCap(uint32_t new_cap, bool is_ls);

    /// \brief Set up BinQueueMgr and log configuration information.
    ///
    /// \param  config_info The reference to the config info object used to
    ///                     initialize values.
    ///
    /// \return true if initialization succeeded.
    bool Initialize(const ConfigInfo& config_info);

  private:

    /// \brief Compute the amount of zombie bytes to add to the queue
    ///
    /// The total amount of zombies bytes to add is based on the amount
    /// of time the packet at the head of the queue has been at the head
    /// of the queue.  Specifically, the delay used is:
    /// min(time since last dequeue, time since enqueue of queue head).
    ///
    /// \param delay Time since enqueue of queue head
    /// \param isLS True if this is a latency sensitive bin, false otherwise
    ///
    /// \return The number of zombie bytes that should be added at this time
    uint32_t BytesToAddGivenDelay(Time delay, bool isLS) const;

    /// Pool containing packets to use.
    PacketPool&                       packet_pool_;

    // Mapping of IRON bins.
    BinMap&                           bin_map_;

    // The queue on which ASAP is acting.
    BinQueueMgr&                      q_mgr_;

    // The bin for which ASAP is managing queues. This could be a multicast
    // group or a unicast destination.
    BinIndex                          my_bin_index_;

    // The bin index for the node ASAP is running on
    BinIndex                          node_bin_index_;

    /// Track the amount of time in ms that appears to be unintentional
    /// delay in dequeuing packets.  This may arise from process swap out,
    /// IO (log files), etc.  This is not counted against the bin in
    /// starvation detection.  Indexed by Bin Index.
    /// MCAST TODO: consider whether this needs to be per bin. For unicast, we
    /// only use one value. If not, rename and update comments. If so, make it
    /// an array of the proper size.
    uint32_t                          sleep_time_by_bin_;

    /// The last time AddAntiStarvationZombies was called, used
    /// to compute possible sleep time.
    Time                              time_of_last_asap_call_;

    /// Track the amount of zombie bytes added per bin due to delay,
    /// for the packet that is currently at the head of the queue.
    /// This is used for the Anti-Starvation Zombies algorithm.
    /// Indexed by Bin Index.
    /// MCAST TODO: consider whether this needs to be per bin. For unicast, we
    /// only use one value. If so, array of the proper size. If not, update
    /// comments.
    uint32_t                          delay_bytes_added_;

    /// The maximum number of zombie bytes we'd need to add to overcome
    /// starvation for this bin. Once we add this number of bytes, this bin
    /// will have the maximum gradient and should be chosen next.
    uint32_t                          gradient_based_cap_;

    /// The maximum number of LS zombie bytes we'd need to add to overcome
    /// LS starvation for this bin. Once we add this number of bytes, this bin
    /// will have the maximum gradient and should be chosen next.
    uint32_t                          gradient_based_ls_cap_;

    /// The time of the last dequeue per bin.  This is used for the Anti-
    /// Starvation Zombies algorithm.
    /// MCAST TODO: consider whether this needs to be per bin. For unicast, we
    /// only use one value. If so, array of the proper size. If not, update
    /// comments.
    Time                              time_of_last_dequeue_;

    /// Current capacity of a path controller in bps, indexed by
    /// the path controller number
    uint64_t                          capacity_estimates_[kMaxPathCtrls];

    /// Average capacity over all bins in bps
    uint64_t                          average_capacity_;

    /// True once the initialization function has been called.
    bool                              initialized_;
  }; // end class ASAP

} // namespace iron

#endif  // IRON_BPF_ASAP_H
