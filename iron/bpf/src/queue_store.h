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

#ifndef IRON_BPF_QUEUE_STORE_H
#define IRON_BPF_QUEUE_STORE_H

#include "bin_indexable_array.h"
#include "bin_map.h"
#include "bin_queue_mgr.h"
#include "packet_pool.h"
#include "queue_depths.h"
#include "shared_memory_if.h"

#include <stdint.h>

namespace iron
{
  class ConfigInfo;
  class Packet;
  class PacketPool;
  class PathController;
  class QueueDepths;
  class BinQueueMgr;
  struct Gradient;

  ///
  /// \brief Container class for Queues and Queue Value Management for all
  ///        multicast groups and destinations and for all unicast
  ///        destinations. This does not depend on the forwarding algorithm
  ///        or the queue value management algorithm. Differences due to the
  ///        different algorithms are encapsulated in the per group/dest
  ///        BinQueueMgrs.
  ///

  class QueueStore
  {
    public:

    /// \brief  Constructor
    ///
    /// \param  packet_pool  Pool containing packet to use.
    /// \param  bin_map      IRON bin mapping.
    /// \param  weight_qd_shared_memory  Memory to share weight queue depths
    //                                   with proxies.
    QueueStore(PacketPool& packet_pool, BinMap& bin_map,
               SharedMemoryIF& weight_qd_shared_memory);

    ///
    /// \brief  Destructor
    ///
    virtual ~QueueStore();

    ///
    /// \brief Initialize the queue depth manager.
    ///
    /// \param  config_info   The reference to the config info object used to
    ///                       initialize values.
    /// \param  node_bin_idx  The node's bin index.
    ///
    /// \return true if success, false otherwise.
    ///
    virtual bool Initialize(const ConfigInfo& config_info,
                            BinIndex node_bin_idx);

    /// \brief Add a queue manager to the queue store.
    ///
    /// \param  config_info   The reference to the config info object used to
    ///                       initialize values.
    /// \param  q_bin_idx     The bin index associated with the new queue.
    /// \param  node_bin_idx  The node's bin index.
    virtual void AddQueueMgr(const ConfigInfo& config_info,
                             BinIndex q_bin_idx, BinIndex node_bin_idx);


    /// \brief Handle any queue depth adjustments needed on a low-fidelity
    /// timer for all groups.
    ///
    /// Used to handle anti-starvation and by subclasses to manage other queue
    /// depth adjustements.
    ///
    /// For the base class, this just triggers anti-starvation adjustments.
    ///
    /// This will be called at least once per BPF select loop. Timing is
    /// handled internally within the function so that different queue depth
    /// managers can act at different time scales.
    virtual void PeriodicAdjustQueueValues();

    ///
    /// \brief  Get the queue depths to be used to generate a QLAM to BPF.
    ///
    /// Memory ownership is transferred to the calling object.  However, that
    /// object shall NOT destroy / free the returned QueueDepth object.  It is
    /// however free to modify it by adding and removing elements to it.
    ///
    /// \param  idx  The unicast destination bin index.
    ///
    /// \return The pointer to the queue depths object to be used in QLAM.
    ///
    inline QueueDepths* GetQueueDepthsForBpfQlam(BinIndex idx)
    {
      return q_mgrs_[idx]->GetQueueDepthsForBpfQlam();
    }

    ///
    /// \brief  Get the queue depths for use in the BPF algorithm.
    ///
    /// Memory ownership is transferred to the calling object.  However, that
    /// object shall NOT destroy / free the returned QueueDepth object.  It is
    /// however free to modify it by adding and removing elements to it.
    ///
    /// \param  idx  The unicast or multicast destination bin index.
    ///
    /// \return The pointer to the queue depths object for use in BPF.
    ///
    inline QueueDepths* GetQueueDepthsForBpf(BinIndex idx)
    {
      return q_mgrs_[idx]->GetQueueDepthsForBpf();
    }

    ///
    /// \brief  Get the virtual queue depths for use in the BPF algorithm.
    ///
    /// Memory ownership is transferred to the calling object.  However, that
    /// object shall NOT destroy / free the returned QueueDepth object.  It is
    /// however free to modify it by adding and removing elements to it.
    ///
    /// \return The pointer to the virtual queue depths object for the queues.
    ///
    virtual inline QueueDepths* GetVirtQueueDepths()
    {
      return &virtual_queue_depths_;
    }

    /// \brief  Set support for EF traffic queues.
    ///
    /// \param  support True to set EF support, false otherwise.
    inline void SetSupportEfForAllGroups(bool support)
    {
      // Make the setting for all unicast and multicast destination bin
      // indexes.
      BinIndex  idx = 0;

      for (bool valid = bin_map_.GetFirstDstBinIndex(idx);
           valid;
           valid = bin_map_.GetNextDstBinIndex(idx))
      {
        q_mgrs_[idx]->set_support_ef(support);
      }
    }

    ///
    /// \brief  Set the passed queue depth object for a nbr seen on a
    ///         particular path controller.
    /// Memory ownership is kept with QueueStore FOR EVER.  The Delete
    /// method below needs to be invoked to remove a queue depth object from
    /// the map.
    ///
    /// \param  dst_bin_idx The bin index representing the destination (unicast)
    ///                     or multicast group.
    /// \param  nbr_bin_idx The bin index of the neighbor.
    /// \param  qd  The pointer to the queue depths object to be associated
    ///             with the path controller.
    ///
    /// \return true on success, false on failure.
    ///
    virtual bool SetNbrQueueDepths(BinIndex dst_bid_idx, BinIndex nbr_bin_idx,
      QueueDepths* qd);

    ///
    /// \brief  Peek at the queue depth object for a neighbor bin index and a
    ///         unicast or multicast destination bin index.
    ///
    /// Memory ownership is kept with QueueStore, although the calling object
    /// can manipulate the returned queue depth object (add, remove bins, etc.).
    ///
    /// \param  dst_bin_idx  The bin index representing the unicast or
    ///                      multicast destination.
    /// \param  nbr_bin_idx  The bin index of the neighbor.  May be a unicast
    ///                      destination or an interior node.
    ///
    /// \return  The pointer to the queue depths object to be associated
    ///           with the path controller.  NULL if nothing found.
    ///
    virtual QueueDepths* PeekNbrQueueDepths(BinIndex dst_bin_idx,
      BinIndex nbr_bin_idx);

    ///
    /// \brief  Set the passed virtual queue depth object for a nbr seen on a
    ///         particular path controller.
    /// Memory ownership is kept with QueueStore FOR EVER.  The Delete
    /// method below needs to be invoked to remove a virtual queue depth object
    /// from the map.
    ///
    /// \param  bidx  The bin index of the neighbor.
    /// \param  qd  The pointer to the virtual queue depths object to be
    ///             associated with the path controller.
    ///
    /// \return true on success, false on failure.
    ///
    virtual bool SetNbrVirtQueueDepths(BinIndex bidx, QueueDepths* qd);

    ///
    /// \brief  Peek the virtual queue depth object for a nbr seen on a
    ///         particular path controller.
    /// Memory ownership is kept with QueueStore, although the calling object
    /// can manipulate the returned queue depth object (add, remove bins, etc.).
    ///
    /// \param  bidx  The bin index of the neighbor.
    ///
    /// \return  The pointer to the virtual queue depths object to be
    ///           associated with the path controller.  NULL if nothing found.
    ///
    virtual QueueDepths* PeekNbrVirtQueueDepths(BinIndex bidx);

    ///
    /// \brief  Delete the virtual queue depth object associated with a nbr
    ///         seen on a particular path controller.
    /// The queue depth object is freed and entry is removed from map.
    ///
    /// \param  bidx  The bin index of the neighbor.
    ///
    virtual void DeleteNbrVirtQueueDepths(BinIndex bidx);

    ///
    /// \brief  Method to print the state of the queues.
    ///
    virtual void PrintDepths();

    ///
    /// \brief  Get the bin queue mgr.
    ///
    /// \param  bin_idx  The unicast or multicast bin index for which we want
    ///                  the queue manager.
    ///
    /// \return Return a reference to the bin queue mgr object.
    ///
    virtual BinQueueMgr* GetBinQueueMgr(BinIndex bin_idx)
    {
      return q_mgrs_[bin_idx];
    }

    ///
    /// \brief  Get a copy of the weighted queue depths.
    ///
    /// \return A queue depths object with the weights exposed to the proxies..
    virtual QueueDepths* GetWQueueDepths();

    ///
    /// \brief  Copy the queue weights to shared memory.
    ///
    /// \return True if copy was successful, false otherwise.
    virtual bool PublishWQueueDepthsToShm();

    /// \brief Forward a capacity update to the BinQueueMgr.
    ///
    /// \param  pc_num        The path controller number
    /// \param  capacity_bps  The current capacity estimate in bps
    inline void ProcessCapacityUpdate(uint32_t pc_num, double capacity_bps)
    {
      // Make the call for all unicast and multicast destination bin indexes.
      BinIndex  idx = 0;

      for (bool valid = bin_map_.GetFirstDstBinIndex(idx);
           valid;
           valid = bin_map_.GetNextDstBinIndex(idx))
      {
        q_mgrs_[idx]->ProcessCapacityUpdate(pc_num, capacity_bps);
      }
    }

    /// \brief Processes and passes gradient info on to the ASAP managers.
    ///
    /// \param  ls_gradients  The ordered list of latency-sensitive gradients.
    /// \param  gradients     The ordered list of gradients.
    void ProcessGradientUpdate(
        OrderedList<Gradient, int64_t>& ls_gradients,
        OrderedList<Gradient, int64_t>& gradients);

    /// \brief Set a reference to a DebuggingStats object in the bin queue
    /// mgr.
    ///
    /// This will allow code in BinQueueMgr to track values over time.
    ///
    /// \param  debug_stats  Pointer to existing DebuggingStats instance.
    inline void SetDebuggingStats(DebuggingStats* debug_stats)
    {
      // Make the setting for all unicast and multicast destination bin
      // indexes.
      debug_stats_ = debug_stats;

      BinIndex  idx = 0;

      for (bool valid = bin_map_.GetFirstDstBinIndex(idx);
           valid;
           valid = bin_map_.GetNextDstBinIndex(idx))
      {
        q_mgrs_[idx]->set_debug_stats(debug_stats);
      }
    }

    /// \brief  Check if the queues to a mcast group index are empty.
    ///
    /// \param  bidx  The bin index of the mcast group.
    ///
    /// \return true if the queues to the destination are empty, false
    ///         otherwise.
    inline bool AreQueuesEmpty(BinIndex bidx)
    {
      return q_mgrs_[bidx]->depth_packets() == 0;
    }

    /// \brief  Check if all the queues are empty.
    ///
    /// MCAST TODO: Optimize once we have the shared memory structures in
    /// place.
    ///
    /// \return true if the queues are empty, false otherwise.
    inline bool AreQueuesEmpty()
    {
      // Check all unicast and multicast destination bin indexes.
      BinIndex  idx = 0;

      for (bool valid = bin_map_.GetFirstDstBinIndex(idx);
           valid;
           valid = bin_map_.GetNextDstBinIndex(idx))
      {
        if (q_mgrs_[idx]->depth_packets() > 0)
        {
          return false;
        }
      }
      return true;
    }

    protected:
    /// Pool containing packets to use.
    PacketPool&                             packet_pool_;

    /// Reference to the bin map.
    BinMap&                                 bin_map_;

    /// The collection of backpressure bins indexed by destination bin index.
    /// Outgoing data packets are enqueued to a bin based its unicast or
    /// multicast destination bin index.
    BinIndexableArray<BinQueueMgr*>         q_mgrs_;

    /// The QueueDepths associated with this local node's virtual queue.
    QueueDepths                             virtual_queue_depths_;

    /// The shared memory object to share weight queue depths with proxies.
    /// TODO: Inspect this and decide whether this needs to be changed for mcast
    //        support.
    SharedMemoryIF&                         weight_qd_shared_memory_;

    /// The array of neighbor virtual queue depths, indexed by unicast
    /// destination or interior node bin index.
    BinIndexableArray<QueueDepths*>         nbr_virtual_queue_depths_;

    private:
    ///
    /// \brief  Disallowed copy constructor.
    ///
    QueueStore(const QueueStore& qdm);

    ///
    /// \brief  Disallowed copy operator.
    ///
    QueueStore& operator= (const QueueStore& qdm);

    /// \brief Use the updated gradients to find the new cap for ASAP.
    ///
    /// \param gradients The list of new gradients, which may be normal
    ///                  gradients or LS.
    /// \param is_ls     True if the gradients list contains latency sensitive
    ///                  gradients.
    void SetASAPCap(OrderedList<Gradient, int64_t>& gradients, bool is_ls);

    /// \brief Queue depths object to be shared with the proxies via shared
    /// memory.
    ///
    /// This will be a concatenation of one depth from each bin's BinQueueMgr.
    QueueDepths                             proxy_depths_;

    /// True if we are running ASAP.
    bool                                    use_anti_starvation_zombies_;

    /// Minimum number of bytes needed by anti-starvation to overcome the
    /// rules in the BPF algorithm for sending to a neighbor.
    /// Although this is a size_t in BPF, we store it signed here so it can be
    /// easily compared to gradients without casting.
    int32_t                                 hysteresis_;

    /// Reference to a DebuggingStats object that can be used to track values
    /// over time. Will be NULL if DEBUG_STATS compile option is disabled.
    DebuggingStats*                         debug_stats_;

    /// The array of flags recording if each maximum gradient value is set,
    /// indexed by unicast or multicast destination bin index.
    BinIndexableArray<bool>                 max_gradient_set_;

    /// The array of maximum gradient values, indexed by unicast or multicast
    /// destination bin index.
    BinIndexableArray<int64_t>              max_gradient_val_;

  };    // End QueueStore class.
}       // End namespace iron
#endif  // IRON_BPF_QUEUE_STORE_H
