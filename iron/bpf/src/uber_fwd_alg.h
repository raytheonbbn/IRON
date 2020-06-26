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

#ifndef IRON_BPF_UBER_FWD_ALG_H
#define IRON_BPF_UBER_FWD_ALG_H

/// \file uber_fwd_alg.h

#include "bin_indexable_array.h"
#include "bin_map.h"
#include "config_info.h"
#include "ipv4_address.h"
#include "ordered_list.h"
#include "packet_history_mgr.h"
#include "path_controller_info.h"
#include "queue_store.h"
#include "rng.h"
#include "string_utils.h"
#include "gradient.h"

#include <string.h>

namespace iron
{
  class BPFwder;

  // Define the structure used to exchange transmit solutions with BPFwder.
  struct TxSolution
  {
    TxSolution()
      : bin_idx(0),
        path_ctrl_index(0),
        pkt(NULL) { }

    BinIndex  bin_idx;
    size_t    path_ctrl_index;
    Packet*   pkt;
  };

  /// \brief  This class is the implementation for the base and latency-aware
  ///         backpressure forwarding algorithms that select the next
  ///         transmission opportunity.  The class intends to keep as much
  ///         common code between base and latency-aware algorithms.
  class UberFwdAlg
  {
  public:

    /// The structure to store potential candidates in the search for next
    /// transmit opportunity.
    /// No pointer in this structure owns any memory.
    struct TransmitCandidate
    {
      bool           is_valid; // True if this candidate has data we can use.
      Packet*        pkt;      // Pointer to the packet.
      int            gradient; // Gradient.
      iron::BinIndex bin_idx;  // Bin index of the candidate.
      std::string    id_to_log;// Bin/mcast id of the candidate to log.
      bool           is_dst;   // Candidate is the destination of bin.
      iron::Time     ttg;      // Ttg of the candidate.
      size_t         path_ctrl_index; // Index of the path controller on
                               // which to send.
      DstVec         dst_vec;  // The multicast destination vector (mcast only).
      iron::Time     ttr;      // The time to reach the destination (ucast only).
      BinQueueMgr*   q_mgr;    // The bin queue mgr (which keeps the phy queue).
      iron::PacketQueue::QueueWalkState dequeue_loc;  // The location of packet
                                                      // in phy queue.
      uint32_t       virtual_len; // The virtual length of the packet.
      LatencyClass   latency_class; // The latency type of the packet.

      // Constructor.
      TransmitCandidate() :
        is_valid(false), pkt(NULL), gradient(-1), bin_idx(0), id_to_log(),
        is_dst(false), ttg(), path_ctrl_index(0), dst_vec(0), ttr(),
        q_mgr(NULL), dequeue_loc(), virtual_len(0),
        latency_class(UNSET_LATENCY)
      {
        ttg.SetInfinite();
      }

      // Unicast Constructor.
      TransmitCandidate(Packet* p, int64_t grad_val, BinIndex bin,
        std::string tolog,
        bool dst, Time& time_to_go, size_t pc_index,
        Time& ttr_on_pc, BinQueueMgr* queue_mgr, uint32_t pkt_len,
        LatencyClass pkt_lat_class)
      : is_valid(true), pkt(p), gradient(grad_val), bin_idx(bin),
          id_to_log(tolog),
          is_dst(dst), ttg(time_to_go), path_ctrl_index(pc_index),
          dst_vec(0), ttr(ttr_on_pc), q_mgr(queue_mgr), dequeue_loc(),
          virtual_len(pkt_len),
          latency_class(pkt_lat_class)
      {}

      // Multicast Constructor.
      TransmitCandidate(Packet* p, int64_t grad_val, BinIndex bin,
        std::string tolog, Time& time_to_go, size_t pc_index,
        DstVec dsts, BinQueueMgr* queue_mgr,
        iron::PacketQueue::QueueWalkState deq_loc, uint32_t pkt_len,
        LatencyClass pkt_lat_class)
      : is_valid(true), pkt(p), gradient(grad_val), bin_idx(bin),
          id_to_log(tolog),
          is_dst(false), ttg(time_to_go), path_ctrl_index(pc_index),
          dst_vec(dsts), ttr(0), q_mgr(queue_mgr), dequeue_loc(deq_loc),
          virtual_len(pkt_len),
          latency_class(pkt_lat_class)
      {}

      // Multicast Packetless Zombie Constructor.
      TransmitCandidate(int64_t grad_val, BinIndex bin,
        std::string tolog, Time& time_to_go, size_t pc_index,
        DstVec dsts, BinQueueMgr* queue_mgr,
        uint32_t pkt_len,
        LatencyClass pkt_lat_class)
      : is_valid(true), pkt(NULL), gradient(grad_val), bin_idx(bin),
          id_to_log(tolog),
          is_dst(false), ttg(time_to_go), path_ctrl_index(pc_index),
          dst_vec(dsts), ttr(), q_mgr(queue_mgr), dequeue_loc(),
          virtual_len(pkt_len),
          latency_class(pkt_lat_class)
      {}

      // Destructor.
      // The pkt pointer is set to NULL but the packet itself is not recycled
      // here.
      ~TransmitCandidate()
      {
        pkt       = NULL;
        q_mgr     = NULL;
        id_to_log = "DESTROYED";
      }

      // ToString method.
      std::string ToString() const
      {
        std::string str;

        if (!is_valid)
        {
          str.append("INVALID CANDIDATE! ");
        }
        if (pkt)
        {
          char  pkt_addr[24];
          snprintf (pkt_addr, sizeof(pkt_addr), "%p", pkt);
          str.append("Pkt ").append(pkt_addr).append("(").append(
            pkt->GetPacketMetadataString()).append("):");
        }
        else
        {
          str.append("Pkt UNKNOWN:");
        }
        str.append(" gradient: ").append(StringUtils::ToString(gradient));
        str.append("B, len: ").append(StringUtils::ToString(virtual_len));
        str.append(" to (bin ").append(id_to_log);
        str.append(", pc ");
        str.append(StringUtils::ToString(
          static_cast<int>(path_ctrl_index)));
        if (dst_vec != 0)
        {
          str.append(", dst_vec ").append(StringUtils::ToString(dst_vec));
        }
        str.append(") with expected ttr ").append(ttr.ToString());
        str.append(" and ").append(ttg.ToString()).append(" to make it");

        return str;
      }

      // Assignment operator.
      TransmitCandidate& operator= (const TransmitCandidate& other)
      {
        is_valid          = other.is_valid;
        pkt               = other.pkt;
        gradient          = other.gradient;
        bin_idx           = other.bin_idx;
        id_to_log         = other.id_to_log;
        is_dst            = other.is_dst;
        ttg               = other.ttg;
        path_ctrl_index   = other.path_ctrl_index;
        dst_vec           = other.dst_vec;
        ttr               = other.ttr;
        q_mgr             = other.q_mgr;
        dequeue_loc       = other.dequeue_loc;
        virtual_len       = other.virtual_len;
        latency_class     = other.latency_class;

        return *this;
      }

      // Equality operator.
      bool operator== (const TransmitCandidate& other)
      {
        if ((is_valid == other.is_valid) &&
            (pkt == other.pkt) &&
            (gradient == other.gradient) &&
            (bin_idx == other.bin_idx) &&
            (is_dst == other.is_dst) &&
            (ttg == other.ttg) &&
            (path_ctrl_index == other.path_ctrl_index) &&
            (dst_vec == other.dst_vec) &&
            (ttr == other.ttr) &&
            (q_mgr == other.q_mgr) &&
            (dequeue_loc == other.dequeue_loc) &&
            (virtual_len == other.virtual_len) &&
            (latency_class == other.latency_class))
        {
          return true;
        }
        return false;
      }
    };  // End TransmitCandidate.

    /// \brief  Complete constructor.
    /// \param  bpfwder The Backpressure Forwarder object.
    /// \param  packet_pool The packet pool for recycling.
    /// \param  bin_map Mapping of IRON bins.
    /// \param  q_store  The queue store.
    /// \param  packet_history_mgr  The packet history manager.
    /// \param  num_path_ctrls  The number of path controllers currently in use.
    /// \param  path_ctrls  The array of path controllers.
    UberFwdAlg(BPFwder& bpfwder, PacketPool& packet_pool,
               BinMap& bin_map, QueueStore* q_store,
               PacketHistoryMgr* packet_history_mgr,
               size_t num_path_ctrls, PathCtrlInfo* path_ctrls);

    /// \brief  Destructor.
    virtual ~UberFwdAlg();

    /// \brief  The method to initialize the BPFwding algorithms.
    ///
    /// \param  config_info The config info object containing the configuration
    ///                     data.
    void Initialize(const ConfigInfo& config_info);

    /// \brief  Set a different bpfwding approach, or modify key variables.
    ///
    /// \param  config_info The config info object containing the configuration
    ///                     data.
    void ResetFwdingAlg(const ConfigInfo& config_info);

    /// \brief  Unified implementation of the algorithms to find the next
    ///         transmission opportunity.  Base does not take latency into
    ///         account, while Latency-Aware does.
    ///
    /// \param  solutions The array of transmit solutions to be sent.
    /// \param  num_solutions The maximum number of solutions that we could
    ///                       find.
    ///
    /// \return The number of solutions that were found, 0 if nothing.
    uint8_t FindNextTransmission(TxSolution* solutions,
                                 uint8_t max_num_solutions);

    /// \brief  Add destinations to a packet transmission when this is the only
    ///         viable path.
    ///
    /// \param  candidate The candidate transmission.
    void McastOpportunisticForwarding(TransmitCandidate& candidate);

    /// \brief  Get the index and value of the lowest latency path.
    ///
    /// \param  latencies_us    The array of latencies in micro-second on each
    ///                         path controller.  Latencies are indexed by path
    ///                         controller number.
    /// \param  num_latencies   The number of latencies in the array.
    /// \param  path_ctrl_index The index of the lowest-latency path controller.
    /// \param  min_ttr         The latency of the lowest-latency path.
    ///
    /// \return true of results were computed, false for no min (then, must pick
    ///         at random).
    static
    bool GetMinLatencyPath(uint32_t* latencies_us, size_t num_latencies,
                           size_t& path_ctrl_index, Time& min_ttr);

    /// \brief  Get the average queuing delay to a destination bin (by index).
    ///
    /// \param  bin_idx  The destination bin index.
    ///
    /// \return  The average queue delay for the destination in us.
    inline uint32_t GetAvgQueueDelay(BinIndex bin_idx)
    {
      return avg_queue_delay_[bin_idx];
    }

    /// \brief  Set the maximum transmit buffer threshold, in Bytes.
    ///
    /// \param  xmit_threshold_bytes  The xmit threshold to set in bytes.
    inline void set_xmit_buf_max_thresh(size_t xmit_threshold_bytes)
    {
      xmit_buf_max_thresh_ = xmit_threshold_bytes;
    }

    /// \brief  Get the maximum transmit buffer threshold, in Bytes.
    ///
    /// \return The xmit threshold to in bytes.
    inline size_t xmit_buf_max_thresh()
    {
      return xmit_buf_max_thresh_;
    }

    /// Allow overriding for the sake of unit tests.
    inline void set_hysteresis(size_t hysteresis)
    {
      hysteresis_ = hysteresis;
    }

  protected:
    /// \brief  Determine if a packet is in history-constrained mode.  A packet
    ///         is history-constrained if all viable paths to the destination
    ///         start with a next-hop that has already been visited.
    ///
    /// \param  pkt           A pointer to the packet.
    /// \param  ttg           The packet's time-to-go.
    /// \param  latencies_us  The array of latencies in micro-second on each
    ///                       path controller.  Latencies are indexed by path
    ///                       controller number.
    /// \param  num_latencies   The number of latencies in the array.
    ///
    /// \return true if the packet is in history-constrained mode, false if still
    ///         in gradient mode.
    bool IsHistoryConstrained(Packet* pkt, Time& ttg,
                              uint32_t* latencies_us,
                              size_t num_latencies);

    /// \brief  Method to compute a one destination bin gradient between this
    ///         node and a neighbor to a group bin, whether unicast or a single
    ///         destination in a multicast group.
    ///
    /// \param  bin The destination bin for which to compute the gradient.
    /// \param  path_ctrl The path controller to the neighbor for which the
    ///                   gradient is computed.
    /// \param  my_qd_for_bin The node's queue depth object for a given group
    ///                       bin.
    /// \param  nbr_qd_for_bin  The neighbor's queue depth object for a given
    ///                         group bin.
    /// \param  my_v_queue_depth  The node's virtual queue depths object.
    /// \param  nbr_v_queue_depth The neighbor's virtual queue depths object.
    /// \param  is_dst The returned indication that the neighbor is also the
    ///                destination.
    /// \param  differential  The returned gradient.
    /// \param  ls_differential The returned ls gradient.
    void ComputeOneBinGradient(
      BinIndex bin, PathController* path_ctrl,
      QueueDepths* my_qd_for_bin, QueueDepths* nbr_qd_for_bin,
      QueueDepths* my_v_queue_depth, QueueDepths* nbr_v_queue_depth,
      bool& is_dst, int64_t& differential, int64_t& ls_differential);

    /// \brief  Method to compute a gradient to a multicast destination between
    ///         this node and a neighbor.
    ///
    /// The computed multicast gradients are stored in the mcast_gradients_
    /// member of this object.
    ///
    /// \param  path_ctrl The path controller to the neighbor for which the
    ///                   gradient is computed.
    /// \param  my_qd_for_bin The node's queue depth object for a given mcast
    ///                       bin.
    /// \param  nbr_qd_for_bin  The neighbor's queue depth object for a given
    ///                         mcast bin.
    /// \param  my_v_queue_depth  The node's virtual queue depths object.
    /// \param  nbr_v_queue_depth The neighbor's virtual queue depths object.
    /// \param  gradient  The returned gradient.
    /// \param  ls_gradient The returned ls gradient.
    void ComputeMulticastGradient(
      PathController* path_ctrl,
      QueueDepths* my_qd_for_bin, QueueDepths* nbr_qd_for_bin,
      QueueDepths* my_v_queue_depth, QueueDepths* nbr_v_queue_depth,
      Gradient& gradient, Gradient& ls_gradient);

    /// \brief  Match a gradient to packets inside a particular queue.  The
    ///         packets will match if it can go on the corresponding path
    ///         controller.  Packets going to the destination on a direct link
    ///         are preferred. If this ttype uses packetless zombie queues,
    ///         then this will just find the number of bytes that should be
    ///         dequeued instead.
    ///
    /// \param  gradient          A reference to the gradient to match.
    /// \param  ttype             The traffic type of the queue to look in.
    /// \param  method_start      The start of the caller method to have
    ///                           consistent timestamps.
    /// \param  consider_latency  Boolean indicating whether to consider latency.
    /// \param  candidates        The list of packet candidates.
    /// \param  max_bytes         The maximum number of bytes to send.
    ///
    /// \return The number of bytes found.
    uint32_t FindUcastPacketsForGradient(const Gradient& gradient,
                      LatencyClass& ttype,
                      Time& method_start,
                      bool consider_latency,
                      OrderedList<TransmitCandidate, Time>& candidates,
                      uint32_t max_bytes);

    /// \brief  Find packets matching a multicast gradient.
    ///
    /// \param  gradient  The candidate gradient.
    /// \param  ttype The traffic type of the packets to get.
    /// \param  candidates  The list of packet candidates, ordered.
    /// \param  max_bytes The maximum number of bytes to fetch.
    ///
    /// \return The number of candidates bytes.
    uint32_t FindMcastPacketsForGradient(const Gradient& gradient,
      LatencyClass& ttype, OrderedList<TransmitCandidate, Time>& candidates,
      uint32_t max_bytes);

    /// \brief  Add a queuing delay measurement to the moving average.  Only
    ///         real packets, with a valid TTG and non-EF may contribute to the
    ///         average.
    ///
    /// \param  queue_delay_us  The queue delay experienced by a packet in us.
    /// \param  bin_idx  The destination bin index of packet.
    void AddDelayToAverage(int64_t queue_delay_us, BinIndex bin_idx);

    /// The boolean indicating whether the object has been initialized.
    bool                    initialized_;

    /// A pointer to the queue store.
    QueueStore*             queue_store_;

    // Mapping of IRON bins.
    BinMap&                 bin_map_;

    /// Manager for tracking and interpreting the packet history vector.
    PacketHistoryMgr*       packet_history_mgr_;

    /// The number of configured PathControllers.
    size_t                  num_path_ctrls_;

    /// Array of path controllers.  This class does not own the memory.
    PathCtrlInfo*           path_ctrls_;

    /// Required minimum queue gradient to select a target node in Bytes.
    size_t                  hysteresis_;

    /// The threshold for utilizing a Path Controller in Bytes. If the
    /// transmit buffer size in the Path Controller exceeds this threshold, no
    /// additional data will be transmitted via the Path Controller.
    size_t                  xmit_buf_max_thresh_;

    /// The threshold in bytes under which a path controller's xmit buffer is
    /// considered free.
    size_t                  xmit_buf_free_thresh_;

    /// The multicast gradients computed by ComputeMulticastGradient().
    BinIndexableArray<int64_t>  mcast_gradients_;

    /// Random number generator instance used by BP Fwding algorithm.
    RNG                     rng_;

  private:
    /// \brief  Disallowed copy constructor.
    UberFwdAlg(const UberFwdAlg& other);

    /// \brief  Disallowed copy operator.
    UberFwdAlg& operator= (const UberFwdAlg& other);

    /// The reference to the backpressure forwarder object needed to get average
    /// time-to-reach values (ttr, the time it takes to reach a destination).
    BPFwder&                bpfwder_;

    /// Packet pool.
    PacketPool&             packet_pool_;

    /// Algorithm name.
    std::string             alg_name_;

    /// Boolean indicating if Base alg is to be used.
    bool                    base_;

    /// The number of packets to inspect inside a queue for fwding algs, in
    /// bytes.
    uint32_t                queue_search_depth_;

    /// The traffic types that can be Zombifiable.
    const LatencyClass*     zombifiable_ttypes_;

    /// The number of Zombifiable traffic types.
    uint8_t                 num_zombifiable_ttypes_;

    /// The traffic types that should be dequeued first.
    const LatencyClass*     priority_dequeue_ttypes_;

    /// The traffic types that should be dequeued first,
    /// with zombies ordered first.
    const LatencyClass*     priority_dequeue_ttypes_zombies_first_;

    /// The number of priority traffic types.
    uint8_t                 num_priority_dequeue_ttypes_;

    /// The traffic types that should be dequeued after EF packets, but that
    /// are queues of actual packets (not size-only packetless zombie queues).
    const LatencyClass*     standard_dequeue_ttypes_;

    /// The traffic types that should be dequeued after EF packets, but that
    /// are queues of actual packets (not size-only packetless zombie queues).
    /// The zombie packets are ordered first.
    const LatencyClass*     standard_dequeue_ttypes_zombies_first_;

    /// The number of standard dequeue traffic types.
    uint8_t                 num_standard_dequeue_ttypes_;

    /// The traffic types for which we only have zombie queues, as opposed to
    /// actual queues of packets.
    LatencyClass            zombie_dequeue_ttypes_[NUM_LATENCY_DEF];

    /// The number of zombie dequeue traffic types.
    uint8_t                 num_zombie_dequeue_ttypes_;

    /// Boolean indicating whether to drop expired packets.
    bool                    drop_expired_;

    enum AntiCircTech
    {
      AC_TECH_NONE                = 0,
      AC_TECH_HEURISTIC_DAG       = 1,
      AC_TECH_CONDITIONAL_DAG     = 2,
    };

    /// Anti-circulation technique.
    AntiCircTech                  anti_circ_;

    /// Boolean indicating whether to use hierarchical forwarding.
    bool                          enable_hierarchical_fwding_;

    /// Boolean indicating if we must dequeue multiple packets.
    bool                          multi_deq_;

    /// Boolean indicating whether to exclude forwarding to infeasible paths.
    bool                          exclude_infinite_paths_;

    /// Boolean indicating whether to use opportunistic forwarding.
    // NOTE: OF on degrades performance.
    bool                          enable_mcast_opportunistic_fwding_;

    /// The opportunistic forwarding floor, in bytes.
    int64_t                       opportunistic_fwding_floor_;

    /// The array of average queue delays per destination bin index in useconds.
    /// 32b representation is ok since it would mean the packets have been
    /// in the queue for at least one hour.
    BinIndexableArray<uint32_t>   avg_queue_delay_;

    /// The array of dequeued bytes per bin index in bytes.  Used in the
    /// FindMcastPacketsForGradient() method.
    BinIndexableArray<uint32_t>   dequeued_bytes_;

    /// The array of priority traffic types. Used in the
    /// FindNextTransmission() method.
    BinIndexableArray<bool>       has_prio_ttypes_;

    /// Do XPLOT of queue delay.
    bool                          xplot_queue_delay_;

    /// Pointers to classes for adding to the ongoing xplot graphs of queue
    /// delay, one for each unicast or multicast destination bin index.  May
    /// be NULL.
    BinIndexableArray<GenXplot*>  delay_xplot_;

  };    // UberFwdAlg
}       // namespace iron
#endif  // IRON_BPF_UBER_FWD_ALG_H
