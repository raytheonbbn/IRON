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

#ifndef IRON_BPF_ZLR_H
#define IRON_BPF_ZLR_H

///
/// \file zlr.h Includes functions implementing the IRON Zombie Latency Reduction
/// algorithm.
///
#include "bin_indexable_array.h"
#include "bin_indexable_array_nc.h"
#include "bin_map.h"
#include "config_info.h"
#include "genxplot.h"
#include "iron_types.h"
#include "itime.h"
#include "packet_pool.h"
#include "queue_depth_dynamics.h"

#include <stdint.h>

namespace iron
{
  class BinQueueMgr;
  struct DequeuedInfo;

  /// \brief Class implementing the zombie latency reduction algorithm.
  ///
  /// ZLR is intended to pad a queue with zombie packets that will never be
  /// sent, thus maintaining the same queue depths (for the purpose of
  /// backpressure and admission control) while decreasing the amount of time a
  /// real packet sits in the queue. To do this, we need to estimate the number
  /// of packets that are always in the queue (even if the queue depth is
  /// increasing and decreasing, there should be some minimum queue depth even
  /// during the dips) and replace those with zombies.
  ///
  /// The ZLR algorithm adds a zombie if and only if two conditions hold:
  /// 1. The queue depth is steady or increasing. We don't want to add zombies
  ///    when the queue depth is decreasing, since that increases the
  ///    likelihood that we'll end up eventually sending the zombies.
  /// 2. The minimum number of non-zombie packets sitting in the queue (even
  ///    over queue depth dips) is still high.
  /// Both of these notions (is the queue depth decreasing? and what's the
  /// minimum number of packets in the queue?) are captured/maintained in the
  /// QueueDepthDynamics class.

  /// There are two instances of ZLR at all times. One adds zombies based on
  /// the accumulation of all non-zombie packets according to the above
  /// algorithm. The other adds latency-sensitive zombies (the zombies aren't
  /// latency-sensitive, but they are paired with latency-sensitive traffic)
  /// based on the accumulation of ONLY latency-sensitive non-zombie data based
  /// on the above algorithm.
  ///
  /// DYNAMIC OBSERVATION WINDOW AND FAST RECOVERY:
  ///
  /// Condition 2 above implies the existence of an observation window: how
  /// long into the past we will look to see what the minimum non-zombie depth
  /// has been. This observation window is dynamically adjusted. If zombies
  /// are sent or if there are (instantaneously) too few non-zombie packets in
  /// the queue, we will increase the size of that window (i.e., look further
  /// into the past when looking for the minimum non-zombie depth). This is
  /// because too few (or no) non-zombie packets means that we added too many
  /// zombies, and thus were likely looking at the wrong minimum non-zombie
  /// depth. If we've gone a long time without sending zombies, we slowly
  /// decrease the observation window size to increase reaction time.
  ///
  /// In a real network, however, we may see occasional queue depth dips that
  /// do NOT mean we added too many zombies: they just mean some sort of blip
  /// happened in the network that caused our queue to temporarily dip. To
  /// account for these situations, ZLR also includes a fast recovery
  /// algorithm.
  ///
  /// Fast recovery watches when we're dequeuing packets to see if we're in
  /// the middle of a steep dequeue period. If so, we enter a fast recovery
  /// "Queue Depth Dip" stage - if we only see one dip, we will quickly
  /// increase our zombies back to the pre-dip level after the dip is
  /// complete. This helps quickly recover from a network blip. However, if
  /// two or more dips occur within a short time, we assume this is
  /// oscillatory, the zombie floor was incorrect, and thus we increase the
  /// observation window as discussed above.
  class ZLR
  {
    public:

    /// Constructor
    ///
    /// \param packet_pool  Reference to the packet pool.
    /// \param bin_map      Reference to the bin map.
    /// \param q_mgr        Reference to the BinQueueMgr.
    /// \param bin_index    Bin on which this ZLR instance is acting.
    ZLR(PacketPool& packet_pool, BinMap& bin_map, BinQueueMgr& q_mgr,
        BinIndex bin_index);

    /// Destructor
    virtual ~ZLR();

    /// \brief Initialize the ZLR object.
    ///
    /// \param  config_info  The configuration information.
    void Initialize(const ConfigInfo& config_info);

    /// \brief Process the change in bytes as applicable for this latency class.
    ///
    /// Note that this signature is asymmetric from DoZLRDequeueProcessing,
    /// which is necessary because we no longer own the packet after it's been
    /// enqueued (but we need a lot of data from the packet after a dequeue).
    ///
    /// \param  bytes  How many bytes were enqueued? uint16_t is sufficient
    ///                because the total length field in the IP header is
    ///                only 16 bits. By using uint16_t instead of uint32_t,
    ///                we avoid the potential for overflow when converting
    ///                to an int32_t to store the net change.
    /// \param  lat    The latency class of the bytes we enqueued. This
    ///                function will determine based on this class whether and
    ///                how to count these bytes towards the dynamics we're
    ///                tracking.
    /// \param  dsts   The destinations for this packet, if multicast. Ignored
    ///                if this ZLR manager is for a unicast bin.
    void DoZLREnqueueProcessing(
      uint16_t bytes, LatencyClass lat, DstVec dsts);

    /// \brief Add zombies if necessary and track the removed bytes.
    ///
    /// \param  dq_info    Information from the packet just dequeued.
    void DoZLRDequeueProcessing(const DequeuedInfo& dq_info);

    /// \brief Set the pointer to the queue depth graph.
    ///
    /// \param bin_idx  Bin for which we are assigning the graph.
    /// \param qd_xplot Pointer to the queue depth graph.
    inline void set_qd_xplot(BinIndex bin_idx, GenXplot* qd_xplot)
    {
      qd_xplot_[bin_idx] = qd_xplot;
    }

    private:

    /// \brief Used to track the state of the ZLR fast recover algorithm.
    ///
    /// The Fast recovery algorithm state machine looks like this:
    ///   STEADY_STATE* ---- quick dip in ----> QUEUE_DEPTH_DIP
    ///       /\             queue depth            |
    ///        |                                    |
    ///        |                                    |
    ///    reset time                       non-zombie depth
    ///      passes                         crosses threshold
    ///        |                        before reset time passes
    ///        |                                    |
    ///        |                                    \/
    ///     RECOVERED <----- pre-dip num ------- RECOVERY
    ///        |           zombies reached
    ///        |       before reset time passes
    ///        |
    ///        |
    ///     quick dip in
    ///     queue depth before
    ///     reset time passes
    ///        |     /\ -
    ///        |     |
    ///        \/    |
    ///     OSCILLATORY*
    ///
    /// In addition, any state will return to STEADY_STATE if the reset time
    /// passes without any movement between states.
    ///
    /// In states marked with *, the dynamic observation window will
    /// increase if a zombie is dequeued or if the number of non-zombie
    /// packets is below the low watermark (and if enough time has passed
    /// since the last window change).
    /// In all states, the dynamic observation window will
    /// decrease if a non-zombie is dequeued, enough time has passed since the
    /// last zombie dequeue, and enough time has passed since the last window
    /// change. (Note that this is probably not possible in QUEUE_DEPTH_DIP
    /// stage, since that stage begins with a zombie dequeue and typically
    /// ends after a very short time period.)
    ///
    enum FastRecoveryState
    {
      /// \brief No sudden dip in queue depth detected.
      ///
      /// In this state, sending zombies or dipping below the low water mark
      /// of non-zombies will cause us to expand the ZLR observation window.
      STEADY_STATE = 0,

      /// \brief Observed a sudden dip in queue depth.
      ///
      /// This stage indicates that we've seen a sudden dip in queue depth and
      /// should start doing fast recovery.
      QUEUE_DEPTH_DIP,

      /// \brief Fast recovery in progress.
      ///
      /// In this stage, every time we dequeue a non-zombie packet, we'll add
      /// a zombie (until we hit the pre-dip zombie level.) During recovery,
      /// we use instantaneous queue depth instead of the minimum over the
      /// observation window.
      RECOVERY,

      /// \brief Fast recovery complete, waiting to see if another dip occurs.
      ///
      /// When in this state, we know that we've just experienced and
      /// recovered from a queue dip. If there's another dip before the fast
      /// recovery algorithm times out, we will consider it an oscillation do
      /// standard recovery instead (increasing the observation window, etc.)
      ///
      RECOVERED,

      /// \brief Additional dips occurred within the fast recovery timeout.
      ///
      /// When this state occurs, we assume the dips are due to an
      /// oscillation, not a spurious event. We therefore react by increasing
      /// the observation window. This is separate from STEADY_STATE because a
      /// dip observed when in STEADY_STATE triggers another fast recovery,
      /// while dips observed in OSCILLATORY state do not.
      OSCILLATORY
    };

    /// \brief Data required for tracking and adjusting fast recovery state.
    struct FastRecoveryData
    {
      /// \brief The current fast recovery state.
      FastRecoveryState               fast_recovery_state;

      /// \brief The number of bytes to count towards whether this is a dip.
      uint32_t                        deq_bytes;

      /// \brief The time this prospective dip started.
      Time                            deq_start_time;

      /// \brief When to stop a fast recovery (based on number of zombie bytes).
      uint32_t                        recovery_zombie_depth_bytes;

      /// \brief Basis time for resetting fast recovery to STEADY_STATE.
      Time                            fast_recovery_start_time;

      /// \brief Default constructor.
      inline FastRecoveryData()
          : fast_recovery_state(STEADY_STATE),
            deq_bytes(2000),
            deq_start_time(Time::Now()),
            recovery_zombie_depth_bytes(0),
            fast_recovery_start_time(Time::Now()) { }
    };

    /// Copy constructor.
    ZLR(const ZLR& other);

    /// Assignment operator
    ZLR operator=(const ZLR& other);

    /// \brief Initialize and generate the key for a per-bin ZLR window graph.
    ///
    /// \param The BinIndex for which we want to generate a plot.
    void SetUpZLRXplot(BinIndex bin_idx);

    /// Reference to the packet pool.
    PacketPool&                     packet_pool_;

    /// Reference to the bin map.
    BinMap&                         bin_map_;

    /// BinQueueMgr to be used to get instantaneous queue depths for relevant
    /// queues.
    BinQueueMgr&                    q_mgr_;

    /// Bin index on which this ZLR instance is acting. Useful for logging.
    BinIndex                        my_bin_index_;

    /// True if this ZLR instance is for a multicast bin.
    bool                            is_multicast_;

    /// If true, create latency-senstivie-specific Zombies for ZLR when the LS
    /// queue is too long. Note: if do_zombie_latency_reduction_ is false,
    /// this will be ignored.
    bool                            do_ls_zombie_latency_reduction_;

    /// If the non-zombie queue depth is at least this large, we will add
    /// zombie packets to reduce queue delay.
    uint32_t                        zlr_high_water_mark_bytes_;

    /// If we have fewer bytes than this of non-zombie packets in a queue, we
    /// will start to decrease the ZLR min queue depth window.
    uint32_t                        zlr_low_water_mark_bytes_;

    /// Queue change rate below which we should NOT add zombie packets. That
    /// is, if the queue depth for a bin is changing at a rate less than this
    /// (if this is negative, that would mean dequeues are happening faster
    /// than enqueues), then we will not replace dequeued packets with
    /// zombies.
    ///
    /// \todo: The rule that uses this value (described above) is likely
    /// unnecessary with the current zlr logic and is leftover from when we
    /// were using instantaneous queue depth (rather than minimum over some
    /// window) to determine whether to add zombies. We should figure out
    /// whether this rule is still necessary. If it is, add more about this
    /// rule in the overall ZLR documentation in the class brief (item 1 in
    /// the current documentation doesn't mention the threshold). If not,
    /// remove the rule.
    int16_t                         zlr_q_change_min_thresh_bytes_per_s_;

    /// The QueueDepthDynamics considering only non-zombie packets for each of
    /// the destination bins, keyed by BinIndex. Whether or not this includes
    /// low latency packets is configured using constant kLSIncludedForZLR in
    /// zlr.cc. Whether or not this includes LS zombies is configured using
    /// constant kLSZombiesIncludedForZLR.
    BinIndexableArrayNc<QueueDepthDynamics>  zlr_queue_depth_dynamics_;

    /// The QueueDepthDynamics considering only latency sensitive non-zombie
    /// packets for each of the destination bins, keyed by BinIndex.
    BinIndexableArrayNc<QueueDepthDynamics>  zlr_ls_queue_depth_dynamics_;

    /// Data for tracking and maintaining the fast recovery state for each
    /// queue.
    BinIndexableArray<FastRecoveryData>  fast_recovery_;

    /// Data for tracking and maintaining the fast recovery state for each
    /// bin's latency sensitive traffic.
    BinIndexableArray<FastRecoveryData>  ls_fast_recovery_;

    /// Boolean variant of array ZLR_DECISION_TTYPES
    bool                     is_zlr_decision_ttype_[iron::NUM_LATENCY_DEF];

    /// Boolean variant of array ZLR_LS_DECISION_TTYPES
    bool                     is_zlr_ls_decision_ttype_[iron::NUM_LATENCY_DEF];

    /// Boolean variant of array ZLR_ZOMBIE_TTYPES
    bool                     is_zlr_zombie_ttype_[iron::NUM_LATENCY_DEF];

    /// Boolean variant of array ZLR_LS_ZOMBIE_TTYPES
    bool                     is_zlr_ls_zombie_ttype_[iron::NUM_LATENCY_DEF];

    /// Pointers to classes for adding to the ongoing xplot graphs of zlr
    /// values, one for each destination bin. May be NULL.
    BinIndexableArray<GenXplot*>    zlr_xplot_;

    /// Pointers to classes for adding to the ongoing xplot queue depth
    /// graphs, one for each destination bin. May be NULL. Owned elsewhere:
    /// this class is not responsible for freeing these.
    BinIndexableArray<GenXplot*>    qd_xplot_;

    /// \brief Process the change in bytes as applicable for this latency class.
    ///
    /// Note that this signature is asymmetric from DoZLRDequeueProcessing,
    /// which is necessary because we no longer own the packet after it's been
    /// enqueued (but we need a lot of data from the packet after a dequeue).
    ///
    /// \param  bytes  How many bytes were enqueued? uint16_t is sufficient
    ///                because the total length field in the IP header is
    ///                only 16 bits. By using uint16_t instead of uint32_t,
    ///                we avoid the potential for overflow when converting
    ///                to an int32_t to store the net change.
    /// \param  lat    The latency class of the bytes we enqueued. This
    ///                function will determine based on this class whether and
    ///                how to count these bytes towards the dynamics we're
    ///                tracking.
    /// \param  bin_index  The destination bin index for which we are
    ///                processing the enqueue.
    void DoPerBinEnqueueProcessing(
      uint16_t bytes, LatencyClass lat, BinIndex bin_index);

    /// \brief Add zombies if necessary and track the removed bytes.
    ///
    /// \param  dq_info   Information from the packet just dequeued.
    /// \param  bin_index The destination bin we are processing.
    void DoPerBinDequeueProcessing(
      const DequeuedInfo& dq_info, BinIndex bin_index);

    /// \brief Update state to allow fast recovery from unexpected dips.
    ///
    /// Update the fast recovery state when we enqueued a packet, including
    /// switching from "queue depth dip" to "recovery" mode if we now have
    /// enough non-zombie packets to start recovering, and restarting the
    /// count to track whether or not we are in a queue depth dip.
    ///
    /// This function does NOT take control of the packet.
    ///
    /// \param bin_idx     The destination bin of the packet just enqueued.
    /// \param process_ls  True if we are considering updating the
    ///                    latency-sensitive ZLR state. False if we are
    ///                    updating the non-LS state.
    /// \param zlr_depth_bytes The current depth of non-zombie packets
    ///                    considered for this ZLR instance (LS or
    ///                    normal). Passed in because it's needed in the
    ///                    calling function as well and is non-trivial to get
    ///                    the value.
    void UpdateFastRecoveryStateOnEnqueue(
      BinIndex bin_idx, bool process_ls, uint32_t zlr_depth_bytes);

    /// \brief Update state to allow recovery from queue depth dips.
    ///
    /// Update the fast recovery state when we dequeued a packet, including
    /// determining whether or not we are in a queue depth dip and what to do
    /// about that, updating the observation window if appropriate,
    /// determining whether a fast recovery is complete, and resetting the
    /// fast recovery algorithm if enough time has gone by since the last
    /// queue depth dip.
    ///
    /// \param dq_info     Information from the packet just dequeued.
    /// \param bin_idx     The destination bin of the packet just dequeued.
    /// \param process_ls  True if we are considering updating the
    ///                    latency-sensitive ZLR state. False if we are
    ///                    updating the non-LS state.
    /// \param zlr_depth_bytes The current depth of non-zombie packets
    ///                    considered for this ZLR instance (LS or
    ///                    normal). Passed in because it's needed in the
    ///                    calling function as well and is non-trivial to get
    ///                    the value.
    void UpdateFastRecoveryStateOnDequeue(const DequeuedInfo& dq_info,
      BinIndex bin_idx, bool process_ls, uint32_t zlr_depth_bytes);

    /// \brief  If necessary, add zombie packets to help reduce latency.
    ///
    /// \param  dq_info     Information from the packet just dequeued.
    /// \param  bin_idx     The destination bin index.
    void DoZombieLatencyReduction(
      const DequeuedInfo& dq_info, BinIndex bin_idx);

  }; // End class ZLR

} // end namespace iron

#endif // IRON_BPF_ZLR_H
