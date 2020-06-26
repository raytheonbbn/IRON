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

#ifndef IRON_BPF_HVYBALL_BIN_QUEUE_MGR_H
#define IRON_BPF_HVYBALL_BIN_QUEUE_MGR_H

/// \file hvyball_bin_queue_mgr.h

#include "queue_store.h"
#include "timer.h"

namespace iron
{
  class ConfigInfo;
  class PacketPool;

  /// \brief HvyballBinQueueMgr class to implement the HvyballBinQueueMgr
  ///        algorithm for latency reduction.
  ///        This algorithm computes weights from the queue depths and uses
  ///        these weights to inform the BPF and admission control algorithms.
  ///        The main algorithm periodically updates weights such that:
  ///        w_T+1 = w_T x beta + q_T+1, where w_T+1 is the weight at time
  ///        T+1, beta is an update factor and q_T+1 is the depth of the queue
  ///        at time T+1.
  ///        Current weights (^w, "w hat") are also tracked such that:
  ///        ^w_t = w_T - q_T + q_current.
  ///        w_T weights are sent to neighbor BPF nodes and current weights
  ///        to UDP/TCP proxy.
  ///        All weights and queue depths are in bytes.
  ///
  class HvyballBinQueueMgr : public BinQueueMgr
  {
    public:

    ///
    /// \brief Heavyball constructor.
    ///
    /// \param  bin_idx      Bin index of the unicast destination or mcast group.
    /// \param  packet_pool  Pool containing packet to use.
    /// \param  bin_map      Mapping of IRON bins.
    HvyballBinQueueMgr(BinIndex bin_idx, PacketPool& packet_pool, BinMap& bin_map);

    ///
    /// \brief HvyballBinQueueMgr destructor.
    ///
    virtual ~HvyballBinQueueMgr();

    ///
    /// \brief Initialize method for heavyball.
    ///
    /// \param  config_info   The reference to the config info object used to
    ///                       initialize values.
    /// \param  node_bin_idx  The node's bin index.
    ///
    /// \return true if success, false otherwise.
    ///
    virtual bool Initialize(const ConfigInfo& config_info,
                            BinIndex node_bin_idx);

    ///
    /// \brief  Get the logical queue depths to be used for BPF decision
    ///         making, in bytes. In this case, the weights.
    /// Memory ownership is transferred to the calling object.  However, that
    /// object shall NOT destroy / free the returned QueueDepth object.  It is
    /// however free to modify it by adding and removing elements to it.
    ///
    /// \return The pointer to the queue depths object for the weights.
    ///
    virtual QueueDepths* GetQueueDepthsForBpf();

    ///
    /// \brief  Get the queue depths to be used to generate a QLAM to BPF
    ///         proxy.
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

    /// \brief Handle any queue depth adjustments needed on a low-fidelity
    /// timer.
    ///
    /// Used to updated heavyball weights.
    ///
    /// This will be called at least once per BPF select loop. Timing is
    /// handled internally within this function.
    virtual void PeriodicAdjustQueueValues();

    ///
    /// \brief  Accessor to the beta value.
    ///
    /// \return The value of beta.
    ///
    inline double beta()
    {
      return beta_;
    }

    ///
    /// \brief  Method to print the state of the weights and queues.
    ///
    void PrintDepths() const;

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

    /// \brief Performs any necessary cleanup and accounting after an enqueue.
    ///
    /// This function is useful because subclasses have algorithm-specific
    /// actions after an enqueue. Params are properties of the packet, rather
    /// than the packet itself, for the sake of thread-safety (assuming we've
    /// given up ownership of the packet as soon as it enters the queue).
    ///
    /// \param   pkt_length_bytes  Length of the enqueued packet (or virtual
    ///                            length, for zombies)
    /// \param   lat               Latency class of the enqueued packet
    /// \param   dsts              Destination bit vector for multicast
    virtual void OnEnqueue(
      uint32_t pkt_length_bytes, LatencyClass lat, DstVec dsts);

    private:

    ///
    /// Disallow the copy constructor.
    ///
    HvyballBinQueueMgr(const HvyballBinQueueMgr& hb);

    ///
    /// Disallow the copy operator.
    ///
    HvyballBinQueueMgr& operator= (const HvyballBinQueueMgr& hb);

    ///
    /// \brief  Method to compute the weights:
    ///         w_T+1 = w_T x beta + current_queues.
    ///
    void ComputeWeights();

    ///
    /// The beta value used to adjust weights (no unit, but should be btw 0 and
    /// and 1).
    ///
    double               beta_;

    ///
    /// The heavyball weight QueueDepths object for the node.
    /// This describes the weights w as computed at the time of the weight
    /// calculations: w_T+1 = w_T x beta + q_T+1.
    ///
    QueueDepths*         weights_;

    ///
    /// The heavyball current weight QueueDepths object for the node.
    /// This describes the current weights ^w to be sent to the UDP proxy and
    /// used by the bpf: ^w_T = w_T - q_T + q_current.  These have to be
    /// maintained with every enqueue and dequeue.
    ///
    QueueDepths*         current_weights_;

    ///
    /// Time in microseconds when we last updated the weights.
    ///
    uint64_t             last_weight_time_;

    ///
    /// The interval at which we compute the HvyballBinQueueMgr weights in
    /// microseconds.
    ////
    uint32_t             weight_computation_interval_;

  };      // End HvyballBinQueueMgr.
}         // End namespace.
#endif    // IRON_BPF_HVYBALL_BIN_QUEUE_MGR_H
