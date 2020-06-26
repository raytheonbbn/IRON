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

#ifndef IRON_BPF_EWMA_BIN_QUEUE_MGR_H
#define IRON_BPF_EWMA_BIN_QUEUE_MGR_H

/// \file ewma_bin_queue_mgr.h

#include "bin_indexable_array.h"
#include "bin_indexable_array_nc.h"
#include "bin_queue_mgr.h"
#include "queue_depth_osc.h"

namespace iron
{
  class ConfigInfo;
  class PacketPool;

  /// \brief Queue manager using an exponential weighted moving average.
  ///        This algorithm maintains a smoothed weighted moving average
  ///        of the queue depth instead of an exact depth, thereby alleviating
  ///        the need for long queues. In this case, even if there is a
  ///        sudden burst of available capacity (common with very short
  ///        queues), that burst will be softened instead of advertised as-is
  ///        for BPF. This prevents a pattern of high-availability leading
  ///        to heavy traffic leading to congestion leading to no traffic
  ///        leading to high-availability. The pattern is instead broken
  ///        because the sudden availability changes are not advertised
  ///        immediately.
  ///
  ///        This is loosely related to the HeavyBall algorithm, which also
  ///        attempts to smooth the advertised weights instead of publicizing
  ///        instantaneous queue depths. The primary advantage of using an
  ///        EWMA over heavyball is that this does not require discrete time
  ///        intervals and a tuned beta.
  ///
  ///        EWMA dynamically tunes the smoothing interval by using an
  ///        instance of QueueDepthOsc to compute the period of
  ///        oscillation. By smoothing over one period, we avoid amplifying
  ///        the oscillations by considering only above-average values or
  ///        below-average values. The desired effect is to completely remove
  ///        the oscillations.
  ///
  ///        All weights and queue depths are in bytes.
  ///
  class EWMABinQueueMgr : public BinQueueMgr
  {
    public:

    ///
    /// \brief EWMABinQueueMgr constructor.
    ///
    /// \param  bin_idx      Bin index of the unicast destination or mcast group.
    /// \param  packet_pool  Pool containing packet to use.
    /// \param  bin_map      Mapping of IRON bins.
    EWMABinQueueMgr(BinIndex bin_idx, PacketPool& packet_pool, BinMap& bin_map);

    ///
    /// \brief EWMABinQueueMgr destructor.
    ///
    virtual ~EWMABinQueueMgr();

    ///
    /// \brief Initialize method for EWMABinQueueMgr.
    ///
    /// \param  config_info   The reference to the config info object used to
    ///                       initialize values.
    /// \param  node_bin_idx  The node's bin index.
    ///
    /// \return true if success, false otherwise.
    ///
    virtual bool Initialize(const ConfigInfo& config_info,
                            BinIndex node_bin_idx);

    /// \brief Handle any queue depth adjustments needed on a low-fidelity
    /// timer.
    ///
    /// In addition to parent class adjustments, this will:
    /// 1. Take samples for the FFT (if it's time).
    /// 2. Recompute weights, to ensure they converge then the exact
    ///    queue depth is static.
    ///
    /// This will be called at least once per BPF select loop. Timing is
    /// handled internally within the function.
    virtual void PeriodicAdjustQueueValues();

    /// \brief Update the weights in response to a queue depth change.
    ///
    /// Called whenever the queue depth for a destination changes. Triggers an
    /// update to the associated moving average queue value.
    virtual void AdjustQueueValuesOnChange(BinIndex dest);

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

    /// \brief  Accessor to the tau value.
    ///
    /// \return The value of tau_usec_.
    ///
    inline double tau_usec()
    {
      return tau_usec_;
    }

    ///
    /// \brief  Method to print the state of the weights and queues.
    ///
    void PrintDepths();

  private:

    ///
    /// Disallow the copy constructor.
    ///
    EWMABinQueueMgr(const EWMABinQueueMgr& hb);

    ///
    /// Disallow the copy operator.
    ///
    EWMABinQueueMgr& operator= (const EWMABinQueueMgr& hb);

    ///
    /// \brief  Method to compute the moving average for a bin.
    ///
    ///         beta = e^(-(t_{i+1} - t_i)/tau)
    ///         w_{i+1} = beta * w_i + (1 - beta) * current_queues
    ///
    /// Note, this can be simplified to:
    ///         w_{i+1} = current_queues + (beta * (w_i - current_queues))
    /// but we do not implement it as such, since this has interim
    /// negative numbers and thus requires casting.
    ///
    /// If linear interpolation is used, the computation is instead:
    ///         normalized_time = (t_{i+1} - t_i) / tau
    ///         beta = e^(-normalized_time)
    ///         beta_li = (1 - beta)/normalized_time
    ///         w_{i+1} = (w_i * beta) + (current_queues * (1 - beta_li))
    ///                   + (previous_queues * (beta_li - beta))
    /// This is a recursive way to compute the exponentially weighted
    /// moving average using a linear interpolation for queue lenghts between
    /// samples (to smooth the weight value over sparse samples).
    ///
    /// This is based on the paper "Algorithms for Unevenly Spaced Time
    /// Series: Moving Averages and Other Rolling Operators" by Andreas
    /// Eckner, First version January 2010, Latest version August 23, 2015.
    ///
    /// \param bin_idx The bin for which we want to compute the updated
    /// weight.
    void ComputeWeight(BinIndex bin_idx);

    /// Last weight computation times by Bin Index.
    BinIndexableArray<int64_t>        last_weight_time_;

    /// The tau value (moving window size) for computing the exponential
    /// weighted moving average for the weights. Units is microseconds, which
    /// must match the time diff computed when weights are updated.
    uint32_t                          tau_usec_;

    /// The tau value used for computing the latency sensitive EWMA.
    uint32_t                          ls_tau_usec_;

    /// The weighted moving average QueueDepths object for the node.
    /// This describes the weights w as computed at the time of the weight
    /// calculations, which are also accurate to be sent to the UDP proxy and
    /// used by the bpf, since they are recomputed on every enqueue and
    /// dequeue. (See ComputeWeights)
    QueueDepths*                      weights_;

    /// Most recent queue depth used for computing EWMA weight. If we are
    /// using linear interpolation, this is used in the next comptuation
    /// as well. If we are NOT using linear interpolation, this is neither
    /// set nor used.
    QueueDepths*                      previous_queue_depth_bytes_;

    /// Manager for computing queue depth oscillation periods.
    BinIndexableArrayNc<QueueDepthOsc>  queue_depth_osc_mgr_;

    /// Manager for computing queue depth oscillation periods for latency
    /// sensitive queues.
    BinIndexableArrayNc<QueueDepthOsc>  ls_queue_depth_osc_mgr_;

    /// True if we want tau to be computed dynamically based on the queue
    /// depth oscillation period. If false, this will use the intiially
    /// configured tau value.
    bool                              use_dynamic_tau_;

  };      // End EWMABinQueueMgr.
}         // End namespace.
#endif    // IRON_BPF_EWMA_BIN_QUEUE_MGR_H
