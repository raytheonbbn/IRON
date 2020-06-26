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

/// With simplified trap utility, the utility is gradually increased or
/// decreased in discrete steps, up to some maximum value. Whether it is
/// increased or decreased is determined by k_val_ and the current queue
/// depth at the BPF. Unlike the TRAP utility, the only required parameter
/// is the priority, p. The other parameters are calculated or a default
/// value is used.

#ifndef IRON_PROXY_COMMON_STRAP_UTILITY_H
#define IRON_PROXY_COMMON_STRAP_UTILITY_H

#include "queue_depths.h"
#include "rng.h"
#include "src_info.h"
#include "src_rate_estimator.h"
#include "timer.h"
#include "utility_fn_if.h"

namespace iron
{
  class KVal;
  class ProxyState;

  class StrapUtility : public UtilityFn
  {
  public:

    /// \brief Constructor.
    ///
    /// \param  src_rate_estimator  Reference to the source rate estimator.
    /// \param  src_info            Flow information.
    /// \param  queue_depths        Reference to the queue depths object.
    /// \param  bin_idx             The bin index (ucast or mcast).
    /// \param  k_val               Reference to the proxy's k value.
    /// \param  flow_id             The flow identifier.
    StrapUtility(SrcRateEstimator& src_rate_estimator, SrcInfo& src_info,
                 QueueDepths& queue_depths, BinIndex bin_idx, KVal& k_val,
                 uint32_t flow_id);

    /// \brief Destructor.
    virtual ~StrapUtility();

    /// \brief Initialize a Strap Utility Function.
    ///
    /// \param  ci  The config info object containing key-value pairs.
    ///
    /// \return True if the Strap Utility Function initialization is
    ///         successful, false otherwise.
    virtual bool Initialize(const ConfigInfo& ci);

    /// \brief  Get the send rate, in bits per second, allowed by the utility
    ///         function.
    ///
    /// \return The rate, in bits per second, at which to admit packets
    ///         into the network in order to maximize utility.
    virtual double GetSendRate();

    /// \brief  Get the fraction of the backlog that should be admitted.
    ///
    /// \return The fraction of the backlog that should be admitted.
    double GetAdmFrac();

    /// \brief  Compute the instantaneous utility.
    ///
    /// \param  send_rate The send rate for this utility.
    inline virtual double ComputeUtility(double send_rate)
    {
      return current_utility_;
    }

    /// \brief Step up or down the slope of the STRAP based on the
    ///        current queue at the BPF.
    ///
    /// This is periodically called via callback.
    ///
    void Step();

    /// \brief Function to update state at the end of an interval and
    /// turn the flow off if needed.
    /// \return True if the flow must be turned off after triaging, false
    ///         if nothing should be done.
    bool CheckUtility();

    /// \brief  Turn a flow on.
    void SetFlowOn();

    /// \brief Accessor function for the restart timer.
    /// \return time The duration of the off-time for a flow, after which
    /// it attempts to restart. The units are microseconds.
    inline double restart_interval_sec() const { return restart_interval_sec_; }

    /// \brief Accessor for the step interval timer.
    ///
    /// \return The step interval timer in microseconds.
    inline double step_interval_sec() const { return step_interval_sec_; }

    /// \brief Accessor to get the current step.
    ///
    /// \return The current step for this STRAP utility function object.
    inline uint8_t curr_step() const { return curr_step_; }

    /// \brief Accessor to get the averaging interval.
    ///
    /// \return The averaging interval for this utility function object,
    ///         in microseconds.
    inline double avg_interval_sec() const { return avg_interval_sec_; }

    /// \brief Get the value of delta.
    ///
    /// \return The value of delta.
    inline double delta() const { return delta_; }

    /// \brief Set the value of delta.
    ///
    /// \param delta the new value of delta.
    inline void set_delta(double delta)
    {
      delta_ = delta;
    }

    /// \brief Reset the inertia of the flow.
    inline void ResetInertia()
    {
      inertia_ = 0.0;
    }

    /// \brief Set the time for the end of the interval relative to now.
    void SetAvgIntervalEnd();

    /// \brief Set the last admitted packet sequence number.
    ///
    /// \param admitted_seq_num The sequence number of the last admitted packet.
    inline void set_admitted_seq_num(uint32_t admitted_seq_num)
    {
      admitted_seq_num_ = admitted_seq_num;
    }

    /// \brief Set the last acked sequence number.
    ///
    /// \param acked_seq_num The last sequence number acked in an RMM.
    inline void set_acked_seq_num(uint32_t acked_seq_num)
    {
      acked_seq_num_ = acked_seq_num;
    }

    /// \brief Set the current reported loss rate.
    ///
    /// \param loss_rate The loss rate reported by the destination.
    inline void set_curr_loss_rate_pct(uint32_t loss_rate)
    {
      curr_loss_rate_pct_ = loss_rate;
    }

    /// \brief Set the flag to indicate if loss triage is enabled.
    ///
    /// \param enabled True if loss triage is enabled.
    inline void set_enable_loss_triage(bool enabled)
    {
      enable_loss_triage_ = enabled;
    }

    /// \brief Check is loss triage is enabled.
    ///
    /// \return True if loss triage is enabled, false otherwise.
    inline bool enable_loss_triage() const
    {
      return enable_loss_triage_;
    }

    private:

    /// Reference to the source rate estimator for the flow.
    SrcRateEstimator&  src_rate_estimator_;

    /// Reference to the source information for the flow.
    SrcInfo&           src_info_;

    /// Backpressure queue normalization parameter (bits^2/sec).
    KVal&              k_val_;

    /// Must have at least this much net utility in order to send packets.
    double             delta_;

    /// When we are stepping down, we are operating under the desired rate and
    /// accumulate a penalty for this. Flows are triaged if the accumulated
    /// penalty is greater than some threshold in a given interval. For the
    /// STRAP utility, the penalty is the size of the backlog.
    double             penalty_;

    /// Time of the end of the current interval in microseconds. The average
    /// time interval is a configurable parameter, and once an interval ends a
    /// new one begins. There can be small gaps between intervals due to
    /// processing delays and delays in the timer trigger. These gaps are
    /// generally small and are not counted toward any interval.
    int64_t            time_interval_end_;

    /// The average interval over which averages are calculated in seconds.
    double             avg_interval_sec_;

    /// Step up/down after this interval, in seconds.
    double             step_interval_sec_;

    /// Attempt to restart the flow after turning it off for this long, in
    /// seconds.
    int64_t            restart_interval_sec_;

    /// The number of steps between 0 and the max rate.
    uint8_t            n_steps_;

    /// The current step we are on.
    uint8_t            curr_step_;

    /// The utility achieved in the last interval.
    double             current_utility_;

    /// RNG object.
    iron::RNG          rng_;

    /// The timer tag for averaging interval and step intervals
    uint32_t           strap_timer_tag_;

    /// A scaling factor based on priority. This is used to scale some
    /// paramters so that higher priority flows behave slightly different from
    /// low priority flows. We use a factor of the form (a*p + b)/(p + b),
    /// which yields a factor of 1 for p=0, and asymptotes to a as p goes to
    /// infinity.
    double             scale_factor_;

    /// The inertia of a flow is used to scale the loss tolerance
    /// and the step-down threshold such that ongoing flows are more
    /// tolerant to loss, up to a maximum of delta. Also, ongoing flows
    /// have a slightly higher threshold before stepping down when
    /// compared to new flows of the same priority.
    double             inertia_;

    /// The maximum queue depth seen.
    uint32_t           max_queue_depths_;

    /// The time the maximum queue depth was observed.
    int64_t            max_queue_time_ms_;

    /// The sequence number of the last admitted packet before making
    /// a stepping decision.
    uint32_t           admitted_seq_num_;

    /// The sequence number of the last admitted packet before making
    /// the prior step.
    uint32_t           last_admitted_seq_num_;

    /// The last acked sequence number.
    uint32_t           acked_seq_num_;

    /// The last acket sequence number at the last step interval.
    uint32_t           last_acked_seq_num_;

    /// The current reported loss rate.
    uint32_t           curr_loss_rate_pct_;

    /// The time-to-go specified in the service definition.
    iron::Time         time_to_go_;

    /// The time of the last loss-based step decision.
    iron::Time         last_step_time_;

    /// The last time a new packet was acked.
    iron::Time         last_acked_time_;

    /// A flag to indicate if loss triage is enabled.
    bool               enable_loss_triage_;

  }; // end class StrapUtility

} // namespace iron

#endif // IRON_PROXY_COMMON_STRAP_UTILITY_H
