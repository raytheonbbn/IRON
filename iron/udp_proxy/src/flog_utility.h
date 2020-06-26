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

/// With floored log  utility, a flow is admitted on a logarithmic utility
/// scale as long as the flow is being properly serviced. If the flow is 
/// not being properly servied, it will be triaged and will not be 
/// automatically restarted. 

#ifndef IRON_UDP_PROXY_FLOG_UTILITY_H
#define IRON_UDP_PROXY_FLOG_UTILITY_H

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

  class FlogUtility : public UtilityFn
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
    FlogUtility(SrcRateEstimator& src_rate_estimator, SrcInfo& src_info,
                 QueueDepths& queue_depths, BinIndex bin_idx, KVal& k_val,
                 uint32_t flow_id);

    /// \brief Destructor.
    virtual ~FlogUtility();

    /// \brief Initialize a Flog Utility Function.
    ///
    /// \param  ci  The config info object containing key-value pairs.
    ///
    /// \return True if the Flog Utility Function initialization is
    ///         successful, false otherwise.
    virtual bool Initialize(const ConfigInfo& ci);

    /// \brief  Get the send rate, in bits per second, allowed by the utility
    ///         function.
    ///
    /// \return The rate, in bits per second, at which to admit packets
    ///         into the network in order to maximize utility.
    virtual double GetSendRate();

    /// \brief  The method to compute whether to triage the flow out.
    ///
    /// \return True if the flow should be triaged, false otherwise.
    virtual bool ConsiderTriage();

    /// \brief  Turn a flow on.
    void SetFlowOn();

    /// \brief  Compute the instantaneous utility.
    ///
    /// \param  send_rate The send rate for this utility.
    virtual double ComputeUtility(double send_rate);

    /// \brief Accessor to get the averaging interval.
    ///
    /// \return The averaging interval for this utility function object,
    ///         in seconds.
    inline double int_length_sec() const { return int_length_sec_; }

    private:

    /// \brief No-arg constructor.
    FlogUtility();

    /// \brief Copy constructor.
    FlogUtility(const FlogUtility& util);

    /// \brief Assignment operator.
    FlogUtility& operator=(const FlogUtility& util);

    /// Reference to the source rate estimator for the flow.
    SrcRateEstimator&  src_rate_estimator_;

    /// Reference to the source information for the flow.
    SrcInfo&           src_info_;

    /// The utility function's max send rate parameter, in bits per second.
    double             m_val_;

    /// Normalized 'a' shape parameter for the utility function.
    double             a_val_;

    /// Backpressure queue normalization parameter (bits^2/sec).
    KVal&              k_val_;

    /// The minimum acceptable rate for the flow.
    double             min_rate_bps_;

    /// When we are stepping down, we are operating under the desired rate and
    /// accumulate a penalty for this. Flows are triaged if the accumulated
    /// penalty is greater than some threshold in a given interval. For the
    /// Flog utility, the penalty is the size of the backlog.
    uint8_t           size_penalty_;

    /// The Flog utility incurs penalty if the backlog is increasing for
    /// consecutive intervals.
    uint8_t           growth_penalty_;

    /// The Flog utility uncurs penalty if the admission rate is less than
    /// the minimum acceptable admission rate.
    uint8_t           rate_penalty_;

    /// The backlog the last time penalty was assessed.
    double            prev_backlog_;

    /// The average admission rate the last time the penalty was assessed. 
    double            prev_adm_rate_;

    /// Utility functions such as the step function and sigmoidal utility
    /// function require some additional history. In particular, if the net
    /// utility of a flow is less than some minimum threshold value delta_*p
    /// over an interval, then the flow should be turned off. The length of
    /// the current interval, in seconds.
    double           int_length_sec_;

    /// Time of the end of the current interval in microseconds. The average
    /// time interval is a configurable parameter, and once an interval ends a
    /// new one begins. There can be small gaps between intervals due to
    /// processing delays and delays in the timer trigger. These gaps are
    /// generally small and are not counted toward any interval.
    int64_t           time_interval_end_usec_;

    /// RNG object.
    iron::RNG         rng_;

    /// The timer tag for averaging interval and step intervals
    uint32_t          flog_timer_tag_;

    /// A scaling factor based on priority. This is used to scale some
    /// paramters so that higher priority flows behave slightly different from
    /// low priority flows. We use a factor of the form (a*p + b)/(p + b),
    /// which yields a factor of 1 for p=0, and asymptotes to a as p goes to
    /// infinity.
    double            scale_factor_;

    /// The average computed admission rate for this flow. 
    double            avg_adm_rate_bps_;

  }; // end class FlogUtility

} // namespace iron

#endif // IRON_UDP_PROXY_FLOG_UTILITY_H
