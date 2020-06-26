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

#ifndef IRON_PROXY_COMMON_TRAP_UTILITY_H
#define	IRON_PROXY_COMMON_TRAP_UTILITY_H

#include "queue_depths.h"
#include "rng.h"
#include "timer.h"
#include "utility_fn_if.h"

namespace iron
{
  class KVal;
  class ProxyState;

  /// With trap utility, the utility is gradually increased or decreased in
  /// discrete steps, up to some maximum value. Whether it is increased or
  /// decreased is determined by k_val_ and the current queue depth at the BPF
  class TrapUtility : public UtilityFn
  {
    public:

    /// \brief Constructor.
    ///
    /// \param  queue_depths  A reference to the queue depths object from BPF.
    /// \param  bin_idx        The bin index (ucast or mcast).
    /// \param  k_val         A reference to the proxy's k value.
    /// \param  flow_id       The flow identifier.
    TrapUtility(QueueDepths& queue_depths, BinIndex bin_idx, KVal& k_val,
                uint32_t flow_id);

    /// \brief Destructor.
    virtual ~TrapUtility();

    /// \brief Initialize a Trap Utility Function.
    ///
    /// \param  ci  The config info object containing key-value pairs.
    ///
    /// \return True if the Trap Utility Function initialization is
    ///         successful, false otherwise.
    virtual bool Initialize(const ConfigInfo& ci);

    /// \brief Get the send rate, in bits per second, allowed by the utility
    /// function.
    ///
    /// \return The rate, in bits per second, at which to admit packets
    ///         into the network in order to maximize utility.
    virtual double GetSendRate();

    /// \brief The method to compute whether to triage the flow out.
    ///
    /// \return True if the flow should be triaged, false otherwise.
    virtual bool ConsiderTriage();

    /// \brief Compute the instantaneous utility.
    ///
    /// \param  send_rate The send rate for this utility.
    ///
    /// \return The computed instantaneous utility.
    inline virtual double ComputeUtility(double send_rate)
    {
      return current_utility_;
    }

    /// \brief Step up or down the slope of the trapezoid based on the current
    /// queue at the BPF.
    ///
    /// This is periodically called.
    void Step();

    /// \brief Update state at the end of an interval and turn the flow off if
    /// needed.
    ///
    /// \return True if the flow must be turned off after triaging, false
    ///         if nothing should be done.
    bool CheckUtility();

    /// \brief  Turn a flow on.
    void SetFlowOn();

    /// \brief Get the end time of the current interval, in microseconds.
    ///
    /// \return The end time of the current interval, in microseconds.
    inline int64_t time_interval_end() const
    {
      return time_interval_end_;
    }

    /// \brief Set the end time of the current interval, in microseconds.
    ///
    /// \param  time  The end time of the current interval, in microseconds.
    inline void set_time_interval_end(int64_t time)
    {
      time_interval_end_ = time;
    }

    /// \brief Get the restart interval, in microseconds.
    ///
    /// \return The restart interval, in microseconds. The restart interval
    ///         is the duration waited before a flow attempts to restart after
    ///         it has been turned off.
    inline int64_t restart_interval_us() const
    {
      return restart_interval_us_;
    }

    /// \brief Get the step interval, in microseconds.
    ///
    /// \return The step interval, in microseconds.
    inline int64_t step_interval_us() const
    {
      return step_interval_us_;
    }

    /// \brief Get the current step.
    ///
    /// \return The current step for this TRAP utility function.
    inline uint8_t curr_step() const
    {
      return curr_step_;
    }

    /// \brief Get the averaging interval, in microseconds.
    ///
    /// \return The averaging interval for this utility function object,
    ///         in microseconds.
    inline int64_t avg_interval_usec() const
    {
      return avg_interval_usec_;
    }

    /// \brief Get the max burst value, in bits per second.
    ///
    /// \return The max burst value, in bits per second.
    inline double b_val() const
    {
      return b_val_;
    }

    /// \brief Get the value of delta.
    ///
    /// \return The value of delta.
    inline double delta() const
    {
      return delta_;
    }

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
      inertia_usec_ = 0;
    }

    /// \brief Reset the last send rate.
    inline void ResetLastSendRate()
    {
      last_send_rate_ = m_val_;
    }

    private:

    /// The utility function's m parameter, in bits per second.
    double     m_val_;

    /// Backpressure queue normalization parameter (bits^2/sec).
    KVal&      k_val_;

    /// The utility function's burst value (max rate at which we will send).
    double     b_val_;

    /// Must have at least this much net utility in order to send packets.
    double     delta_;

    /// When we are stepping down, we are operating under the desired rate and
    /// accumulate a penalty for this. Flows are triaged if the accumulated
    /// penalty is greater than some threshold in a given interval.
    uint64_t   penalty_;

    /// Utility functions such as the step function and sigmoidal utility
    /// function require some additional history. In particular, if the net
    /// utility of a flow is less than some minimum threshold value delta_ for
    /// th_ consecutive intervals, then the flow should be turned off.  The
    /// length of the current interval, in microseconds.
    int64_t    interval_length_;

    /// Time of the end of the current interval in microseconds. The average
    /// time interval is a configurable parameter, and once an interval ends a
    /// new one begins. There can be small gaps between intervals due to
    /// processing delays and delays in the timer trigger. These gaps are
    /// generally small and are not counted toward any interval.
    int64_t    time_interval_end_;

    /// The time the send rate, and queue length was updated, in the current
    /// interval, in microseconds. Used to calculate the average send rate and
    /// the average queue depth over an interval.
    int64_t    time_of_last_update_;

    /// The average interval over which averages are calculated in
    /// microseconds.
    int64_t    avg_interval_usec_;

    /// Step up/down after this interval, in microseconds.
    int64_t    step_interval_us_;

    /// Attempt to restart the flow after turning it off for this long,
    /// in microseconds.
    int64_t    restart_interval_us_;

    /// The number of steps between 0 and the max rate.
    uint8_t    n_steps_;

    /// The current step we are on.
    uint8_t    curr_step_;

    /// The size of the last step
    uint8_t    last_step_size_;

    /// The last computed send rate.
    double     last_send_rate_;

    /// The utility achieved in the last interval
    double     current_utility_;

    /// RNG object.
    iron::RNG  rng_;

    /// The timer tag for averaging interval and step intervals
    uint32_t  trap_timer_tag_;

    /// The inertia is added to the avg_interval to made it a little
    /// harder to displace an ongoing flow.
    uint32_t  inertia_usec_;

  }; // end class TrapUtility

} // namespace iron

#endif // IRON_PROXY_COMMON_TRAP_UTILITY_H
