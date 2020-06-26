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

#ifndef IRON_PROXY_COMMON_UTILITY_FN_IF_H
#define	IRON_PROXY_COMMON_UTILITY_FN_IF_H

#include "iron_constants.h"
#include "iron_types.h"

#include <string>

#include <stdint.h>

/// \brief An abstract interface class for utility functions.
///
/// This object will be used to store the configurable parameters and the
/// current state needed to calculate the utility of sending packets and
/// therefore the rate at which packets should be sent based on the depths of
/// queues at the IRON Backpressure Forwarder. The main purpose of a utility
/// function object is to calculate the send rate, based on the instantaneous
/// queue depth for the destination at the local node.
///
/// With inelastic utility functions such as "step" and "sigmoidal", the
/// utility is also calculated using the average queue depth and average send
/// rate, averaged over fixed time intervals. If the average utility is less
/// than some theshold value for a number of consecutive intervals then the
/// flow is turned off.
namespace iron
{
  class ConfigInfo;
  class ProxyState;
  class QueueDepths;
  class Time;

  class UtilityFn
  {
  public:

    typedef enum
    {
      LOG,
      FLOG,
      TRAP,
      STRAP,
      UNDEFINED_UT
    } UtilityFunctionType;

    /// Constructor.
    ///
    /// \param  queue_depths  The queue depths object from which to get bin
    ///                       depths.
    /// \param  bin_index     The bin index for this flow (may be mcast or
    ///                       unicast).
    /// \param  flow_id       The id of the flow.
    UtilityFn(QueueDepths& queue_depths, BinIndex bin_idx, uint32_t flow_id)
      : queue_depths_(queue_depths),
        bin_idx_(bin_idx),
        flow_id_(flow_id),
        flow_state_(FLOW_ON),
        p_val_(1.0)
    {
    }

    /// Destructor.
    virtual ~UtilityFn()
    {
    }

    /// \brief Initialize a flow's Utility Function.
    ///
    /// \param  ci  The config info object containing (name, value) pairs to
    ///             initialize the flow's utility function.
    ///
    /// \return True if the flow's Utility Function initialization is
    ///         successful, false otherwise.
    virtual bool Initialize(const ConfigInfo& ci) = 0;

    /// \brief Get the send rate, in bits per second, allowed by the utility
    /// function.
    ///
    /// \return The rate, in bits per second, at which to admit packets
    ///         into the network in order to maximize utility.
    virtual double GetSendRate() = 0;

    /// \brief Set the priority of a flow.
    ///
    /// \param priority The new priority of the flow.
    inline void set_priority(double priority) { p_val_ = priority; }

    /// \brief Get the flow priority.
    ///
    /// \return The flow priority.
    inline  double priority() const { return p_val_; }

    /// \brief Get the on/off state of the flow.
    ///
    /// \return The flow state.
    virtual inline FlowState flow_state() { return flow_state_; }

    /// \brief  Set the flow state.
    ///
    /// \param  flow_state  The state to be set for the flow.
    ///                     ON: the flow should be turned on and not triaged
    ///                       out,
    ///                     TRIAGED:the flow is temporarily off waiting for
    ///                       restart in the Proxy,
    ///                     OFF: the flow has been terminated by the
    ///                       supervisory control.
    virtual inline void set_flow_state(FlowState flow_state)
    {
      flow_state_ = flow_state;
    }

    /// \brief  Compute the instantaneous utility.
    ///
    /// \param  rate  The send or receive rate for this utility.
    virtual double ComputeUtility(double rate) = 0;

    /// \brief  Get the id of the flow.
    ///
    /// \return The flow id.
    inline uint32_t flow_id() { return flow_id_; }

    protected:

    /// The queue depths objects used by the utility functions to compute
    /// rates, etc.
    QueueDepths&     queue_depths_;

    iron::BinIndex   bin_idx_;

    /// The id of the flow.
    uint32_t         flow_id_;

    /// The state of the flow: OFF, temporarily triaged out, ON.
    FlowState        flow_state_;

    /// The utility function's relative priority
    double           p_val_;

    private:

    /// \brief Copy constructor.
    UtilityFn(const UtilityFn& other);

    /// \brief Copy operator.
    UtilityFn& operator=(const UtilityFn& other);

  }; // end class UtilityFn

} // namespace iron


#endif	// IRON_PROXY_COMMON_UTILITY_FN_IF_H
