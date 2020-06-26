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

#ifndef IRON_PROXY_COMMON_LOG_UTILITY_H
#define	IRON_PROXY_COMMON_LOG_UTILITY_H

#include "utility_fn_if.h"

/// With log utility function, the utility gained from sending packets
/// decrease on a log scale with the current queue depth.
namespace iron
{
  class KVal;
  class ProxyState;

  class LogUtility : public UtilityFn
  {
    public:

    /// \brief Constructor.
    ///
    /// \param  queue_depths  A reference to the queue depths object from BPF.
    /// \param  bin_idx       The bin index (mcast or ucast).
    /// \param  k_val         A reference to the proxy's k value.
    /// \param  flow_id       The flow identifier.
    LogUtility(QueueDepths& queue_depths, BinIndex bin_idx, KVal& k_val,
               uint32_t flow_id);

    /// \brief destructor
    virtual ~LogUtility() {};

    /// \brief Initialize the Log Utility Function.
    ///
    /// \param  ci  The config info object containing the (key, value)
    ///             pairs for initialization.
    ///
    /// \return True if the Log Utility Function initialization is successful,
    ///         false otherwise.
    virtual bool Initialize(const ConfigInfo& ci);

    /// \brief Get the send rate, in bits per second, allowed by the utility
    /// function.
    ///
    /// \return The rate, in bits per second, at which to admit packets
    ///         into the network in order to maximize utility.
    virtual double GetSendRate();

    /// \brief  Compute the instantaneous utility.
    ///
    /// \param  send_rate The send rate for this utility.
    virtual double ComputeUtility(double send_rate);

    private:

    /// The utility function's max send rate parameter, in bits per second.
    double    m_val_;

    /// Backpressure queue normalization parameter (bits^2/sec).
    KVal&     k_val_;

    /// Normalized 'a' shape parameter for the utility function.
    double    a_val_;

  }; // end class LogUtility

} // namespace iron

#endif // IRON_PROXY_COMMON_LOG_UTILITY_H
