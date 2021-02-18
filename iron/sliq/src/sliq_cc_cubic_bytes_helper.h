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

/// Cubic algorithm, helper class to TCP cubic.
/// For details see:
///   http://netsrv.csc.ncsu.edu/export/cubic_a_new_tcp_2008.pdf

#ifndef IRON_SLIQ_CC_CUBIC_BYTES_HELPER_H
#define IRON_SLIQ_CC_CUBIC_BYTES_HELPER_H

#include "sliq_private_types.h"
#include "sliq_types.h"

#include "itime.h"

namespace sliq
{
  /// Helper class for the Cubic Bytes Congestion Control Algorithm.
  class CubicBytesHelper
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  conn_id  The connection ID.
    CubicBytesHelper(EndptId conn_id);

    /// \brief Destructor.
    virtual ~CubicBytesHelper();

    /// \brief Set the number of TCP flows.
    ///
    /// \param  num_flows  The number of TCP flows.
    inline void SetNumTcpFlows(int num_flows)
    {
      num_streams_ = num_flows;
    }

    /// \brief Reset the cubic state.
    void Reset();

    /// \brief Compute a new congestion window size, in bytes, to use after a
    /// loss event.
    ///
    /// \param  cur_cwnd  The current congestion window size in bytes.
    ///
    /// \return  The new congestion window size, in bytes.  The new congestion
    ///          window is a multiplicative decrease of our current window.
    size_t CongestionWindowAfterPacketLoss(size_t cur_cwnd);

    /// \brief Compute a new congestion window size, in bytes, to use after a
    /// received ACK.
    ///
    /// \param  acked_bytes  The number of additional bytes ACKed.
    /// \param  cur_cwnd     The current congestion window, in bytes.
    /// \param  delay_min    The minimum delay.
    /// \param  now          The current time.
    ///
    /// \return  The new congestion window size, in bytes.  The new congestion
    ///          window follows a cubic function that depends on the time
    ///          passed since the last packet loss.
    size_t CongestionWindowAfterAck(size_t acked_bytes, size_t cur_cwnd,
                                    const iron::Time& delay_min,
                                    const iron::Time& now);

   private:

    /// \brief Copy constructor.
    CubicBytesHelper(const CubicBytesHelper& cbh);

    /// \brief Assignment operator.
    CubicBytesHelper& operator=(const CubicBytesHelper& cbh);

    /// Get the maximum cubic time interval.
    ///
    /// \return  The maximum cubic time interval.
    static const iron::Time MaxCubicTimeInterval()
    {
      return iron::Time::FromMsec(30);
    }

    /// Compute the TCP Cubic alpha value based on the current number of
    /// connections.
    ///
    /// \return  The computed TCP Cubic alpha value.
    double Alpha() const;

    /// Compute the TCP Cubic beta value based on the current number of
    /// connections.
    ///
    /// \return  The computed TCP Cubic beta value.
    double Beta() const;

    /// The connection ID.
    EndptId     conn_id_;

    /// Number of connections to simulate.
    int         num_streams_;

    /// Time when this cycle started, after last loss event.
    iron::Time  epoch_;

    /// Time when we updated last_congestion_window.
    iron::Time  last_update_time_;

    /// Last congestion window used.
    size_t      last_cwnd_;

    /// Maximum congestion window used just before last loss event.  Note: To
    /// improve fairness to other streams, an additional back off is applied
    /// to this value if the new value is below our latest value.
    size_t      last_max_cwnd_;

    /// Number of ACKed bytes since the cycle started (epoch).
    size_t      acked_bytes_count_;

    /// TCP Reno equivalent congestion window in packets.
    size_t      estimated_tcp_cwnd_;

    /// Origin point of cubic function.
    size_t      origin_point_cwnd_;

    /// Time to origin point of cubic function in 2^10 fractions of a second.
    uint32_t    time_to_origin_point_;

    /// Last congestion window in packets computed by cubic function.
    size_t      last_target_cwnd_;

  }; // end class CubicBytesHelper

} // namespace sliq

#endif // IRON_SLIQ_CC_CUBIC_BYTES_HELPER_H
