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

//============================================================================
//
// This code is derived in part from the stablebits libquic code available at:
// https://github.com/stablebits/libquic.
//
// The stablebits code was forked from the devsisters libquic code available
// at:  https://github.com/devsisters/libquic
//
// The devsisters code was extracted from Google Chromium's QUIC
// implementation available at:
// https://chromium.googlesource.com/chromium/src.git/+/master/net/quic/
//
// The original source code file markings are preserved below.

// Copyright (c) 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//============================================================================

#ifndef IRON_SLIQ_RTT_MANAGER_H_
#define IRON_SLIQ_RTT_MANAGER_H_

#include "sliq_types.h"

#include "log.h"
#include "itime.h"

namespace sliq
{
  class Connection;

  /// A class for managing RTT measurements.
  class RttManager
  {

   public:

    /// Constructor.
    RttManager();

    /// Destructor.
    virtual ~RttManager();

    /// Updates the RTT from an incoming ACK packet.
    ///
    /// \param  conn_id     The connection ID.
    /// \param  rtt_sample  The new RTT sample.
    void UpdateRtt(EndptId conn_id, const iron::Time& rtt_sample);

    /// \brief Get the next RTO time.
    ///
    /// The next RTO time is computed as follows:
    ///
    ///   RTO = max( (A + 4D + ACK_DELAY), 200 msec )
    ///
    /// where A is the smoothed RTT, D is the smoothed mean deviation, and
    /// ACK_DELAY is the amount of time that an ACK can be delayed by a
    /// receiver.
    ///
    /// \return The next RTO time.
    iron::Time GetRtoTime() const;

    /// \brief Get the retransmission time.
    ///
    /// The retransmission time is computed as follows:
    ///
    ///   RTO = A + (M * D) + ACK_DELAY
    ///
    /// where A is the smoothed RTT, M is the multiplier, D is the smoothed
    /// mean deviation, and ACK_DELAY is the amount of time that an ACK can be
    /// delayed by a receiver.
    ///
    /// \param  multiplier  The smoothed mean deviation multiplier.  Defaults
    ///                     to 4, per RFC 6298.
    ///
    /// \return The retransmission time.
    iron::Time GetRexmitTime(int multiplier = 4) const;

    /// \brief Get the fast retransmission time.
    ///
    /// The retransmission time is computed as follows:
    ///
    ///   RTO = A + 4D
    ///
    /// where A is the smoothed RTT and D is the smoothed mean deviation.
    /// This is for use when packets are lost and ACKs are not being delayed
    /// by a receiver.
    ///
    /// \return The fast retransmission time.
    iron::Time GetFastRexmitTime() const;

    /// \brief Get the smoothed RTT.
    ///
    /// \return The smoothed RTT.
    inline iron::Time smoothed_rtt() const
    {
      return smoothed_rtt_;
    }

    /// \brief Get the RTT's smoothed mean deviation.
    ///
    /// \return The RTT's smoothed mean deviation.
    inline iron::Time mean_deviation() const
    {
      return mean_deviation_;
    }

    /// \brief Get the latest RTT received.
    ///
    /// \return The latest RTT received.
    inline iron::Time latest_rtt() const
    {
      return latest_rtt_;
    }

    /// \brief Get the minimum RTT received.
    ///
    /// \return The minimum RTT received.
    inline iron::Time minimum_rtt() const
    {
      return min_rtt_;
    }

   private:

    /// \brief Copy constructor.
    RttManager(const RttManager& rm);

    /// \brief Assignment operator.
    RttManager& operator=(const RttManager& rm);

    /// The initializeation flag.
    bool         initialized_;

    /// The smoothed RTT.
    iron::Time   smoothed_rtt_;

    /// Smoothed mean deviation.  Approximation of standard deviation.  The
    /// error is roughly 1.25 times larger than the standard deviation, for a
    /// normally distributed signal.
    iron::Time   mean_deviation_;

    /// The latest RTT.
    iron::Time   latest_rtt_;

    /// The minimum RTT.
    iron::Time   min_rtt_;

  }; // end class RttManager

} // namespace sliq

#endif // IRON_SLIQ_RTT_MANAGER_H_
