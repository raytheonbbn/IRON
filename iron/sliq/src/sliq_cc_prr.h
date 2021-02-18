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

#ifndef IRON_SLIQ_CC_PRR_H
#define IRON_SLIQ_CC_PRR_H

#include "sliq_private_types.h"
#include "sliq_types.h"


namespace sliq
{
  ///
  /// Implements Proportional Rate Reduction (PRR) per RFC 6937.
  ///
  /// OnPacketLost() should be called on the first loss that triggers a
  /// recovery period, and all other methods in this class should only be
  /// called when in recovery.
  class Prr
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  conn_id  The connection ID.
    Prr(EndptId conn_id);

    /// \brief Destructor.
    virtual ~Prr();

    /// \brief Called on the first loss that triggers a recovery period.
    ///
    /// \param  bytes_in_flight  The number of bytes in flight.
    void OnPacketLost(size_t bytes_in_flight);

    /// \brief Called on any data packet transmission or retransmission during
    /// a recovery period.
    ///
    /// \param  sent_bytes  The number of bytes sent.
    void OnPacketSent(size_t sent_bytes);

    /// \brief Called on any ACK packet received during a recovery period.
    ///
    /// \param  acked_bytes  The number of additional bytes ACKed.
    void OnPacketAcked(size_t acked_bytes);

    /// \brief Called to check if a new data packet can be sent or not.
    ///
    /// \param  cwnd_bytes       The congestion window size in bytes.
    /// \param  bytes_in_flight  The number of bytes in flight.
    /// \param  ssthresh_bytes   The slow start threshold size in bytes.
    ///
    /// \return  True if a new data packet can be sent, or false otherwise.
    bool CanSend(size_t cwnd_bytes, size_t bytes_in_flight,
                 size_t ssthresh_bytes) const;

   private:

    /// The connection ID.
    EndptId  conn_id_;

    /// Bytes sent since the last loss event.  This is the same as "prr_out_"
    /// in RFC 6937.
    size_t   bytes_sent_since_loss_;

    /// Bytes ACKed since the last loss event.  This is the same as
    /// "prr_delivered_" in RFC 6937.
    size_t   bytes_delivered_since_loss_;

    /// The ACK count since the last loss event.
    size_t   ack_count_since_loss_;

    /// The congestion window before the last loss event.
    size_t   bytes_in_flight_before_loss_;

  }; // end class Prr

} // namespace sliq

#endif // IRON_SLIQ_CC_PRR_H
