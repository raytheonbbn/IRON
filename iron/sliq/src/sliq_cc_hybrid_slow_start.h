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

#ifndef IRON_SLIQ_CC_HYBRID_SLOW_START_H
#define IRON_SLIQ_CC_HYBRID_SLOW_START_H

#include "sliq_private_types.h"
#include "sliq_types.h"

#include "itime.h"


namespace sliq
{
  ///
  /// This class is a helper class to TcpCubicSender.
  ///
  /// Slow start is the initial startup phase of TCP, and it lasts until first
  /// packet loss.  This class implements hybrid slow start of the TCP cubic
  /// send side congestion algorithm.  The key feaure of hybrid slow start is
  /// that it tries to avoid running into the wall too hard during the slow
  /// start phase, which the traditional TCP implementation does.
  ///
  /// This does not implement ACK train detection because it interacts poorly
  /// with pacing.
  ///
  /// See:
  /// http://netsrv.csc.ncsu.edu/export/hybridstart_pfldnet08.pdf
  /// http://research.csc.ncsu.edu/netsrv/sites/default/files/
  ///   hystart_techreport_2008.pdf
  class HybridSlowStart
  {

   public:

    /// Constructor.
    ///
    /// \param  conn_id  The connection ID.
    HybridSlowStart(EndptId conn_id);

    /// Destructor.
    virtual ~HybridSlowStart();

    /// \brief Called when an ACK packet is received.
    ///
    /// Used to end the current RTT round.
    ///
    /// \param  acked_seq_num  The next expected sequence number from the
    ///                        received ACK packet.
    /// \param  in_slow_start  Specifies if congestion control is currently in
    ///                        slow start or not.
    void OnPacketAcked(PktSeqNumber acked_seq_num, bool in_slow_start);

    /// \brief Called when a data packet is transmitted.
    ///
    /// Do not call when a data packet is retransmitted.  Used to mark the
    /// last packet in the current RTT round.
    ///
    /// \param  seq_num  The sequence number of the data packet sent.
    inline void OnPacketSent(PktSeqNumber seq_num)
    {
      last_sent_seq_num_ = seq_num;
    }

    /// \brief Queries if slow start should be exited.
    ///
    /// This should be called each time a new RTT measurement is made when
    /// processing a received ACK packet.
    ///
    /// \param  rtt        The new RTT measurement.
    /// \param  min_rtt    The lowest RTT we have seen during the session.
    /// \param  cwnd_pkts  The congestion window size, in packets.
    ///
    /// \return  True if slow start should be exited, or false otherwise.
    bool ShouldExitSlowStart(iron::Time rtt, iron::Time min_rtt,
                             size_t cwnd_pkts);

    /// \brief Start a new slow start phase.
    ///
    /// This should be called when a RTO timeout occurs.
    void Restart();

   private:

    /// \brief Copy constructor.
    HybridSlowStart(const HybridSlowStart& hss);

    /// \brief Assignment operator.
    HybridSlowStart& operator=(const HybridSlowStart& hss);

    /// \brief Called to start a new RTT round.
    void StartReceiveRound();

    /// \brief Determine if this ACKed data packed ends the current RTT
    /// round.
    ///
    /// \param  acked_seq_num  The sequence number of the data packet being
    ///                        ACKed.
    ///
    /// \return  True if this ACK is the last sequence number of our current
    ///          RTT start round, false otherwise.
    bool IsEndOfRound(PktSeqNumber acked_seq_num) const;

    /// Whether a condition for exiting slow start has been found.
    enum HystartState
    {
      NOT_FOUND,

      /// Too much increase in the round's min_rtt was observed.
      DELAY,
    };

    /// The connection ID.
    EndptId       conn_id_;

    /// Records if the hybrid slow start has been started.
    bool          started_;

    /// Records if increasing delay is found.
    HystartState  hystart_found_;

    /// Last sequence number sent which was cwnd limited.
    PktSeqNumber  last_sent_seq_num_;

    /// End of the receive round.
    PktSeqNumber  end_seq_num_;

    /// Number of rtt samples in the current round.
    uint32_t      rtt_sample_count_;

    /// The minimum rtt of current round.
    iron::Time    current_min_rtt_;

  }; // end class HybridSlowStart

} // namespace sliq

#endif // IRON_SLIQ_CC_HYBRID_SLOW_START_H
