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

#ifndef IRON_SLIQ_CC_FIXED_RATE_H
#define IRON_SLIQ_CC_FIXED_RATE_H

#include "sliq_cc_interface.h"
#include "sliq_private_defs.h"
#include "sliq_private_types.h"
#include "sliq_connection.h"


namespace sliq
{

  /// \brief A send-side replacement for a congestion control algorithm that
  /// sends at a configurable, fixed rate.
  ///
  /// For use in testing parts of SLIQ (such as error control algorithms) when
  /// it is important that congestion control algorithms do not interfere with
  /// the test results.  The send rate is utilized on both the local and
  /// remote sides of the SLIQ connection via the SLIQ connection handshake
  /// header.  Thus, the send rate is set by the side that originates the
  /// connection.
  ///
  /// This is not an actual congestion control algorithm, and must not be used
  /// when congestion control is needed.
  ///
  /// Note that this class is not thread-safe.
  class FixedRate : public CongCtrlInterface
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  conn_id    The connection ID.
    /// \param  is_client  The flag determining if this is the client or
    ///                    server side of the connection.
    FixedRate(EndptId conn_id, bool is_client);

    /// \brief Destructor.
    virtual ~FixedRate();

    /// \brief Configure the congestion control algorithm.
    ///
    /// \param  cc_params  The congestion control parameters to use.
    ///
    /// \return  Returns true on success, or false if an error occurs.
    virtual bool Configure(const CongCtrl& cc_params);

    /// \brief Called once the connection is established.
    ///
    /// \param  now  The current time.
    /// \param  rtt  The initial RTT estimate from the connection handshake.
    virtual void Connected(const iron::Time& now, const iron::Time& rtt);

    /// \brief Determine if non-RTO timeout retransmitted packets should be
    /// paced or not.
    ///
    /// \return  True if the congestion control algorithm requires pacing of
    ///          non-RTO timeout retransmitted packets, or false if it
    ///          requires immediate sending.
    virtual bool UseRexmitPacing();

    /// \brief Determine if the congestion window size should be used to
    /// compute capacity estimates.
    ///
    /// \return  True if the congestion control algorithm's congestion window
    ///          size should be used to compute capacity estimates, or false
    ///          if the congestion control algorithm's rate estimate should be
    ///          used instead.
    virtual bool UseCongWinForCapEst();

    /// \brief Determine if the oldest unacknowledged packet must be reported
    /// for each stream or not.
    ///
    /// If so, then the ReportUnaPkt() method must be called with the oldest
    /// unacknowledged packet sequence number for all streams.
    ///
    /// \return  True if the congestion control algorithm requires reporting
    ///          of the oldest unacknowledged packet for all streams, or false
    ///          if not.
    virtual bool UseUnaPktReporting();

    /// \brief Ajust the TCP friendliness/aggressiveness of the congestion
    /// control algorithm.
    ///
    /// \param  num_flows  The number of TCP flows to emulate in terms of
    ///                    TCP friendliness/aggressiveness.  The higher the
    ///                    number, the more aggressive.  Must be greater than
    ///                    or equal to one.
    ///
    /// \return  Returns true on success, or false if this setting is not
    ///          supported by the algorithm.
    virtual bool SetTcpFriendliness(uint32_t num_flows);

    /// \brief Add a new stream.
    ///
    /// Must be called when a new stream is added to the connection, and
    /// before any data packets are sent.  This is necessary in order to
    /// include the stream in connection-level congestion control decisions.
    ///
    /// \param  stream_id          The stream's ID.
    /// \param  init_send_seq_num  The initial data packet send sequence
    ///                            number that will be used in the stream.
    ///
    /// \return  Returns true on success, or false if an error occurs.
    virtual bool ActivateStream(StreamId stream_id,
                                PktSeqNumber init_send_seq_num);

    /// \brief Deactivate a stream.
    ///
    /// Must be called when an active stream becomes inactive.  This is
    /// necessary in order to eliminate the stream from connection-level
    /// congestion control decisions.
    ///
    /// \param  stream_id  The stream's ID.
    ///
    /// \return  Returns true on success, or false if an error occurs.
    virtual bool DeactivateStream(StreamId stream_id);

    /// \brief Called before the OnRttUpdate(), OnPacketLost(), and
    /// OnPacketAcked() calls for a collection of received ACK packets (all
    /// within a single UDP packet).
    ///
    /// \param  ack_time  The ACK packet collection's receive time.
    virtual void OnAckPktProcessingStart(const iron::Time& ack_time);

    /// \brief Called when an update to the round-trip-time occurs while
    /// processing received ACK packets.
    ///
    /// \param  stream_id   The stream's ID.
    /// \param  ack_time    The ACK packet's receive time.
    /// \param  send_ts     The sender's timestamp from the ACK packet, in
    ///                     microseconds.
    /// \param  recv_ts     The receiver's timestamp from when the ACK packet
    ///                     was received, in microseconds.
    /// \param  seq_num     The lost packet's sequence number.
    /// \param  cc_seq_num  The lost packet's congestion control sequence
    ///                     number as assigned by OnPacketSent().
    /// \param  rtt         The measured round-trip-time.
    /// \param  bytes       The size of the packet being ACKed in bytes.
    /// \param  cc_val      The CC-specific value that was stored when the
    ///                     packet was sent or resent.
    virtual void OnRttUpdate(StreamId stream_id, const iron::Time& ack_time,
                             PktTimestamp send_ts, PktTimestamp recv_ts,
                             PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                             const iron::Time& rtt, uint32_t bytes,
                             float cc_val);

    /// \brief Called when a packet could be considered lost while processing
    /// received ACK packets.
    ///
    /// The method is called repeatedly for each packet that might be
    /// considered lost until it returns true.
    ///
    /// Note that the UpdateCounts() method must be called after all calls to
    /// this method are complete for an ACK packet.
    ///
    /// \param  stream_id   The stream's ID.
    /// \param  ack_time    The ACK packet's receive time.
    /// \param  seq_num     The lost packet's sequence number.
    /// \param  cc_seq_num  The lost packet's congestion control sequence
    ///                     number as assigned by OnPacketSent().
    /// \param  bytes       The lost packet's size in bytes.
    ///
    /// \return  True if the packet should be considered lost and scheduled
    ///          for retransmission immediately, or false if not.
    virtual bool OnPacketLost(StreamId stream_id, const iron::Time& ack_time,
                              PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                              uint32_t bytes);

    /// \brief Called when a packet is ACKed (reported as received) while
    /// processing received ACK packets.
    ///
    /// This method must only be called once for each packet when it is ACKed.
    ///
    /// Note that the UpdateCounts() method must be called after all calls to
    /// this method are complete for an ACK packet.
    ///
    /// \param  stream_id   The stream's ID.
    /// \param  ack_time    The ACK packet's receive time.
    /// \param  seq_num     The ACKed packet's sequence number.
    /// \param  cc_seq_num  The congestion control sequence number, as
    ///                     assigned by OnPacketSent(), of the ACKed packet.
    /// \param  ne_seq_num  The ACK packet's next expected sequence number.
    /// \param  bytes       The size of the packet being ACKed in bytes.
    virtual void OnPacketAcked(StreamId stream_id, const iron::Time& ack_time,
                               PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                               PktSeqNumber ne_seq_num, uint32_t bytes);

    /// \brief Called when all of the OnRttUpdate(), OnPacketLost(), and
    /// OnPacketAcked() calls are complete for a collection of received ACK
    /// packets (all within a single UDP packet).
    ///
    /// \param  ack_time  The ACK packet collection's receive time.
    virtual void OnAckPktProcessingDone(const iron::Time& ack_time);

    /// \brief Called when a data packet is transmitted the first time.
    ///
    /// Do not call on data packet retransmissions.  This function must be
    /// called for every new data packet sent to the wire.  It returns an
    /// assigned congestion control sequence number for the packet.
    ///
    /// Note that the UpdateCounts() method must be called after this call is
    /// complete.
    ///
    /// \param  stream_id  The stream's ID.
    /// \param  send_time  The data packet's transmission time.
    /// \param  seq_num    The data packet's sequence number.
    /// \param  pld_bytes  The number of payload bytes transmitted.
    /// \param  tot_bytes  The total number of bytes transmitted.
    /// \param  cc_val     The reference to a CC-specific value that is stored
    ///                    for the sent packet.
    ///
    /// \return  The data packet's assigned congestion control sequence
    ///          number.
    virtual PktSeqNumber OnPacketSent(StreamId stream_id,
                                      const iron::Time& send_time,
                                      PktSeqNumber seq_num,
                                      uint32_t pld_bytes, uint32_t tot_bytes,
                                      float& cc_val);

    /// \brief Called when a data packet is retransmitted.
    ///
    /// Do not call on the original data packet transmission.
    ///
    /// Note that the UpdateCounts() method must be called after this call is
    /// complete.
    ///
    /// \param  stream_id   The stream's ID.
    /// \param  send_time   The data packet's retransmission time.
    /// \param  seq_num     The data packet's sequence number.
    /// \param  cc_seq_num  The data packet's congestion control sequence
    ///                     number as assigned by OnPacketSent().
    /// \param  pld_bytes   The number of payload bytes transmitted.
    /// \param  tot_bytes   The total number of bytes transmitted.
    /// \param  rto         True if the retransmission is due to an RTO event.
    /// \param  orig_cc     True if this is the congestion control algorithm
    ///                     that sent the original data packet.
    /// \param  cc_val      The reference to a CC-specific value that is
    ///                     stored for the resent packet.
    virtual void OnPacketResent(StreamId stream_id,
                                const iron::Time& send_time,
                                PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                                uint32_t pld_bytes, uint32_t tot_bytes,
                                bool rto, bool orig_cc, float& cc_val);

    /// \brief Called when the retransmission timeout (RTO) timer fires.
    ///
    /// Note that OnPacketLost() will not be called for these packets.
    ///
    /// \param  pkt_rexmit  Indicates if the oldest missing packet on the
    ///                     highest priority stream has been retransmitted due
    ///                     to the RTO timer or not.
    virtual void OnRto(bool pkt_rexmit);

    /// \brief Called when an outage is over.
    virtual void OnOutageEnd();

    /// \brief Check if a new data packet can be sent.
    ///
    /// This method is used to determine if the algorithm is currently
    /// allowing or blocking the transmission of a new data packet.  Do not
    /// call this method to check if a data packet retransmission can occur.
    ///
    /// Note that TimeUntilSend() should be called in order to pace data
    /// packet transmissions.
    ///
    /// \param  now    The current time.
    /// \param  bytes  The number of bytes that would be sent.
    ///
    /// \return  True if not currently congestion control blocked, or false
    ///          otherwise.
    virtual bool CanSend(const iron::Time& now, uint32_t bytes);

    /// \brief Check if a fast retransmit data packet can be sent.
    ///
    /// This method is used to determine if the algorithm is currently
    /// allowing or blocking the fast retransmission of a data packet.  Do not
    /// call this method to check if a new data packet transmission can occur.
    ///
    /// Note that if UseRexmitPacing() returns true, then TimeUntilSend()
    /// should be called in order to pace the retransmission.
    ///
    /// \param  now      The current time.
    /// \param  bytes    The number of bytes that would be resent.
    /// \param  orig_cc  True if this is the congestion control algorithm that
    ///                  sent the original data packet.
    ///
    /// \return  True if not currently congestion control blocked, or false
    ///          otherwise.
    virtual bool CanResend(const iron::Time& now, uint32_t bytes,
                           bool orig_cc);

    /// \brief Calculate the time of the next data packet transmission.
    ///
    /// The method is used to implement send pacing of data packets.  If the
    /// returned time is zero, then a transmission can occur immediately.
    /// Otherwise, the next transmission must wait for the returned time to
    /// elapse first.  This method will never return an infinite time.
    ///
    /// This method should always be called for new data packets, and should
    /// only be called for non-RTO timeout retransmitted data packets if
    /// UseRexmitPacing() returns true.
    ///
    /// \param  now  The current time.
    ///
    /// \return  The amount of time until the next send can occur.
    virtual iron::Time TimeUntilSend(const iron::Time& now);

    /// \brief Get the current pacing rate, in bits per second.
    ///
    /// May be zero if the rate is unknown.
    ///
    /// Note that the pacing rate might be higher than the computed congestion
    /// control rate for window-based congestion controls to ensure that the
    /// congestion window gets filled completely.
    ///
    /// \return  The pacing rate of the congestion control algorithm, in bits
    ///          per second.
    virtual Capacity PacingRate();

    /// \brief Get the current estimated channel capacity, in bits per second.
    ///
    /// \return  The current estimated channel capacity, in bits per second,
    ///          or 0 if there is no estimate.
    virtual Capacity CapacityEstimate();

    /// \brief Get any optional congestion control parameters that must be
    /// transferred to the other end of the connection.
    ///
    /// These parameters are exhanged for synchronization of the congestion
    /// control algorithm.  They are sent best effort.
    ///
    /// \param  seq_num    A reference where the sequence number for the
    ///                    message is placed when true is returned.
    /// \param  cc_params  A reference where the congestion control parameters
    ///                    to be sent are placed when true is returned.
    ///
    /// \return  True if there are congestion control parameters to be sent.
    virtual bool GetSyncParams(uint16_t& seq_num, uint32_t& cc_params);

    /// \brief Process the received congestion control parameters from the
    /// other end of the connection for synchronization of the algorithm.
    ///
    /// These parameters are exhanged for synchronization of the congestion
    /// control algorithm.  They are sent best effort.
    ///
    /// \param  now        The current time.
    /// \param  seq_num    The received sequence number.
    /// \param  cc_params  The received congestion control parameters.
    virtual void ProcessSyncParams(const iron::Time& now, uint16_t seq_num,
                                   uint32_t cc_params);

    /// \brief Process the received congestion control packet train packet
    /// header from the peer.
    ///
    /// These parameters are exhanged for characterizing the channel to the
    /// peer.  They are sent best effort.
    ///
    /// \param  now  The current time.
    /// \param  hdr  A reference to the received congestion control packet
    ///              train header.
    virtual void ProcessCcPktTrain(const iron::Time& now,
                                   CcPktTrainHeader& hdr);

    /// \brief Queries if the congestion control algorithm is currently in
    /// slow start.
    ///
    /// When true, the CapacityEstimate() is expected to be too low.
    ///
    /// \return  True if the congestion control algorithm is currently in slow
    ///          start, or false otherwise.
    virtual bool InSlowStart();

    /// \brief Queries if the congestion control algorithm is currently in
    /// fast recovery.
    ///
    /// \return  True if the congestion control algorithm is currently in fast
    ///          recovery, or false otherwise.
    virtual bool InRecovery();

    /// \brief Get the current congestion window size, in bytes.
    ///
    /// \return  The current congestion window size, in bytes.  Note, this is
    ///          not the *available* window.  Some congestion control
    ///          algorithms may not use a congestion window and will return 0.
    virtual uint32_t GetCongestionWindow();

    /// \brief Get the current slow start threshold, in bytes.
    ///
    /// \return  The size of the slow start congestion window, in bytes, aka
    ///          ssthresh.  Some congestion control algorithms do not define a
    ///          slow start threshold and will return 0.
    virtual uint32_t GetSlowStartThreshold();

    /// \brief Get the congestion control type.
    ///
    /// \return  The congestion control type.
    virtual CongCtrlAlg GetCongestionControlType();

    /// \brief Close the congestion control object.
    virtual void Close();

   private:

    /// \brief Copy constructor.
    FixedRate(const FixedRate& fr);

    /// \brief Assignment operator.
    FixedRate& operator=(const FixedRate& fr);

    /// \brief Update the next send time based on a transmission.
    ///
    /// \param  now    The current time.
    /// \param  bytes  The total number of bytes (SLIQ headers and payload)
    ///                just transmitted.
    void UpdateNextSendTime(const iron::Time& now, size_t bytes);

    /// The connected flag.
    bool          connected_;

    /// The fixed send rate, in bps (bits/second).
    Capacity      send_rate_bps_;

    /// The next congestion control sequence number to be sent.
    PktSeqNumber  nxt_cc_seq_num_;

    /// The time that the next packet can be sent.
    iron::Time    next_send_time_;

    /// The tolerance used for timers.
    iron::Time    timer_tolerance_;

  }; // end class FixedRate

}; // namespace sliq

#endif // IRON_SLIQ_CC_FIXED_RATE_H
