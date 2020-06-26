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

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//============================================================================

#ifndef IRON_SLIQ_CC_PACING_SENDER_H_
#define IRON_SLIQ_CC_PACING_SENDER_H_

#include "sliq_cc_interface.h"
#include "sliq_private_defs.h"
#include "sliq_private_types.h"
#include "sliq_rtt_manager.h"


namespace sliq
{

  /// \brief A wrapper for adding pacing to congestion control algorithms.
  ///
  /// Note that this class is not thread-safe.
  class PacingSender : public CongCtrlInterface
  {

   public:

    /// \brief Constructor.
    ///
    /// Creates a pacing sender that wraps the specified congestion control
    /// object.  This object takes ownership of the cc_alg object.
    ///
    /// \param  conn_id               The connection ID.
    /// \param  is_client             The flag determining if this is the
    ///                               client or server side of the connection.
    /// \param  cc_alg                The congestion control algorithm.
    /// \param  timer_granularity     Indicates to the pacer to send that far
    ///                               into the future, since it should not
    ///                               expect a callback before that time
    ///                               delta.
    /// \param  initial_packet_burst  The number of packets sent without
    ///                               pacing after quiescence.
    PacingSender(EndptId conn_id, bool is_client, CongCtrlInterface* cc_alg,
                 const iron::Time& timer_granularity,
                 size_t initial_packet_burst);

    /// \brief Destructor.
    virtual ~PacingSender();

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

    /// \brief Report the oldest unacknowledged packet for a stream.
    ///
    /// \param  stream_id       The stream's ID.
    /// \param  has_una_pkt     A flag reporting if the stream currently has
    ///                         an oldest unacknowledged packet or not.
    /// \param  una_cc_seq_num  The oldest unacknowledged packet's congestion
    ///                         control sequence number as assigned by
    ///                         OnPacketSent().  Only required if has_una_pkt
    ///                         is true.
    virtual void ReportUnaPkt(StreamId stream_id, bool has_una_pkt,
                              PktSeqNumber una_cc_seq_num);

    /// \brief Report if a fast retransmission timeout (RTO) timer is
    /// currently required.
    ///
    /// \return  Returns true if a fast RTO timer is currently required.
    virtual bool RequireFastRto();

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

    /// \brief Called when the packet counts must be adjusted.
    ///
    /// The packets in flight and bytes in flight counts include all unACKed
    /// packets.  The pipe size count includes all packets not ACKed, and adds
    /// the packet size once if the packet is not lost, and adds the packet
    /// size once if the packet has been retransmitted (so a packet that is
    /// not lost and retransmitted will be counted twice).  See RFC 6675,
    /// section 2.
    ///
    /// This method must be called once after the all of the OnPacketLost(),
    /// OnPacketAcked(), or OnPacketSent() methods are called for handling an
    /// ACK packet or sending a new data packet.
    ///
    /// \param  pif_adj   The adjustment to the number of packets in flight.
    ///                   Can be positive, zero, or negative.
    /// \param  bif_adj   The adjustment to the number of bytes in flight.
    ///                   Can be positive, zero, or negative.
    /// \param  pipe_adj  The adjustment to the pipe size, in bytes.
    ///                   Can be positive, zero, or negative.
    virtual void UpdateCounts(int32_t pif_adj, int64_t bif_adj,
                              int64_t pipe_adj);

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
    PacingSender(const PacingSender& ps);

    /// \brief Assignment operator.
    PacingSender& operator=(const PacingSender& ps);

    /// The congestion control algorithm being wrapped.
    CongCtrlInterface*  cc_alg_;

    /// The estimated system timer granularity.
    iron::Time          timer_granularity_;

    /// Configured maximum size of the burst coming out of quiescence. The
    /// burst is never larger than the current CWND in packets.
    size_t              initial_packet_burst_;

    /// Number of unpaced packets to be sent before packets are delayed.
    size_t              burst_tokens_;

    /// Send time of the last packet considered delayed.
    iron::Time          last_delayed_packet_sent_time_;

    /// When the next packet can be sent.
    iron::Time          ideal_next_packet_send_time_;

    /// Set to true when the last send was delayed.
    mutable bool        was_last_send_delayed_;

  }; // end class PacingSender

} // namespace sliq

#endif // IRON_SLIQ_CC_PACING_SENDER_H_
