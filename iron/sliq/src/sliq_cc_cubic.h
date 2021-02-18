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

#ifndef IRON_SLIQ_CC_CUBIC_H
#define IRON_SLIQ_CC_CUBIC_H

#include "sliq_cc_interface.h"
#include "sliq_private_defs.h"
#include "sliq_private_types.h"
#include "sliq_rtt_manager.h"


namespace sliq
{

  /// \brief The TCP CUBIC send-side congestion control algorithm adapted to
  /// work on bytes (as opposed to segments).
  ///
  /// This implementation of CUBIC, with Hybrid Slow Start (aka HyStart) and
  /// Proportional Rate Reduction (aka PRR), is based on the following
  /// documents:
  ///
  /// - Ha, S., Rhee, I., and Xu, L.  "CUBIC: A New TCP-Friendly High-Speed
  ///   TCP Variant".
  ///   https://research.csc.ncsu.edu/netsrv/sites/default/files/
  ///     cubic_a_new_tcp_2008.pdf
  ///
  /// - Updates to the CUBIC algorithm as implemented in the Linux 4.6.3
  ///   kernel.
  ///
  /// - Ha, S., and Rhee, I.  "Taming the Elephants: New TCP Slow Start".
  ///   https://research.csc.ncsu.edu/netsrv/sites/default/files/
  ///     hystart_techreport_2008.pdf
  ///
  /// - Updates to the HyStart algorithm as implemented in the Linux 4.6.3
  ///   kernel.
  ///
  /// - Mathis, M., Dukkipati, N., and Cheng, Y.  "Proportional Rate Reduction
  ///   for TCP".  RFC 6937.
  ///
  /// - Blanton, E., Allman, M., Wang, L., Jarvinen, I., Kojo, M., and
  ///   Nishida, Y.  "A Conservative Loss Recovery Algorithm Based on
  ///   Selective Acknowledgement (SACK) for TCP".  RFC 6675.
  ///
  /// - Allman, M., Paxson, V., and Blanton, E.  "TCP Congestion Control".
  ///   RFC 5681.
  ///
  /// Note that since SLIQ utilizes selective ACKs, the TCP Limited Transmit
  /// algorithm is not needed as specified in RFC 6675, page 8, item (3).
  /// SLIQ will reduce the number of bytes in flight for packets beyond
  /// snd_una that are ACKed, and this will behave similarly to TCP Limited
  /// Transmit.
  ///
  /// Note that the congestion window and slow start threshold values are
  /// computes in bytes, not segments.  This implementation follows TCP in
  /// only counting payload bytes in sent packets.
  ///
  /// \todo Should Ethernet, IP, UDP, and/or SLIQ headers be included in
  /// packet sizes for the congestion window computations?
  ///
  /// Note that this class is not thread-safe.
  class Cubic : public CongCtrlInterface
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  conn_id    The connection ID.
    /// \param  is_client  The flag determining if this is the client or
    ///                    server side of the connection.
    /// \param  rtt_mgr    A reference to the RTT manager.
    Cubic(EndptId conn_id, bool is_client, RttManager& rtt_mgr);

    /// \brief Destructor.
    virtual ~Cubic();

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

    /// \brief Get the current send pacing rate.
    ///
    /// May be zero if the rate is unknown.
    ///
    /// Note that the send pacing rate might be higher than the send rate for
    /// window-based congestion controls to ensure that the congestion window
    /// gets filled completely.
    ///
    /// \return  The current send pacing rate, in bits per second.  May be
    ///          zero.
    virtual Capacity SendPacingRate();

    /// \brief Get the current send rate.
    ///
    /// \return  The current send rate, in bits per second.
    virtual Capacity SendRate();

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
    Cubic(const Cubic& cb);

    /// \brief Assignment operator.
    Cubic& operator=(const Cubic& cb);

    /// \brief Compute the current send pacing rate.
    ///
    /// \return  The current send pacing rate in bits per second.
    double ComputePacingRate();

    /// \brief Update the next send time based on a transmission.
    ///
    /// \param  now    The current time.
    /// \param  bytes  The number of bytes just transmitted.
    void UpdateNextSendTime(const iron::Time& now, uint32_t bytes);

    /// \brief Update the CC sequence number for the lowest unACKed packet.
    void UpdateSndUna();

    /// \brief Restart an idle connection if needed.
    ///
    /// If the protocol is idle (not sending any packets) within one RTO
    /// period, then the congestion window is adjusted back to slow start.
    ///
    /// \param  now  The current time.
    void RestartIdleConnection(const iron::Time& now);

    /// \brief Check if the flow is congestion window limited.
    ///
    /// \return  True if the flow is congestion window limited.
    bool IsCwndLimited();

    /// \brief Update the congestion windowwhen in slow start or congestion
    /// avoidance.
    ///
    /// \param  now  The current time.
    void UpdateCwnd(const iron::Time& now);

    /// \brief Update the congestion window when in congestion avoidance using
    /// a CUBIC function.
    ///
    /// \param  now          The current time.
    /// \param  acked_bytes  The number of bytes that were ACKed.
    void CubicUpdate(const iron::Time& now, int64_t acked_bytes);

    /// \brief Recalculate the slow start threshold.
    ///
    /// \return  The updated slow start threshold value in bytes.
    int64_t CubicRecalcSsthresh();

    /// \brief Reset the CUBIC congestion control algorithm.
    void CubicReset();

    /// \brief Update HyStart delay increase detection when a new RTT sample
    /// is available.
    ///
    /// \param  delay  The new RTT sample.
    void HystartDelayUpdate(const iron::Time& delay);

    /// \brief Update HyStart ACK-train bandwidth-delay product detection when
    /// a collection of ACK packets have been received.
    ///
    /// \param  now  The current time.
    void HystartAckTrainUpdate(const iron::Time& now);

    /// \brief Reset the HyStart algorithm.
    void HystartReset();

    /// \brief Start the Proportional Rate Reduction algorithm for fast
    /// recovery.
    void BeginPrr();

    /// \brief Update the Proportional Rate Reduction algorithm for fast
    /// recovery after ACK processing.
    void UpdatePrr();

    /// \brief End the Proportional Rate Reduction algorithm for fast
    /// recovery.
    void EndPrr();

#ifdef SLIQ_CC_DEBUG
    /// \brief Print the congestion control state information.
    ///
    /// \param  fn  The calling function name string.
    void PrintState(const char* fn);
#endif

    /// \brief The per-stream congestion control information structure.
    ///
    /// Used for tracking stream-specific snd_una sequence numbers in order to
    /// determine the connection's snd_una.
    struct StreamCcInfo
    {
      StreamCcInfo();
      virtual ~StreamCcInfo();
      void AddStream(StreamId stream_id);
      void DelStream(StreamId stream_id);

      int       num_streams;
      StreamId  stream_ids[kMaxStreamId + 1];

      struct
      {
        // Records if the stream is initialized.
        bool          init_flag;
        // Records if the stream has an unacknowledged packet or not.
        bool          una_flag;
        // The oldest unacknowledged CC sequence number when una_flag is
        // true.
        PktSeqNumber  una_seq_num;
      }         cc_info[kMaxStreamId + 1];
    };

    /// \brief The Hybrid Slow Start events that can be detected.
    ///
    /// Designed to be combined into masks of events.
    enum HystartEvent
    {
      /// The Hybrid Slow Start ACK train event detection.
      kHystartAckTrainEvent = (1u << 0),

      /// The Hybrid Slow Start delay event detection.
      kHystartDelayEvent    = (1u << 1)
    };

    /// The RTT statistics.
    RttManager&       rtt_mgr_;

    /// The CUBIC TCP friendliness configuration setting.
    bool              config_cubic_tcp_friendliness_;

    /// The CUBIC fast convergence configuration setting.
    bool              config_cubic_fast_convergence_;

    /// The Hybrid Slow Start (HyStart) configuration setting.
    bool              config_hystart_;

    /// The HyStart events to be detected when enabled.
    uint32_t          config_hystart_detect_;

    /// The Proportional Rate Reduction (PRR) bounding algorithm to use.  May
    /// be Conservative Reduction Bound (CRB) by setting this to true, or Slow
    /// Start Reduction Bound (SSRB) by setting this to false.  Note that SSRB
    /// is more aggressive.
    bool              config_prr_crb_;

    /// The idle connection restart configuration setting.
    bool              config_idle_restart_;

    /// The flag to record when the snd_una_ member must be updated.
    bool              update_snd_una_;

    /// The CC sequence number for the lowest unACKed packet.
    PktSeqNumber      snd_una_;

    /// The CC sequence number for the next packet to be sent.
    PktSeqNumber      snd_nxt_;

    /// The CC sequence number for the right edge of the window when a
    /// congestion event occurs.
    PktSeqNumber      high_seq_;

    /// The byte offset for the next packet to be sent.  Can safely wrap
    /// around to zero.
    uint32_t          snd_nxt_byte_offset_;

    /// The array of byte offsets for each packet sent, as well as for the
    /// next packet to be sent.
    uint32_t*         pkt_byte_offset_;

    /// The congestion window size in bytes.
    int64_t           cwnd_;

    /// The slow start threshold size in bytes.
    int64_t           ssthresh_;

    /// The CUBIC beta value.  May be adjusted to make it more aggressive.
    /// Note that this is (1 - beta) using beta from the CUBIC paper.
    double            cubic_beta_;

    /// The CUBIC TCP congestion window size estimate in bytes.
    int64_t           cubic_cwnd_tcp_;

    /// The CUBIC scaled congestion window size in bytes when the last packet
    /// was lost.
    int64_t           cubic_cwnd_last_max_;

    /// The CUBIC last updated congestion window size in bytes.
    int64_t           cubic_last_cwnd_;

    /// The time when cubic_last_cwnd_ was set.
    iron::Time        cubic_last_time_;

    /// The CUBIC epoch start time after a packet was lost.
    iron::Time        cubic_epoch_start_;

    /// The minimum observed delay (RTT).
    iron::Time        cubic_delay_min_;

    /// The CUBIC origin point in bytes.
    int64_t           cubic_origin_point_;

    /// The CUBIC congestion window count limit for cubic_cwnd_cnt_.  Controls
    /// when cwnd_ should be increased.
    int64_t           cubic_cnt_;

    /// The CUBIC ACKed packet byte count for updating cubic_cwnd_tcp_.
    int64_t           cubic_ack_cnt_;

    /// The CUBIC ACKed packet byte count for updating cwnd_.
    int64_t           cubic_cwnd_cnt_;

    /// The CUBIC time period, as a number of 1/1024 second intervals, that
    /// the window growth function takes to increase the congestion window
    /// size to cubic_origin_point_.
    int64_t           cubic_k_;

    /// The end sequence number of the HyStart round.
    PktSeqNumber      hystart_end_seq_;

    /// The beginning of each HyStart round.  Used in ACK train detection.
    iron::Time        hystart_round_start_;

    /// The last time when the ACK spacing is close.  Used in ACK train
    /// detection.
    iron::Time        hystart_last_ack_;

    /// The minimum RTT of the current HyStart round.  Used in delay event
    /// detection.
    iron::Time        hystart_curr_rtt_;

    /// The number of samples to decide hystart_curr_rtt_.
    uint32_t          hystart_sample_cnt_;

    /// The HyStart exit points that have been found.
    uint32_t          hystart_found_;

    /// The RTO event flag.  Set to true when the RTO timer expires, and is
    /// reset to false when a packet is successfully ACKed.
    bool              in_rto_;

    /// The flag controlling when fast recovery (PRR) should be entered.
    bool              enter_fast_recovery_;

    /// The fast recovery flag.  Set to true when in fast recovery (PRR).
    bool              in_fast_recovery_;

    /// The CC sequence number for exiting PRR.
    PktSeqNumber      prr_recovery_point_;

    /// The number of newly delivered bytes to the receiver in PRR.
    int64_t           prr_delivered_;

    /// The total number of bytes sent while in PRR.
    int64_t           prr_out_;

    /// The flight size, in bytes, at the start of PRR.
    int64_t           prr_recover_fs_;

    /// The number of bytes that should be sent in response to received ACK
    /// packets while in PRR.
    int64_t           prr_sndcnt_;

    /// The last application packet transmission time.
    iron::Time        last_app_send_time_;

    /// The last protocol packet transmission time.
    iron::Time        last_proto_send_time_;

    /// The next packet transmission time used for send pacing.
    iron::Time        next_send_time_;

    /// The tolerance used for send pacing timers.
    iron::Time        timer_tolerance_;

    /// The maximum number of bytes in flight in the last window.
    int64_t           max_bytes_out_;

    /// The snd_nxt_ CC sequence number when max_bytes_out_ is updated.
    PktSeqNumber      max_bytes_seq_;

    /// The total number of bytes in flight before a collection of received
    /// ACK packets is processed.
    int64_t           pre_ack_bytes_in_flight_;

    /// The flight size in bytes.  Only includes packets that have been sent
    /// and have not been cumulatively ACKed yet.  See RFC 5681 for details.
    int64_t           flight_size_;

    /// The per-stream congestion control information.
    StreamCcInfo      stream_cc_info_;

  }; // end class Cubic

} // namespace sliq

#endif // IRON_SLIQ_CC_CUBIC_H
