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

#ifndef IRON_SLIQ_CC_COPA2_H
#define IRON_SLIQ_CC_COPA2_H

#include "sliq_cc_interface.h"
#include "sliq_private_defs.h"
#include "sliq_private_types.h"
#include "sliq_connection.h"


namespace sliq
{

  /// \brief The Copa2 send-side congestion control algorithm.
  ///
  /// Implements the Copa2 algorithm as described in the following paper:
  ///
  ///   Arun, V., and Balakrishnan, H.  Copa: Congestion Control Combining
  ///   Objective Optimization with Simple Window Adjustments.  Submitted to
  ///   USENIX NSDI (2018).
  ///
  /// Note the following deviations:
  /// - The initial congestion window size is set to 3 packets instead of 10
  ///   packets.
  /// - In order to support different packet sizes, the Copa2 congestion
  ///   window size is converted from packets to bytes using a nominal packet
  ///   size of 1000 bytes.  When updating the congestion window size, the
  ///   adjustments amounts are scaled by the ratio of the packet size to the
  ///   nominal packet size.
  /// - The congestion window size increases are skipped when the current
  ///   congestion window size is greater than twice the number of nominal
  ///   packets in flight in order to prevent it from growing indefinitely
  ///   when the send rate is not keeping the channel full.
  /// - During fast startup, the packet pair inter-receive time is not
  ///   computed at the local side when the two FS_ACK packets are received.
  ///   Instead, the far side computes the packet pair inter-receive time and
  ///   sends it back to the local side in the second FS_ACK packet.  We have
  ///   found that this method generates much more accurate bottleneck link
  ///   rate estimates, and should work better over asymmetric links.
  /// - During fast startup, 11 packet pairs are sent instead of 10, and the
  ///   measurements from the first packet pair are not used for estimating
  ///   the bottleneck link rate.  We have found that the first packet pair
  ///   measurements can be very inaccurate compared to later packet pair
  ///   measurements.
  /// - The fast startup equation listed in the paper is not correct.  The
  ///   equation listed in the paper is (2 / (delta * (Rmin + Rmax))).  The
  ///   correct equation is (2 / (delta * (Rmax - Rmin))).
  /// - As discussed in the paper in Section 4.2, TCP mode only works properly
  ///   if the propagation delay is greater than or equal to the queueing
  ///   delay and the senders that are sharing the bottleneck link have the
  ///   same propagation delays.  However, the TCP compatibility algorithm as
  ///   specified in the paper did not work well in our testing.  Thus, this
  ///   implementation uses a modified algorithm which is currently a work in
  ///   progress.
  /// - A minimum RTT tracking algorithm developed by BBN is included.  This
  ///   detects when the minimum RTT should be increased and increases it.
  ///   Note that this algorithm is only used when in default mode.
  /// - In order to improve operation when the network latency increases to
  ///   high levels, a selective damper developed by BBN is included.  This
  ///   damper is only activated when an unusually large number of packets are
  ///   detected in the computed queueing delay.  Once activated, the damper
  ///   waits until the computed queueing delay is measured as being 1/delta
  ///   packets (2 packets).  When this occurs, it sets the congestion window
  ///   size to the value in use when the packet was sent and holds it there
  ///   for one RTT, then waits another RTT before allowing the damper to be
  ///   used again.  The result is the elimination of the large, slow
  ///   oscillations as Copa2 locks onto the correct send rate.
  ///
  /// \todo Improve the Copa2 TCP compatibility algorithm.
  ///
  /// Note that this class is not thread-safe.
  class Copa2 : public CongCtrlInterface
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  conn_id    The connection ID.
    /// \param  is_client  The flag determining if this is the client or
    ///                    server side of the connection.
    /// \param  cc_id      The congestion control ID.
    /// \param  conn       A reference to the associated connection.
    /// \param  framer     A reference to the packet framer.
    /// \param  pkt_pool   A reference to packet pool.
    /// \param  timer      A reference to timer.
    Copa2(EndptId conn_id, bool is_client, CcId cc_id, Connection& conn,
          Framer& framer, iron::PacketPool& pkt_pool, iron::Timer& timer);

    /// \brief Destructor.
    virtual ~Copa2();

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
    Copa2(const Copa2& c);

    /// \brief Assignment operator.
    Copa2& operator=(const Copa2& c);

    /// \brief Get the current time as a double.
    ///
    /// The returned time is the number of seconds since start-up as a
    /// floating point number.
    ///
    /// \param  now  The current time.
    ///
    /// \return  The current time, in seconds, as a double.
    double CurrentTime(const iron::Time& now);

    /// \brief Update the next send time based on a transmission.
    ///
    /// \param  now    The current time.
    /// \param  bytes  The number of bytes just transmitted.
    void UpdateNextSendTime(const iron::Time& now, size_t bytes);

    /// \brief Send a packet pair consisting of two congestion control packet
    /// train packets.
    ///
    /// \param  first_seq  The first packet sequence number to use.  The
    ///                    second sequence number will be one larger than this
    ///                    number.
    void SendPktPair(uint8_t first_seq);

    /// \brief Send a packet pair acknowledgement packet consisting of a
    /// single congestion control packet train packet.
    ///
    /// \param  seq       The sequence number to acknowledge.
    /// \param  irt_usec  The packet pair inter-receive time observed, or 0 if
    ///                   not used.
    void SendPktPairAck(uint8_t seq, uint32_t irt_usec);

    /// \brief Send a fast startup packet pair and start the necessary timer
    /// for the next event.
    void FsPktPairCallback();

    /// \brief End fast startup and transition to closed loop operation.
    void FsDoneCallback();

    /// The number of packet pairs sent within two RTTs during fast startup.
    static const size_t  kNumFsPairs         = 11;

    /// The maximum number of periods during which parameters are tracked for
    /// TCP compatibility.  Must be set to the larger of kDfltModePeriods and
    /// kTcpModePeriods.  The MIT algorithm would have this set to 2.
    static const size_t  kTcpCompStateSize   = 4;

    /// The number of TCP compatibility periods during which parameters are
    /// tracked when in default mode.  The MIT algorithm would have this set
    /// to 2.
    static const size_t  kDfltModePeriods    = 4;

    /// The number of TCP compatibility periods during which parameters are
    /// tracked when in TCP mode.  The MIT algorithm would have this set to 2.
    static const size_t  kTcpModePeriods     = 3;

    /// The number of RTT periods in each TCP compatibility period when in
    /// default mode.  The MIT algorithm would have this set to 2.
    static const size_t  kDfltModeRttPeriods = 32;

    /// The number of RTT periods in each TCP compatibility period when in
    /// TCP mode.  The MIT algorithm would have this set to 2.
    static const size_t  kTcpModeRttPeriods  = 2;

    /// The number of RTT periods used in tracking increases to the minimum
    /// RTT.
    static const size_t  kMinRttPeriods      = 8;

    /// The number of RTT periods used in tracking the inter-send times as
    /// part of the minimum RTT tracking recovery mechanism.
    static const size_t  kMinRttIstPeriods   = (kMinRttPeriods + 2);

    /// \brief The Copa2 operating states.
    enum OpState
    {
      NOT_CONNECTED = 0,
      FAST_STARTUP  = 1,
      CLOSED_LOOP   = 2
    };

    /// \brief The structure for fast startup state.
    struct FastStartup
    {
      FastStartup();
      ~FastStartup();
      void Clear();

      /// The number of packets pairs sent.
      uint32_t             pairs_sent_;

      /// The send time for each FS_DATA packet pair.
      iron::Time           pair_send_time_[kNumFsPairs];

      /// The receive time of the first FS_DATA packet in each packet pair.
      iron::Time           pair_recv_time_[kNumFsPairs];

      /// The RTT estimate computed for each packet pair, in seconds.
      double               rtt_[kNumFsPairs];

      /// The bottleneck link rate estimate for each packet pair, in packets
      /// per second.
      double               rate_[kNumFsPairs];

      /// The timer handle used for performing fast startup operations at the
      /// correct time.
      iron::Timer::Handle  timer_;
    };

    /// \brief The fast startup packet types.
    enum FsPktType
    {
      FS_DATA = 0,
      FS_ACK  = 1
    };

    /// \brief The structure for minimum RTT tracking.
    struct MinRttTracking
    {
      MinRttTracking();
      ~MinRttTracking();

      /// The minimum RTT observed in the current RTT period, in seconds.
      double      recent_min_rtt_;

      /// The array of minimum RTTs for each RTT period, in seconds.
      double      min_rtt_[kMinRttPeriods];

      /// The number of minimum RTTs in the array.
      uint32_t    count_;

      /// The index where the next minimum RTT will be placed.
      uint32_t    next_rtt_index_;

      /// The array of inter-send times at the end of each RTT period, in
      /// seconds.  The oldest element is used to recover the send rate when
      /// the minimum RTT is increased.
      double      ist_[kMinRttIstPeriods];

      /// The index where the next inter-send time will be placed.
      uint32_t    next_ist_index_;

      /// The previous update time.
      iron::Time  prev_time_;
   };

    /// \brief The structure for TCP compatibility.
    struct TcpCompat
    {
      TcpCompat();
      ~TcpCompat();

      /// The flag recording if currently in default mode (false) or TCP mode
      /// (true).
      bool        in_tcp_mode_;

      /// The number of RTT periods in the current TCP compatibility period.
      size_t      rtt_periods_;

      /// The threshold value, in seconds, for determining if a queueing delay
      /// indicates a nearly empty bottleneck queue or not.
      double      nearly_empty_threshold_;

      /// The maximum queueing delay observed in the current RTT period, in
      /// seconds.
      double      recent_max_qd_;

      /// The minimum queueing delay observed in the current RTT period, in
      /// seconds.
      double      recent_min_qd_;

      /// The array of maximum queueing delays observed for each TCP
      /// compatibility period, in seconds.
      double      max_qd_[kTcpCompStateSize];

      /// The number of nearly empty queue events observed in the current RTT
      /// period.
      uint32_t    recent_neq_;

      /// The array of counts of nearly empty queue events for each TCP
      /// compatibility period.
      uint32_t    neq_[kTcpCompStateSize];

      /// The index where the next maximum queueing delay and nearly empty
      /// queue event count will be placed.
      uint32_t    next_index_;

      /// The RTT period counter for ending the current TCP compatibility
      /// period.
      uint32_t    rtt_period_cnt_;

      /// The time that the next delta update due to a packet being ACKed will
      /// occur.
      iron::Time  next_delta_update_time_ack_;

      /// The time that the next delta update due to a packet being lost will
      /// occur.
      iron::Time  next_delta_update_time_loss_;
    };

    /// \brief The damper states.
    enum DamperState
    {
      DAMPER_MONITOR_HIGH = 0,
      DAMPER_MONITOR_LOW  = 1,
      DAMPER_HOLD         = 2,
      DAMPER_WAIT         = 3
    };

    /// \brief The structure for damping large oscillations that may occur on
    /// high latency links.
    struct Damper
    {
      Damper();
      ~Damper();

      /// The current damping state.
      DamperState  state_;

      /// The sent packet counter for use in the damper hold state.
      uint32_t     hold_cnt_;
    };

    /// \brief The congestion window update directions used for updating the
    /// velocity.
    enum VelDir
    {
      VEL_DIR_NEITHER = 0,
      VEL_DIR_UP      = 1,
      VEL_DIR_DOWN    = 2
    };

    /// The congestion control identifier assigned to this object.
    CcId               cc_id_;

    /// The associated connection.
    Connection&        conn_;

    /// The packet framer.
    Framer&            framer_;

    /// The pool containing reusable packets.
    iron::PacketPool&  packet_pool_;

    /// The timer manager.
    iron::Timer&       timer_;

    /// The current operating state.
    OpState            state_;

    /// The fast startup state.
    FastStartup        fs_;

    /// The minimum RTT tracking state.
    MinRttTracking     mrt_;

    /// The TCP compatibility state.
    TcpCompat          tc_;

    /// The damper state.
    Damper             damper_;

    /// The algorithmic parameter for aggressiveness.
    double             delta_;

    /// The last RTT measurement, in seconds.
    double             last_rtt_;

    /// The minimum RTT observed, in seconds.  This is an estimate of the
    /// round-trip delay with no queueing delays.
    double             min_rtt_;

    /// The congestion window size, in packets.
    double             cwnd_;

    /// The current inter-send time, in seconds.
    double             ist_;

    /// The congestion window adjustment velocity parameter.
    uint32_t           velocity_;

    /// The number of times that the congestion window has been increased in
    /// the current RTT period.
    uint32_t           cwnd_adj_up_;

    /// The number of times that the congestion window has been decreased in
    /// the current RTT period.
    uint32_t           cwnd_adj_down_;

    /// The congestion window adjustment direction from the previous RTT
    /// period.
    VelDir             prev_direction_;

    /// The number of velocity adjustments in the same direction.
    uint32_t           vel_same_direction_cnt_;

    /// The congestion control sequence number at the start of the current
    /// velocity update period.
    PktSeqNumber       vel_cc_seq_num_;

    /// The next congestion control sequence number to be sent.
    PktSeqNumber       nxt_cc_seq_num_;

    /// The start time, used for computing a floating point time.
    iron::Time         start_time_point_;

    /// The RTT period end time.
    iron::Time         rtt_period_end_;

    /// The time that the next packet can be sent.
    iron::Time         next_send_time_;

    /// The tolerance used for timers.
    iron::Time         timer_tolerance_;

  }; // end class Copa2

}; // namespace sliq

#endif // IRON_SLIQ_CC_COPA2_H
