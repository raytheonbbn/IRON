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

#ifndef IRON_SLIQ_CC_COPA_H
#define IRON_SLIQ_CC_COPA_H

#include "sliq_cc_interface.h"
#include "sliq_private_defs.h"
#include "sliq_private_types.h"

#include "itime.h"
#include "rng.h"


namespace sliq
{
  /// \brief The Copa utility modes.
  enum CopaMode
  {
    CONSTANT_DELTA,
    MAX_THROUGHPUT
  };

  /// \brief The Copa send-side congestion control algorithm.
  ///
  /// May operate with either deterministic inter-send times (Deterministic
  /// Copa) or randomized inter-send times (Copa).  May operate with a fixed
  /// delta value or with a policy controller that selects the proper delta
  /// value dynamically.
  ///
  /// Note that this class is not thread-safe.
  class Copa : public CongCtrlInterface
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  conn_id    The connection ID.
    /// \param  is_client  The flag determining if this is the client or
    ///                    server side of the connection.
    /// \param  rng        A reference to the random number generator.
    Copa(EndptId conn_id, bool is_client, iron::RNG& rng);

    /// \brief Destructor.
    virtual ~Copa();

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
    Copa(const Copa& c);

    /// \brief Assignment operator.
    Copa& operator=(const Copa& c);

    /// \brief Get the current time as a double.
    ///
    /// The returned time is the number of seconds since start-up as a
    /// floating point number.
    ///
    /// \param  now  The current time.
    ///
    /// \return  The current time, in seconds, as a double.
    double CurrentTime(const iron::Time& now);

    /// \brief Randomize an inter-send time using an exponential distribution.
    ///
    /// \param  intersend  The inter-send time to randomize, in seconds.
    ///
    /// \return  The randomized inter-send time, in seconds.
    double RandomizeIntersend(double intersend);

    /// \brief Update the unACKed RTT estimate.
    ///
    /// \param  fp_now  The current time as a floating point number.
    void UpdateUnackedRttEstimate(double fp_now);

    /// \brief Update the next send time based on a transmission.
    ///
    /// \param  now    The current time.
    /// \param  bytes  The number of bytes just transmitted.
    void UpdateNextSendTime(const iron::Time& now, size_t bytes);

    /// \brief Update the delta value.
    ///
    /// \param  now       The current time.
    /// \param  pkt_lost  A flag indicating if the update is due to a packet
    ///                   being treated as lost.
    void UpdateDelta(const iron::Time& now, bool pkt_lost);

    /// \brief Update the inter-send time.
    ///
    /// \param  now  The current time.
    void UpdateIntersendTime(const iron::Time& now);

#ifdef SLIQ_COPA_MRT

    /// \brief Update the minimum RTT estimate.
    void UpdateMinRtt();

#endif

    /// \brief A structure for unACKed packet data.
    struct PacketData
    {
      /// The packet's congestion control sequence number.
      PktSeqNumber  cc_seq_num;

      /// The packet's index in the minimum RTT tracking data array.
      uint16_t      min_rtt_index;

      /// The packet's flags.
      uint16_t      flags;

      /// The packet's send time.
      double        send_time;

      /// The inter-send time, in seconds, in place when the packet was sent.
      double        intersend_time;
    };

    /// \brief A structure for minimum RTT tracking packet data.
    struct MinRttPktData
    {
      /// The packet's send time.
      double  send_time;

      /// The total number of sent bytes when the packet was sent.
      double  sent_bytes;
    };

    /// \brief A structure for minimum RTT tracking line fitting data.
    struct MinRttLineData
    {
      /// The number of kilobytes in the bottleneck queue when the packet was
      /// sent (X-axis).
      double  x_queued_kbytes;

      /// The RTT measurement from receipt of the ACK packet in milliseconds
      /// (Y-axis).
      double  y_rtt_msec;
    };

    /// \brief An exponentially weighted moving average (EWMA) for
    /// non-periodic readings.
    ///
    /// It uses a timestamp, which is normalized to average over a RTT time
    /// period in update().
    ///
    /// Note that this is a custom EWMA algorithm, not the usual non-periodic
    /// EWMA algorithm.
    class TimeEwma
    {

     public:

      /// \brief Constructor.
      ///
      /// \param  conn_id  The connection ID.
      /// \param  alpha    The EWMA alpha value.  Lower values weight older
      ///                  readings less.
      TimeEwma(EndptId conn_id, double alpha);

      /// \brief Destructor.
      virtual ~TimeEwma() {}

      /// \brief Update the EWMA with another measurement.
      ///
      /// \param  value  The value of the reading, in seconds.
      /// \param  now    The current time, in seconds.
      /// \param  rtt    The current round-trip-time measurement, in seconds.
      void Update(double value, double now, double rtt);

      /// \brief Force the EWMA to a specific value.
      ///
      /// \param  value  The new value for the EWMA, in seconds.
      /// \param  now    The current time, in seconds.
      void ForceSet(double value, double now);

      /// \brief Get the EWMA value, in seconds.
      inline operator double() const
      {
        return ewma_;
      }

      /// \brief Get the maximum value of two TimeEwma objects.
      ///
      /// \param  other  A reference to the other TimeEwma object.
      ///
      /// \return  The maximum value, in seconds.
      inline double max(const TimeEwma& other) const
      {
        return ((ewma_ > other.ewma_) ? ewma_ : other.ewma_);
      }

     private:

      /// \brief Copy constructor.
      TimeEwma(const TimeEwma& te);

      /// \brief Assignment operator.
      TimeEwma& operator=(const TimeEwma& te);

      /// The connection ID.
      EndptId  conn_id_;

      /// A flag indicating if the EWMA is valid or not.
      bool     valid_;

      /// The current EWMA value, in seconds.
      double   ewma_;

      /// The denominator used in the EWMA computations.
      double   den_;

      /// The EWMA alpha parameter.
      double   alpha_;

      /// The timestamp of the last update.
      double   last_ts_;

    }; // end class TimeEwma

    /// The random number generator.
    iron::RNG&              rng_;

    /// The current Copa utility mode.
    CopaMode                mode_;

    /// The setting for randomizing inter-send times.
    bool                    random_send_;

    /// The algorithmic parameter for aggressiveness.
    double                  delta_;

    /// The inter-send time to use for pacing packets to be sent, in seconds.
    double                  intersend_time_;

    /// The calculated inter-send time, in seconds.
    double                  calc_intersend_time_;

    /// The calculated inter-send time prevailing when the last ACKed packet
    /// was sent, in seconds.
    double                  prev_intersend_time_;

    /// The minimum RTT observed, in seconds.  This is an estimate of the
    /// round-trip delay with no queueing delays.
    double                  min_rtt_;

    /// The EWMA RTT computed from ACKed packets, in seconds.
    TimeEwma                rtt_acked_;

    /// The EWMA RTT computed in place of lost packets, in seconds.
    TimeEwma                rtt_unacked_;

    /// The next congestion control sequence number to be ACKed in the unACKed
    /// packet info.
    PktSeqNumber            una_cc_seq_num_;

    /// The next congestion control sequence number to be sent.
    PktSeqNumber            nxt_cc_seq_num_;

    /// The highest congestion control sequence number ACKed.
    PktSeqNumber            ack_cc_seq_num_;

    /// The circular array of unACKed packet information, with elements from
    /// una_cc_seq_num_ up to (but not including) nxt_cc_seq_num_.
    PacketData*             unacked_pkts_;

#ifdef SLIQ_COPA_MRT

    // The minimum RTT tracking dataset counter used for debug logging.
    uint32_t                mrt_cnt_;

    /// The consecutive number of times a minimum RTT change has been
    /// detected.
    uint32_t                mrt_trips_;

    /// The next minimum RTT tracking element index to be assigned.
    uint32_t                nxt_mrt_pkts_idx_;

    /// The number of points in the array of minimum RTT tracking line fitting
    /// data.
    uint32_t                num_mrt_pts_;

    /// The circular array of minimum RTT tracking information.
    MinRttPktData*          mrt_pkts_;

    /// The array of minimum RTT tracking line fitting data.
    MinRttLineData*         mrt_line_;

#endif // SLIQ_COPA_MRT

    /// The start time, used for computing a floating point time.
    iron::Time              start_time_point_;

    /// The time that the next packet can be sent.
    iron::Time              next_send_time_;

    /// The time of the last policy controller update.
    iron::Time              prev_delta_update_time_;

    /// The tolerance used for timers.
    iron::Time              timer_tolerance_;

    /// The next synchronization sequence number to be sent.
    uint16_t                sync_send_seq_num_;

    /// The last synchronization sequence number received.
    uint16_t                sync_recv_seq_num_;

    /// The policy controller synchronization parameter to be sent.
    uint16_t                sync_params_;

    /// The last policy controller synchronization parameter sent.
    uint16_t                prev_sync_params_;

    /// The time of the last policy controller synchronization.
    iron::Time              prev_sync_time_;

    /// The locally computed delta value for synchronization.
    double                  local_sync_delta_;

    /// The remotely computed delta value for synchronization.
    double                  remote_sync_delta_;

    /// The count of packets sent between policy controller updates.
    uint32_t                send_cnt_;

    /// The count of quiescent periods between policy controller updates.
    uint32_t                quiescent_cnt_;

    /// The total number of packets ACKed.
    uint64_t                num_pkts_acked_;

    /// The total number of packets lost.
    uint64_t                num_pkts_lost_;

  }; // end class Copa

}; // namespace sliq

#endif // IRON_SLIQ_CC_COPA_H
