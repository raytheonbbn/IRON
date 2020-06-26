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

#include "sliq_cc_cubic.h"
#include "sliq_types.h"

#include "itime.h"
#include "log.h"

#include <inttypes.h>
#include <math.h>
#include <string.h>
#include <sys/param.h>

using ::sliq::Capacity;
using ::sliq::Cubic;
using ::sliq::CongCtrlAlg;
using ::sliq::PktSeqNumber;
using ::sliq::RttManager;
using ::iron::Log;
using ::iron::Time;


namespace
{
  /// Class name for logging.
  const char*         kClassName = "Cubic";

  /// The CUBIC maximum segment size (MSS) in bytes.  Does not include the IP
  /// or UDP headers required to encapsulate the SLIQ packets.
  const int32_t       kCubicMss = sliq::kMaxPacketSize;

  /// The initial congestion control sequence number.
  const PktSeqNumber  kInitCcSeqNum = 1;

  /// The initial congestion window size in bytes, as per RFC 5681, section
  /// 3.1.
  /// \todo Should this be increased to 10 segments, as per RFC 6928?
  const int64_t       kInitCwnd = (3 * kCubicMss);

  /// The initial slow start threshold size in bytes.  This is ~1.4 million
  /// segments, which is essentially infinite, as per RFC 5681, section 3.1.
  const int64_t       kInitSsthresh = 0x7fffffffUL;

  /// The CUBIC beta value.  Note that this is (1 - beta) using beta from the
  /// CUBIC paper.  From Linux-4.6.3.
  const double        kCubicBeta = 0.7;

  /// The number of bits to shift by for the CUBIC cube scaling factor.  This
  /// comes from 1024 (which is from scaling kCubeCwndScale, resulting in "C")
  /// times 1024^3 (which is from time, in units of 1/1024 second, cubed).
  /// This is 1024^4, or a shift of 40 bits.  From Linux-4.6.3.
  const int64_t       kCubeScale = 40;

  /// The CUBIC cube congestion window scale ("C", which is 410 / 1024 = 0.4).
  /// From Linux-4.6.3.
  const int64_t       kCubeCwndScale = 410;

  /// The CUBIC cube root factor.  From Linux-4.6.3.
  const uint64_t      kCubeRootFactor = (
    (static_cast<uint64_t>(1) << kCubeScale) /
    static_cast<uint64_t>(kCubeCwndScale) /
    static_cast<uint64_t>(kCubicMss));

  /// The time limit in microseconds for CUBIC updates when cwnd does not
  /// change.  This is equal to 1/32 of a second, as per Linux-4.6.3.
  const int64_t       kCubicTimeLimitUsec = 31250;

  /// The time limit in microseconds for CUBIC update the congestion window
  /// count limit, as per Linux-4.6.3.
  const int64_t       kCubicUpdateThreshUsec = 4000;

  /// The idle time threshold in microseconds for updating the epoch start
  /// time, as per Linux-4.6.3.
  const int64_t       kCubicIdleThreshUsec = 4000;

  /// The congestion window size limit in bytes for triggering HyStart.  As
  /// per HyStart paper, and converted to bytes.
  const int64_t       kHystartLowWindow = (16 * kCubicMss);

  /// The HyStart ACK train detection time limit in milliseconds.  As per
  /// HyStart paper.
  const int64_t       kHystartAckDeltaMsec = 2;

  /// The HyStart ACK train detection delay multiplier.  As per HyStart paper.
  const double        kHystartAckMultiplier = 0.5;

  /// The minimum number of samples required for HyStart delay event
  /// detection.  As per HyStart paper.
  const uint32_t      kHystartMinSamples = 8;

  // The HyStart delay divisor for delay event detection.  As per the HyStart
  // paper (16) and corrected in Linux-4.6.3 (8).
  const int64_t       kHystartDelayDivisor = 8;

  /// The HyStart delay threshold minimum.  Used for delay event detection.
  /// As per the HyStart paper (2) and corrected in Linux-4.6.2 (4).
  const int64_t       kHystartDelayMinMsec = 4;

  /// The HyStart delay threshold maximum.  Used for delay event detection.
  /// As per the HyStart paper (8) and corrected in Linux-4.6.2 (16).
  const int64_t       kHystartDelayMaxMsec = 16;

  /// The send pacing quiescent threshold, in seconds.
  const double        kPacingQuiescentThreshold = 0.01;

  /// The send pacing slow start multiplicative ratio, as per Linux-4.6.3.
  const double        kPacingSlowStartRatio = 2.0;

  /// The send pacing congestion avoidance multiplicative ratio, as per
  /// Linux-4.6.3.
  const double        kPacingCongAvoidRatio = 1.2;

  /// The number of microseconds in a second.
  const double        kNumMicrosPerSecond = (1000.0 * 1000.0);

}


//============================================================================
Cubic::Cubic(EndptId conn_id, bool is_client, RttManager& rtt_mgr)
    : CongCtrlInterface(conn_id, is_client),
      rtt_mgr_(rtt_mgr),
      config_cubic_tcp_friendliness_(true),
      config_cubic_fast_convergence_(true),
      config_hystart_(true),
      config_hystart_detect_(kHystartAckTrainEvent | kHystartDelayEvent),
      config_prr_crb_(false),
      config_idle_restart_(false),
      update_snd_una_(false),
      snd_una_(kInitCcSeqNum),
      snd_nxt_(kInitCcSeqNum),
      high_seq_(kInitCcSeqNum),
      snd_nxt_byte_offset_(0),
      pkt_byte_offset_(NULL),
      cwnd_(kInitCwnd),
      ssthresh_(kInitSsthresh),
      cubic_beta_(kCubicBeta),
      cubic_cwnd_tcp_(0),
      cubic_cwnd_last_max_(0),
      cubic_last_cwnd_(0),
      cubic_last_time_(),
      cubic_epoch_start_(),
      cubic_delay_min_(),
      cubic_origin_point_(0),
      cubic_cnt_(0),
      cubic_ack_cnt_(0),
      cubic_cwnd_cnt_(0),
      cubic_k_(0),
      hystart_end_seq_(kInitCcSeqNum),
      hystart_round_start_(),
      hystart_last_ack_(),
      hystart_curr_rtt_(),
      hystart_sample_cnt_(0),
      hystart_found_(0),
      in_rto_(false),
      enter_fast_recovery_(false),
      in_fast_recovery_(false),
      prr_recovery_point_(kInitCcSeqNum),
      prr_delivered_(0),
      prr_out_(0),
      prr_recover_fs_(0),
      prr_sndcnt_(0),
      last_app_send_time_(),
      last_proto_send_time_(),
      next_send_time_(),
      timer_tolerance_(Time::FromMsec(1)),
      max_bytes_out_(0),
      max_bytes_seq_(snd_nxt_),
      pre_ack_bytes_in_flight_(0),
      flight_size_(0),
      stream_cc_info_()
{
}

//============================================================================
Cubic::~Cubic()
{
  // Delete dynamically allocated memory.
  if (pkt_byte_offset_ != NULL)
  {
    delete [] pkt_byte_offset_;
    pkt_byte_offset_ = NULL;
  }
}

//============================================================================
bool Cubic::Configure(const CongCtrl& cc_params)
{
  // Allocate the array of packet byte offsets.
  if (pkt_byte_offset_ == NULL)
  {
    pkt_byte_offset_ = new uint32_t[kMaxCongCtrlWindowPkts];

    if (pkt_byte_offset_ == NULL)
    {
      LogF(kClassName, __func__, "Packet offset array allocation error.\n");
      return false;
    }
  }

  // Initialize the array of packet byte offsets for the first packet to be
  // sent.
  pkt_byte_offset_[snd_nxt_ % kMaxCongCtrlWindowPkts] = snd_nxt_byte_offset_;

  // Initialize CUBIC.  From the CUBIC algorithm "Initialization" step.
  cwnd_     = kInitCwnd;
  ssthresh_ = kInitSsthresh;

  CubicReset();

  // Initialize HyStart.
  if (config_hystart_)
  {
    HystartReset();
  }

  return true;
}

//============================================================================
void Cubic::Connected(const Time& now, const Time& rtt)
{
  return;
}

//============================================================================
bool Cubic::UseRexmitPacing()
{
  return true;
}

//============================================================================
bool Cubic::UseCongWinForCapEst()
{
  return true;
}

//============================================================================
bool Cubic::UseUnaPktReporting()
{
  return true;
}

//============================================================================
bool Cubic::SetTcpFriendliness(uint32_t num_flows)
{
  if (num_flows < 1)
  {
    num_flows = 1;
  }

  // Adjust the CUBIC beta value.
  double  flows = static_cast<double>(num_flows);

  cubic_beta_ = (((flows - 1.0) + kCubicBeta) / flows);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated beta to %f for %"
       PRIu32 " flows.\n", conn_id_, cubic_beta_, num_flows);
#endif

  return true;
}

//============================================================================
bool Cubic::ActivateStream(StreamId stream_id, PktSeqNumber init_send_seq_num)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args stream %" PRIStreamId
       " init_seq %" PRIPktSeqNumber ".\n", conn_id_, stream_id,
       init_send_seq_num);
#endif

  if (stream_id > kMaxStreamId)
  {
    return false;
  }

  // Add the stream to the state information.
  stream_cc_info_.AddStream(stream_id);

  return true;
}

//============================================================================
bool Cubic::DeactivateStream(StreamId stream_id)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args stream %" PRIStreamId
       ".\n", conn_id_, stream_id);
#endif

  if (stream_id > kMaxStreamId)
  {
    return false;
  }

  // Remove the stream from the state information.
  stream_cc_info_.DelStream(stream_id);

  return true;
}

//============================================================================
void Cubic::OnAckPktProcessingStart(const Time& ack_time)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": ACK processing start.\n",
       conn_id_);
#endif

  // Reset the ACK packet processing state.
  pre_ack_bytes_in_flight_ = bytes_in_flight_;
  enter_fast_recovery_     = false;

#ifdef SLIQ_CC_DEBUG
  PrintState("OnAckPktProcessingStart()");
#endif
}

//============================================================================
void Cubic::OnRttUpdate(StreamId stream_id, const Time& ack_time,
                        PktTimestamp send_ts, PktTimestamp recv_ts,
                        PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                        const Time& rtt, uint32_t bytes, float cc_val)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args stream %" PRIStreamId
       " seq %" PRIPktSeqNumber " cc_seq %" PRIPktSeqNumber " rtt %f bytes %"
       PRIu32 " cc_val %f.\n", conn_id_, stream_id, seq_num, cc_seq_num,
       rtt.ToDouble(), bytes, static_cast<double>(cc_val));
#endif

  // Note that the reported RTT is already limited to positive, non-zero
  // values, so there is no need to test for negative values in this method.

  // Discard delay samples right after fast recovery (for 1 second).  Note
  // that ack_time is approximately the current time.  As per Linux-4.6.3.
  Time  limit(1);

  if ((!cubic_epoch_start_.IsZero()) &&
      ((ack_time - cubic_epoch_start_) < limit))
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Rtt update ignored, "
         "too soon after fast recovery.\n", conn_id_);
#endif

    return;
  }

  // Update the minimum observed delay.  From the CUBIC algorithm "On each
  // ACK" step.
  // \todo What if a route change increases the base RTT?
  if (cubic_delay_min_.IsZero() || (cubic_delay_min_ > rtt))
  {
    cubic_delay_min_ = rtt;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Update delay_min %f.\n",
         conn_id_, cubic_delay_min_.ToDouble());
#endif
  }

  // Perform HyStart delay increase detection.  Note that HyStart triggers
  // when cwnd is larger than some threshold.
  if (config_hystart_ && (cwnd_ < ssthresh_) && (cwnd_ >= kHystartLowWindow))
  {
    HystartDelayUpdate(rtt);
  }

#ifdef SLIQ_CC_DEBUG
  PrintState("OnRttUpdate()");
#endif
}

//============================================================================
bool Cubic::OnPacketLost(StreamId stream_id, const Time& ack_time,
                         PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                         uint32_t bytes)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args stream %" PRIStreamId
       " seq %" PRIPktSeqNumber " cc_seq %" PRIPktSeqNumber ".\n", conn_id_,
       stream_id, seq_num, cc_seq_num);
#endif

  if (in_fast_recovery_)
  {
    // We are currently in fast recovery.  If the lost packet is within the
    // current fast recovery window, then it is already covered by the other
    // packets that are lost.  Otherwise, the lost packet is outside of the
    // current fast recovery window.
    return (SEQ_LT(cc_seq_num, prr_recovery_point_));
  }

  // Once all of the ACK packets have been processed, enter fast recovery.
  enter_fast_recovery_ = true;

  return true;
}

//============================================================================
void Cubic::OnPacketAcked(StreamId stream_id, const Time& ack_time,
                          PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                          PktSeqNumber ne_seq_num, uint32_t bytes)

{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args stream %" PRIStreamId
       " seq %" PRIPktSeqNumber " cc_seq %" PRIPktSeqNumber " ne_seq %"
       PRIPktSeqNumber " bytes %" PRIu32 ".\n", conn_id_, stream_id, seq_num,
       cc_seq_num, ne_seq_num, bytes);
#endif

  // End any current RTO event.
  in_rto_ = false;

  return;
}

//============================================================================
void Cubic::OnAckPktProcessingDone(const Time& ack_time)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": ACK processing done.\n",
       conn_id_);
#endif

  // If required, update the lowest unACKed sequence number for all of the
  // streams in the connection.
  if (update_snd_una_)
  {
    UpdateSndUna();
  }

  // Check if fast recovery must be entered or exited.
  if (in_fast_recovery_)
  {
    // Per RFC 6675, section 5, action (A), exit fast recovery when HighACK >
    // RecoveryPoint.  Note that snd_una_ is just beyond HighACK.
    if (SEQ_GEQ(snd_una_, prr_recovery_point_))
    {
      EndPrr();
    }
  }
  else
  {
    // Per RFC 6675, section 5.1, paragraph 2, avoid entering fast recovery
    // after an RTO occurs until HighACK >= RecoveryPoint.
    if ((enter_fast_recovery_) && SEQ_GEQ(snd_una_, prr_recovery_point_))
    {
      BeginPrr();
    }
  }

  // Update the state based on the ACK packets that have just been processed.
  if (in_fast_recovery_)
  {
    // In fast recovery.
    UpdatePrr();
  }
  else
  {
    // Perform HyStart ACK-train bandwidth-delay product detection.  Note that
    // HyStart triggers when cwnd is larger than some threshold.
    if (config_hystart_ && (cwnd_ < ssthresh_) &&
        (cwnd_ >= kHystartLowWindow))
    {
      HystartAckTrainUpdate(ack_time);
    }

    // In slow start or congestion avoidance.  Update the congestion window.
    UpdateCwnd(ack_time);
  }

#ifdef SLIQ_CC_DEBUG
  PrintState("OnAckPktProcessingDone()");
#endif
}

//============================================================================
PktSeqNumber Cubic::OnPacketSent(StreamId stream_id, const Time& send_time,
                                 PktSeqNumber seq_num, uint32_t pld_bytes,
                                 uint32_t /* tot_bytes */, float& cc_val)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args stream %" PRIStreamId
       " seq %" PRIPktSeqNumber " bytes %" PRIu32 ".\n", conn_id_, stream_id,
       seq_num, pld_bytes);
#endif

  // Update the maximum bytes in flight per RTT.  Don't forget to add the size
  // of this packet being sent.
  int64_t  bytes_out = (bytes_in_flight_ + pld_bytes);

  if (SEQ_GEQ(snd_una_, max_bytes_seq_) || (bytes_out > max_bytes_out_))
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Update max bytes out "
         "from %" PRId64 " to %" PRId64" seq %" PRIPktSeqNumber ".\n",
         conn_id_, max_bytes_out_, bytes_out, snd_nxt_);
#endif

    max_bytes_out_ = bytes_out;
    max_bytes_seq_ = snd_nxt_;
  }

  // Assign a congestion control sequence number to the packet.
  PktSeqNumber  cc_seq_num = snd_nxt_;
  snd_nxt_++;

  // Update the byte offset for the next packet to be sent.
  snd_nxt_byte_offset_ += pld_bytes;
  pkt_byte_offset_[snd_nxt_ % kMaxCongCtrlWindowPkts] = snd_nxt_byte_offset_;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Assign seq %"
       PRIPktSeqNumber " to ccseq %" PRIPktSeqNumber ".\n", conn_id_, seq_num,
       cc_seq_num);
#endif

  // If the application was idle for a while, then shift the
  // cubic_epoch_start_ to keep the cwnd growth to a cubic curve.
  if (bytes_in_flight_ == 0)
  {
    if (!cubic_epoch_start_.IsZero())
    {
      Time  delta = (send_time - last_app_send_time_);
      Time  limit = Time::FromUsec(kCubicIdleThreshUsec);

      if (delta > limit)
      {
        cubic_epoch_start_ += delta;

        if (cubic_epoch_start_ > send_time)
        {
          cubic_epoch_start_ = send_time;
        }

#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": App was idle, "
             "shift epoch start to %s.\n", conn_id_,
             cubic_epoch_start_.ToString().c_str());
#endif
      }
    }
  }

  // Fast recovery must keep track of all packet transmissions.
  if (in_fast_recovery_)
  {
    prr_out_ += pld_bytes;
  }

  // Store the last send time.
  last_app_send_time_   = send_time;
  last_proto_send_time_ = send_time;

  // Update the next send time.
  UpdateNextSendTime(send_time, pld_bytes);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Sent data on stream %"
       PRIStreamId " seq %" PRIPktSeqNumber " bytes %" PRIu32 " ccseq %"
       PRIPktSeqNumber ".\n", conn_id_, stream_id, seq_num, pld_bytes,
       cc_seq_num);

  PrintState("OnPacketSent()");
#endif

  return cc_seq_num;
}

//============================================================================
void Cubic::OnPacketResent(StreamId stream_id, const Time& send_time,
                           PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                           uint32_t pld_bytes, uint32_t /* tot_bytes */,
                           bool rto, bool orig_cc, float& cc_val)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args stream %" PRIStreamId
       " seq %" PRIPktSeqNumber " cc_seq %" PRIPktSeqNumber " bytes %" PRIu32
       " rto %d.\n", conn_id_, stream_id, seq_num, cc_seq_num, pld_bytes,
       static_cast<int>(rto));
#endif

  // If the retransmission is due to an RTO event, then do not update any of
  // the state.
  if (rto)
  {
    return;
  }

  // Fast recovery must keep track of all packet transmissions.
  if (in_fast_recovery_)
  {
    prr_out_ += pld_bytes;

    // Note that because of SLIQ's selective ACK reporting and lost packet
    // bookkeeping, there is no need to update "HighRxt" and "RescueRxt" as
    // stated in RFC 6675, page 8, number (4.3).
  }

  // Store the last send time.
  last_proto_send_time_ = send_time;

  // Update the next send time.
  UpdateNextSendTime(send_time, pld_bytes);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Resent data on stream %"
       PRIStreamId " seq %" PRIPktSeqNumber " bytes %" PRIu32 ".\n", conn_id_,
       stream_id, seq_num, pld_bytes);

  PrintState("OnPacketResent()");
#endif
}

//============================================================================
void Cubic::ReportUnaPkt(StreamId stream_id, bool has_una_pkt,
                         PktSeqNumber una_cc_seq_num)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args stream %" PRIStreamId
       " has_una %d  una_cc_seq %" PRIPktSeqNumber ".\n", conn_id_, stream_id,
       static_cast<int>(has_una_pkt),
       static_cast<PktSeqNumber>(has_una_pkt ? una_cc_seq_num : 0));
#endif

  if (!stream_cc_info_.cc_info[stream_id].init_flag)
  {
    return;
  }

  // Update the lowest unACKed sequence number for the stream.
  stream_cc_info_.cc_info[stream_id].una_flag    = has_una_pkt;
  stream_cc_info_.cc_info[stream_id].una_seq_num = una_cc_seq_num;

  // The lowest unACKed sequence number for all of the streams needs updated.
  update_snd_una_ = true;
}

//============================================================================
void Cubic::OnRto(bool pkt_rexmit)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args pkt_rexmit %d.\n",
       conn_id_, static_cast<int>(pkt_rexmit));
#endif

  // Reduce ssthresh if needed.  The resend test (after last OR) comes from
  // RFC 5681, section 3.1, just after equation (4).  While this resend test
  // is not completely accurate due to multiple streams, it should still work.
  if (((!in_fast_recovery_) && (!in_rto_)) || SEQ_LEQ(high_seq_, snd_una_) ||
      (in_rto_ && (!pkt_rexmit)))
  {
    ssthresh_ = CubicRecalcSsthresh();
  }

  // A congestion event has occurred.
  high_seq_ = snd_nxt_;

  // Reset cwnd to the loss window, LW, which is one segment, per RFC 5681,
  // section 3.1, in the next to last paragraph.
  cwnd_           = kCubicMss;
  cubic_cwnd_cnt_ = 0;

  // Reset CUBIC.  From the CUBIC algorithm "Timeout" step.
  CubicReset();

  // Reset HyStart.
  if (config_hystart_)
  {
    HystartReset();
  }

  // Per RFC 6675, section 5.1, paragraph 2, if an RTO occurs while in fast
  // recovery, exit fast recovery and set RecoveryPoint to HighData (note that
  // snd_nxt_ is just beyond HighData).
  if (in_fast_recovery_)
  {
    in_fast_recovery_   = false;
    prr_recovery_point_ = snd_nxt_;
  }

  // An RTO event has been started.
  in_rto_ = true;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": RTO - cwnd %" PRId64
       " ssthresh %" PRId64 ".\n", conn_id_, cwnd_, ssthresh_);

  PrintState("OnRto()");
#endif
}

//============================================================================
void Cubic::OnOutageEnd()
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Outage is over.\n",
       conn_id_);
#endif

  // The sent packet manager might have dropped packets.  Make sure that
  // snd_una_ is updated before making any other changes.
  if (update_snd_una_)
  {
    UpdateSndUna();
  }

  // Reset the congestion window to enter slow start.
  cwnd_ = kInitCwnd;

#ifdef SLIQ_CC_DEBUG
  PrintState("OnOutageEnd()");
#endif
}

//============================================================================
bool Cubic::CanSend(const Time& now, uint32_t bytes)
{
  bool  rv = false;

  // Even though cwnd is computed in bytes, make sure that the maximum number
  // of packets supported in cwnd is never exceeded.
  if ((snd_nxt_ - snd_una_) >= kMaxCongCtrlWindowPkts)
  {
    LogW(kClassName, __func__, "Conn %" PRIEndptId ": CC window size reached "
         "%zu packets.\n", conn_id_, kMaxCongCtrlWindowPkts);
  }
  else
  {
    if (in_fast_recovery_)
    {
      // In fast recovery.  This test just needs to honor prr_out_ and
      // prr_sndcnt_.  Note that RFC 6937, section 3, states that prr_out must
      // be "strictly less than or equal to sndcnt".  Thus, we have to add in
      // the number of bytes for this request.
      rv = ((prr_out_ + bytes) <= prr_sndcnt_);
    }
    else
    {
      // In slow start or congestion avoidance.  Perform the normal cwnd test.
      // Note that bytes_in_flight_ is allowed to go over cwnd_ for the last
      // packet to "fit" into cwnd and have IsCwndLimited() work correctly.
      // Thus, we do not add in the number of bytes for this request.
      rv = (bytes_in_flight_ < cwnd_);
    }
  }

  if (config_idle_restart_ && rv)
  {
    // Possibly restart an idle connection.
    RestartIdleConnection(now);
  }

  return rv;
}

//============================================================================
bool Cubic::CanResend(const Time& now, uint32_t bytes, bool orig_cc)
{
  bool  rv = true;

  if (in_fast_recovery_)
  {
    // In fast recovery.  This test just needs to honor prr_out_ and
    // prr_sndcnt_.  Note that RFC 6937, section 3, states that prr_out must
    // be "strictly less than or equal to sndcnt".  Thus, we have to add in
    // the number of bytes for this request.
    rv = ((prr_out_ + bytes) <= prr_sndcnt_);
  }
  else
  {
    // Fast retransmissions should not happen in slow start or congestion
    // avoidance.
    if (orig_cc)
    {
      LogA(kClassName, __func__, "Conn %" PRIEndptId ": Requesting fast "
           "retransmission when not in fast recovery, allowing.\n", conn_id_);
    }
  }

  if (config_idle_restart_ && rv)
  {
    // Possibly restart an idle connection.
    RestartIdleConnection(now);
  }

  return rv;
}

//============================================================================
Time Cubic::TimeUntilSend(const Time& now)
{
  // Check if the send can happen immediately.
  if (now.Add(timer_tolerance_) >= next_send_time_)
  {
    return Time();
  }

  // Wait to send.
  return (next_send_time_ - now);
}

//============================================================================
Capacity Cubic::PacingRate()
{
  double  rate_bps = ComputePacingRate();

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Pacing rate %f bps.\n",
       conn_id_, rate_bps);
#endif

  return static_cast<Capacity>(rate_bps);
}

//============================================================================
Capacity Cubic::CapacityEstimate()
{
  // The current rate in bps is:  rate = ((cwnd * 8) / srtt)
  Time    srtt     = rtt_mgr_.smoothed_rtt();
  double  rate_bps = ((static_cast<double>(cwnd_) * 8.0 *
                       kNumMicrosPerSecond) /
                      static_cast<double>(srtt.GetTimeInUsec()));

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Capacity estimate %f "
       "bps.\n", conn_id_, rate_bps);
#endif

  return static_cast<Capacity>(rate_bps);
}

//============================================================================
bool Cubic::GetSyncParams(uint16_t& seq_num, uint32_t& cc_params)
{
  return false;
}

//============================================================================
void Cubic::ProcessSyncParams(const Time& now, uint16_t seq_num,
                              uint32_t cc_params)
{
  return;
}

//============================================================================
void Cubic::ProcessCcPktTrain(const Time& now, CcPktTrainHeader& hdr)
{
  return;
}

//============================================================================
bool Cubic::InSlowStart()
{
  return (cwnd_ < ssthresh_);
}

//============================================================================
bool Cubic::InRecovery()
{
  return in_fast_recovery_;
}

//============================================================================
uint32_t Cubic::GetCongestionWindow()
{
  return static_cast<uint32_t>(cwnd_);
}

//============================================================================
uint32_t Cubic::GetSlowStartThreshold()
{
  return static_cast<uint32_t>(ssthresh_);
}

//============================================================================
CongCtrlAlg Cubic::GetCongestionControlType()
{
  return TCP_CUBIC_CC;
}

//============================================================================
void Cubic::Close()
{
  return;
}

//============================================================================
double Cubic::ComputePacingRate()
{
  // The current rate in bps is:  rate = ((cwnd * 8) / srtt)
  Time    srtt     = rtt_mgr_.smoothed_rtt();
  double  rate_bps = ((static_cast<double>(cwnd_) * 8.0 *
                       kNumMicrosPerSecond) /
                      static_cast<double>(srtt.GetTimeInUsec()));

  // In slow start, set the pacing rate to 200% of the current rate.  In
  // congestion avoidance, set the pacing rate to 120% of the current rate.
  //
  // Note that the normal slow start condition is (cwnd < ssthresh).  However,
  // if (cwnd >= (ssthresh / 2)), then we are approaching the end of slow
  // start and should start to slow down.
  if (cwnd_ < (ssthresh_ / 2))
  {
    rate_bps *= kPacingSlowStartRatio;
  }
  else
  {
    rate_bps *= kPacingCongAvoidRatio;
  }

  return rate_bps;
}

//============================================================================
void Cubic::UpdateNextSendTime(const Time& now, uint32_t bytes)
{
  // Get the pacing rate.
  double  rate_bps = ComputePacingRate();

  // Compute the packet inter-send time using the size of the packet just
  // sent.
  double  pkt_intersend_time = ((static_cast<double>(bytes) * 8.0) /
                                rate_bps);

  // If the current time is more than kPacingQuiescentThreshold seconds beyond
  // the stored next send time, then the sender is considered to have been
  // quiescent for a time, so the next send time must be computed from now.
  // Otherwise, the send pacing timer must have been used, so add the
  // inter-send time for this packet to the stored next send time.
  if (now > next_send_time_.Add(kPacingQuiescentThreshold))
  {
    next_send_time_ = now.Add(pkt_intersend_time);
  }
  else
  {
    next_send_time_ = next_send_time_.Add(pkt_intersend_time);
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Waiting for packet "
       "intersend time %f sec for rate %f bps.\n", conn_id_,
       pkt_intersend_time, rate_bps);
#endif
}

//============================================================================
void Cubic::UpdateSndUna()
{
  int  num_streams = stream_cc_info_.num_streams;
  snd_una_         = snd_nxt_;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Reset snd_una to %"
       PRIPktSeqNumber ".\n", conn_id_, snd_una_);
#endif

  for (int i = 0; i < num_streams; ++i)
  {
    StreamId  stream_id = stream_cc_info_.stream_ids[i];

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Stream %" PRIStreamId
         " una_flag %d una_seq_num %" PRIPktSeqNumber ".\n", conn_id_,
         stream_id,
         static_cast<int>(stream_cc_info_.cc_info[stream_id].una_flag),
         stream_cc_info_.cc_info[stream_id].una_seq_num);
#endif

    if ((stream_cc_info_.cc_info[stream_id].init_flag) &&
        (stream_cc_info_.cc_info[stream_id].una_flag) &&
        (SEQ_LT(stream_cc_info_.cc_info[stream_id].una_seq_num, snd_una_)))
    {
      snd_una_ = stream_cc_info_.cc_info[stream_id].una_seq_num;
    }
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Update snd_una %"
       PRIPktSeqNumber ".\n", conn_id_, snd_una_);
#endif

  // Since snd_una_ might have been updated, recompute the flight size in
  // bytes for the connection.
  flight_size_ = static_cast<int64_t>(
    pkt_byte_offset_[snd_nxt_ % kMaxCongCtrlWindowPkts] -
    pkt_byte_offset_[snd_una_ % kMaxCongCtrlWindowPkts]);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Update flight_size %"
       PRId64 ".\n", conn_id_, flight_size_);
#endif

  // If snd_una_ has moved appreciably beyond the stored high_seq_, then
  // move it forward to prevent sequence number wrap-around from confusing
  // things.  The number 4 here is arbitrary but sufficient.
  if (SEQ_GT((snd_una_ - 4), high_seq_))
  {
    high_seq_ = (snd_una_ - 4);
  }

  // Reset the flag.
  update_snd_una_ = false;
}

//============================================================================
void Cubic::RestartIdleConnection(const Time& now)
{
  // Possibly restart an idle connection, as per RFC 5681, section 4.1.  This
  // requires the protocol being idle for the RTO period, at which point, the
  // congestion window is set to be:
  //
  //   IW   = (3 * MSS);
  //   RW   = min(IW, cwnd);
  //   cwnd = RW;
  //
  // Do not restart while in fast recovery or when recovering from an RTO
  // timer expiration event.
  if ((!in_fast_recovery_) && (!in_rto_) && (cwnd_ > kInitCwnd) &&
      ((now - last_proto_send_time_) > rtt_mgr_.GetRtoTime()))
  {
    // Reset CUBIC.
    CubicReset();

    // Reset HyStart.
    if (config_hystart_)
    {
      HystartReset();
    }

    // Set the congestion window size to RW.  Leave the slow start threshold
    // alone.
    cwnd_ = kInitCwnd;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Restart idle "
         "connection, cwnd %" PRId64 ".\n", conn_id_, cwnd_);
#endif
  }
}

//============================================================================
bool Cubic::IsCwndLimited()
{
  // If in slow start, ensure cwnd grows to twice what was ACKed.
  if (cwnd_ < ssthresh_)
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": In slow start, test (%"
         PRId64 " < %" PRId64 ").\n", conn_id_, cwnd_, (2 * max_bytes_out_));
#endif

    return (cwnd_ < (2 * max_bytes_out_));
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": In cong avoid, test (%"
       PRId64 " >= %" PRId64 ").\n", conn_id_, pre_ack_bytes_in_flight_,
       cwnd_);
#endif

  // Note that this must use the pre-ACK bytes in flight, as the ACK packets
  // will have reduced the bytes in flight as they are processed.
  return (pre_ack_bytes_in_flight_ >= cwnd_);
}

//============================================================================
void Cubic::UpdateCwnd(const Time& now)
{
  if (!IsCwndLimited())
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Not cwnd limited.\n",
         conn_id_);
#endif

    return;
  }

  // Compute the number of bytes that were ACKed.
  int64_t  acked_bytes = (pre_ack_bytes_in_flight_ - bytes_in_flight_);

  // Handle slow start and congestion avoidance separately.
  if (cwnd_ < ssthresh_)
  {
    // Slow start.

    // End the HyStart RTT round if it is time, as per HyStart paper.
    if (config_hystart_ && SEQ_GT(snd_una_, hystart_end_seq_))
    {
      HystartReset();
    }

    // When in slow start, increment cwnd by the number of bytes ACKed, as per
    // RFC 5681, section 3.1, equation (2).
    cwnd_ += MIN(acked_bytes, kCubicMss);
  }
  else
  {
    // Congestion avoidance.  The following logic comes from the CUBIC
    // algorithm "On each ACK" step, with updates from Linux-4.6.3.

    // Update the CUBIC limit cubic_cnt_.
    CubicUpdate(now, acked_bytes);

    // Update the congestion window based on the CUBIC parameters.  This is
    // roughly cwnd += (1 / cwnd) for every packet that was ACKed.
    if (cubic_cwnd_cnt_ >= cubic_cnt_)
    {
#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Cubic incr 1, "
           "cwnd_cnt %" PRId64 " cnt %" PRId64 " old cwnd %" PRId64 " new "
           "cwnd %" PRId64 ".\n", conn_id_, cubic_cwnd_cnt_, cubic_cnt_,
           cwnd_, static_cast<int64_t>(cwnd_ + kCubicMss));
#endif

      cubic_cwnd_cnt_ = 0;
      cwnd_          += kCubicMss;
    }

    cubic_cwnd_cnt_ += acked_bytes;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Cubic, update cwnd_cnt "
         "%" PRId64 ".\n", conn_id_, cubic_cwnd_cnt_);
#endif

    if (cubic_cwnd_cnt_ >= cubic_cnt_)
    {
      int64_t  delta = (cubic_cwnd_cnt_ / cubic_cnt_);

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Cubic incr 2, delta %"
           PRId64 " old cwnd_cnt %" PRId64 " new cwnd_cnt %" PRId64 " old "
           "cwnd %" PRId64 " new cwnd %" PRId64 ".\n", conn_id_, delta,
           cubic_cwnd_cnt_, (cubic_cwnd_cnt_ - (delta * cubic_cnt_)), cwnd_,
           (cwnd_ + (delta * kCubicMss)));
#endif

      cubic_cwnd_cnt_ -= (delta * cubic_cnt_);
      cwnd_           += (delta * kCubicMss);
    }
  }

  // Limit the congestion window if needed.
  if (cwnd_ > static_cast<int64_t>(kMaxCongCtrlWindowPkts * kCubicMss))
  {
    cwnd_ = static_cast<int64_t>(kMaxCongCtrlWindowPkts * kCubicMss);
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Result cwnd_cnt %" PRId64
       " cwnd %" PRId64 ".\n", conn_id_, cubic_cwnd_cnt_, cwnd_);
#endif
}

//============================================================================
void Cubic::CubicUpdate(const Time& now, int64_t acked_bytes)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args acked_bytes %" PRId64
       ".\n", conn_id_, acked_bytes);
#endif

  // This logic comes from the CUBIC algorithm "cubic_update()" step.

  // Increment by the number of ACKed packet bytes.
  cubic_ack_cnt_ += acked_bytes;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Update ack_cnt %" PRId64
       ".\n", conn_id_, cubic_ack_cnt_);
#endif

  // CUBIC updates with no change to cwnd are limited by time.
  Time  time_limit = Time::FromUsec(kCubicTimeLimitUsec);

  if ((cubic_last_cwnd_ == cwnd_) && ((now - cubic_last_time_) <= time_limit))
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": No change to cwnd %"
         PRId64 " within time limit.\n", conn_id_, cwnd_);
#endif

    return;
  }

  // The CUBIC function can update cubic_cnt_ at most once per time interval.
  // On all cwnd reduction events, cubic_epoch_start_ is set to zero, which
  // will force a recalculation of cubic_cnt_.
  time_limit = Time::FromUsec(kCubicUpdateThreshUsec);

  if ((cubic_epoch_start_.IsZero()) ||
      ((now - cubic_last_time_) > time_limit))
  {
    // Record the last cwnd and time.
    cubic_last_cwnd_ = cwnd_;
    cubic_last_time_ = now;

    // Start a new epoch if required.
    if (cubic_epoch_start_.IsZero())
    {
      cubic_epoch_start_ = now;

      if (cwnd_ < cubic_cwnd_last_max_)
      {
        cubic_k_            = static_cast<int64_t>(
          cbrt(static_cast<double>(kCubeRootFactor) *
               static_cast<double>(cubic_cwnd_last_max_ - cwnd_)));
        cubic_origin_point_ = cubic_cwnd_last_max_;
      }
      else
      {
        cubic_k_            = 0;
        cubic_origin_point_ = cwnd_;
      }

      cubic_ack_cnt_  = acked_bytes;
      cubic_cwnd_tcp_ = cwnd_;

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Epoch start, cwnd %"
           PRId64 " cwnd_last_max %" PRId64 " k %" PRId64 " origin_point %"
           PRId64 " ack_cnt %" PRId64 " cwnd_tcp %" PRId64 ".\n", conn_id_,
           cwnd_, cubic_cwnd_last_max_, cubic_k_, cubic_origin_point_,
           cubic_ack_cnt_, cubic_cwnd_tcp_);
#endif
    }

    // Compute (now + cubic_delay_min_ - cubic_epoch_start_) as a number of
    // 1/1024 second intervals.
    Time     t_obj  = (now + cubic_delay_min_ - cubic_epoch_start_);
    int64_t  t      = ((t_obj.GetTimeInMsec() << 10) / 1000);
    int64_t  offset = 0;

    // Update cubic_cnt_.
    if (t < cubic_k_)
    {
      offset = (cubic_k_ - t);
    }
    else
    {
      offset = (t - cubic_k_);
    }

    int64_t  delta  = (((kCubeCwndScale * offset * offset * offset) >>
                        kCubeScale) * kCubicMss);
    int64_t  target = 0;

    if (t < cubic_k_)
    {
      target = (cubic_origin_point_ - delta);
    }
    else
    {
      target = (cubic_origin_point_ + delta);
    }

    if (target > cwnd_)
    {
      cubic_cnt_ = ((cwnd_ / (target - cwnd_)) * kCubicMss);
    }
    else
    {
      cubic_cnt_ = (100 * cwnd_);
    }

    if ((cubic_cwnd_last_max_ == 0) && (cubic_cnt_ > (20 * kCubicMss)))
    {
      cubic_cnt_ = (20 * kCubicMss);
    }

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Cubic update, t %"
         PRId64 " k %" PRId64 " offset %" PRId64 " delta %" PRId64 " target %"
         PRId64 " cnt %" PRId64 ".\n", conn_id_, t, cubic_k_, offset, delta,
         target, cubic_cnt_);
#endif
  }

  // Update TCP-friendly behavior.
  if (config_cubic_tcp_friendliness_)
  {
    // This logic comes from the CUBIC algorithm "cubic_tcp_friendliness()"
    // step.  Note that the beta used may be adjusted for aggressiveness.
    int64_t  delta = static_cast<int64_t>(
      round(static_cast<double>(cwnd_) * ((1.0 + cubic_beta_) /
                                          (3.0 * (1.0 - cubic_beta_)))));

    // Update the estimated TCP cwnd.
    while (cubic_ack_cnt_ > delta)
    {
      cubic_ack_cnt_  -= delta;
      cubic_cwnd_tcp_ += kCubicMss;

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": TCP friendly loop, "
           "delta %" PRId64 " ack_cnt %" PRId64 " cwnd_tcp %" PRId64 ".\n",
           conn_id_, delta, cubic_ack_cnt_, cubic_cwnd_tcp_);
#endif
    }

    // If CUBIC is slower than the estimated TCP, then adjust cubic_cnt_ down.
    if (cubic_cwnd_tcp_ > cwnd_)
    {
      delta            = (cubic_cwnd_tcp_ - cwnd_);
      int64_t  max_cnt = ((cwnd_ / delta) * kCubicMss);

      if (cubic_cnt_ > max_cnt)
      {
#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": TCP friendly "
             "adjust, delta %" PRId64 " max_cnt %" PRId64 " cnt %" PRId64
             ".\n", conn_id_, delta, max_cnt, cubic_cnt_);
#endif

        cubic_cnt_ = max_cnt;
      }
    }
  }

  // Limit cubic_cnt_ to at least 2 segments.
  cubic_cnt_ = MAX(cubic_cnt_, (2 * kCubicMss));
}

//============================================================================
int64_t Cubic::CubicRecalcSsthresh()
{
  // The following logic comes from the CUBIC algorithm "Packet loss" step.

  int64_t  new_ssthresh = 0;

  // End the epoch.
  cubic_epoch_start_.Zero();

  // Record CUBIC's last maximum cwnd.
  if ((cwnd_ < cubic_cwnd_last_max_) && (config_cubic_fast_convergence_))
  {
    // Note that the beta value adjusted for aggressiveness is not used here.
    // This needs to use the constant, base, beta value.
    cubic_cwnd_last_max_ = static_cast<int64_t>(
      round(static_cast<double>(cwnd_) * ((1.0 + kCubicBeta) / 2.0)));
  }
  else
  {
    cubic_cwnd_last_max_ = cwnd_;
  }

  // Recalculate ssthresh using beta that can be adjusted for aggressiveness.
  // Do not let it drop below 2 segments.
  //
  // Note that this calculation is in place of equation (4) from RFC 5681,
  // page 7:
  //   ssthresh = max( (FlightSize / 2), (2 * SMSS) )
  new_ssthresh = MAX(static_cast<int64_t>(round(static_cast<double>(cwnd_) *
                                                cubic_beta_)),
                     (2 * kCubicMss));

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": cwnd %" PRId64
       " cwnd_last_max %" PRId64 " new ssthresh %" PRId64 ".\n", conn_id_,
       cwnd_, cubic_cwnd_last_max_, new_ssthresh);
#endif

  return new_ssthresh;
}

//============================================================================
void Cubic::CubicReset()
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": CUBIC reset.\n",
       conn_id_);
#endif

  // Reset CUBIC.  From the CUBIC algorithm "cubic_reset()" step.
  cubic_cwnd_tcp_      = 0;
  cubic_cwnd_last_max_ = 0;
  cubic_last_cwnd_     = 0;
  cubic_last_time_.Zero();
  cubic_epoch_start_.Zero();
  cubic_delay_min_.Zero();
  cubic_origin_point_  = 0;
  cubic_cnt_           = 0;
  cubic_ack_cnt_       = 0;
  cubic_cwnd_cnt_      = 0;
  cubic_k_             = 0;

  hystart_found_ = 0;
}

//============================================================================
void Cubic::HystartDelayUpdate(const Time& delay)
{
  // Return if hystart has already found what it was looking for.
  if (hystart_found_ & config_hystart_detect_)
  {
    return;
  }

  if (config_hystart_detect_ & kHystartDelayEvent)
  {
    // Watch for a delay increase event.  Obtain the minimum delay of a fixed
    // number of packets, then monitor the delay.
    if (hystart_sample_cnt_ < kHystartMinSamples)
    {
      if ((hystart_curr_rtt_.IsZero()) || (hystart_curr_rtt_ > delay))
      {
        hystart_curr_rtt_ = delay;
      }

      ++hystart_sample_cnt_;
    }
    else
    {
      // Compare the hystart minimum with the overall minimum plus a threshold
      // amount.  If the delay has grown long enough, then exit slow start.
      Time  delay_thresh = Time::FromMsec(
        MIN(MAX((cubic_delay_min_.GetTimeInMsec() / kHystartDelayDivisor),
                kHystartDelayMinMsec), kHystartDelayMaxMsec));

      if (hystart_curr_rtt_ > (cubic_delay_min_ + delay_thresh))
      {
        hystart_found_ |= kHystartDelayEvent;
        ssthresh_       = cwnd_;

#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Exit slow start, "
             "enter congestion avoidance - delay - cwnd %" PRId64 " ssthresh "
             "%" PRId64 ".\n", conn_id_, cwnd_, ssthresh_);
#endif
      }
    }
  }
}

//============================================================================
void Cubic::HystartAckTrainUpdate(const Time& now)
{
  // Return if hystart has already found what it was looking for.
  if (hystart_found_ & config_hystart_detect_)
  {
    return;
  }

  if (config_hystart_detect_ & kHystartAckTrainEvent)
  {
    // Watch for an ACK-train event.
    Time  limit = Time::FromMsec(kHystartAckDeltaMsec);

    if ((now - hystart_last_ack_) <= limit)
    {
      hystart_last_ack_ = now;

      limit = cubic_delay_min_;
      limit.Multiply(kHystartAckMultiplier);

      if ((now - hystart_round_start_) > limit)
      {
        hystart_found_ |= kHystartAckTrainEvent;
        ssthresh_       = cwnd_;

#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Exit slow start, "
             "enter congestion avoidance - ACK train - cwnd %" PRId64
             " ssthresh %" PRId64 ".\n", conn_id_, cwnd_, ssthresh_);
#endif
      }
    }
  }
}

//============================================================================
void Cubic::HystartReset()
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": HyStart reset.\n",
       conn_id_);
#endif

  Time  now = Time::Now();

  hystart_end_seq_     = snd_nxt_;
  hystart_round_start_ = now;
  hystart_last_ack_    = now;
  hystart_curr_rtt_.Zero();
  hystart_sample_cnt_  = 0;
}

//============================================================================
void Cubic::BeginPrr()
{
  // As per RFC 6937, section 3, with additions for CUBIC.

  // This is the target cwnd after recovery.  Once fast recovery is over, set
  // cwnd equal to this value.
  ssthresh_ = CubicRecalcSsthresh();

  prr_delivered_  = 0;               // Total bytes delivered during recovery.
  prr_out_        = 0;               // Total bytes sent during recovery.
  prr_recover_fs_ = flight_size_;    // FlightSize at the start of recovery.
  prr_sndcnt_     = 0;               // Cumulative bytes allowed to be sent.
  cubic_cwnd_cnt_ = 0;               // Reset ACKed packet byte count.

  // Enter fast recovery, saving the point at which it ends.
  in_fast_recovery_   = true;
  prr_recovery_point_ = snd_nxt_;

  // A congestion event has occurred.
  high_seq_ = snd_nxt_;

  // A packet was considered lost back in OnPacketLost(), which will cause the
  // sent packet manager to add the packet to the fast retransmit list in the
  // stream, and will cause the lost packet to be retransmitted at the proper
  // time using Stream::OnCanResend().  This implements the fast retransmit as
  // per RFC 6675, page 8, item (4.3), and RFC 5681, page 9, item 3.  Note
  // that this will likely be a retransmission of snd_una_ for the highest
  // priority stream, but it might be another lost packet depending on the
  // exact packet loss and reordering that took place.

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Enter FR - cwnd %" PRId64
       " ssthresh %" PRId64 ".\n", conn_id_, cwnd_, ssthresh_);

  PrintState("BeginPrr()");
#endif
}

//============================================================================
void Cubic::UpdatePrr()
{
  // As per RFC 6937, section 3, with additions for CUBIC.  Note that pipe is
  // always updated, so the RFC 6675 pipe algorithm does not need to be
  // executed here.

  int64_t  sndcnt         = 0;
  int64_t  delivered_data = (pre_ack_bytes_in_flight_ - bytes_in_flight_);

  prr_delivered_ += delivered_data;

  if (pipe_ > ssthresh_)
  {
    // Proportional rate reduction.
    sndcnt = (static_cast<int64_t>(
                ceil(static_cast<double>(prr_delivered_) *
                     static_cast<double>(ssthresh_) /
                     static_cast<double>(prr_recover_fs_))) - prr_out_);
  }
  else
  {
    int64_t  limit = 0;

    // Two versions of the Reduction Bound.
    if (config_prr_crb_)
    {
      // PRR-CRB:  Conservative Reduction Bound.
      limit = (prr_delivered_ - prr_out_);
    }
    else
    {
      // PRR-SSRB:  Slow Start Reduction Bound.
      limit = (MAX((prr_delivered_ - prr_out_), delivered_data) + kCubicMss);
    }

    // Attempt to catch up, as permitted by limit.
    sndcnt = MIN((ssthresh_ - pipe_), limit);
  }

  // Note that prr_sndcnt_ limits the packets that can be transmitted in
  // CanSend() and CanResend(), as per RFC 6937, section 3.
  if (sndcnt > 0)
  {
    prr_sndcnt_ += sndcnt;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Add %" PRId64 " to "
         "sndcnt, total %" PRId64 ".\n", conn_id_, sndcnt, prr_sndcnt_);
#endif
  }

  // Note that the NextSeq() logic, as per RFC 6675, page 6, is implemented in
  // the connection and stream OnCanWrite(), OnCanSend(), and OnCanResend()
  // methods.  See the comments in Connection::OnCanWrite() for details.

#ifdef SLIQ_CC_DEBUG
  PrintState("UpdatePrr()");
#endif
}

//============================================================================
void Cubic::EndPrr()
{
  // Set cwnd to the new target computed at start of fast recovery, as per RFC
  // 6937.
  cwnd_             = ssthresh_;
  in_fast_recovery_ = false;

  // \todo Is this needed to prevent the ACKs that caused fast recovery to end
  // from updating cwnd further right now?

  // pre_ack_bytes_in_flight_ = bytes_in_flight_;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": End FR, cwnd %" PRId64
       ".\n", conn_id_, cwnd_);
#endif
}

//============================================================================
Cubic::StreamCcInfo::StreamCcInfo()
    : num_streams(0)
{
  for (int i = 0; i < (kMaxStreamId + 1); ++i)
  {
    stream_ids[i]          = 0;
    cc_info[i].init_flag   = false;
    cc_info[i].una_flag    = false;
    cc_info[i].una_seq_num = 0;
  }
}

//============================================================================
Cubic::StreamCcInfo::~StreamCcInfo()
{}

//============================================================================
void Cubic::StreamCcInfo::AddStream(StreamId stream_id)
{
  if (cc_info[stream_id].init_flag)
  {
    LogF(kClassName, __func__, "Stream %" PRIStreamId " already "
         "initialized.\n", stream_id);
    return;
  }

  // Add the stream.
  cc_info[stream_id].init_flag   = true;
  cc_info[stream_id].una_flag    = false;
  cc_info[stream_id].una_seq_num = 0;

  stream_ids[num_streams] = stream_id;
  num_streams++;
}

//============================================================================
void Cubic::StreamCcInfo::DelStream(StreamId stream_id)
{
  if (cc_info[stream_id].init_flag)
  {
    cc_info[stream_id].init_flag = false;

    // Update the list of all active stream IDs.
    if (num_streams > 0)
    {
      bool  found = false;

      for (int i = 0; i < num_streams; ++i)
      {
        if (!found)
        {
          found = (stream_ids[i] == stream_id);
        }
        else
        {
          if (i > 0)
          {
            stream_ids[i - 1] = stream_ids[i];
          }
        }
      }

      if (found)
      {
        num_streams--;
      }
    }
  }
}

#ifdef SLIQ_CC_DEBUG
//============================================================================
void Cubic::PrintState(const char* fn)
{
  char  state[4];

  if (in_fast_recovery_)
  {
    strncpy(state, "FR", 3);
  }
  else if (cwnd_ < ssthresh_)
  {
    strncpy(state, "SS", 3);
  }
  else
  {
    strncpy(state, "CA", 3);
  }

  LogD(kClassName, __func__, "*** Conn %" PRIEndptId ": %s - cwnd %" PRId64
       " ssthresh %" PRId64 " pif %" PRId32 " bif %" PRId64 " pipe %" PRId64
       " fn %s.\n",
       conn_id_, state, cwnd_, ssthresh_, pkts_in_flight_, bytes_in_flight_,
       pipe_, fn);

  LogD(kClassName, __func__, "State: update_snd_una_ %d snd_una_ %"
       PRIPktSeqNumber " snd_nxt_ %" PRIPktSeqNumber " high_seq_ %"
       PRIPktSeqNumber " snd_nxt_byte_offset_ %" PRIu32 " cubic_beta_ %f "
       "cubic_cwnd_tcp_ %" PRId64 " cubic_cwnd_last_max_ %" PRId64
       " cubic_last_cwnd_ %" PRId64 " cubic_last_time_ %s cubic_epoch_start_ "
       "%s cubic_delay_min_ %f cubic_origin_point_ %" PRId64 " cubic_cnt_ %"
       PRId64 " cubic_ack_cnt_ %" PRId64 " cubic_cwnd_cnt_ %" PRId64
       " cubic_k_ %" PRId64 " hystart_end_seq_ %" PRIPktSeqNumber
       " hystart_round_start_ %s hystart_last_ack_ %s hystart_curr_rtt_ %f "
       "hystart_sample_cnt_ %" PRIu32 " hystart_found_ %" PRIu32 " in_rto_ "
       "%d enter_fast_recovery_ %d in_fast_recovery_ %d prr_recovery_point_ %"
       PRIPktSeqNumber " prr_delivered_ %" PRId64 " prr_out_ %" PRId64
       " prr_recover_fs_ %" PRId64 " prr_sndcnt_ %" PRId64
       " last_app_send_time_ %s last_proto_send_time_ %s next_send_time_ %s "
       "max_bytes_out_ %" PRId64 " max_bytes_seq_ %" PRIPktSeqNumber
       " pre_ack_bytes_in_flight_ %" PRId64 " flight_size_ %" PRId64 "\n",
       static_cast<int>(update_snd_una_), snd_una_, snd_nxt_, high_seq_,
       snd_nxt_byte_offset_, cubic_beta_, cubic_cwnd_tcp_,
       cubic_cwnd_last_max_, cubic_last_cwnd_,
       cubic_last_time_.ToString().c_str(),
       cubic_epoch_start_.ToString().c_str(), cubic_delay_min_.ToDouble(),
       cubic_origin_point_, cubic_cnt_, cubic_ack_cnt_, cubic_cwnd_cnt_,
       cubic_k_, hystart_end_seq_, hystart_round_start_.ToString().c_str(),
       hystart_last_ack_.ToString().c_str(), hystart_curr_rtt_.ToDouble(),
       hystart_sample_cnt_, hystart_found_, static_cast<int>(in_rto_),
       static_cast<int>(enter_fast_recovery_),
       static_cast<int>(in_fast_recovery_), prr_recovery_point_,
       prr_delivered_, prr_out_, prr_recover_fs_, prr_sndcnt_,
       last_app_send_time_.ToString().c_str(),
       last_proto_send_time_.ToString().c_str(),
       next_send_time_.ToString().c_str(), max_bytes_out_, max_bytes_seq_,
       pre_ack_bytes_in_flight_, flight_size_);
}
#endif
