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

#include "sliq_cc_cubic_bytes.h"
#include "sliq_types.h"

#include "itime.h"
#include "log.h"
#include "unused.h"

#include <inttypes.h>

using ::sliq::Capacity;
using ::sliq::CubicBytes;
using ::sliq::CongCtrlAlg;
using ::sliq::HybridSlowStart;
using ::sliq::kMaxCongCtrlWindowPkts;
using ::sliq::PktSeqNumber;
using ::sliq::RttManager;
using ::iron::Log;
using ::iron::Time;


namespace
{
  /// Class name for logging.
  const char*     UNUSED(kClassName)  = "CubicBytes";

  // Constants based on TCP defaults.

  /// Default maximum packet size used in the Linux TCP implementation.
  const size_t    kDefaultTcpMss = 1460;

  /// The minimum cwnd, in bytes, based on RFC 3782 (TCP NewReno) for cwnd
  /// reductions on a fast retransmission.
  const size_t    kDefaultMinimumCongestionWindow = (2 * kDefaultTcpMss);

  /// The maximum segment size, in bytes.
  const size_t    kMaxSegmentSize = kDefaultTcpMss;

  /// Initial congestion control window size in bytes.
  const size_t    kInitCongCtrlWindowBytes = (2 * kDefaultTcpMss);

  /// Initial slow start threshold in bytes.
  const size_t    kInitSlowStartThresholdBytes = (6 * kDefaultTcpMss);

  /// The maximum burst size, in bytes.
  const size_t    kMaxBurstBytes = (3 * kMaxSegmentSize);

  /// The maximum congestion control window size in bytes.
  const size_t    kMaxCongCtrlWindowBytes = (kMaxCongCtrlWindowPkts *
                                             kDefaultTcpMss);

  /// The TCP Reno backoff factor.
  const double    kRenoBeta = 0.7;

  /// The minimum number of streams.  This gives better non-congestion loss
  /// behavior.
  const int       kMinNumStreams = 2;

  /// The number of microseconds in a second.
  const double    kNumMicrosPerSecond = (1000.0 * 1000.0);
}

//============================================================================
CubicBytes::CubicBytes(EndptId conn_id, bool is_client, RttManager& rtt_mgr,
                       bool reno)
    : CongCtrlInterface(conn_id, is_client),
      hybrid_slow_start_(conn_id),
      cubic_(conn_id),
      prr_(conn_id),
      rtt_mgr_(rtt_mgr),
      stream_cc_info_(),
      next_cc_seq_num_(1),
      reno_(reno),
      num_acked_pkts_(0),
      in_fast_recovery_(false),
      cwnd_(kInitCongCtrlWindowBytes),
      min_cwnd_(kDefaultMinimumCongestionWindow),
      max_cwnd_(kMaxCongCtrlWindowBytes),
      ssthresh_(kInitSlowStartThresholdBytes),
      num_rexmits_(0)
{
}

//============================================================================
CubicBytes::~CubicBytes()
{
  return;
}

//============================================================================
bool CubicBytes::Configure(const CongCtrl& cc_params)
{
  return true;
}

//============================================================================
void CubicBytes::Connected(const Time& now, const Time& rtt)
{
  return;
}

//============================================================================
bool CubicBytes::UseRexmitPacing()
{
  return false;
}

//============================================================================
bool CubicBytes::UseCongWinForCapEst()
{
  return true;
}

//============================================================================
bool CubicBytes::UseUnaPktReporting()
{
  return false;
}

//============================================================================
bool CubicBytes::SetTcpFriendliness(uint32_t num_flows)
{
  // Set the number of TCP flows in CUBIC.
  int  nf = num_flows;

  if (nf < kMinNumStreams)
  {
    nf = kMinNumStreams;
  }

  cubic_.SetNumTcpFlows(nf);

  return true;
}

//============================================================================
bool CubicBytes::ActivateStream(StreamId stream_id,
                                PktSeqNumber init_send_seq_num)
{
  if (stream_id > kMaxStreamId)
  {
    return false;
  }

  stream_cc_info_.AddStream(stream_id, init_send_seq_num);

  return true;
}

//============================================================================
bool CubicBytes::DeactivateStream(StreamId stream_id)
{
  if (stream_id > kMaxStreamId)
  {
    return false;
  }

  stream_cc_info_.DelStream(stream_id);

  return true;
}

//============================================================================
void CubicBytes::OnAckPktProcessingStart(const Time& ack_time)
{
  return;
}

//============================================================================
void CubicBytes::OnRttUpdate(StreamId /* stream_id */,
                             const Time& /* ack_time */,
                             PktTimestamp /* send_ts */,
                             PktTimestamp /* recv_ts */,
                             PktSeqNumber /* seq_num */,
                             PktSeqNumber /* cc_seq_num */,
                             const Time& /* rtt */, uint32_t /* bytes */,
                             float /* cc_val */)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Rtt update.\n", conn_id_);
#endif

  // If currently in slow start, then check if slow start should be exited.
  if (InSlowStart() &&
      hybrid_slow_start_.ShouldExitSlowStart(rtt_mgr_.latest_rtt(),
                                             rtt_mgr_.minimum_rtt(),
                                             (cwnd_ / kMaxSegmentSize)))
  {
    // Exit slow start, enter congestion avoidance.
    ssthresh_ = cwnd_;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Exit slow start, enter "
         "congestion avoidance - cwnd %zu ssthresh %zu.\n", conn_id_, cwnd_,
         ssthresh_);
#endif
  }
}

//============================================================================
bool CubicBytes::OnPacketLost(StreamId stream_id, const Time& /* ack_time */,
                              PktSeqNumber seq_num,
                              PktSeqNumber /* cc_seq_num */,
                              uint32_t /* bytes */)
{
  if (in_fast_recovery_)
  {
    // TCP NewReno (RFC6582) says that once a loss occurs and fast recovery is
    // begun, any losses in packets already sent should be treated as a single
    // loss event, since it's expected.  However, the packet should be
    // considered lost and retransmitted immediately.
    if (stream_cc_info_.IgnoreLoss(stream_id, seq_num))
    {
#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "ooo Conn %" PRIEndptId ": Args seq %"
           PRIPktSeqNumber "\n", conn_id_, seq_num);

      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Ignoring loss for "
           "stream %" PRIStreamId " seq %" PRIPktSeqNumber ", part of fast "
           "recovery, consider lost.\n", conn_id_, stream_id, seq_num);

      PrintState("OnPacketLost()");
#endif

      return true;
    }

    // This loss is beyond the fast recovery window.  Do not consider the
    // packet lost yet.
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Ignoring loss for "
         "stream %" PRIStreamId " seq %" PRIPktSeqNumber ", outside of fast "
         "recovery, not considering lost.\n", conn_id_, stream_id, seq_num);
#endif

    return false;
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "ooo Conn %" PRIEndptId ": Args seq %"
       PRIPktSeqNumber "\n", conn_id_, seq_num);
#endif

  // Leave congestion avoidance, and enter a fast recovery period.
  prr_.OnPacketLost(bytes_in_flight_);

  // Adjust the congestion window size.
  if (reno_)
  {
    cwnd_ = cwnd_ * RenoBeta();
  }
  else
  {
    cwnd_ = cubic_.CongestionWindowAfterPacketLoss(cwnd_);

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated cubic cwnd "
         "%zu\n", conn_id_, cwnd_);
#endif
  }

  // Store the congestion window as the slow start threshold.
  ssthresh_ = cwnd_;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated cubic ssthresh "
       "%zu\n", conn_id_, ssthresh_);
#endif

  // Enforce TCP's minimum congestion window of 2*MSS.
  if (cwnd_ < min_cwnd_)
  {
    cwnd_ = min_cwnd_;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated cwnd to min "
         "%zu\n", conn_id_, cwnd_);
#endif
  }

  // Record the largest sequence number sent thus far for each stream.  This
  // is used to determine when the fast recovery period is over.
  stream_cc_info_.EnterFastRecovery();
  in_fast_recovery_ = true;

  // Reset the packet count from congestion avoidance mode.  We start counting
  // again when we're out of fast recovery.
  num_acked_pkts_ = 0;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Loss of stream %"
       PRIStreamId " seq %" PRIPktSeqNumber " largest sent seq %"
       PRIPktSeqNumber ".\n", conn_id_, stream_id, seq_num,
       stream_cc_info_.cc_info[stream_id].last_sent_seq_num);

  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Entering fast recovery - "
       "cwnd %zu ssthresh %zu.\n", conn_id_, cwnd_, ssthresh_);

  PrintState("OnPacketLost()");
#endif

  return true;
}

//============================================================================
void CubicBytes::OnPacketAcked(StreamId stream_id, const Time& ack_time,
                               PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                               PktSeqNumber ne_seq_num, uint32_t bytes)

{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "ooo Conn %" PRIEndptId ": Args stream %"
       PRIStreamId " seq %" PRIPktSeqNumber " bytes %" PRIu32 " next exp seq "
       "%" PRIPktSeqNumber " ccseq %" PRIPktSeqNumber ".\n", conn_id_,
       stream_id, seq_num, bytes, ne_seq_num, cc_seq_num);
#endif

  // Update any fast recovery information and check if fast recovery should
  // end.
  if (in_fast_recovery_ && stream_cc_info_.AckedPacket(stream_id, ne_seq_num))
  {
    in_fast_recovery_ = false;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Leaving fast "
         "recovery.\n", conn_id_);
#endif
  }

  // If in fast recovery, then update PRR with the number of bytes ACKed.
  if (in_fast_recovery_)
  {
    prr_.OnPacketAcked(bytes);

#ifdef SLIQ_CC_DEBUG
    PrintState("OnPacketAcked()");
#endif

    return;
  }

  // Not currently in fast recovery.  Update the congestion window.
  MaybeIncreaseCwnd(bytes, ack_time);

  // Update any slow start information.
  hybrid_slow_start_.OnPacketAcked(cc_seq_num, InSlowStart());

#ifdef SLIQ_CC_DEBUG
  PrintState("OnPacketAcked()");
#endif
}

//============================================================================
void CubicBytes::OnAckPktProcessingDone(const Time& ack_time)
{
  // Allow one fast retransmission.  Note that this shouldn't be necessary
  // since PRR is in use and all fast retransmission should occur in fast
  // recovery.
  num_rexmits_ = 1;
}

//============================================================================
PktSeqNumber CubicBytes::OnPacketSent(StreamId stream_id,
                                      const Time& /*send_time*/,
                                      PktSeqNumber seq_num,
                                      uint32_t pld_bytes,
                                      uint32_t /* tot_bytes */,
                                      float& /* cc_val */)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "ooo Conn %" PRIEndptId ": Args bif %" PRId64
       " seq %" PRIPktSeqNumber " bytes %" PRIu32 "\n", conn_id_,
       bytes_in_flight_, seq_num, pld_bytes);
#endif

  if (SEQ_LEQ(seq_num, stream_cc_info_.cc_info[stream_id].last_sent_seq_num))
  {
    LogW(kClassName, __func__, "Conn %" PRIEndptId ": Packet seq %"
         PRIPktSeqNumber " <= largest send seq %" PRIPktSeqNumber ".\n",
         conn_id_, seq_num,
         stream_cc_info_.cc_info[stream_id].last_sent_seq_num);
  }

  // Assign a congestion control sequence number to the packet.
  PktSeqNumber  cc_seq_num = next_cc_seq_num_;
  next_cc_seq_num_++;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Assign seq %"
       PRIPktSeqNumber " to ccseq %" PRIPktSeqNumber ".\n", conn_id_, seq_num,
       cc_seq_num);
#endif

  // If currently in fast recovery, then update PRR with the number of payload
  // bytes sent.
  if (in_fast_recovery_)
  {
    prr_.OnPacketSent(pld_bytes);
  }

  // Always update the largest sent sequence number.
  stream_cc_info_.SentPacket(stream_id, seq_num);

  // Always update any slow start information.
  hybrid_slow_start_.OnPacketSent(cc_seq_num);

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
void CubicBytes::OnPacketResent(StreamId stream_id,
                                const Time& /* send_time */,
                                PktSeqNumber seq_num,
                                PktSeqNumber /* cc_seq_num */,
                                uint32_t pld_bytes, uint32_t /* tot_bytes */,
                                bool rto, bool /* orig_cc */,
                                float& /* cc_val */)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "ooo Conn %" PRIEndptId ": Args bif %" PRId64
       " seq %" PRIPktSeqNumber " bytes %" PRIu32 "\n", conn_id_,
       bytes_in_flight_, seq_num, pld_bytes);
#endif

  if (SEQ_GT(seq_num, stream_cc_info_.cc_info[stream_id].last_sent_seq_num))
  {
    LogW(kClassName, __func__, "Conn %" PRIEndptId ": Packet seq %"
         PRIPktSeqNumber " > largest send seq %" PRIPktSeqNumber ".\n",
         conn_id_, seq_num,
         stream_cc_info_.cc_info[stream_id].last_sent_seq_num);
  }

  // If the retransmission is due to an RTO event, then do not update any of
  // the state.
  if (rto)
  {
    return;
  }

  // If currently in fast recovery, then update PRR with the number of bytes
  // sent.
  if (in_fast_recovery_)
  {
    prr_.OnPacketSent(pld_bytes);
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Resent data on stream %"
       PRIStreamId " seq %" PRIPktSeqNumber " bytes %" PRIu32 ".\n", conn_id_,
       stream_id, seq_num, pld_bytes);

  PrintState("OnPacketResent()");
#endif
}

//============================================================================
void CubicBytes::OnRto(bool pkt_rexmit)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "ooo Conn %" PRIEndptId ": Args pkt_rexmit %d\n",
       conn_id_, static_cast<int>(pkt_rexmit));
#endif

  // Exit fast recovery.
  if (in_fast_recovery_)
  {
    in_fast_recovery_ = false;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Leaving fast recovery "
         "period.\n", conn_id_);
#endif
  }

  // If there were no packets retransmitted, then stop processing.
  if (!pkt_rexmit)
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": RTO, no "
         "retransmissions.\n", conn_id_);

    PrintState("OnRto(false)");
#endif

    return;
  }

  // Start over in slow start.
  cubic_.Reset();
  hybrid_slow_start_.Restart();
  ssthresh_ = cwnd_ / 2;
  cwnd_     = min_cwnd_;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Entering slow start.\n",
       conn_id_);

  LogD(kClassName, __func__, "Conn %" PRIEndptId ": RTO - cwnd %zu ssthresh "
       "%zu.\n", conn_id_, cwnd_, ssthresh_);

  PrintState("OnRto(true)");
#endif
}

//============================================================================
void CubicBytes::OnOutageEnd()
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "ooo Conn %" PRIEndptId ": Outage is over.\n",
       conn_id_);
#endif

  // Start over in slow start.
  cubic_.Reset();
  hybrid_slow_start_.Restart();
  in_fast_recovery_ = false;
  cwnd_             = (2 * kDefaultTcpMss);
  ssthresh_         = (6 * kDefaultTcpMss);

#ifdef SLIQ_CC_DEBUG
  PrintState("OnOutageEnd()");
#endif
}

//============================================================================
bool CubicBytes::CanSend(const Time& /* now */, uint32_t /* bytes */)
{
  // If currently in fast recovery, then PRR is used.
  if (in_fast_recovery_)
  {
    return prr_.CanSend(cwnd_, bytes_in_flight_, ssthresh_);
  }

  return (static_cast<ssize_t>(cwnd_) > bytes_in_flight_);
}

//============================================================================
bool CubicBytes::CanResend(const Time& /* now */, uint32_t /* bytes */,
                           bool /* orig_cc */)
{
  // We should be in fast recovery, and PRR should be used to make this
  // decision.
  if (in_fast_recovery_)
  {
    return prr_.CanSend(cwnd_, bytes_in_flight_, ssthresh_);
  }

  // This should not occur.  Still, allow a single fast retransmission per ACK
  // packet collection processed.
  LogW(kClassName, __func__, "Conn %" PRIEndptId ": Requesting fast "
       "retransmission when not in fast recovery, num_rexmits %zu.\n",
       conn_id_, num_rexmits_);

  bool  rv = (num_rexmits_ > 0);

  if (rv)
  {
    --num_rexmits_;
  }

  return rv;
}

//============================================================================
Time CubicBytes::TimeUntilSend(const Time& /* now */)
{
  // This class does not do any send pacing by itself.
  return Time();
}

//============================================================================
Capacity CubicBytes::SendPacingRate()
{
  // We pace at twice the rate of the underlying sender's channel capacity
  // estimate during slow start and 1.25x during congestion avoidance to
  // ensure pacing doesn't prevent us from filling the window.
  Time    srtt            = rtt_mgr_.smoothed_rtt();
  double  bits_per_second = ((static_cast<double>(cwnd_) * 8.0 *
                              kNumMicrosPerSecond) /
                             static_cast<double>(srtt.GetTimeInUsec()));

  if (InSlowStart())
  {
    bits_per_second *= 2;
  }
  else
  {
    bits_per_second *= 1.25;
  }

  Capacity  bps = static_cast<Capacity>(bits_per_second);

  return bps;
}

//============================================================================
Capacity CubicBytes::SendRate()
{
  Time       srtt            = rtt_mgr_.smoothed_rtt();
  double     bits_per_second = ((static_cast<double>(cwnd_) * 8.0 *
                                 kNumMicrosPerSecond) /
                                static_cast<double>(srtt.GetTimeInUsec()));
  Capacity   bps             = static_cast<Capacity>(bits_per_second);

  return bps;
}

//============================================================================
bool CubicBytes::GetSyncParams(uint16_t& seq_num, uint32_t& cc_params)
{
  return false;
}

//============================================================================
void CubicBytes::ProcessSyncParams(const Time& now, uint16_t seq_num,
                                   uint32_t cc_params)
{
  return;
}

//============================================================================
void CubicBytes::ProcessCcPktTrain(const Time& now, CcPktTrainHeader& hdr)
{
  return;
}

//============================================================================
bool CubicBytes::InSlowStart()
{
  return (cwnd_ < ssthresh_);
}

//============================================================================
bool CubicBytes::InRecovery()
{
  return in_fast_recovery_;
}

//============================================================================
uint32_t CubicBytes::GetCongestionWindow()
{
  return cwnd_;
}

//============================================================================
uint32_t CubicBytes::GetSlowStartThreshold()
{
  return ssthresh_;
}

//============================================================================
CongCtrlAlg CubicBytes::GetCongestionControlType()
{
  return reno_ ? TCP_RENO_BYTES_CC : TCP_CUBIC_BYTES_CC;
}

//============================================================================
void CubicBytes::Close()
{
  return;
}

//============================================================================
double CubicBytes::RenoBeta() const
{
  // kNConnectionBeta is the backoff factor after loss for our N-connection
  // emulation, which emulates the effective backoff of an ensemble of N
  // TCP-Reno connections on a single loss event.  The effective multiplier is
  // computed as:

  int  ns = stream_cc_info_.num_streams;

  if (ns < kMinNumStreams)
  {
    ns = kMinNumStreams;
  }

  return (((static_cast<double>(ns) - 1.0) + kRenoBeta) /
          static_cast<double>(ns));
}

//============================================================================
void CubicBytes::MaybeIncreaseCwnd(uint32_t acked_bytes, const Time& now)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args bytes %" PRIu32
       " bif %" PRId64 "\n", conn_id_, acked_bytes, bytes_in_flight_);
#endif

  // Called when we receive an ACK.  Normal TCP tracks how many packets one
  // ACK represents, but SLIQ has a separate ACK for each packet.
  if (in_fast_recovery_)
  {
    LogW(kClassName, __func__, "Conn %" PRIEndptId ": Never increase the "
         "cwnd during fast recovery.\n", conn_id_);
    return;
  }

  // We don't update the congestion window unless we are close to using the
  // window we have available.
  if (!IsCwndLimited())
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Is not cwnd limited, "
         "not updating cwnd %zu ssthres %zu.\n", conn_id_, cwnd_, ssthresh_);
#endif

    return;
  }

  // If cwnd is already at the maximum size allowed, then do not increase it
  // further.
  if (cwnd_ >= max_cwnd_)
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Hit cwnd limit, not "
         "updating cwnd %zu ssthres %zu.\n", conn_id_, cwnd_, ssthresh_);
#endif

    return;
  }

  // If in slow start, then use exponential growth.
  if (InSlowStart())
  {
    // Increase cwnd by one for each ACK.
    cwnd_ += kMaxSegmentSize;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Slow start - cwnd %zu "
         "ssthres %zu.\n", conn_id_, cwnd_, ssthresh_);
#endif

    return;
  }

  // Currently in congestion avoidance.
  if (reno_)
  {
    // Classic Reno congestion avoidance.
    ++num_acked_pkts_;

    int  ns = stream_cc_info_.num_streams;

    if (ns < kMinNumStreams)
    {
      ns = kMinNumStreams;
    }

    // Divide by the number of streams (ns) to smoothly increase the cwnd at a
    // faster rate than conventional Reno.
    if ((num_acked_pkts_ * static_cast<uint64_t>(ns)) >=
        (cwnd_ / kMaxSegmentSize))
    {
      cwnd_           += kMaxSegmentSize;
      num_acked_pkts_  = 0;
    }

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Reno - cwnd %zu "
         "ssthres %zu ACK cnt %" PRIu64 ".\n", conn_id_, cwnd_, ssthresh_,
         num_acked_pkts_);
#endif
  }
  else
  {
    Time  min_rtt = rtt_mgr_.minimum_rtt();

    cwnd_ = cubic_.CongestionWindowAfterAck(acked_bytes, cwnd_, min_rtt, now);

    if (cwnd_ > max_cwnd_)
    {
      cwnd_ = max_cwnd_;
    }

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Cubic - cwnd %zu "
         "ssthres %zu.\n", conn_id_, cwnd_, ssthresh_);
#endif
  }
}

//============================================================================
bool CubicBytes::IsCwndLimited()
{
  if (bytes_in_flight_ >= static_cast<ssize_t>(cwnd_))
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Clearly cwnd limited "
         "cwnd %zu bif %" PRId64 " result 1.\n", conn_id_, cwnd_,
         bytes_in_flight_);
#endif

    return true;
  }

  const size_t  available_bytes    = (cwnd_ - bytes_in_flight_);
  const bool    slow_start_limited =
    (InSlowStart() && (bytes_in_flight_ > static_cast<ssize_t>(cwnd_ / 2)));

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Checking cwnd %zu bif %"
       PRId64 " available_bytes %zu in_slow_start %d slow_start_limited %d "
       "result %d.\n", conn_id_, cwnd_, bytes_in_flight_, available_bytes,
       static_cast<int>(InSlowStart()), static_cast<int>(slow_start_limited),
       static_cast<int>(slow_start_limited ||
                        (available_bytes <= kMaxBurstBytes)));
#endif

  return (slow_start_limited || (available_bytes <= kMaxBurstBytes));
}

//============================================================================
CubicBytes::StreamCcInfo::StreamCcInfo()
    : num_streams(0), num_exits(0)
{
  for (int i = 0; i < (kMaxStreamId + 1); ++i)
  {
    stream_ids[i]                = 0;
    cc_info[i].init_flag         = false;
    cc_info[i].fr_exit_flag      = false;
    cc_info[i].last_sent_seq_num = 0;
    cc_info[i].fr_exit_seq_num   = 0;
  }
}

//============================================================================
CubicBytes::StreamCcInfo::~StreamCcInfo()
{}

//============================================================================
void CubicBytes::StreamCcInfo::AddStream(StreamId stream_id,
                                         PktSeqNumber init_seq_num)
{
  if (cc_info[stream_id].init_flag)
  {
    return;
  }

  // Add the stream assuming that we are already in fast recovery.
  cc_info[stream_id].init_flag         = true;
  cc_info[stream_id].fr_exit_flag      = true;
  cc_info[stream_id].last_sent_seq_num = (init_seq_num - 1);
  cc_info[stream_id].fr_exit_seq_num   = (init_seq_num - 1);

  stream_ids[num_streams] = stream_id;
  num_streams++;
  num_exits++;
}

//============================================================================
void CubicBytes::StreamCcInfo::SentPacket(StreamId stream_id,
                                          PktSeqNumber sent_seq_num)
{
  // Update the last sent sequence number.
  if (cc_info[stream_id].init_flag)
  {
    cc_info[stream_id].last_sent_seq_num = sent_seq_num;
  }
}

//============================================================================
void CubicBytes::StreamCcInfo::EnterFastRecovery()
{
  // Prepare all of the streams for fast recovery.
  for (int i = 0; i < num_streams; ++i)
  {
    StreamId  stream_id = stream_ids[i];

    cc_info[stream_id].fr_exit_flag    = false;
    cc_info[stream_id].fr_exit_seq_num = cc_info[stream_id].last_sent_seq_num;
  }

  // Set the number of streams that have exited to zero.
  num_exits = 0;
}

//============================================================================
bool CubicBytes::StreamCcInfo::IgnoreLoss(StreamId stream_id,
                                          PktSeqNumber seq_num)
{
  // Check if the lost packet sequence number is within the fast recovery
  // window.
  if ((cc_info[stream_id].init_flag) &&
      (SEQ_LEQ(seq_num, cc_info[stream_id].fr_exit_seq_num)))
  {
    return true;
  }

  return false;
}

//============================================================================
bool CubicBytes::StreamCcInfo::AckedPacket(StreamId stream_id,
                                           PktSeqNumber ne_seq_num)
{
  // Update the stream's fast recovery state.
  if (cc_info[stream_id].init_flag &&
      (!cc_info[stream_id].fr_exit_flag) &&
      SEQ_GT(ne_seq_num, cc_info[stream_id].fr_exit_seq_num))
  {
    cc_info[stream_id].fr_exit_flag = true;
    num_exits++;
  }

  // Return true if fast recovery should be exited.
  return (num_exits >= num_streams);
}

//============================================================================
void CubicBytes::StreamCcInfo::DelStream(StreamId stream_id)
{
  if (cc_info[stream_id].init_flag)
  {
    cc_info[stream_id].init_flag = false;

    // Correct the fast recovery exit information.
    if (cc_info[stream_id].fr_exit_flag)
    {
      cc_info[stream_id].fr_exit_flag = false;
      num_exits--;
    }

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
void CubicBytes::PrintState(const char* fn)
{
  if (in_fast_recovery_)
  {
    LogD(kClassName, __func__, "*** Conn %" PRIEndptId ": Fast recovery - "
         "cwnd %zu ssthresh %zu #conn %d fn %s\n",
         conn_id_, cwnd_, ssthresh_, stream_cc_info_.num_streams, fn);
  }
  else if (cwnd_ < ssthresh_)
  {
    LogD(kClassName, __func__, "*** Conn %" PRIEndptId ": Slow start - "
         "cwnd %zu ssthresh %zu #conn %d fn %s\n",
         conn_id_, cwnd_, ssthresh_, stream_cc_info_.num_streams, fn);
  }
  else
  {
    LogD(kClassName, __func__, "*** Conn %" PRIEndptId ": Cubic - "
         "cwnd %zu ssthresh %zu #conn %d fn %s\n",
         conn_id_, cwnd_, ssthresh_, stream_cc_info_.num_streams, fn);
  }
}
#endif
