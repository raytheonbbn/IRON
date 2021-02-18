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

#include "sliq_cc_fixed_rate.h"

#include "log.h"

#include <inttypes.h>


using ::sliq::Capacity;
using ::sliq::CongCtrlAlg;
using ::sliq::FixedRate;
using ::sliq::PktSeqNumber;
using ::iron::Log;
using ::iron::Time;


namespace
{
  /// The class name string for logging.
  const char*   kClassName          = "FixedRate";

  /// The inter-send time quiescent threshold, in seconds.
  const double  kQuiescentThreshold = 0.01;

  /// The packet overhead due to Ethernet (14 bytes), IP (20 bytes), and UDP
  /// (8 bytes), in bytes.  This assumes that no 802.1Q tag is present in the
  /// Ethernet frame, and that no IP header options are present.
  const size_t  kPktOverheadBytes   = 42;
}


//============================================================================
FixedRate::FixedRate(EndptId conn_id, bool is_client)
    : CongCtrlInterface(conn_id, is_client),
      connected_(false),
      send_rate_bps_(0),
      nxt_cc_seq_num_(0),
      next_send_time_(),
      timer_tolerance_(Time::FromMsec(1))
{
  // Initialize the next send time.
  if (!next_send_time_.GetNow())
  {
    LogF(kClassName, __func__, "Failed to get current time.\n");
  }
}

//============================================================================
FixedRate::~FixedRate()
{
  return;
}

//============================================================================
bool FixedRate::Configure(const CongCtrl& cc_params)
{
  if (cc_params.fixed_send_rate == 0)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Invalid fixed send "
         "rate %" PRICapacity " bps.\n", conn_id_, cc_params.fixed_send_rate);
    return false;
  }

  send_rate_bps_ = cc_params.fixed_send_rate;

  LogC(kClassName, __func__, "Conn %" PRIEndptId ": Setting fixed send "
       "rate to %" PRICapacity " bps.\n", conn_id_, send_rate_bps_);

  return true;
}

//============================================================================
void FixedRate::Connected(const Time& /* now */, const Time& /* rtt */)
{
  connected_ = true;
}

//============================================================================
bool FixedRate::UseRexmitPacing()
{
  return true;
}

//============================================================================
bool FixedRate::UseCongWinForCapEst()
{
  return false;
}

//============================================================================
bool FixedRate::UseUnaPktReporting()
{
  return false;
}

//============================================================================
bool FixedRate::SetTcpFriendliness(uint32_t /* num_flows */)
{
  return true;
}

//============================================================================
bool FixedRate::ActivateStream(StreamId /* stream_id */,
                               PktSeqNumber /* init_send_seq_num */)
{
  return true;
}

//============================================================================
bool FixedRate::DeactivateStream(StreamId /* stream_id */)
{
  return true;
}

//============================================================================
void FixedRate::OnAckPktProcessingStart(const Time& /* ack_time */)
{
  return;
}

//============================================================================
void FixedRate::OnRttUpdate(StreamId /* stream_id */,
                            const Time& /* ack_time */,
                            PktTimestamp /* send_ts */,
                            PktTimestamp /* recv_ts */,
                            PktSeqNumber /* seq_num */,
                            PktSeqNumber /* cc_seq_num */,
                            const Time& /* rtt */, uint32_t /* bytes */,
                            float /* cc_val */)
{
  return;
}

//============================================================================
bool FixedRate::OnPacketLost(StreamId /* stream_id */,
                             const Time& /* ack_time */,
                             PktSeqNumber /* seq_num */,
                             PktSeqNumber /* cc_seq_num */,
                             uint32_t /* bytes */)
{
  return true;
}

//============================================================================
void FixedRate::OnPacketAcked(StreamId /* stream_id */,
                              const Time& /* ack_time */,
                              PktSeqNumber /* seq_num */,
                              PktSeqNumber /* cc_seq_num */,
                              PktSeqNumber /* ne_seq_num */,
                              uint32_t /* bytes */)
{
  return;
}

//============================================================================
void FixedRate::OnAckPktProcessingDone(const Time& /* ack_time */)
{
  return;
}

//============================================================================
PktSeqNumber FixedRate::OnPacketSent(StreamId stream_id,
                                     const Time& send_time,
                                     PktSeqNumber seq_num, uint32_t pld_bytes,
                                     uint32_t tot_bytes, float& cc_val)
{
  // Assign a CC sequence number to the packet.
  PktSeqNumber  cc_seq_num = nxt_cc_seq_num_;
  ++nxt_cc_seq_num_;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": On Send: stream=%"
       PRIStreamId " seq_num=%" PRIPktSeqNumber " cc_seq_num=%"
       PRIPktSeqNumber " send_time=%s size=%" PRIu32 "/%" PRIu32
       " cc_val=%f\n", conn_id_, stream_id, seq_num, cc_seq_num,
       send_time.ToString().c_str(), pld_bytes, tot_bytes,
       static_cast<double>(cc_val));
#endif

  // Update the next send time.
  UpdateNextSendTime(send_time, tot_bytes);

  return cc_seq_num;
}

//============================================================================
void FixedRate::OnPacketResent(StreamId stream_id, const Time& send_time,
                               PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                               uint32_t pld_bytes, uint32_t tot_bytes,
                               bool rto, bool orig_cc, float& cc_val)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": On Resend: stream=%"
       PRIStreamId " seq_num=%" PRIPktSeqNumber " cc_seq_num=%"
       PRIPktSeqNumber " send_time=%s size=%" PRIu32 "/%" PRIu32" rto=%d "
       "orig_cc=%d cc_val=%f\n", conn_id_, stream_id, seq_num, cc_seq_num,
       send_time.ToString().c_str(), pld_bytes, tot_bytes,
       static_cast<int>(rto), static_cast<int>(orig_cc),
       static_cast<double>(cc_val));
#endif

  // Update the next send time if this is not due to an RTO event.
  if (!rto)
  {
    UpdateNextSendTime(send_time, tot_bytes);
  }
}

//============================================================================
void FixedRate::OnRto(bool /* pkt_rexmit */)
{
  return;
}

//============================================================================
void FixedRate::OnOutageEnd()
{
  return;
}

//============================================================================
bool FixedRate::CanSend(const Time& /* now */, uint32_t /* bytes */)
{
  // Once the connection is set up, always allow sends.
  return connected_;
}

//============================================================================
bool FixedRate::CanResend(const Time& /* now */, uint32_t /* bytes */,
                          bool /* orig_cc */)
{
  // FixedRate paces fast retransmissions, so this can just return true.
  return true;
}

//============================================================================
Time FixedRate::TimeUntilSend(const Time& now)
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
Capacity FixedRate::SendPacingRate()
{
  return send_rate_bps_;
}

//============================================================================
Capacity FixedRate::SendRate()
{
  return send_rate_bps_;
}

//============================================================================
bool FixedRate::GetSyncParams(uint16_t& /* seq_num */,
                              uint32_t& /* cc_params */)
{
  return false;
}

//============================================================================
void FixedRate::ProcessSyncParams(const Time& /* now */,
                                  uint16_t /* seq_num */,
                                  uint32_t /* cc_params */)
{
  return;
}

//============================================================================
void FixedRate::ProcessCcPktTrain(const Time& /* now */,
                                  CcPktTrainHeader& /* hdr */)
{
  return;
}

//============================================================================
bool FixedRate::InSlowStart()
{
  return false;
}

//============================================================================
bool FixedRate::InRecovery()
{
  return false;
}

//============================================================================
uint32_t FixedRate::GetCongestionWindow()
{
  return 0;
}

//============================================================================
uint32_t FixedRate::GetSlowStartThreshold()
{
  return 0;
}

//============================================================================
CongCtrlAlg FixedRate::GetCongestionControlType()
{
  return FIXED_RATE_TEST_CC;
}

//============================================================================
void FixedRate::Close()
{
  return;
}

//============================================================================
void FixedRate::UpdateNextSendTime(const Time& now, size_t bytes)
{
  // Update the next send time using the packet size, the send rate, and the
  // stored next send time.  This maintains inter-send time accuracy.
  double  ist = ((8.0 * static_cast<double>(bytes + kPktOverheadBytes)) /
                 static_cast<double>(send_rate_bps_));

  // If the current time is more than kQuiescentThreshold seconds beyond the
  // stored next send time, then the sender is considered to have been
  // quiescent for a time, so the next send time must be computed from now.
  // Otherwise, the send pacing timer must have been used, so add the
  // inter-send time for this packet to the stored next send time.
  if (now > next_send_time_.Add(kQuiescentThreshold))
  {
    next_send_time_ = now.Add(ist);
  }
  else
  {
    next_send_time_ = next_send_time_.Add(ist);
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Waiting for "
       "intersend_time=%f\n", conn_id_, ist);
#endif
}
