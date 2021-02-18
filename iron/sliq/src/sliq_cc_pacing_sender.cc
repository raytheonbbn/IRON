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

#include "sliq_cc_pacing_sender.h"
#include "sliq_types.h"

#include "itime.h"

using ::sliq::Capacity;
using ::sliq::CongCtrlAlg;
using ::sliq::PacingSender;
using ::sliq::PktSeqNumber;
using ::iron::Time;


namespace
{
  /// Control the pacing burst option.
  const bool      kLimitPacingBurst = true;

  /// The number of microseconds in a second.
  const uint64_t  kNumMicrosPerSecond = (1000 * 1000);

  /// Default maximum packet size used in the Linux TCP implementation.
  const size_t    kDefaultTcpMss = 1460;
}

//============================================================================
PacingSender::PacingSender(EndptId conn_id, bool is_client,
                           CongCtrlInterface* cc_alg,
                           const Time& timer_granularity,
                           size_t initial_packet_burst)
    : CongCtrlInterface(conn_id, is_client),
      cc_alg_(cc_alg),
      timer_granularity_(timer_granularity),
      initial_packet_burst_(initial_packet_burst),
      burst_tokens_(initial_packet_burst),
      last_delayed_packet_sent_time_(),
      ideal_next_packet_send_time_(),
      was_last_send_delayed_(false)
{
}

//============================================================================
PacingSender::~PacingSender()
{
  if (cc_alg_ != NULL)
  {
    delete cc_alg_;
    cc_alg_ = NULL;
  }
}

//============================================================================
bool PacingSender::Configure(const CongCtrl& cc_params)
{
  return cc_alg_->Configure(cc_params);
}

//============================================================================
void PacingSender::Connected(const Time& now, const Time& rtt)
{
  cc_alg_->Connected(now, rtt);
}

//============================================================================
bool PacingSender::UseRexmitPacing()
{
  return cc_alg_->UseRexmitPacing();
}

//============================================================================
bool PacingSender::UseCongWinForCapEst()
{
  return cc_alg_->UseCongWinForCapEst();
}

//============================================================================
bool PacingSender::UseUnaPktReporting()
{
  return cc_alg_->UseUnaPktReporting();
}

//============================================================================
bool PacingSender::SetTcpFriendliness(uint32_t num_flows)
{
  return cc_alg_->SetTcpFriendliness(num_flows);
}

//============================================================================
bool PacingSender::ActivateStream(StreamId stream_id,
                                  PktSeqNumber init_send_seq_num)
{
  return cc_alg_->ActivateStream(stream_id, init_send_seq_num);
}

//============================================================================
bool PacingSender::DeactivateStream(StreamId stream_id)
{
  return cc_alg_->DeactivateStream(stream_id);
}

//============================================================================
void PacingSender::OnAckPktProcessingStart(const Time& ack_time)
{
  cc_alg_->OnAckPktProcessingStart(ack_time);
}

//============================================================================
void PacingSender::OnRttUpdate(StreamId stream_id, const Time& ack_time,
                               PktTimestamp send_ts, PktTimestamp recv_ts,
                               PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                               const Time& rtt, uint32_t bytes, float cc_val)
{
  cc_alg_->OnRttUpdate(stream_id, ack_time, send_ts, recv_ts, seq_num,
                       cc_seq_num, rtt, bytes, cc_val);
}

//============================================================================
bool PacingSender::OnPacketLost(StreamId stream_id, const Time& ack_time,
                                PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                                uint32_t bytes)
{
  return cc_alg_->OnPacketLost(stream_id, ack_time, seq_num, cc_seq_num,
                               bytes);
}

//============================================================================
void PacingSender::OnPacketAcked(StreamId stream_id, const Time& ack_time,
                                 PktSeqNumber seq_num,
                                 PktSeqNumber cc_seq_num,
                                 PktSeqNumber ne_seq_num, uint32_t bytes)
{
  cc_alg_->OnPacketAcked(stream_id, ack_time, seq_num, cc_seq_num, ne_seq_num,
                         bytes);
}

//============================================================================
void PacingSender::OnAckPktProcessingDone(const Time& ack_time)
{
  cc_alg_->OnAckPktProcessingDone(ack_time);
}

//============================================================================
PktSeqNumber PacingSender::OnPacketSent(StreamId stream_id,
                                        const Time& send_time,
                                        PktSeqNumber seq_num,
                                        uint32_t pld_bytes,
                                        uint32_t tot_bytes, float& cc_val)
{
  // Call into the congestion control algorithm first.
  PktSeqNumber  cc_seq_num = cc_alg_->OnPacketSent(stream_id, send_time,
                                                   seq_num, pld_bytes,
                                                   tot_bytes, cc_val);

  // If there are no bytes in flight, then update the number of burst tokens
  // allowed.  Note that bytes in flight does not reflect the packet just sent
  // yet.
  if (bytes_in_flight_ == 0)
  {
    // Add more burst tokens anytime the connection is leaving quiescence, but
    // limit it to the equivalent of a single bulk write, not exceeding the
    // current cwnd in packets.
    if (kLimitPacingBurst)
    {
      burst_tokens_ = (cc_alg_->GetCongestionWindow() / kDefaultTcpMss);

      if (burst_tokens_ > initial_packet_burst_)
      {
        burst_tokens_ = initial_packet_burst_;
      }
    }
    else
    {
      burst_tokens_ = initial_packet_burst_;
    }
  }

  // If there are burst tokens left, consume one for the packet just sent and
  // return.
  if (burst_tokens_ > 0)
  {
    --burst_tokens_;
    was_last_send_delayed_ = false;
    last_delayed_packet_sent_time_.Zero();
    ideal_next_packet_send_time_.Zero();

    return cc_seq_num;
  }

  // The next packet should be sent as soon as the current packets have been
  // transferred.
  Capacity  bits_per_second = cc_alg_->SendPacingRate();
  Time      delay;

  if (bits_per_second > 0)
  {
    delay = Time::FromUsec(pld_bytes * 8 * kNumMicrosPerSecond /
                           bits_per_second);
  }

  // If the last send was delayed, and the timer took a long time to get
  // invoked, allow the connection to make up for lost time.
  if (was_last_send_delayed_)
  {
    ideal_next_packet_send_time_ += delay;

    // The send was application limited if it takes longer than the pacing
    // delay between sent packets.
    bool  application_limited =
      ((!last_delayed_packet_sent_time_.IsZero()) &&
       (send_time > last_delayed_packet_sent_time_.Add(delay)));

    bool  making_up_for_lost_time =
      (ideal_next_packet_send_time_ <= send_time);

    // As long as we're making up time and not application limited, continue
    // to consider the packets delayed, allowing the packets to be sent
    // immediately.
    if (making_up_for_lost_time && !application_limited)
    {
      last_delayed_packet_sent_time_ = send_time;
    }
    else
    {
      was_last_send_delayed_ = false;
      last_delayed_packet_sent_time_.Zero();
    }
  }
  else
  {
    ideal_next_packet_send_time_ = Time::Max(
      ideal_next_packet_send_time_.Add(delay), send_time.Add(delay));
  }

  return cc_seq_num;
}

//============================================================================
void PacingSender::OnPacketResent(StreamId stream_id, const Time& send_time,
                                  PktSeqNumber seq_num,
                                  PktSeqNumber cc_seq_num, uint32_t pld_bytes,
                                  uint32_t tot_bytes, bool rto, bool orig_cc,
                                  float& cc_val)
{
  // Retransmissions cannot be held up in a packet queue, so they cannot be
  // paced.
  cc_alg_->OnPacketResent(stream_id, send_time, seq_num, cc_seq_num,
                          pld_bytes, tot_bytes, rto, orig_cc, cc_val);
}

//============================================================================
void PacingSender::ReportUnaPkt(StreamId stream_id, bool has_una_pkt,
                                PktSeqNumber una_cc_seq_num)
{
  cc_alg_->ReportUnaPkt(stream_id, has_una_pkt, una_cc_seq_num);
}

//============================================================================
bool PacingSender::RequireFastRto()
{
  return cc_alg_->RequireFastRto();
}

//============================================================================
void PacingSender::OnRto(bool pkt_rexmit)
{
  cc_alg_->OnRto(pkt_rexmit);
}

//============================================================================
void PacingSender::OnOutageEnd()
{
  cc_alg_->OnOutageEnd();
}

//============================================================================
void PacingSender::UpdateCounts(int32_t pif_adj, int64_t bif_adj,
                                int64_t pipe_adj)
{
  // Adjust the local member as well as the congestion control algorithm
  // object.
  pkts_in_flight_  += pif_adj;
  bytes_in_flight_ += bif_adj;
  pipe_            += pipe_adj;
  cc_alg_->UpdateCounts(pif_adj, bif_adj, pipe_adj);
}

//============================================================================
bool PacingSender::CanSend(const Time& now, uint32_t bytes)
{
  return cc_alg_->CanSend(now, bytes);
}

//============================================================================
bool PacingSender::CanResend(const Time& now, uint32_t bytes, bool orig_cc)
{
  return cc_alg_->CanResend(now, bytes, orig_cc);
}

//============================================================================
Time PacingSender::TimeUntilSend(const Time& now)
{
  // Call into the congestion control algorithm first.
  Time  time_until_send = cc_alg_->TimeUntilSend(now);

  // Don't pace if there are burst tokens available or we are leaving
  // quiescence.
  if ((burst_tokens_ > 0) || (bytes_in_flight_ == 0))
  {
    return time_until_send;
  }

  // If the underlying sender prevents sending right now, then pass on the
  // time value.
  if (!time_until_send.IsZero())
  {
    return time_until_send;
  }

  // If the next send time is larger than the timer granularity, then wait to
  // send.
  if (ideal_next_packet_send_time_ > now.Add(timer_granularity_))
  {
    was_last_send_delayed_ = true;
    return ideal_next_packet_send_time_.Subtract(now);
  }

  // Send the packet immediately.
  return Time();
}

//============================================================================
Capacity PacingSender::SendPacingRate()
{
  return cc_alg_->SendPacingRate();
}

//============================================================================
Capacity PacingSender::SendRate()
{
  return cc_alg_->SendRate();
}

//============================================================================
bool PacingSender::GetSyncParams(uint16_t& seq_num, uint32_t& cc_params)
{
  return cc_alg_->GetSyncParams(seq_num, cc_params);
}

//============================================================================
void PacingSender::ProcessSyncParams(const Time& now, uint16_t seq_num,
                                     uint32_t cc_params)
{
  cc_alg_->ProcessSyncParams(now, seq_num, cc_params);
}

//============================================================================
void PacingSender::ProcessCcPktTrain(const Time& now, CcPktTrainHeader& hdr)
{
  cc_alg_->ProcessCcPktTrain(now, hdr);
}

//============================================================================
bool PacingSender::InSlowStart()
{
  return cc_alg_->InSlowStart();
}

//============================================================================
bool PacingSender::InRecovery()
{
  return cc_alg_->InRecovery();
}

//============================================================================
uint32_t PacingSender::GetCongestionWindow()
{
  return cc_alg_->GetCongestionWindow();
}

//============================================================================
uint32_t PacingSender::GetSlowStartThreshold()
{
  return cc_alg_->GetSlowStartThreshold();
}

//============================================================================
CongCtrlAlg PacingSender::GetCongestionControlType()
{
  return cc_alg_->GetCongestionControlType();
}

//============================================================================
void PacingSender::Close()
{
  return cc_alg_->Close();
}
