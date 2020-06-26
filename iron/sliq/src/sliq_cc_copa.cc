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

#include "sliq_cc_copa.h"

#include "log.h"
#include "unused.h"

#include <cmath>
#include <cstring>
#include <inttypes.h>


using ::sliq::Capacity;
using ::sliq::CongCtrlAlg;
using ::sliq::Copa;
using ::sliq::CopaMode;
using ::sliq::PktSeqNumber;
using ::iron::Log;
using ::iron::RNG;
using ::iron::Time;


namespace
{
  /// The class name string for logging.
  const char*     UNUSED(kClassName)    = "Copa";

  /// The default value for delta.
  const double    kDefaultDelta         = 0.1;

  /// The minimum value for delta.  Not applicable if delta is constant.
  const double    kMinDelta             = 0.004;

  /// The maximum value for delta.  Not applicable if delta is constant.
  const double    kMaxDelta             = 0.1;

  /// The maximum floating point time value, in seconds, before wrapping
  /// around to zero again.
  const double    kMaxFpTime            = 3600.0;

  /// The default inter-send time for the first kNumProbePkts packets, in
  /// seconds.
  const double    kDefaultIntersendTime = 0.1;

  /// The minimum supported inter-send time, in seconds.  This supports 1000
  /// byte packets at 1 Gbps, or 100 byte packets at 100 Mbps.
  const double    kMinIntersendTime     = 0.000008;

  /// The maximum reasonable inter-send time, in seconds.
  const double    kMaxIntersendTime     = 0.200;

  /// The inter-send time quiescent threshold, in seconds.
  const double    kQuiescentThreshold   = 0.01;

  /// The default minimum RTT, in seconds.  This is large to cause any
  /// realistic RTT to be smaller than this value.
  const double    kDefaultMinRtt        = 3600.0;

  /// The EWMA alpha parameter for RTT measurements.  Lower values weight
  /// older readings less.  Note: This used to be set to 0.875, but was raised
  /// to minimize send rate oscillations.
  const double    kRttAlpha             = 0.94;

  /// The number of RTTs between calls to the policy controller, which updates
  /// delta.
  const double    kPolicyCtrlIntRtts    = 4.0;

  /// The maximum time between calls to the policy controller, in seconds.
  const double    kPolicyCtrlMaxIntSec  = 1.0;

  /// The policy controller additive increase delta adjustment value.
  const double    kPolicyCtrlAddInc     = 0.0025;

  /// The policy controller multiplicative decrease delta adjustment value.
  const double    kPolicyCtrlMultDec    = (1.0 / 1.1);

  /// The policy controller quantization factor for delta.  The increment is
  /// 1.0 divided by this value.
  const double    kPolicyCtrlQuantDelta = 10000.0;

  /// The policy controller delta update threshold.
  /// \todo This was set to 0.0100, but the 3-node-tcp-perf experiment had
  /// trouble with asymmetric send rates.  As a temporary work-around, set
  /// this threshold to a large value to force the received delta value to
  /// always be used.
  const double    kPolicyCtrlSyncThresh = 0.1000;

  /// The maximum policy controller delta synchronization interval in seconds.
  const double    kPolicyCtrlSyncIntSec = 2.0;

  /// The number of startup data packets sent while the inter-send times are
  /// fixed at kDefaultIntersendTime.
  const uint64_t  kNumProbePkts         = 10;

#ifdef SLIQ_COPA_MRT

  /// The amount of inter-send time randomization required by the minimum RTT
  /// tracking algorithm.
  const double    kMinRttTrkIstRand     = 0.30;

  /// The number of points to use in the minimum RTT tracking line fitting.
  const uint32_t  kMinRttTrkPoints      = 500;

  /// The amount that the minimum RTT estimate must have changed in order to
  /// be updated.
  const double    kMinRttTrkThreshold   = 1.5;

#endif // SLIQ_COPA_MRT

  /// The packet overhead due to Ethernet (8 + 14 + 4 = 26 bytes), IP
  /// (20 bytes), and UDP (8 bytes), in bytes.  This assumes that no 802.1Q
  /// tag is present in the Ethernet frame, and that no IP header options are
  /// present.
  const size_t    kPktOverheadBytes     = 54;

  /// The nominal packet size, including the SLIQ data header and payload,
  /// used for converting computed packet intervals into send intervals for
  /// variable sized packets.
  const size_t    kNominalPktSizeBytes  = 1000;

  /// The PacketData ACKed flag.
  const uint16_t  kAckedFlag            = 0x1;

  /// The PacketData resent flag.
  const uint16_t  kResentFlag           = 0x2;

  /// The PacketData flag indicating that the packet should be skipped when
  /// updating the unACKed RTT estimate until it has been resent again.
  const uint16_t  kSkipUntilResentFlag  = 0x4;
}


// Macro for checking a received CC synchronization sequence number, with s
// being the new sequence number and r the last sequence number.
#define CC_SYNC_SEQ_NUM_OK(s, r)  ((((s) > (r)) && (((s) - (r)) < 32768)) || \
                                   (((s) < (r)) && (((r) - (s)) > 32768)))


//============================================================================
Copa::Copa(EndptId conn_id, bool is_client, RNG& rng)
    : CongCtrlInterface(conn_id, is_client),
      rng_(rng),
      mode_(CONSTANT_DELTA),
      random_send_(false),
      delta_(kDefaultDelta),
      intersend_time_(kDefaultIntersendTime),
      calc_intersend_time_(kDefaultIntersendTime),
      prev_intersend_time_(0.0),
      min_rtt_(kDefaultMinRtt),
      rtt_acked_(conn_id, kRttAlpha),
      rtt_unacked_(conn_id, kRttAlpha),
      una_cc_seq_num_(0),
      nxt_cc_seq_num_(0),
      ack_cc_seq_num_(0),
      unacked_pkts_(NULL),
#ifdef SLIQ_COPA_MRT
      mrt_cnt_(0),
      mrt_trips_(0),
      nxt_mrt_pkts_idx_(0),
      num_mrt_pts_(0),
      mrt_pkts_(NULL),
      mrt_line_(NULL),
#endif // SLIQ_COPA_MRT
      start_time_point_(),
      next_send_time_(),
      prev_delta_update_time_(),
      timer_tolerance_(Time::FromMsec(1)),
      sync_send_seq_num_(1),
      sync_recv_seq_num_(0),
      sync_params_(0),
      prev_sync_params_(0),
      prev_sync_time_(),
      local_sync_delta_(kDefaultDelta),
      remote_sync_delta_(-1.0),
      send_cnt_(0),
      quiescent_cnt_(0),
      num_pkts_acked_(0),
      num_pkts_lost_(0)
{
  // Initialize the time members.
  if (!start_time_point_.GetNow())
  {
    LogF(kClassName, __func__, "Failed to get current time.\n");
    return;
  }

  next_send_time_         = start_time_point_;
  prev_delta_update_time_ = start_time_point_;
}

//============================================================================
Copa::~Copa()
{
  // Delete the arrays of information.
  if (unacked_pkts_ != NULL)
  {
    delete [] unacked_pkts_;
    unacked_pkts_ = NULL;
  }

#ifdef SLIQ_COPA_MRT
  if (mrt_pkts_ != NULL)
  {
    delete [] mrt_pkts_;
    mrt_pkts_ = NULL;
  }

  if (mrt_line_ != NULL)
  {
    delete [] mrt_line_;
    mrt_line_ = NULL;
  }
#endif // SLIQ_COPA_MRT
}

//============================================================================
bool Copa::Configure(const CongCtrl& cc_params)
{
  // Allocate the circular array of unACKed packet information.
  unacked_pkts_ = new (std::nothrow) PacketData[kMaxCongCtrlWindowPkts];

  if (unacked_pkts_ == NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Error allocating "
         "packet data.\n", conn_id_);
    return false;
  }

#ifdef SLIQ_COPA_MRT
  // Allocate the circular array of minimum RTT tracking packet information.
  mrt_pkts_ = new (std::nothrow) MinRttPktData[kMaxCongCtrlWindowPkts];

  if (mrt_pkts_ == NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Error allocating "
         "minRTT packet data.\n", conn_id_);
    return false;
  }

  memset(mrt_pkts_, 0, (sizeof(MinRttPktData) * kMaxCongCtrlWindowPkts));
  mrt_pkts_[kMaxCongCtrlWindowPkts - 1].send_time = (kMaxFpTime / 2.0);

  // Allocate the array of minimum RTT tracking line fitting data.
  mrt_line_ = new (std::nothrow) MinRttLineData[kMinRttTrkPoints];

  if (mrt_line_ == NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Error allocating "
         "minRTT line data.\n", conn_id_);
    return false;
  }
#endif // SLIQ_COPA_MRT

  // If delta is not set in time, we don't want it to be 0.
  delta_       = kDefaultDelta;
  random_send_ = !(cc_params.deterministic_copa);

  if (random_send_)
  {
    LogW(kClassName, __func__, "Conn %" PRIEndptId ": Warning, using Copa "
         "with randomized inter-send times, performance will be "
         "sub-optimal.\n", conn_id_);
  }

  switch (cc_params.algorithm)
  {
    case COPA_CONST_DELTA_CC:
      mode_  = CONSTANT_DELTA;
      delta_ = cc_params.copa_delta;
      LogI(kClassName, __func__, "Conn %" PRIEndptId ": Constant delta mode "
           "with delta = %f.\n", conn_id_, delta_);
      break;

    case COPA_M_CC:
      mode_  = MAX_THROUGHPUT;
      delta_ = kDefaultDelta;
      LogI(kClassName, __func__, "Conn %" PRIEndptId ": Maximize throughput "
           "mode.\n", conn_id_);
      break;

    default:
      LogF(kClassName, __func__, "Conn %" PRIEndptId ": Unknown Copa mode "
           "specified.\n", conn_id_);
      return false;
  }

  return true;
}

//============================================================================
void Copa::Connected(const Time& /* now */, const Time& /* rtt */)
{
  return;
}

//============================================================================
bool Copa::UseRexmitPacing()
{
  return true;
}

//============================================================================
bool Copa::UseCongWinForCapEst()
{
  return false;
}

//============================================================================
bool Copa::UseUnaPktReporting()
{
  return false;
}

//============================================================================
bool Copa::SetTcpFriendliness(uint32_t /* num_flows */)
{
  return true;
}

//============================================================================
bool Copa::ActivateStream(StreamId /* stream_id */,
                          PktSeqNumber /* init_send_seq_num */)
{
  return true;
}

//============================================================================
bool Copa::DeactivateStream(StreamId /* stream_id */)
{
  return true;
}

//============================================================================
void Copa::OnAckPktProcessingStart(const Time& /* ack_time */)
{
  return;
}

//============================================================================
void Copa::OnRttUpdate(StreamId stream_id, const Time& ack_time,
                       PktTimestamp /* send_ts */, PktTimestamp /* recv_ts */,
                       PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                       const Time& rtt, uint32_t /* bytes */,
                       float /* cc_val */)
{
  double  calc_rtt = rtt.ToDouble();

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "** Conn %" PRIEndptId ": On RTT Update: "
       "stream_id=%" PRIStreamId " seq_num=%" PRIPktSeqNumber " cc_seq_num=%"
       PRIPktSeqNumber " ack_time=%s calc_rtt=%f\n", conn_id_, stream_id,
       seq_num, cc_seq_num, ack_time.ToString().c_str(), calc_rtt);
#endif

  // Update the minimum RTT value observed.
  if (calc_rtt < min_rtt_)
  {
    min_rtt_ = calc_rtt;

#ifdef SLIQ_COPA_MRT
    // Reset the minimum RTT tracking algorithm.
    num_mrt_pts_ = 0;
    ++mrt_cnt_;
#endif // SLIQ_COPA_MRT

    LogA(kClassName, __func__, "Conn %" PRIEndptId ": Updated min_rtt=%f\n",
         conn_id_, min_rtt_);
  }

#ifdef SLIQ_COPA_MRT
  // Look up the packet info.
  PacketData&  pd = unacked_pkts_[cc_seq_num % kMaxCongCtrlWindowPkts];

  // Update the minRTT tracker.  Wait until the probing is complete.
  if (num_pkts_acked_ >= kNumProbePkts)
  {
    // Verify the minimum RTT element index.
    if ((pd.min_rtt_index >= 0) &&
        (pd.min_rtt_index < kMaxCongCtrlWindowPkts))
    {
      // Now that this packet has an RTT measurement, compute an estimate of
      // the number of kilobytes in the bottleneck queue when the packet was
      // sent.  The number of kilobytes will be the point's X value, and the
      // RTT measurement in milliseconds will be the point's Y value.
      MinRttPktData&   mp = mrt_pkts_[pd.min_rtt_index];
      MinRttLineData&  ml = mrt_line_[num_mrt_pts_];

      ml.x_queued_kbytes = 0.0;
      ml.y_rtt_msec      = (calc_rtt * 1000.0);

      uint32_t  i          = pd.min_rtt_index;
      double    delta_time = 0.0;

      while (delta_time < (calc_rtt - min_rtt_))
      {
        ml.x_queued_kbytes += (mrt_pkts_[i].sent_bytes * 0.001);

        // Move i backward one packet.
        i = ((i == 0) ? (kMaxCongCtrlWindowPkts - 1) : (i - 1));

        delta_time = (mp.send_time - mrt_pkts_[i].send_time);

        if (delta_time < 0.0)
        {
          delta_time += kMaxFpTime;
        }
      }

      ++num_mrt_pts_;

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Create minRTT point %"
           PRIu32 " x=%f y=%f\n", conn_id_, (num_mrt_pts_ - 1),
           ml.x_queued_kbytes, ml.y_rtt_msec);
      LogA(kClassName, __func__, "PLT_MRP %" PRIu32 " %f %f\n", mrt_cnt_,
           ml.x_queued_kbytes, ml.y_rtt_msec);
#endif
    }
    else
    {
      LogW(kClassName, __func__, "Conn %" PRIEndptId ": Warning, invalid "
           "minRTT index=%" PRIu16 " for cc_seq_num=%" PRIPktSeqNumber ".\n",
           conn_id_, pd.min_rtt_index, cc_seq_num);
    }
  }

  // Check if it is time to update the minimum RTT estimate, possibly
  // increasing it.
  if (num_mrt_pts_ >= kMinRttTrkPoints)
  {
    UpdateMinRtt();

    // Reset the minimum RTT tracking algorithm.
    num_mrt_pts_ = 0;
    ++mrt_cnt_;
  }
#endif // SLIQ_COPA_MRT

  double  fp_now = CurrentTime(ack_time);

  // Update the current RTT estimate for ACKed packets.  Note that the minimum
  // RTT should never be greater than the current RTT estimate.
  if (rtt_acked_ >= min_rtt_)
  {
    rtt_acked_.Update(calc_rtt, fp_now, min_rtt_);

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated rtt_acked=%f\n",
         conn_id_, static_cast<double>(rtt_acked_));
#endif
  }
  else
  {
    rtt_acked_.ForceSet(min_rtt_, fp_now);

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Force rtt_acked=%f\n",
         conn_id_, static_cast<double>(rtt_acked_));
#endif
  }

#ifdef SLIQ_CC_DEBUG
  LogA(kClassName, __func__, "Conn %" PRIEndptId ": PLT_RTT %f %f %f %f\n",
       conn_id_, fp_now, calc_rtt, static_cast<double>(rtt_acked_), min_rtt_);
#endif
}

//============================================================================
bool Copa::OnPacketLost(StreamId /* stream_id */, const Time& /* ack_time */,
                        PktSeqNumber /* seq_num */,
                        PktSeqNumber /* cc_seq_num */, uint32_t /* bytes */)
{
  return true;
}

//============================================================================
void Copa::OnPacketAcked(StreamId stream_id, const Time& ack_time,
                         PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                         PktSeqNumber ne_seq_num, uint32_t bytes)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "** Conn %" PRIEndptId ": On ACK: stream_id=%"
       PRIStreamId " seq_num=%" PRIPktSeqNumber " cc_seq_num=%"
       PRIPktSeqNumber " ne_seq_num=%" PRIPktSeqNumber " ack_time=%s bytes=%"
       PRIu32 "\n", conn_id_, stream_id, seq_num, cc_seq_num, ne_seq_num,
       ack_time.ToString().c_str(), bytes);
#endif

  // Check if the packet info is active.
  if (SEQ_LT(cc_seq_num, una_cc_seq_num_) ||
      SEQ_GEQ(cc_seq_num, nxt_cc_seq_num_))
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": No packet info for "
         "cc_seq_num=%" PRIPktSeqNumber "\n", conn_id_, cc_seq_num);
#endif

    return;
  }

  // Look up the packet info.
  PacketData&  pd = unacked_pkts_[cc_seq_num % kMaxCongCtrlWindowPkts];

  // Check if the packet has already been ACKed.
  if (pd.flags & kAckedFlag)
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Packet cc_seq_num=%"
         PRIPktSeqNumber " is already ACKed.\n", conn_id_, cc_seq_num);
#endif
    return;
  }

  // Set the ACKed flag in the packet info.
  pd.flags |= kAckedFlag;

  // Update the highest ACKed sequence number.
  if (SEQ_GT(cc_seq_num, ack_cc_seq_num_))
  {
    ack_cc_seq_num_ = cc_seq_num;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated "
         "ack_cc_seq_num=%" PRIPktSeqNumber "\n", conn_id_, ack_cc_seq_num_);
#endif

    // Grab the computed inter-send time used for the packet.  This is the
    // mean inter-send time prevailing at the time when the last ACKed packet
    // was sent.
    prev_intersend_time_ = pd.intersend_time;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated "
         "prev_intersend_time=%f\n", conn_id_, prev_intersend_time_);
#endif

  }

  // Update the number of packets ACKed.
  ++num_pkts_acked_;

  // Update delta.
  UpdateDelta(ack_time, false);

  return;
}

//============================================================================
void Copa::OnAckPktProcessingDone(const Time& ack_time)
{
  // Update the unACKed packet information.
  if (SEQ_GEQ(ack_cc_seq_num_, una_cc_seq_num_) &&
      SEQ_LT(ack_cc_seq_num_, nxt_cc_seq_num_))
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Finding unACKed packet "
         "info for cc_seq_num=%" PRIPktSeqNumber "\n", conn_id_,
         ack_cc_seq_num_);
#endif

    // Loop over the packet info objects up to and including this packet.
    while (SEQ_LT(una_cc_seq_num_, nxt_cc_seq_num_))
    {
      PacketData&  pd = unacked_pkts_[una_cc_seq_num_ %
                                      kMaxCongCtrlWindowPkts];

      // Stop when just beyond the highest ACKed sequence number.
      if (SEQ_GT(pd.cc_seq_num, ack_cc_seq_num_))
      {
        break;
      }

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updating unACKed "
           "packet info for cc_seq_num=%" PRIPktSeqNumber "\n", conn_id_,
           pd.cc_seq_num);
#endif

      // If the packet was not ACKed, then consider it lost.
      if (!(pd.flags & kAckedFlag))
      {
#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Considering "
             "cc_seq_num=%" PRIPktSeqNumber " lost\n", conn_id_,
             pd.cc_seq_num);
#endif

        // Consider this packet lost as far as updating delta is concerned.
        UpdateDelta(ack_time, true);
        ++num_pkts_lost_;
      }

      // Delete the packet information.
      ++una_cc_seq_num_;

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Erased packet info "
           "for cc_seq_num=%" PRIPktSeqNumber "\n", conn_id_,
           (una_cc_seq_num_ - 1));
#endif
    }
  }
#ifdef SLIQ_CC_DEBUG
  else
  {
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": No unACKed packet info "
         "for cc_seq_num=%" PRIPktSeqNumber "\n", conn_id_, ack_cc_seq_num_);
  }
#endif

  double  fp_now = CurrentTime(ack_time);

  // Set the current RTT estimate for unACKed packets equal to that for ACKed
  // packets.
  rtt_unacked_.ForceSet(rtt_acked_, fp_now);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Forced rtt_unacked=%f\n",
       conn_id_, static_cast<double>(rtt_unacked_));
#endif

  // Update the current RTT estimate for unACKed packets.
  UpdateUnackedRttEstimate(fp_now);

  // Update the inter-send time.
  if (num_pkts_acked_ >= kNumProbePkts)
  {
    UpdateIntersendTime(ack_time);
  }
}

//============================================================================
PktSeqNumber Copa::OnPacketSent(StreamId stream_id, const Time& send_time,
                                PktSeqNumber seq_num, uint32_t pld_bytes,
                                uint32_t /* tot_bytes */, float& /* cc_val */)
{
  // Make sure that the circular array size will not be exceeded.
  if ((nxt_cc_seq_num_ - una_cc_seq_num_) >= kMaxCongCtrlWindowPkts)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Circular array size "
         "exceeded, current size=%" PRIPktSeqNumber ".\n", conn_id_,
         (nxt_cc_seq_num_ - una_cc_seq_num_));

    // The oldest packets must be dropped to allow this method to succeed.
    while ((nxt_cc_seq_num_ - una_cc_seq_num_) >= kMaxCongCtrlWindowPkts)
    {
      ++una_cc_seq_num_;
    }
  }

  // Assign a CC sequence number to the packet.
  PktSeqNumber  cc_seq_num = nxt_cc_seq_num_;
  ++nxt_cc_seq_num_;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "** Conn %" PRIEndptId ": On Send: stream=%"
       PRIStreamId " seq_num=%" PRIPktSeqNumber " cc_seq_num=%"
       PRIPktSeqNumber " send_time=%s size=%" PRIu32 "\n", conn_id_,
       stream_id, seq_num, cc_seq_num, send_time.ToString().c_str(),
       pld_bytes);
#endif

  // Add an unACKed packet data structure for the packet.
  double       fp_now = CurrentTime(send_time);
  PacketData&  pd     = unacked_pkts_[cc_seq_num % kMaxCongCtrlWindowPkts];

  pd.cc_seq_num     = cc_seq_num;
  pd.flags          = 0;
  pd.send_time      = fp_now;
  pd.intersend_time = calc_intersend_time_;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Added packet info for "
       "stream=%" PRIStreamId " seq_num=%" PRIPktSeqNumber " cc_seq_num=%"
       PRIPktSeqNumber " send_time=%s calc_intersend_time=%f\n", conn_id_,
       stream_id, seq_num, cc_seq_num, send_time.ToString().c_str(),
       calc_intersend_time_);
#endif

#ifdef SLIQ_COPA_MRT
  // Add a minRTT element for the packet.
  MinRttPktData&  mp = mrt_pkts_[nxt_mrt_pkts_idx_];

  pd.min_rtt_index = nxt_mrt_pkts_idx_;

  mp.send_time  = fp_now;
  mp.sent_bytes = static_cast<double>(pld_bytes);

  ++nxt_mrt_pkts_idx_;

  if (nxt_mrt_pkts_idx_ >= kMaxCongCtrlWindowPkts)
  {
    nxt_mrt_pkts_idx_ = 0;
  }
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Added minRTT index=%"
       PRIu16 " for cc_seq_num=%" PRIPktSeqNumber " send_time=%f "
       "sent_bytes=%f\n", conn_id_, pd.min_rtt_index, cc_seq_num,
       mp.send_time, mp.sent_bytes);
#endif
#endif // SLIQ_COPA_MRT

  // Set the current RTT estimate for unACKed packets equal to that for ACKed
  // packets.
  rtt_unacked_.ForceSet(rtt_acked_, fp_now);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Forced rtt_unacked=%f\n",
       conn_id_, static_cast<double>(rtt_unacked_));
#endif

  // Update the current RTT estimate for unACKed packets.
  UpdateUnackedRttEstimate(fp_now);

  // Update the inter-send time.
  if (num_pkts_acked_ >= kNumProbePkts)
  {
    UpdateIntersendTime(send_time);
  }

  // Update the next send time.
  UpdateNextSendTime(send_time, pld_bytes);

  // Update the send count for the policy controllers.
  ++send_cnt_;

  return cc_seq_num;
}

//============================================================================
void Copa::OnPacketResent(StreamId stream_id, const Time& send_time,
                          PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                          uint32_t pld_bytes, uint32_t /* tot_bytes */,
                          bool rto, bool orig_cc, float& /* cc_val */)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "** Conn %" PRIEndptId ": On Resend: stream=%"
       PRIStreamId " seq_num=%" PRIPktSeqNumber " cc_seq_num=%"
       PRIPktSeqNumber " send_time=%s size=%" PRIu32 " rto=%d orig_cc=%d\n",
       conn_id_, stream_id, seq_num, cc_seq_num, send_time.ToString().c_str(),
       pld_bytes, static_cast<int>(rto), static_cast<int>(orig_cc));
#endif

  double  fp_now = CurrentTime(send_time);

  if (orig_cc)
  {
    // Look up the packet info.
    PacketData&  pd = unacked_pkts_[cc_seq_num % kMaxCongCtrlWindowPkts];

    if (SEQ_GEQ(cc_seq_num, una_cc_seq_num_) &&
        SEQ_LT(cc_seq_num, nxt_cc_seq_num_))
    {
      // Update the packet info.  Clear any ACKed flag and set the resent
      // flag.
      pd.flags          = kResentFlag;
      pd.send_time      = fp_now;
      pd.intersend_time = calc_intersend_time_;

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated packet info "
           "for stream=%" PRIStreamId " seq_num=%" PRIPktSeqNumber
           " cc_seq_num=%" PRIPktSeqNumber " send_time=%f "
           "calc_intersend_time=%f\n", conn_id_, stream_id, seq_num,
           cc_seq_num, fp_now, calc_intersend_time_);
#endif
    }

#ifdef SLIQ_COPA_MRT
    // Add a new minRTT element for the packet.  This leaves any old minRTT
    // elements for previous transmissions/retransmissions of the packet.
    if (pd.cc_seq_num == cc_seq_num)
    {
      MinRttPktData&  mp = mrt_pkts_[nxt_mrt_pkts_idx_];

      pd.min_rtt_index = nxt_mrt_pkts_idx_;

      mp.send_time  = fp_now;
      mp.sent_bytes = static_cast<double>(pld_bytes);

      ++nxt_mrt_pkts_idx_;

      if (nxt_mrt_pkts_idx_ >= kMaxCongCtrlWindowPkts)
      {
        nxt_mrt_pkts_idx_ = 0;
      }

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Added minRTT index=%"
           PRIu16 " for cc_seq_num=%" PRIPktSeqNumber " send_time=%f "
           "sent_bytes=%f\n", conn_id_, pd.min_rtt_index, cc_seq_num,
           mp.send_time, mp.sent_bytes);
#endif
    }
    else
    {
      LogW(kClassName, __func__, "Conn %" PRIEndptId ": Warning, no minRTT "
           "element for cc_seq_num=%" PRIPktSeqNumber ".\n", conn_id_,
           cc_seq_num);
    }
#endif // SLIQ_COPA_MRT
  }

  // Set the current RTT estimate for unACKed packets equal to that for ACKed
  // packets.
  rtt_unacked_.ForceSet(rtt_acked_, fp_now);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Forced rtt_unacked=%f\n",
       conn_id_, static_cast<double>(rtt_unacked_));
#endif

  // Update the current RTT estimate for unACKed packets.
  UpdateUnackedRttEstimate(fp_now);

  // Update the inter-send time.
  if (num_pkts_acked_ >= kNumProbePkts)
  {
    UpdateIntersendTime(send_time);
  }

  // Update the next send time if this is not due to an RTO event.
  if (!rto)
  {
    UpdateNextSendTime(send_time, pld_bytes);
  }
}

//============================================================================
void Copa::OnRto(bool /* pkt_rexmit */)
{
  return;
}

//============================================================================
void Copa::OnOutageEnd()
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Outage is over.\n",
       conn_id_);
#endif

#ifdef SLIQ_COPA_MRT
  // Reset the minimum RTT tracking algorithm.
  num_mrt_pts_ = 0;
  ++mrt_cnt_;
#endif // SLIQ_COPA_MRT

  // Find the last known good value for the inter-send time when the outage
  // began.
  double  last_good_ist = -1.0;

  for (PktSeqNumber cc_seq_num = una_cc_seq_num_;
       SEQ_LT(cc_seq_num, nxt_cc_seq_num_); ++cc_seq_num)
  {
    PacketData&  pd = unacked_pkts_[cc_seq_num % kMaxCongCtrlWindowPkts];

    // The packet must not have been resent in order to be usable.
    if (!(pd.flags & kResentFlag))
    {
      last_good_ist = pd.intersend_time;
      break;
    }
  }

  // If a last known good inter-send time was not found, then use the default
  // inter-send time.
  if (last_good_ist < -0.01)
  {
    last_good_ist = kDefaultIntersendTime;
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Error finding last "
         "known good inter-send time, using %f.\n", conn_id_, last_good_ist);
  }

  // Perpare the unACKed packet information for restarting.
  for (PktSeqNumber cc_seq_num = una_cc_seq_num_;
       SEQ_LT(cc_seq_num, nxt_cc_seq_num_); ++cc_seq_num)
  {
    PacketData&  pd = unacked_pkts_[cc_seq_num % kMaxCongCtrlWindowPkts];

    // Force the packet's inter-send time to the last known good value.
    pd.intersend_time = last_good_ist;

    // If the packet is not ACKed yet, then set the "skip until resent" flag.
    if (!(pd.flags & kAckedFlag))
    {
      pd.flags = kSkipUntilResentFlag;
    }
  }

  // Set inter-send times to the last known good value.
  calc_intersend_time_ = last_good_ist;
  intersend_time_      = last_good_ist;
  prev_intersend_time_ = (last_good_ist * 2.0);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated "
       "prev_intersend_time=%f\n", conn_id_, prev_intersend_time_);
#endif
}

//============================================================================
bool Copa::CanSend(const Time& /* now */, uint32_t /* bytes */)
{
  // Copa has no congestion window, but the circular array of packet
  // information must not be exceeded.
  return ((nxt_cc_seq_num_ - una_cc_seq_num_) < kMaxCongCtrlWindowPkts);
}

//============================================================================
bool Copa::CanResend(const Time& /* now */, uint32_t /* bytes */,
                     bool /* orig_cc */)
{
  // Copa paces fast retransmissions, so this can just return true.
  return true;
}

//============================================================================
Time Copa::TimeUntilSend(const Time& now)
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
Capacity Copa::PacingRate()
{
  double  pacing_rate_bps = (((kNominalPktSizeBytes + kPktOverheadBytes) *
                              8.0) / calc_intersend_time_);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Pacing rate %f bps.\n",
       conn_id_, pacing_rate_bps);
#endif

  return static_cast<Capacity>(pacing_rate_bps);
}

//============================================================================
Capacity Copa::CapacityEstimate()
{
  return PacingRate();
}

//============================================================================
bool Copa::GetSyncParams(uint16_t& seq_num, uint32_t& cc_params)
{
  // Only send if there is a synchronization parameter waiting.
  if ((mode_ == MAX_THROUGHPUT) && (is_client_) && (sync_params_ != 0))
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Sending CC sync param %"
         PRIu16 ".\n", conn_id_, sync_params_);
#endif

    // After copying the parameters out, set them to zero to avoid sending
    // them again until delta is recalculated.
    seq_num      = sync_send_seq_num_++;
    cc_params    = sync_params_;
    sync_params_ = 0;

    return true;
  }

  return false;
}

//============================================================================
void Copa::ProcessSyncParams(const Time& now, uint16_t seq_num,
                             uint32_t cc_params)
{
  if ((mode_ == MAX_THROUGHPUT) && (!is_client_) && (cc_params != 0) &&
      CC_SYNC_SEQ_NUM_OK(seq_num, sync_recv_seq_num_))
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Received CC sync param "
         "%" PRIu32 ".\n", conn_id_, cc_params);
#endif

    // Record the sequence number and time of reception.
    sync_recv_seq_num_ = seq_num;
    prev_sync_time_    = now;

    // Convert the parameter into a valid delta value.
    double  new_delta = (static_cast<double>(cc_params & 0xffff) /
                         kPolicyCtrlQuantDelta);

    if (new_delta < kMinDelta)
    {
      new_delta = kMinDelta;
    }
    else if (new_delta > kMaxDelta)
    {
      new_delta = kMaxDelta;
    }

    if (new_delta != remote_sync_delta_)
    {
#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Received sync "
           "old_remote_delta=%f new_remote_delta=%f\n", conn_id_,
           remote_sync_delta_, new_delta);
#endif

      remote_sync_delta_ = new_delta;

      // The server side must consider this remotely computed delta value.
      if (fabs(remote_sync_delta_ - local_sync_delta_) <=
          kPolicyCtrlSyncThresh)
      {
#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Policy controller "
             "sync to remote_delta=%f (local_delta=%f)\n", conn_id_,
             remote_sync_delta_, local_sync_delta_);
        LogA(kClassName, __func__, "Conn %" PRIEndptId ": PLT_DELTA %f %f %f "
             "%f %f\n", conn_id_, CurrentTime(now), calc_intersend_time_,
             min_rtt_, remote_sync_delta_, remote_sync_delta_);
#endif

        delta_ = remote_sync_delta_;
      }
    }
  }
}

//============================================================================
void Copa::ProcessCcPktTrain(const Time& now, CcPktTrainHeader& hdr)
{
  return;
}

//============================================================================
bool Copa::InSlowStart()
{
  // Consider the probe packets as a form of slow start.
  return (num_pkts_acked_ < kNumProbePkts);
}

//============================================================================
bool Copa::InRecovery()
{
  // There is no fast recovery in Copa.
  return false;
}

//============================================================================
uint32_t Copa::GetCongestionWindow()
{
  // Copa is not window-based.
  return 0;
}

//============================================================================
uint32_t Copa::GetSlowStartThreshold()
{
  // Copa is not window-based.
  return 0;
}

//============================================================================
CongCtrlAlg Copa::GetCongestionControlType()
{
  return ((mode_ == CONSTANT_DELTA) ? COPA_CONST_DELTA_CC :
          COPA_M_CC);
}

//============================================================================
void Copa::Close()
{
#ifdef SLIQ_CC_DEBUG
  LogI(kClassName, __func__, "Conn %" PRIEndptId ": Number of packets: "
       "ACKed=%" PRIu64 " unACKed=%" PRIu64 "\n", conn_id_, num_pkts_acked_,
       num_pkts_lost_);
#endif
}

//============================================================================
double Copa::CurrentTime(const Time& now)
{
  double  rv = ((now - start_time_point_).ToDouble());

  if (rv >= kMaxFpTime)
  {
    start_time_point_ = start_time_point_.Add(kMaxFpTime);
    rv                -= kMaxFpTime;
  }

  return rv;
}

//============================================================================
double Copa::RandomizeIntersend(double intersend)
{
  if (intersend == 0.0)
  {
    return 0.0;
  }

  double  z = 0.0;

  // Pull a uniform random number (0 < z < 1).
  do
  {
    z = rng_.GetDouble(1.0);
  }
  while ((z == 0.0) || (z == 1.0));

  // Compute an exponential random variable using the inversion method.
  double  exp_value = (-1.0 * intersend * log(z));

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Randomize: lambda=%f "
       "value=%f\n", conn_id_, (1.0 / intersend), exp_value);
#endif

  return exp_value;
}

//============================================================================
void Copa::UpdateUnackedRttEstimate(double fp_now)
{
  // Update the current RTT estimate for unACKed packets.
  for (PktSeqNumber cc_seq_num = una_cc_seq_num_;
       SEQ_LT(cc_seq_num, nxt_cc_seq_num_); ++cc_seq_num)
  {
    PacketData&  pd = unacked_pkts_[cc_seq_num % kMaxCongCtrlWindowPkts];

    // Obey any "skip until resent" flag.
    if (pd.flags & kSkipUntilResentFlag)
    {
      continue;
    }

    // Compute the wait time thus far.
    double  wait_time = (fp_now - pd.send_time);

    if (wait_time < 0.0)
    {
      wait_time += kMaxFpTime;
    }

    // Check if this packet should have been ACKed by now.
    if ((!(pd.flags & kAckedFlag)) && (wait_time > rtt_unacked_))
    {
#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updating state using "
           "unACKed packet info for cc_seq_num=%" PRIPktSeqNumber "\n",
           conn_id_, pd.cc_seq_num);
#endif

      // Update the current RTT estimate for unACKed packets.
      rtt_unacked_.Update(wait_time, fp_now, min_rtt_);

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated "
           "rtt_unacked=%f with wait time=%f\n", conn_id_,
           static_cast<double>(rtt_unacked_), wait_time);
#endif
    }
    else
    {
      // If this packet has not been resent and the wait time is less than the
      // RTT estimate, then stop the loop (the wait times will only be less
      // than the current wait time for packets further on in the array).
      if ((!(pd.flags & kResentFlag)) && (wait_time < rtt_unacked_))
      {
        break;
      }
    }
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": At %f: intersend_time=%f "
       "calc_intersend_time=%f rtt_acked=%f rtt_unacked=%f\n", conn_id_,
       fp_now, intersend_time_, calc_intersend_time_,
       static_cast<double>(rtt_acked_), static_cast<double>(rtt_unacked_));
#endif
}

//============================================================================
void Copa::UpdateNextSendTime(const Time& now, size_t bytes)
{
  // Update the next send time using the packet size and the stored next send
  // time.  This maintains inter-send time accuracy.
  double  pkt_intersend_time =
    (intersend_time_ *
     (static_cast<double>(bytes + kDataHdrBaseSize + kPktOverheadBytes) /
      static_cast<double>(kNominalPktSizeBytes + kPktOverheadBytes)));

  // If the current time is more than kQuiescentThreshold seconds beyond the
  // stored next send time, then the sender is considered to have been
  // quiescent for a time, so the next send time must be computed from now.
  // Otherwise, the send pacing timer must have been used, so add the
  // inter-send time for this packet to the stored next send time.
  if (now > next_send_time_.Add(kQuiescentThreshold))
  {
    next_send_time_ = now.Add(pkt_intersend_time);

    // Update the quiescent count for the policy controllers.
    ++quiescent_cnt_;
  }
  else
  {
    next_send_time_ = next_send_time_.Add(pkt_intersend_time);
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Waiting for "
       "intersend_time=%f\n", conn_id_, intersend_time_);
  LogA(kClassName, __func__, "Conn %" PRIEndptId ": PLT_WAIT %f %f\n",
       conn_id_, CurrentTime(now), intersend_time_);
#endif
}

//============================================================================
void Copa::UpdateDelta(const Time& now, bool /* pkt_lost */)
{
  // If delta is being held constant, then return immediately.
  if (mode_ == CONSTANT_DELTA)
  {
    return;
  }

  // Get the RTT estimate to use.
  double  rtt_ewma = rtt_acked_.max(rtt_unacked_);

  // Only allow the policy controller to update delta once every N RTTs, where
  // N is a constant, or at least once every maximum interval.
  double  wait_time = (kPolicyCtrlIntRtts * rtt_ewma);

  if (wait_time > kPolicyCtrlMaxIntSec)
  {
    wait_time = kPolicyCtrlMaxIntSec;
  }

  if (now < (prev_delta_update_time_.Add(wait_time)))
  {
    return;
  }

  // Allow the specific policy controller to determine the action to take.
  // If action is positive, then increase delta.  If action is negative, then
  // decrease delta.  If action is zero, then do not change delta.
  double  target_delta = local_sync_delta_;
  int     action       = 0;
  bool    allow_sync   = true;

  switch (mode_)
  {
    case MAX_THROUGHPUT:
      // This mode attempts to queue a reasonable number of packets at the
      // bottleneck link, while totally ignoring any packet losses.

      // If either no packets were sent or there was a period of quiescence,
      // then do not change delta or send a CC sync.
      if ((send_cnt_ == 0) || (quiescent_cnt_ > 0))
      {
        allow_sync = false;
        break;
      }

      // Calculate the target delta value using the experimentally confirmed
      // equation:
      //
      //   delta = ( (8 * pkt_size_bytes) / (link_rate_bps * rtt_sec) )
      //
      // The minimum RTT observed is "rtt_sec", but we do not know the link
      // rate.  However, the equation for computing our best guess at the
      // current link rate is (where "Tau" is the packet inter-send time):
      //
      //   link_rate_bps = ( (8 * pkt_size_bytes) / Tau)
      //
      // This gives us:
      //
      //   delta = ( (8 * pkt_size_bytes) /
      //             (((8 * pkt_size_bytes) / Tau) * rtt_sec) )
      //
      // Which reduces to the simple equation:
      //
      //   delta = ( Tau / rtt_sec )
      //
      target_delta = (calc_intersend_time_ / min_rtt_);

      // Take action only if delta really needs to be adjusted.
      if (target_delta > (local_sync_delta_ + kPolicyCtrlAddInc))
      {
        action = 1;
      }
      else if (target_delta < (local_sync_delta_ * kPolicyCtrlMultDec))
      {
        action = -1;
      }

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Raw tau=%f rtt=%f "
           "target_delta=%f\n", conn_id_, calc_intersend_time_, min_rtt_,
           target_delta);
#endif
      break;

    default:
      LogE(kClassName, __func__, "Conn %" PRIEndptId ": Unknown Copa mode, "
           "no policy controller action taken.\n", conn_id_);
  }

  // Following the rules for Copa's policy controller algorithm, use an
  // additive-increase/multiplicative-decrease (AIMD) adjustment algorithm to
  // limit the changes made to delta.  The result is in "target_delta".
  if (action > 0)  // Become less aggressive.
  {
    target_delta = (local_sync_delta_ + kPolicyCtrlAddInc);
  }
  else if (action < 0)  // Become more aggressive.
  {
    target_delta = (local_sync_delta_ * kPolicyCtrlMultDec);
  }
  else
  {
    target_delta = local_sync_delta_;
  }

  // Obey the absolute limits on delta that have been discovered
  // experimentally, keeping delta within the range where it performs well.
  if (target_delta < kMinDelta)
  {
    target_delta = kMinDelta;
  }
  else if (target_delta > kMaxDelta)
  {
    target_delta = kMaxDelta;
  }

  // Quantize the delta value for possible transport to the far end.
  target_delta = (round(target_delta * kPolicyCtrlQuantDelta) /
                  kPolicyCtrlQuantDelta);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Policy controller "
       "computed old_local_delta=%f new_local_delta=%f\n", conn_id_,
       local_sync_delta_, target_delta);
#endif

  // Update the local delta value.
  local_sync_delta_ = target_delta;

  // Possibly update the delta value used by Copa.
  double  UNUSED(old_delta) = delta_;

  if (is_client_)
  {
    // The client side always uses the locally computed delta value.
    delta_ = local_sync_delta_;

    // Possibly notify the server side of the new delta value.  Only notify if
    // sync's are allowed, and if delta has changed or enough time has passed.
    if (allow_sync)
    {
      uint16_t  param = static_cast<uint16_t>(delta_ * kPolicyCtrlQuantDelta);

      if ((param != prev_sync_params_) ||
          (now >= (prev_sync_time_.Add(kPolicyCtrlSyncIntSec))))
      {
        sync_params_      = param;
        prev_sync_params_ = param;
        prev_sync_time_   = now;
      }
    }
  }
  else
  {
    // The server side must consider any remotely computed delta value, which
    // is good for up to three times the maximum synchronization interval.
    if ((remote_sync_delta_ > 0.0) &&
        (now <= prev_sync_time_.Add(kPolicyCtrlSyncIntSec * 3.0)) &&
        (fabs(remote_sync_delta_ - local_sync_delta_) <=
         kPolicyCtrlSyncThresh))
    {
#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Policy controller "
           "sync to remote_delta=%f (local_delta=%f)\n", conn_id_,
           remote_sync_delta_, local_sync_delta_);
#endif

      delta_ = remote_sync_delta_;
    }
    else
    {
#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Policy controller "
           "sync to local_delta=%f (remote_delta=%f)\n", conn_id_,
           local_sync_delta_, remote_sync_delta_);
#endif

      delta_ = local_sync_delta_;
    }
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Policy controller "
       "updated t=%f old_delta=%f new_delta=%f\n", conn_id_, CurrentTime(now),
       old_delta, delta_);
  LogA(kClassName, __func__, "Conn %" PRIEndptId ": PLT_DELTA %f %f %f %f "
       "%f\n", conn_id_, CurrentTime(now), calc_intersend_time_, min_rtt_,
       (calc_intersend_time_ / min_rtt_), delta_);
#endif

#ifdef SLIQ_COPA_MRT
  // If delta is changing, then reset the minimum RTT tracking algorithm.
  if (delta_ != old_delta)
  {
    num_mrt_pts_ = 0;
    ++mrt_cnt_;
  }
#endif // SLIQ_COPA_MRT

  // Record the time that delta was updated.
  prev_delta_update_time_ = now;

  // Reset the policy controller counts.
  send_cnt_      = 0;
  quiescent_cnt_ = 0;
}

//============================================================================
void Copa::UpdateIntersendTime(const Time& now)
{
  // Get the RTT estimate to use.
  double  rtt_ewma = rtt_acked_.max(rtt_unacked_);

  // Compute the time spent in the bottleneck queue.
  double  queuing_delay = (rtt_ewma - min_rtt_);

  // Compute the inter-send time.
  calc_intersend_time_ = (delta_ * queuing_delay);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Computed rtt_ewma=%f "
       "(acked=%f unacked=%f) min_rtt=%f delta=%f queuing_delay=%f "
       "calc_intersend_time=%f\n", conn_id_, rtt_ewma,
       static_cast<double>(rtt_acked_), static_cast<double>(rtt_unacked_),
       min_rtt_, delta_, queuing_delay, calc_intersend_time_);
#endif

  // Apply a lower limit on the inter-send time of (Tprev / 2).
  if (prev_intersend_time_ > 0.0)
  {
    double  lower_limit = (0.5 * prev_intersend_time_);

    if (calc_intersend_time_ < lower_limit)
    {
      calc_intersend_time_ = lower_limit;

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Limit to Tprev/2, "
           "calc_intersend_time=%f\n", conn_id_, calc_intersend_time_);
#endif
    }
  }

  // Limit the inter-send time to a minimum allowable value.
  if (calc_intersend_time_ < kMinIntersendTime)
  {
    calc_intersend_time_ = kMinIntersendTime;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Absolute minimum "
         "limit, calc_intersend_time=%f\n", conn_id_, calc_intersend_time_);
#endif
  }

  // Limit the inter-send time to a maximum of either 2 times the RTT estimate
  // or a fixed value, whichever is larger.
  double  max_ist = (static_cast<double>(rtt_acked_) * 2.0);

  if (max_ist < kMaxIntersendTime)
  {
    max_ist = kMaxIntersendTime;
  }

  if (calc_intersend_time_ > max_ist)
  {
    calc_intersend_time_ = max_ist;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Current maximum limit, "
         "calc_intersend_time=%f\n", conn_id_, calc_intersend_time_);
#endif
  }

  // Randomly distribute the computed inter-send time for actual use, if
  // needed.
  if (random_send_)
  {
    intersend_time_ = RandomizeIntersend(calc_intersend_time_);
  }
  else
  {
#ifdef SLIQ_COPA_MRT
    // In order for the minimum RTT tracking algorithm to operate correctly,
    // the inter-send times must be randomized using a uniform distribution.
    intersend_time_ = (calc_intersend_time_ *
                       (rng_.GetDouble(2.0 * kMinRttTrkIstRand) +
                        (1.0 - kMinRttTrkIstRand)));
#else
    // Do not randomize the inter-send time.
    intersend_time_ = calc_intersend_time_;
#endif // SLIQ_COPA_MRT
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated inter-send time "
       "t=%f queuing_delay=%f calc_intersend_time=%f intersend_time=%f "
       "rtt_acked=%f rtt_unacked=%f\n", conn_id_, CurrentTime(now),
       queuing_delay, calc_intersend_time_, intersend_time_,
       static_cast<double>(rtt_acked_), static_cast<double>(rtt_unacked_));
  LogA(kClassName, __func__, "Conn %" PRIEndptId ": PLT_IST %f %f\n",
       conn_id_, CurrentTime(now), intersend_time_);
#endif
}

#ifdef SLIQ_COPA_MRT

//============================================================================
void Copa::UpdateMinRtt()
{
  // First, compute the mean of both X and Y.
  uint32_t  i     = 0;
  double    x_mean = 0.0;
  double    y_mean = 0.0;

#ifdef SLIQ_CC_DEBUG
  // For debugging only.
  double  x_min = 1.0e16;
  double  x_max = -1.0;
  double  y_min = 1.0e16;
  double  y_max = -1.0;
#endif

  for (i = 0; i < kMinRttTrkPoints; ++i)
  {
    MinRttLineData&  ml = mrt_line_[i];

    x_mean += ml.x_queued_kbytes;
    y_mean += ml.y_rtt_msec;

#ifdef SLIQ_CC_DEBUG
    // For debugging only.
    if (ml.x_queued_kbytes < x_min)
    {
      x_min = ml.x_queued_kbytes;
    }
    if (ml.x_queued_kbytes > x_max)
    {
      x_max = ml.x_queued_kbytes;
    }
    if (ml.y_rtt_msec < y_min)
    {
      y_min = ml.y_rtt_msec;
    }
    if (ml.y_rtt_msec > y_max)
    {
      y_max = ml.y_rtt_msec;
    }
#endif
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Estimate minRTT x_min=%f "
       "x_max=%f y_min=%f y_max=%f\n", conn_id_, x_min, x_max, y_min, y_max);
#endif

  x_mean = (x_mean / static_cast<double>(kMinRttTrkPoints));
  y_mean = (y_mean / static_cast<double>(kMinRttTrkPoints));

  // Next, compute the variance and covariance.
  double  x_var = 0.0;
  double  y_var = 0.0;
  double  cov   = 0.0;

  for (i = 0; i < kMinRttTrkPoints; ++i)
  {
    MinRttLineData&  ml = mrt_line_[i];

    double  x_delta = (ml.x_queued_kbytes - x_mean);
    double  y_delta = (ml.y_rtt_msec - y_mean);

    x_var += (x_delta * x_delta);
    y_var += (y_delta * y_delta);
    cov   += (x_delta * y_delta);
  }

  x_var = (x_var / static_cast<double>(kMinRttTrkPoints));
  y_var = (y_var / static_cast<double>(kMinRttTrkPoints));
  cov   = (cov / static_cast<double>(kMinRttTrkPoints));

  // Make sure that there is some X variance.
  if (x_var < 0.0000001)
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Estimate minRTT "
         "x_mean=%f y_mean=%f x_var=%f y_var=%f cov=%f exit early\n",
         conn_id_, x_mean, y_mean, x_var, y_var, cov);
    LogA(kClassName, __func__, "PLT_MRL %" PRIu32 " 0.0 %f\n", mrt_cnt_,
         y_mean);
    LogA(kClassName, __func__, "PLT_MRL %" PRIu32 " %f %f\n", mrt_cnt_, x_max,
         y_mean);
#endif

    return;
  }

  // The covariance matrix is A = | a  b |
  //                              | c  d |
  //
  // with:  a = x_var,  b = c = cov,  d = y_var

  // Compute the trace (T = a + d) and determinant (D = ad - bc) of A.
  double  tr  = (x_var + y_var);
  double  det = ((x_var * y_var) - (cov * cov));

  // Compute the eigenvalues of A, lambda 1 (l1) and lambda 2 (l2).
  double  term1 = (0.5 * tr);
  double  term2 = sqrt((0.25 * tr * tr) - det);
  double  l1    = (term1 + term2);
  double  l2    = (term1 - term2);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Estimate minRTT tr=%f "
       "det=%f term1=%f term2=%f l1=%f l2=%f\n", conn_id_, tr, det, term1,
       term2, l1, l2);
#endif

  if ((cov > -0.0000001) && (cov < 0.0000001))
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId ": Covariance is zero.\n",
         conn_id_);
  }

  // There are two possible slopes using the eigenvectors.  Use the one that
  // has a positive slope.
  //
  //   | L1 - d |   | L2 - d |
  //   |    c   | , |    c   |
  //
  // Note that the slopes are:  (change in Y) / (change in X)
  //
  // Use slope-intercept form:  y = mx + b
  //
  // Note that 'x' is the number of queued bits, 'm' is 1/rate, and 'b' is the
  // minimum RTT.
  double  m = (cov / (l1 - y_var));

  if (m < 0.0)
  {
    m = (cov / (l2 - y_var));
  }

  // Finally, compute b, the y-intercept, in milliseconds.  This is the
  // estimated minimum RTT value.  Note that b can be negative, but this will
  // not cause a problem.
  double  b = (y_mean - (m * x_mean));

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Estimate minRTT "
       "x_mean=%f y_mean=%f x_var=%f y_var=%f cov=%f m=%g b=%f\n", conn_id_,
       x_mean, y_mean, x_var, y_var, cov, m, b);
  LogA(kClassName, __func__, "PLT_MRL %" PRIu32 " 0.0 %f\n", mrt_cnt_, b);
  LogA(kClassName, __func__, "PLT_MRL %" PRIu32 " %f %f\n", mrt_cnt_, x_max,
       ((m * x_max) + b));
#endif

  // Check if there is enough of an increase in the new estimate in order to
  // trip the algorithm.  Convert b to seconds for the test.
  b *= 0.001;

  if (b > (min_rtt_ * kMinRttTrkThreshold))
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Trip minRTT old=%f "
         "new=%f\n", conn_id_, min_rtt_, b);
#endif

    ++mrt_trips_;

    // If there are two consecutive trips, then actually update minRTT.
    if (mrt_trips_ >= 2)
    {
      LogA(kClassName, __func__, "Conn %" PRIEndptId ": Update min_rtt "
           "old=%f new=%f\n", conn_id_, min_rtt_, b);

      min_rtt_   = b;
      mrt_trips_ = 0;
    }
  }
  else
  {
    mrt_trips_ = 0;
  }
}

#endif // SLIQ_COPA_MRT

//============================================================================
Copa::TimeEwma::TimeEwma(EndptId conn_id, double alpha)
    : conn_id_(conn_id),
      valid_(false),
      ewma_(0.0),
      den_(0.0),
      alpha_(alpha),
      last_ts_(0.0)
{
  if ((alpha_ <= 0.0) || (alpha_ >= 1.0))
  {
    LogF("TimeEwma", __func__, "Invalid alpha value: %f\n", alpha_);
  }
}

//============================================================================
void Copa::TimeEwma::Update(double value, double now, double rtt)
{
  if ((now < last_ts_) && ((last_ts_ - now) < (0.5 * kMaxFpTime)))
  {
    // This used to be a fatal log message, but there are cases we have
    // observed where the local monotonic clock can go backwards.
    LogE("TimeEwma", __func__, "Conn %" PRIEndptId ": Invalid timestamp (%f "
         "< %f).\n", conn_id_, now, last_ts_);
    return;
  }

  // The first reading is handled specially.
  if (!valid_)
  {
    valid_   = true;
    ewma_    = value;
    den_     = 1.0;
    last_ts_ = now;

    return;
  }

  double  time_delta = (now - last_ts_);

  if (time_delta < 0.0)
  {
    time_delta += kMaxFpTime;
  }

  double  ewma_factor = pow(alpha_, (time_delta / rtt));
  double  new_den     = (1.0 + (ewma_factor * den_));
  double  new_ewma    = ((value + (ewma_factor * ewma_ * den_)) / new_den);

  if (((value > ewma_) && (new_ewma < ewma_)) ||
      ((value < ewma_) && (new_ewma > ewma_)))
  {
    LogW("TimeEwma", __func__, "Conn %" PRIEndptId ": Ewma overflowed, "
         "resetting.\n", conn_id_);
    ewma_ = value;
    den_  = 1.0;
  }
  else
  {
    ewma_ = new_ewma;
    den_  = new_den;
  }

  last_ts_ = now;
}

//============================================================================
void Copa::TimeEwma::ForceSet(double value, double now)
{
  valid_   = true;
  ewma_    = value;
  den_     = 1.0;
  last_ts_ = now;
}
