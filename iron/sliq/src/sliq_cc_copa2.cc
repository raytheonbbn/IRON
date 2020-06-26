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

#include "sliq_cc_copa2.h"

#include "callback.h"
#include "log.h"

#include <inttypes.h>


using ::sliq::Capacity;
using ::sliq::CongCtrlAlg;
using ::sliq::Copa2;
using ::sliq::PktSeqNumber;
using ::iron::CallbackNoArg;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::Time;
using ::iron::Timer;


namespace
{
  /// The class name string for logging.
  const char*   kClassName            = "Copa2";

  /// The default value for delta.
  const double  kDefaultDelta         = 0.5;

  /// The minimum value for delta.
  const double  kMinDelta             = 0.000001;

  /// The maximum value for delta.
  const double  kMaxDelta             = 0.5;

  /// The initial nearly empty queue delay in seconds.
  const double  kInitNeqThreshold     = 0.025;

  /// The factor for computing the nearly empty queueing delay.
  const double  kNeqFactor            = 0.1;

  /// The low factor for determining if the bottleneck queue is stable when in
  /// default mode.
  const double  kStableQueueLoFactor  = 0.8;

  /// The high factor for determining if the bottleneck queue is stable when
  /// in default mode.
  const double  kStableQueueHiFactor  = 5.0;

  /// The inter-send time quiescent threshold, in seconds.
  const double  kQuiescentThreshold   = 0.01;

  /// The minimum RTT tracking factor.
  const double  kMinRttTrackFactor    = 1.1;

  /// The minimum RTT tracking amount, in seconds.
  const double  kMinRttTrackAmount    = 0.0005;

  /// The minimum RTT tracking minimum sampling period, in seconds.
  const double  kMinRttMinPeriod      = 0.012;

  /// The minimum RTT tracking reset threshold, in seconds.
  const double  kMinRttResetThreshold = 0.080;

  /// The large RTT value, in seconds.  This is large to cause any realistic
  /// RTT to be smaller than this value.
  const double  kHugeRtt              = 3600.0;

  /// The amount to add to the connection establishment RTT estimate, in
  /// seconds.  This makes the estimate very conservative.
  const double  kConnRttAdj           = 0.025;

  /// The minimum congestion window size, in packets.
  const double  kMinCwndPkts          = 2.0;

  /// The initial congestion window size, in packets.
  const double  kInitCwndPkts         = 3.0;

  /// The damper's queueing delay threshold value, in packets.
  const double  kDamperThresPkts      = 200.0;

  /// The packet overhead due to Ethernet (8 + 14 + 4 = 26 bytes), IP
  /// (20 bytes), and UDP (8 bytes), in bytes.  This assumes that no 802.1Q
  /// tag is present in the Ethernet frame, and that no IP header options are
  /// present.
  const size_t  kPktOverheadBytes     = 54;

  /// The nominal packet size, including the SLIQ data header and payload,
  /// used for converting computed packet intervals into send intervals for
  /// variable sized packets.
  const size_t  kNominalPktSizeBytes  = 1000;

  /// The maximum supported startup send rate, in packets per second.
  const double  kMaxStartupRate       = 11500.0;

  /// The maximum supported send rate, in packets per second.  This supports
  /// 1000 byte packets at 10 Gbps, or 100 byte packets at 1 Gbps.
  const double  kMaxRate              = (1.0e10 /
                                         (8.0 * (kNominalPktSizeBytes +
                                                 kPktOverheadBytes)));

  /// The minimum packet inter-send time, in seconds.
  const double  kMinIst               = (1.0 / kMaxRate);

  /// The congestion window size below which fast RTOs must be used.
  /// Determined experimentally for packet error rates up to 0.4.
  const double  kFastRtoCwndThres     = 32.0;
}


//============================================================================
Copa2::FastStartup::FastStartup()
    : pairs_sent_(0), pair_send_time_(), pair_recv_time_(), rtt_(), rate_(),
      timer_()
{
}

//============================================================================
Copa2::FastStartup::~FastStartup()
{
  return;
}

//============================================================================
void Copa2::FastStartup::Clear()
{
  pairs_sent_ = 0;

  for (size_t i = 0; i < kNumFsPairs; ++i)
  {
    pair_send_time_[i].Zero();
    pair_recv_time_[i].Zero();
    rtt_[i]  = 0.0;
    rate_[i] = 0.0;
  }
}

//============================================================================
Copa2::MinRttTracking::MinRttTracking()
    : recent_min_rtt_(kHugeRtt), min_rtt_(), count_(0), next_rtt_index_(0),
      ist_(), next_ist_index_(0), prev_time_()
{
  return;
}

//============================================================================
Copa2::MinRttTracking::~MinRttTracking()
{
  return;
}

//============================================================================
Copa2::TcpCompat::TcpCompat()
    : in_tcp_mode_(false), rtt_periods_(kDfltModeRttPeriods),
      nearly_empty_threshold_(kInitNeqThreshold), recent_max_qd_(0.0),
      recent_min_qd_(kHugeRtt), max_qd_(), recent_neq_(0), neq_(),
      next_index_(0), rtt_period_cnt_(0), next_delta_update_time_ack_(),
      next_delta_update_time_loss_()
{
  for (size_t i = 0; i < kTcpCompStateSize; ++i)
  {
    max_qd_[i] = 0.0;
    neq_[i]    = 1;
  }
}

//============================================================================
Copa2::TcpCompat::~TcpCompat()
{
  return;
}

//============================================================================
Copa2::Damper::Damper()
    : state_(DAMPER_MONITOR_HIGH), hold_cnt_(0)
{
  return;
}

//============================================================================
Copa2::Damper::~Damper()
{
  return;
}

//============================================================================
Copa2::Copa2(EndptId conn_id, bool is_client, CcId cc_id, Connection& conn,
             Framer& framer, PacketPool& pkt_pool, Timer& timer)
    : CongCtrlInterface(conn_id, is_client),
      cc_id_(cc_id),
      conn_(conn),
      framer_(framer),
      packet_pool_(pkt_pool),
      timer_(timer),
      state_(NOT_CONNECTED),
      fs_(),
      mrt_(),
      tc_(),
      damper_(),
      delta_(kDefaultDelta),
      last_rtt_(kHugeRtt),
      min_rtt_(kHugeRtt),
      cwnd_(kInitCwndPkts),
      ist_(1.0),
      velocity_(1),
      cwnd_adj_up_(0),
      cwnd_adj_down_(0),
      prev_direction_(VEL_DIR_NEITHER),
      vel_same_direction_cnt_(0),
      vel_cc_seq_num_(0),
      nxt_cc_seq_num_(0),
      start_time_point_(),
      rtt_period_end_(),
      next_send_time_(),
      timer_tolerance_(Time::FromMsec(1))
{
  // Initialize the time members.
  if (!start_time_point_.GetNow())
  {
    LogF(kClassName, __func__, "Failed to get current time.\n");
    return;
  }

  rtt_period_end_ = start_time_point_;
  next_send_time_ = start_time_point_;
}

//============================================================================
Copa2::~Copa2()
{
  // Cancel all of the timers.
  timer_.CancelTimer(fs_.timer_);

  // Clean up the timer callback object pools.
  CallbackNoArg<Copa2>::EmptyPool();
}

//============================================================================
bool Copa2::Configure(const CongCtrl& /* cc_params */)
{
  return true;
}

//============================================================================
void Copa2::Connected(const Time& now, const Time& rtt)
{
  if (state_ != NOT_CONNECTED)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Invalid state %d.\n",
         conn_id_, static_cast<int>(state_));
    return;
  }

  // Get the handshake RTT measurement in seconds.
  double  handshake_rtt = rtt.ToDouble();

  // Initialize the fast startup state.
  state_    = FAST_STARTUP;
  last_rtt_ = (handshake_rtt + kConnRttAdj);
  min_rtt_  = handshake_rtt;
  fs_.Clear();

  LogA(kClassName, __func__, "Conn %" PRIEndptId ": Initial min_rtt=%f\n",
       conn_id_, min_rtt_);

  // Send the first packet pair immediately.
  timer_.CancelTimer(fs_.timer_);
  FsPktPairCallback();
}

//============================================================================
bool Copa2::UseRexmitPacing()
{
  return true;
}

//============================================================================
bool Copa2::UseCongWinForCapEst()
{
  return true;
}

//============================================================================
bool Copa2::UseUnaPktReporting()
{
  return false;
}

//============================================================================
bool Copa2::SetTcpFriendliness(uint32_t /* num_flows */)
{
  return true;
}

//============================================================================
bool Copa2::ActivateStream(StreamId /* stream_id */,
                           PktSeqNumber /* init_send_seq_num */)
{
  return true;
}

//============================================================================
bool Copa2::DeactivateStream(StreamId /* stream_id */)
{
  return true;
}

//============================================================================
void Copa2::OnAckPktProcessingStart(const Time& /* ack_time */)
{
  return;
}

//============================================================================
void Copa2::OnRttUpdate(StreamId stream_id, const Time& ack_time,
                        PktTimestamp /* send_ts */,
                        PktTimestamp /* recv_ts */, PktSeqNumber seq_num,
                        PktSeqNumber cc_seq_num, const Time& rtt,
                        uint32_t bytes, float cc_val)
{
  if (state_ != CLOSED_LOOP)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Invalid state %d.\n",
         conn_id_, static_cast<int>(state_));
    return;
  }

  // Get the RTT measurement in seconds.
  double  measured_rtt = rtt.ToDouble();

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "** Conn %" PRIEndptId ": On RTT Update: "
       "stream_id=%" PRIStreamId " seq_num=%" PRIPktSeqNumber " cc_seq_num=%"
       PRIPktSeqNumber " ack_time=%s measured_rtt=%f size=%" PRIu32
       " cc_val=%f\n", conn_id_, stream_id, seq_num, cc_seq_num,
       ack_time.ToString().c_str(), measured_rtt, bytes,
       static_cast<double>(cc_val));
#endif

  // Update the minimum RTT value observed.
  if (measured_rtt < min_rtt_)
  {
    min_rtt_ = measured_rtt;

    LogA(kClassName, __func__, "Conn %" PRIEndptId ": Updated min_rtt=%f\n",
         conn_id_, min_rtt_);
  }

  if (measured_rtt < mrt_.recent_min_rtt_)
  {
    mrt_.recent_min_rtt_ = measured_rtt;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated "
         "recent_min_rtt=%f\n", conn_id_, mrt_.recent_min_rtt_);
#endif
  }

  // Save the last rtt measurement, which is in seconds.
  last_rtt_ = measured_rtt;

  // Update the velocity.
  if (SEQ_GEQ(cc_seq_num, vel_cc_seq_num_))
  {
    // Adjust the velocity.
    VelDir  direction = VEL_DIR_NEITHER;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Cwnd adjustments up=%"
         PRIu32 " down=%" PRIu32 "\n", conn_id_, cwnd_adj_up_,
         cwnd_adj_down_);
#endif

    if ((cwnd_adj_up_ + cwnd_adj_down_) > 0)
    {
      double  threshold = ((2.0 * (cwnd_adj_up_ + cwnd_adj_down_)) / 3.0);

      if (cwnd_adj_up_ >= threshold)
      {
        direction = VEL_DIR_UP;
      }
      else if (cwnd_adj_down_ >= threshold)
      {
        direction = VEL_DIR_DOWN;
      }

      if ((prev_direction_ != VEL_DIR_NEITHER) &&
          (direction == prev_direction_))
      {
        if ((velocity_ == 1) && (vel_same_direction_cnt_ < 3))
        {
          ++vel_same_direction_cnt_;
        }
        else
        {
          velocity_ *= 2;
        }
      }
      else
      {
        vel_same_direction_cnt_ = 0;
        velocity_               = 1;
      }
    }
    else
    {
      vel_same_direction_cnt_ = 0;
      velocity_               = 1;
    }

    // Prepare for the next velocity update.
    cwnd_adj_up_    = 0;
    cwnd_adj_down_  = 0;
    prev_direction_ = direction;
    vel_cc_seq_num_ = nxt_cc_seq_num_;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Update velocity=%"
         PRIu32 "\n", conn_id_, velocity_);
#endif
  }

  // Check if an RTT period has ended.
  if (ack_time > rtt_period_end_)
  {
    // Update the minimum RTT tracking.
    double  duration_sec = ((ack_time - mrt_.prev_time_).ToDouble());

    if (duration_sec >= kMinRttMinPeriod)
    {
      mrt_.ist_[mrt_.next_ist_index_] = ist_;
      mrt_.next_ist_index_            =
        ((mrt_.next_ist_index_ + 1) % kMinRttIstPeriods);

      if (mrt_.recent_min_rtt_ < kHugeRtt)
      {
        mrt_.min_rtt_[mrt_.next_rtt_index_] = mrt_.recent_min_rtt_;
        mrt_.recent_min_rtt_                = kHugeRtt;
        mrt_.next_rtt_index_                =
          ((mrt_.next_rtt_index_ + 1) % kMinRttPeriods);

        if (mrt_.count_ < kMinRttPeriods)
        {
          ++(mrt_.count_);
        }

        // If not in TCP mode and enough RTT samples are available, then check
        // if the minimum RTT should be adjusted upward.
        if ((!tc_.in_tcp_mode_) && (mrt_.count_ >= kMinRttPeriods))
        {
          // Find the oldest minimum RTT sample in the array, and the smallest
          // minimum RTT of the other samples in the array.
          double  oldest_cand_min_rtt = mrt_.min_rtt_[mrt_.next_rtt_index_];
          double  cand_min_rtt        = kHugeRtt;

          for (uint32_t i = 0; i < kMinRttPeriods; ++i)
          {
            if ((i != mrt_.next_rtt_index_) &&
                (mrt_.min_rtt_[i] < cand_min_rtt))
            {
              cand_min_rtt = mrt_.min_rtt_[i];
            }
          }

          // Only include the oldest minimum RTT sample if it is not a
          // half-step sample.
          if ((oldest_cand_min_rtt >
               (min_rtt_ + (0.6 * (cand_min_rtt - min_rtt_)))) ||
              (oldest_cand_min_rtt <
               (min_rtt_ + (0.4 * (cand_min_rtt - min_rtt_)))))
          {
            if (oldest_cand_min_rtt < cand_min_rtt)
            {
              cand_min_rtt = oldest_cand_min_rtt;
            }
          }

          // If the candidate minimum RTT exceeds the current minimum RTT by
          // the specified factor, then adjust the minimum RTT upward.
          if ((cand_min_rtt > (kMinRttTrackFactor * min_rtt_)) &&
              (cand_min_rtt > (min_rtt_ + kMinRttTrackAmount)))
          {
            min_rtt_ = cand_min_rtt;

            LogA(kClassName, __func__, "Conn %" PRIEndptId ": Increased "
                 "min_rtt=%f\n", conn_id_, min_rtt_);

            // Use the updated minimum RTT value to decide what to do with the
            // congestion window size and the inter-send time.
            if (min_rtt_ <= kMinRttResetThreshold)
            {
              // Reset both.
              cwnd_ = kMinCwndPkts;
              ist_  = (min_rtt_ / cwnd_);
            }
            else
            {
              // Adjust the current congestion window for the change in
              // minimum RTT.  This assumes that the channel capacity has not
              // changed, and is the fastest way to adapt on high-latency
              // channels.
              cwnd_ = (min_rtt_ / mrt_.ist_[mrt_.next_ist_index_]);
              ist_  = mrt_.ist_[mrt_.next_ist_index_];
            }

            // Reset the rest of the Copa2 parameters.
            delta_          = kDefaultDelta;
            velocity_       = 1;
            cwnd_adj_up_    = 0;
            cwnd_adj_down_  = 0;
            prev_direction_ = VEL_DIR_NEITHER;

            // Reset the damper state.
            damper_.state_    = DAMPER_MONITOR_HIGH;
            damper_.hold_cnt_ = 0;
          }
        }
      }

      // Record the current time.
      mrt_.prev_time_ = ack_time;
    }

    // Update the TCP compatibility state.
    ++tc_.rtt_period_cnt_;

    // Check if the TCP compatibility period is over or not.
    if (tc_.rtt_period_cnt_ >= tc_.rtt_periods_)
    {
      // If in default mode and there were no nearly empty queue events during
      // the period, then test if the maximum and minimum queueing delays
      // observed during this period fit the pattern of a very stable queueing
      // condition.  When this condition occurs, the observed queueing delays
      // never drop down to the nearly empty queueing delay threshold value.
      if ((!tc_.in_tcp_mode_) && (tc_.recent_neq_ == 0))
      {
        if ((tc_.recent_min_qd_ >= (kStableQueueLoFactor * ist_)) &&
            (tc_.recent_max_qd_ <= (kStableQueueHiFactor * ist_)))
        {
#ifdef SLIQ_CC_DEBUG
          LogD(kClassName, __func__, "Stable queue detected\n");
#endif
          tc_.recent_neq_ = 1;
        }
      }

      tc_.recent_min_qd_ = kHugeRtt;

      // Record the maximum queueing delay witnessed during the period.
      tc_.max_qd_[tc_.next_index_] = tc_.recent_max_qd_;
      tc_.recent_max_qd_           = 0.0;

      // Record the number of nearly empty queue events witnessed during the
      // period.
      tc_.neq_[tc_.next_index_] = tc_.recent_neq_;
      tc_.recent_neq_           = 0;

      // Update the nearly empty queueing delay threshold value.
      double  overall_max_qd = tc_.max_qd_[0];

      for (uint32_t j = 1; j < kTcpCompStateSize; ++j)
      {
        if (tc_.max_qd_[j] > overall_max_qd)
        {
          overall_max_qd = tc_.max_qd_[j];
        }
      }

      tc_.nearly_empty_threshold_ = (kNeqFactor * overall_max_qd);

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Update nearly empty "
           "queue threshold %f (%f %f %f %f)\n", conn_id_,
           tc_.nearly_empty_threshold_, tc_.max_qd_[0], tc_.max_qd_[1],
           tc_.max_qd_[2], tc_.max_qd_[3]);
#endif

      // Update the TCP compatibility mode.  If the sender detects a nearly
      // empty queue in all of the most recent TCP compatibility periods that
      // are to be checked, then use default mode.  Otherwise, use TCP mode.

      // \todo Complete the Copa2 TCP compatibility algorithm.  Until
      // completed, the algorithm is disabled.  To re-enable it, delete the
      // following #ifdef.
#ifdef DISABLE_TCP_COMPAT
      bool    new_in_tcp_mode = false;
      size_t  lim             = (tc_.in_tcp_mode_ ? kTcpModePeriods :
                                 kDfltModePeriods);
      size_t  idx             = ((tc_.next_index_ + kTcpCompStateSize + 1 -
                                  lim) % kTcpCompStateSize);

      for (size_t k = 0; k < lim; ++k)
      {
        if (tc_.neq_[idx] == 0)
        {
          new_in_tcp_mode = true;

          // Reset the damper state.
          damper_.state_    = DAMPER_MONITOR_HIGH;
          damper_.hold_cnt_ = 0;

          break;
        }

        idx = ((idx + 1) % kTcpCompStateSize);
      }

      tc_.in_tcp_mode_ = new_in_tcp_mode;
      tc_.rtt_periods_ = (new_in_tcp_mode ? kTcpModeRttPeriods :
                          kDfltModeRttPeriods);
#endif

      if (!tc_.in_tcp_mode_)
      {
        delta_ = kDefaultDelta;

#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated delta=%f\n",
             conn_id_, delta_);
#endif
      }

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated TCP "
           "compatibility mode %d (%" PRIu32 ": %" PRIu32 " %" PRIu32 " %"
           PRIu32 " %" PRIu32 " )\n", conn_id_,
           static_cast<int>(tc_.in_tcp_mode_), tc_.next_index_, tc_.neq_[0],
           tc_.neq_[1], tc_.neq_[2], tc_.neq_[3]);
#endif

      // Start a new TCP compatibility RTT period.
      tc_.next_index_     = ((tc_.next_index_ + 1) % kTcpCompStateSize);
      tc_.rtt_period_cnt_ = 0;
    }

    // Start a new RTT period.
    rtt_period_end_ = (ack_time + rtt);
  }

  // Estimate the queueing delay, which is in seconds.
  double  queueing_delay = (measured_rtt - min_rtt_);

  // Update the TCP compatibility state based on the queueing delay.
  if (queueing_delay > tc_.recent_max_qd_)
  {
    tc_.recent_max_qd_ = queueing_delay;
  }

  if (queueing_delay < tc_.recent_min_qd_)
  {
    tc_.recent_min_qd_ = queueing_delay;
  }

  if (queueing_delay < tc_.nearly_empty_threshold_)
  {
    ++(tc_.recent_neq_);
  }

  // Update the damper state.
  if (damper_.state_ == DAMPER_MONITOR_HIGH)
  {
    // Watch for instances when there are clearly too many packets queued at
    // the bottleneck link.  This cannot be done in TCP mode.
    if ((!tc_.in_tcp_mode_) && ((queueing_delay / ist_) > kDamperThresPkts))
    {
      damper_.state_ = DAMPER_MONITOR_LOW;

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Damper MONITOR_HIGH "
           "-> MONITOR_LOW.\n", conn_id_);
#endif
    }
  }
  else if (damper_.state_ == DAMPER_MONITOR_LOW)
  {
    // Watch for when the queueing delay just drops below 1/delta packets.
    if ((queueing_delay / ist_) < (1.0 / kDefaultDelta))
    {
      damper_.state_    = DAMPER_HOLD;
      damper_.hold_cnt_ = 0;

      cwnd_           = static_cast<double>(cc_val);
      velocity_       = 1;
      cwnd_adj_up_    = 0;
      cwnd_adj_down_  = 0;
      prev_direction_ = VEL_DIR_NEITHER;

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Damper MONITOR_LOW "
           "-> HOLD at cwnd=%f.\n", conn_id_, cwnd_);
#endif
    }
  }

  // Compute the current target rate, which is in packets per second.
  double  lambda_target = kMaxRate;

  if (queueing_delay > 0.0)
  {
    lambda_target = (1.0 / (delta_ * queueing_delay));
  }

  // Compute the current rate, which is in packets per second.
  double  lambda = (cwnd_ / measured_rtt);

  // Limit the velocity so that the rate can never more than double once per
  // RTT.
  uint32_t  max_velocity = static_cast<uint32_t>(delta_ * cwnd_);

  if (velocity_ > max_velocity)
  {
    velocity_ = max_velocity;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Reduce velocity=%"
         PRIu32 "\n", conn_id_, velocity_);
#endif
  }

  // Make sure that the velocity is never less than 1.
  if (velocity_ < 1)
  {
    velocity_ = 1;
  }

  // Adjust the congestion window size, which is in packets.  Scale the
  // adjustment amount by the size of the packet.
  double  cwnd_adj = ((static_cast<double>(bytes) *
                       static_cast<double>(velocity_)) /
                      (static_cast<double>(kNominalPktSizeBytes -
                                           kDataHdrBaseSize) *
                       delta_ * cwnd_));

  if (damper_.state_ != DAMPER_HOLD)
  {
    if (lambda <= lambda_target)
    {
      // Only increase the congestion window if the current number of packets
      // in flight is at least one-half of the current congestion window size.
      // This prevents the congestion window size from increasing indefinitely
      // when the sender is not keeping the channel full.
      double  pif = (static_cast<double>(bytes_in_flight_) /
                     static_cast<double>(kNominalPktSizeBytes -
                                         kDataHdrBaseSize));

      if (((cwnd_ <= 8.0) && (pif >= (cwnd_ - 4.0))) ||
          ((cwnd_ > 8.0) && (pif >= (0.5 * cwnd_))))
      {
        cwnd_ += cwnd_adj;
        ++cwnd_adj_up_;

#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Increased "
             "cwnd=%f\n", conn_id_, cwnd_);
#endif
      }
#ifdef SLIQ_CC_DEBUG
      else
      {
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Froze cwnd=%f "
             "pif=%f\n", conn_id_, cwnd_, pif);
      }
#endif
    }
    else
    {
      cwnd_ -= cwnd_adj;
      ++cwnd_adj_down_;

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Decreased cwnd=%f\n",
           conn_id_, cwnd_);
#endif
    }
  }

  // Limit how small/large the congestion window size can be.
  if (cwnd_ < kMinCwndPkts)
  {
    cwnd_ = kMinCwndPkts;
  }

  if (cwnd_ > static_cast<double>(kMaxCongCtrlWindowPkts))
  {
    cwnd_ = static_cast<double>(kMaxCongCtrlWindowPkts);
  }

  // Update the current inter-send time.
  ist_ = (last_rtt_ / cwnd_);

  // Limit the inter-send time if needed.
  if (ist_ < kMinIst)
  {
    ist_ = kMinIst;
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Computed rtt=%f "
       "min_rtt=%f queueing_delay=%f lambda_target=%f lambda=%f cwnd=%f "
       "ist=%f\n", conn_id_, measured_rtt, min_rtt_, queueing_delay,
       lambda_target, lambda, cwnd_, ist_);
  LogA(kClassName, __func__, "Conn %" PRIEndptId ": PLT_COPA2 %f %f %f %f %f "
       "%f %" PRIu32 " %f %0.9f %f\n", conn_id_, CurrentTime(ack_time),
       last_rtt_, min_rtt_, queueing_delay, lambda_target, lambda, velocity_,
       cwnd_, ist_,
       (static_cast<double>(bytes_in_flight_) /
        static_cast<double>(kNominalPktSizeBytes - kDataHdrBaseSize)));
#endif
}

//============================================================================
bool Copa2::OnPacketLost(StreamId /* stream_id */, const Time& /* ack_time */,
                         PktSeqNumber /* seq_num */,
                         PktSeqNumber /* cc_seq_num */, uint32_t /* bytes */)
{
  // If a packet has been lost, we are in TCP mode, and an RTT period has
  // passed, then increase the delta value.
  //
  //   delta' = 2 * delta
  //
  // This has the effect of decreasing the target send rate, which will force
  // the congestion window size to shrink.  The net result is a TCP-like
  // multiplicative decrease in the window size.
  //
  // Given that the number of buffered packets is equal to (1 / delta), this
  // has the effect of halving the buffer size.
  //
  //   new_buf_size = (1 / delta')
  //                = (1 / 2) * (1 / delta)
  //
  if (tc_.in_tcp_mode_)
  {
    Time  now = Time::Now();

    if (now > tc_.next_delta_update_time_loss_)
    {
      delta_ = (2.0 * delta_);

      if (delta_ < kMaxDelta)
      {
        delta_ = kMaxDelta;
      }

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Increased delta=%f\n",
           conn_id_, delta_);
#endif

      tc_.next_delta_update_time_loss_ = (now + Time(last_rtt_));
    }
  }

  return true;
}

//============================================================================
void Copa2::OnPacketAcked(StreamId /* stream_id */,
                          const Time& ack_time,
                          PktSeqNumber /* seq_num */,
                          PktSeqNumber /* cc_seq_num */,
                          PktSeqNumber /* ne_seq_num */, uint32_t /* bytes */)
{
  // If in TCP mode and an RTT period has passed, then decrease the delta
  // value.
  //
  //   delta' = 1 / (1 + (1 / delta))
  //
  // This has the effect of increasing the target send rate, which
  // will allow the congestion window size to grow.  The net result is a
  // TCP-like additive increase in the window size.
  //
  // Given that the number of buffered packets is equal to (1 / delta), this
  // has the effect of adding one packet to the buffer size.
  //
  //   new_buf_size = (1 / delta')
  //                = (1 / delta) + 1
  //
  if (tc_.in_tcp_mode_ && (ack_time > tc_.next_delta_update_time_ack_))
  {
    delta_ = (1.0 / (1.0 + (1.0 / delta_)));

    if (delta_ < kMinDelta)
    {
      delta_ = kMinDelta;
    }

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Decreased delta=%f\n",
         conn_id_, delta_);
#endif

    tc_.next_delta_update_time_ack_ = (ack_time + Time(last_rtt_));
  }
}

//============================================================================
void Copa2::OnAckPktProcessingDone(const Time& /* ack_time */)
{
  return;
}

//============================================================================
PktSeqNumber Copa2::OnPacketSent(StreamId stream_id, const Time& send_time,
                                 PktSeqNumber seq_num, uint32_t pld_bytes,
                                 uint32_t /* tot_bytes */, float& cc_val)
{
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

  // Record the congestion window size.
  cc_val = static_cast<float>(cwnd_);

  // Check if the damper state should be updated.
  if ((damper_.state_ == DAMPER_HOLD) || (damper_.state_ == DAMPER_WAIT))
  {
    ++damper_.hold_cnt_;

    if (damper_.hold_cnt_ > cwnd_)
    {
      if (damper_.state_ == DAMPER_HOLD)
      {
#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Damper HOLD -> "
             "WAIT.\n", conn_id_);
#endif

        damper_.state_ = DAMPER_WAIT;
      }
      else
      {
#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Damper WAIT -> "
             "MONITOR_HIGH.\n", conn_id_);
#endif

        damper_.state_ = DAMPER_MONITOR_HIGH;
      }

      damper_.hold_cnt_ = 0;
    }
  }

  // Update the next send time.
  UpdateNextSendTime(send_time, pld_bytes);

  return cc_seq_num;
}

//============================================================================
void Copa2::OnPacketResent(StreamId stream_id, const Time& send_time,
                           PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                           uint32_t pld_bytes, uint32_t /* tot_bytes */,
                           bool rto, bool orig_cc, float& cc_val)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "** Conn %" PRIEndptId ": On Resend: stream=%"
       PRIStreamId " seq_num=%" PRIPktSeqNumber " cc_seq_num=%"
       PRIPktSeqNumber " send_time=%s size=%" PRIu32 " rto=%d orig_cc=%d\n",
       conn_id_, stream_id, seq_num, cc_seq_num, send_time.ToString().c_str(),
       pld_bytes, static_cast<int>(rto), static_cast<int>(orig_cc));
#endif

  // Update the congestion window size.
  cc_val = static_cast<float>(cwnd_);

  // Check if the damper state should be updated.
  if ((damper_.state_ == DAMPER_HOLD) || (damper_.state_ == DAMPER_WAIT))
  {
    ++damper_.hold_cnt_;

    if (damper_.hold_cnt_ > cwnd_)
    {
      if (damper_.state_ == DAMPER_HOLD)
      {
#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Damper HOLD -> "
             "WAIT.\n", conn_id_);
#endif

        damper_.state_ = DAMPER_WAIT;
      }
      else
      {
#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Damper WAIT -> "
             "MONITOR_HIGH.\n", conn_id_);
#endif

        damper_.state_ = DAMPER_MONITOR_HIGH;
      }

      damper_.hold_cnt_ = 0;
    }
  }

  // Update the next send time if this is not due to an RTO event.
  if (!rto)
  {
    UpdateNextSendTime(send_time, pld_bytes);
  }
}

//============================================================================
bool Copa2::RequireFastRto()
{
  // If the congestion window size is too small, then use fast RTOs.
  return (cwnd_ < kFastRtoCwndThres);
}

//============================================================================
void Copa2::OnRto(bool /* pkt_rexmit */)
{
  return;
}

//============================================================================
void Copa2::OnOutageEnd()
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Outage is over.\n",
       conn_id_);
#endif

  return;
}

//============================================================================
bool Copa2::CanSend(const Time& /* now */, uint32_t /* bytes */)
{
  // If the congestion window size is greater than the number of bytes in
  // flight, then the sender is not congestion control blocked.
  return ((state_ == CLOSED_LOOP) &&
          ((cwnd_ * (kNominalPktSizeBytes - kDataHdrBaseSize)) >
           bytes_in_flight_));
}

//============================================================================
bool Copa2::CanResend(const Time& /* now */, uint32_t /* bytes */,
                      bool /* orig_cc */)
{
  // Copa2 paces fast retransmissions, so this can just return true.
  return true;
}

//============================================================================
Time Copa2::TimeUntilSend(const Time& now)
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
Capacity Copa2::PacingRate()
{
  double  pacing_rate_bps = (((kNominalPktSizeBytes + kPktOverheadBytes) *
                              8.0) / ist_);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Pacing rate %f bps.\n",
       conn_id_, pacing_rate_bps);
#endif

  return static_cast<Capacity>(pacing_rate_bps);
}

//============================================================================
Capacity Copa2::CapacityEstimate()
{
  return PacingRate();
}

//============================================================================
bool Copa2::GetSyncParams(uint16_t& seq_num, uint32_t& cc_params)
{
  return false;
}

//============================================================================
void Copa2::ProcessSyncParams(const Time& now, uint16_t seq_num,
                              uint32_t cc_params)
{
  return;
}

//============================================================================
void Copa2::ProcessCcPktTrain(const Time& now, CcPktTrainHeader& hdr)
{
  uint32_t  pair = (hdr.pt_seq_num / 2);

  // Check if this is an FS_DATA packet.
  if (hdr.pt_pkt_type == FS_DATA)
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Received packet pair "
         "FS_DATA with seq=%" PRIu8 ".\n", conn_id_, hdr.pt_seq_num);
#endif

    // Update local state and compute the packet pair inter-receive time to
    // send back in the FS_ACK packet.
    uint32_t  irt_usec = 0;

    if ((hdr.pt_seq_num % 2) == 0)
    {
      // This is the first FS_DATA packet for a pair.  Record its receive
      // time.
      fs_.pair_recv_time_[pair] = now;
    }
    else
    {
      // This is the second FS_DATA packet for a pair.  Compute the delay
      // between receipt of the two packets.
      if (!fs_.pair_recv_time_[pair].IsZero())
      {
        Time  irt = (now - fs_.pair_recv_time_[pair]);

        irt_usec = static_cast<uint32_t>(irt.GetTimeInUsec());

        if (irt_usec == 0)
        {
          irt_usec = 1;
        }

#ifdef SLIQ_CC_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Second packet of "
             "pair received, irt=%f.\n", conn_id_, irt.ToDouble());
#endif
      }
    }

    // Send an FS_ACK packet immediately.
    SendPktPairAck(hdr.pt_seq_num, irt_usec);
    return;
  }

  // This is an FS_ACK packet.

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Received packet pair "
       "FS_ACK with seq=%" PRIu8 ".\n", conn_id_, hdr.pt_seq_num);
#endif

  // Copa2 must be in the fast startup state to process the FS_ACK packet.
  if (state_ != FAST_STARTUP)
  {
    // It is possible for an FS_ACK packet to arrive late.  Thus, if we are in
    // the CLOSED_LOOP state, just ignore the packet without logging an error.
    if (state_ != CLOSED_LOOP)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId ": Invalid state %d.\n",
           conn_id_, static_cast<int>(state_));
    }
    return;
  }

  if ((hdr.pt_seq_num % 2) == 0)
  {
    // This is an FS_ACK of the first packet in the pair.  Use it for an RTT
    // estimate.
    if (!fs_.pair_send_time_[pair].IsZero())
    {
      Time  diff = (now - fs_.pair_send_time_[pair]);

      fs_.rtt_[pair] = diff.ToDouble();

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": First packet of pair "
           "FS_ACKed, rtt=%f.\n", conn_id_, fs_.rtt_[pair]);
#endif
    }
  }
  else
  {
    // This is an FS_ACK of the second packet in the pair.  Use it for a
    // bottleneck link rate estimate in packets per second.
    if (hdr.pt_inter_recv_time != 0)
    {
      double  irt_sec = (static_cast<double>(hdr.pt_inter_recv_time) *
                         0.000001);

      fs_.rate_[pair] = (1.0 / irt_sec);

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Second packet of "
           "pair FS_ACKed, irt=%f rate=%f.\n", conn_id_, irt_sec,
           fs_.rate_[pair]);
#endif
    }
  }

  // If this is the last FS_ACK needed, then end fast startup immediately.
  if (hdr.pt_seq_num == ((2 * kNumFsPairs) - 1))
  {
    timer_.CancelTimer(fs_.timer_);
    FsDoneCallback();
  }
}

//============================================================================
bool Copa2::InSlowStart()
{
  // Consider any state other than CLOSED_LOOP as slow start.
  return (state_ != CLOSED_LOOP);
}

//============================================================================
bool Copa2::InRecovery()
{
  // There is no fast recovery in Copa2.
  return false;
}

//============================================================================
uint32_t Copa2::GetCongestionWindow()
{
  // Convert the congestion window size from packets to bytes.
  return (cwnd_ * (kNominalPktSizeBytes - kDataHdrBaseSize));
}

//============================================================================
uint32_t Copa2::GetSlowStartThreshold()
{
  // There is no slow start threshold in Copa2.
  return 0;
}

//============================================================================
CongCtrlAlg Copa2::GetCongestionControlType()
{
  return COPA2_CC;
}

//============================================================================
void Copa2::Close()
{
  return;
}

//============================================================================
double Copa2::CurrentTime(const Time& now)
{
  return ((now - start_time_point_).ToDouble());
}

//============================================================================
void Copa2::UpdateNextSendTime(const Time& now, size_t bytes)
{
  // Update the next send time using the packet size and the stored next send
  // time.  This maintains inter-send time accuracy.
  double  pkt_intersend_time =
    (ist_ *
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
  }
  else
  {
    next_send_time_ = next_send_time_.Add(pkt_intersend_time);
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Waiting for "
       "intersend_time=%f\n", conn_id_, pkt_intersend_time);
#endif
}

//============================================================================
void Copa2::SendPktPair(uint8_t first_seq)
{
  // Send two congestion control packet train FS_DATA packets, each having a
  // length equal to the Copa2 nominal data packet size, as fast as possible.
  size_t  payload_len = (kNominalPktSizeBytes - kCcPktTrainHdrSize);

  if (!conn_.SendCcPktTrainPkts(cc_id_, FS_DATA, first_seq, 0, payload_len,
                                2))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Error sending FS_DATA "
         "packets.\n", conn_id_);
  }
#ifdef SLIQ_CC_DEBUG
  else
  {
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Sent packet pair "
         "FS_DATA with seq=%" PRIu8 " and seq=%" PRIu8 " with payload=%zu "
         "bytes.\n", conn_id_, first_seq, (first_seq + 1), payload_len);
  }
#endif
}

//============================================================================
void Copa2::SendPktPairAck(uint8_t seq, uint32_t irt_usec)
{
  // Send a congestion control packet train FS_ACK packet.
  if (!conn_.SendCcPktTrainPkts(cc_id_, FS_ACK, seq, irt_usec, 0, 1))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Error sending FS_ACK "
         "packet.\n", conn_id_);
  }
#ifdef SLIQ_CC_DEBUG
  else
  {
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Sent packet pair "
         "FS_ACK with seq=%" PRIu8 ".\n", conn_id_, seq);
  }
#endif
}

//============================================================================
void Copa2::FsPktPairCallback()
{
  if (state_ != FAST_STARTUP)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Invalid state %d.\n",
         conn_id_, static_cast<int>(state_));
    return;
  }

  // Record the time that the next packet pairs were sent.
  fs_.pair_send_time_[fs_.pairs_sent_] = Time::Now();

  // Send the next packet pair.
  SendPktPair(2 * fs_.pairs_sent_);
  ++(fs_.pairs_sent_);

  // Start a timer for the next event.
  if (fs_.pairs_sent_ < kNumFsPairs)
  {
    // Start the next timer to send 10 packet pairs over 2 RTTs.
    Time                  duration((2.0 * last_rtt_) /
                                   static_cast<double>(kNumFsPairs));
    CallbackNoArg<Copa2>  callback(this, &Copa2::FsPktPairCallback);

    if (!timer_.StartTimer(duration, &callback, fs_.timer_))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId ": Error starting "
           "packet pair timer.\n", conn_id_);
    }
  }
  else
  {
    // Wait up to 20 RTTs, or a maximum of one second, for FS_ACKs from the
    // last packet pair sent.
    double  wait_time = (2.0 * static_cast<double>(kNumFsPairs) * last_rtt_);

    if (wait_time > 1.0)
    {
      wait_time = 1.0;
    }

    Time                  duration(wait_time);
    CallbackNoArg<Copa2>  callback(this, &Copa2::FsDoneCallback);

    if (!timer_.StartTimer(duration, &callback, fs_.timer_))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId ": Error starting done "
           "timer.\n", conn_id_);
    }
  }
}

//============================================================================
void Copa2::FsDoneCallback()
{
  if (state_ != FAST_STARTUP)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Invalid state %d.\n",
         conn_id_, static_cast<int>(state_));
    return;
  }

  // Find the minimum, maximum, and mean RTT estimates, as well as the
  // bottleneck link rate estimate (mu).
  uint32_t  rtt_cnt  = 0;
  uint32_t  rate_cnt = 0;
  double    rtt_min  = kHugeRtt;
  double    rtt_max  = -1.0;
  double    mean_rtt = 0.0;
  double    mu       = 0.0;

  // Start at 1, skipping the first sample.  This is because the first sample
  // is usually very inaccurate.
  for (size_t pair = 1; pair < kNumFsPairs; ++pair)
  {
    double rtt_est = fs_.rtt_[pair];

    if (rtt_est > 0.0)
    {
      mean_rtt += rtt_est;
      ++rtt_cnt;

      if (rtt_est < rtt_min)
      {
        rtt_min = rtt_est;
      }

      if (rtt_est > rtt_max)
      {
        rtt_max = rtt_est;
      }
    }

    double rate_est = fs_.rate_[pair];

    if (rate_est > 0.0)
    {
      mu += rate_est;
      ++rate_cnt;
    }
  }

  // If there was not enough data, then restart the fast startup.
  if ((rtt_cnt == 0) || (rate_cnt == 0))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Incomplete fast "
         "startup, trying again.\n", conn_id_);
    fs_.Clear();
    timer_.CancelTimer(fs_.timer_);
    FsPktPairCallback();
    return;
  }

  // Complete the mean computations.
  mean_rtt = (mean_rtt / static_cast<double>(rtt_cnt));
  mu       = (mu / static_cast<double>(rate_cnt));

  // Compute the target rate, in packets per second.
  double  lambda_target = mu;

  if (rtt_max > rtt_min)
  {
    double  tmp = (2.0 / (delta_ * (rtt_max - rtt_min)));

    if (tmp < mu)
    {
      lambda_target = tmp;
    }
  }

  // Limit the target rate to the maximum allowable startup rate.
  if (lambda_target > kMaxStartupRate)
  {
    lambda_target = kMaxStartupRate;
  }

  // Set the initial parameters based on the fast startup results.
  last_rtt_ = mean_rtt;
  min_rtt_  = rtt_min;
  cwnd_     = (lambda_target * rtt_min);
  ist_      = (1.0 / lambda_target);

  LogA(kClassName, __func__, "Conn %" PRIEndptId ": Fast startup, rtt_min=%f "
       "rtt_max=%f mean_rtt=%f mu=%f lambda_target=%f last_rtt=%f min_rtt=%f "
       "cwnd=%f ist=%f\n", conn_id_, rtt_min, rtt_max, mean_rtt, mu,
       lambda_target, last_rtt_, min_rtt_, cwnd_, ist_);

  // The algorithm is now ready for closed loop operation.
  state_ = CLOSED_LOOP;
}
