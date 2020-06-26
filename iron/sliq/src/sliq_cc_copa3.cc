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

#include "sliq_cc_copa3.h"

#include "callback.h"
#include "log.h"

#include <inttypes.h>


using ::sliq::Capacity;
using ::sliq::CongCtrlAlg;
using ::sliq::Copa3;
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
  const char*   kClassName           = "Copa3";

  /// The smoothed RTT alpha parameter.
  const double  kSrttAlpha           = (1.0 / 16.0);

  /// The default value for delta.
  const double  kDefaultDelta        = 0.5;

  /// The slow start RTT threshold, in seconds.
  const double  kSlowStartThreshold  = 0.05;

  /// The inter-send time quiescent threshold, in seconds.
  const double  kQuiescentThreshold  = 0.01;

  /// The large RTT value, in seconds.  This is large to cause any realistic
  /// RTT to be smaller than this value.
  const double  kHugeRtt             = 7200.0;

  /// The amount to add to the smoothed RTT for computing the packet pair
  /// intersend time, in seconds.
  const double  kPktPairRttAdj       = 0.025;

  /// The maximum period between transmission of the local minimum RTT to the
  /// peer, in seconds.
  const double  kReportMinRttPeriod  = 4.0;

  /// The initial congestion window size, in packets.
  const double  kInitCwndPkts        = 3.0;

  /// The minimum congestion window size, in packets.
  const double  kMinCwndPkts         = 2.0;

  /// The maximum congestion window size for always allowing a congestion
  /// window size increase, in packets.
  const double  kIncCwndPkts         = 16.0;

  /// The maximum portion of the congestion window that can be unused in order
  /// to allow a congestion window size increase.
  const double  kIncCwndRatio        = 0.5;

  /// The damper's queueing delay threshold value, in packets.
  const double  kDamperThresPkts     = 40.0;

  /// The packet overhead due to Ethernet (8 + 14 + 4 = 26 bytes), IP
  /// (20 bytes), and UDP (8 bytes), in bytes.  This assumes that no 802.1Q
  /// tag is present in the Ethernet frame, and that no IP header options are
  /// present.
  const size_t  kPktOverheadBytes    = 54;

  /// The nominal packet size, including the SLIQ data header and payload,
  /// used for converting computed packet intervals into send intervals for
  /// variable sized packets.
  const size_t  kNominalPktSizeBytes = 1000;

  /// The maximum supported startup send rate, in packets per second.
  const double  kMaxStartupRate      = 11500.0;

  /// The maximum supported send rate, in packets per second.  This supports
  /// 1000 byte packets at 10 Gbps, or 100 byte packets at 1 Gbps.
  const double  kMaxRate             = (1.0e10 /
                                        (8.0 * (kNominalPktSizeBytes +
                                                kPktOverheadBytes)));

  /// The minimum packet inter-send time, in seconds.
  const double  kMinIst              = (1.0 / (2.0 * kMaxRate));

  /// The congestion window size below which fast RTOs must be used.
  /// Determined experimentally for packet error rates up to 0.4.
  const double  kFastRtoCwndThres    = 32.0;
}


// Macro for checking a received CC synchronization sequence number, with s
// being the new sequence number and r the last sequence number.
#define CC_SYNC_SEQ_NUM_OK(s, r)  ((((s) > (r)) && (((s) - (r)) < 32768)) || \
                                   (((s) < (r)) && (((r) - (s)) > 32768)))


//============================================================================
Copa3::FastStartup::FastStartup()
    : pairs_sent_(0), pair_send_time_(), pair_recv_time_(), rtt_(), rate_(),
      timer_()
{
}

//============================================================================
Copa3::FastStartup::~FastStartup()
{
  return;
}

//============================================================================
void Copa3::FastStartup::Clear()
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
Copa3::DelayBin::DelayBin()
    : min_delay_(kHugeRtt), obs_time_()
{
  return;
}

//============================================================================
Copa3::DelayBin::~DelayBin()
{
  return;
}

//============================================================================
Copa3::DelayTracker::DelayTracker()
    : recent_min_delay_(kHugeRtt), recent_obs_time_(), bin_(), count_(0),
      next_index_(0), prev_time_()
{
  return;
}

//============================================================================
Copa3::DelayTracker::~DelayTracker()
{
  return;
}

//============================================================================
void Copa3::DelayTracker::Update(double delay, const Time& now,
                                 double win_sec, double& result)
{
  // Update the recent minimum delay observed.
  if (delay < recent_min_delay_)
  {
    recent_min_delay_ = delay;
    recent_obs_time_  = now;
  }

  // Check if the current bin period is over.
  Time  bin_dur(win_sec / static_cast<double>(kDelayTrackerBins));

  if (now >= (prev_time_ + bin_dur))
  {
    // Record the recent minimum delay in the next bin in the window.
    bin_[next_index_].min_delay_ = recent_min_delay_;
    bin_[next_index_].obs_time_  = recent_obs_time_;

    // Update the number of minimum RTTs in the circular array.
    if (count_ < kDelayTrackerBins)
    {
      ++count_;
    }

    // Find the lowest minimum RTT in the specified time window.
    Time      win_start_time = (now - Time(win_sec));
    double    cand_min_delay = recent_min_delay_;
    uint32_t  idx            = ((next_index_ == 0) ? (kDelayTrackerBins - 1) :
                                (next_index_ - 1));

    for (uint32_t i = 1; i < count_; ++i)
    {
      if (bin_[idx].obs_time_ < win_start_time)
      {
        // Invalidate the bin to prevent increases in the RTT from including
        // it again later.
        bin_[idx].min_delay_ = kHugeRtt;
      }
      else
      {
        if (bin_[idx].min_delay_ < cand_min_delay)
        {
          cand_min_delay = bin_[idx].min_delay_;
        }
      }

      idx = ((idx == 0) ? (kDelayTrackerBins - 1) : (idx - 1));
    }

    // Pass the lowest minimum delay back to the caller only if a valid
    // minimum delay was found.
    if (cand_min_delay < kHugeRtt)
    {
      result = cand_min_delay;
    }

    // Reset for the next update.
    recent_min_delay_ = kHugeRtt;

    next_index_ = ((next_index_ + 1) % kDelayTrackerBins);
    prev_time_  = now;
  }
  else
  {
    // Update the result as needed.
    if (delay < result)
    {
      result = delay;
    }
  }
}

//============================================================================
Copa3::VelocityState::VelocityState(PktSeqNumber initial_cc_seq_num,
                                    double initial_cwnd)
    : prev_direction_(VEL_DIR_NEITHER), same_direction_cnt_(0),
      start_cc_seq_num_(initial_cc_seq_num), start_cwnd_(initial_cwnd),
      start_cwnd_increasing_(true)
{
  return;
}

//============================================================================
Copa3::VelocityState::~VelocityState()
{
  return;
}

//============================================================================
void Copa3::VelocityState::Update(PktSeqNumber next_cc_seq_num,
                                  double current_cwnd, bool cwnd_increasing,
                                  uint32_t& result_velocity)
{
  VelDir  dir = VEL_DIR_NEITHER;

  // Determine the current direction.
  if (current_cwnd > start_cwnd_)
  {
    dir = VEL_DIR_UP;
  }
  else if (current_cwnd < start_cwnd_)
  {
    dir = VEL_DIR_DOWN;
  }

  if ((dir != VEL_DIR_NEITHER) && (dir == prev_direction_))
  {
    // Direction is the same as in the previous window.  Only start doubling
    // the velocity after the direction has remained the same for 3 RTTs.
    if ((result_velocity == 1) && (same_direction_cnt_ < 3))
    {
      ++same_direction_cnt_;
    }
    else
    {
      result_velocity *= 2;
    }
  }
  else
  {
    // Direction is NEITHER or not the same as in the previous window.  Reset
    // the velocity to 1.
    same_direction_cnt_ = 0;
    result_velocity     = 1;
  }

  // Reset for the next update.
  prev_direction_        = dir;
  start_cc_seq_num_      = next_cc_seq_num;
  start_cwnd_            = current_cwnd;
  start_cwnd_increasing_ = cwnd_increasing;
}

//============================================================================
void Copa3::VelocityState::Reset(PktSeqNumber next_cc_seq_num,
                                 double current_cwnd, bool cwnd_increasing,
                                 uint32_t& result_velocity)
{
  prev_direction_        = VEL_DIR_NEITHER;
  same_direction_cnt_    = 0;
  start_cc_seq_num_      = next_cc_seq_num;
  start_cwnd_            = current_cwnd;
  start_cwnd_increasing_ = cwnd_increasing;
  result_velocity        = 1;
}

//============================================================================
Copa3::Damper::Damper()
    : state_(DAMPER_MONITOR_HIGH), hold_cnt_(0)
{
  return;
}

//============================================================================
Copa3::Damper::~Damper()
{
  return;
}

//============================================================================
bool Copa3::Damper::OnRttUpdate(double queueing_delay, double ist,
                                double delta)
{
  bool  rv = false;

  if (state_ == DAMPER_MONITOR_HIGH)
  {
    // Watch for instances when there are clearly too many packets queued at
    // the bottleneck link.
    if ((queueing_delay / ist) > kDamperThresPkts)
    {
      state_ = DAMPER_MONITOR_LOW;
    }
  }
  else if (state_ == DAMPER_MONITOR_LOW)
  {
    // Watch for when the queueing delay just drops below 1/delta packets.
    if ((queueing_delay / ist) < (1.0 / delta))
    {
      state_    = DAMPER_HOLD;
      hold_cnt_ = 0;
      rv        = true;
    }
  }

  return rv;
}

//============================================================================
void Copa3::Damper::OnPktSend(double cwnd)
{
  // Check if the damper state should be updated.
  if ((state_ == DAMPER_HOLD) || (state_ == DAMPER_WAIT))
  {
    ++hold_cnt_;

    if (hold_cnt_ > cwnd)
    {
      if (state_ == DAMPER_HOLD)
      {
        state_ = DAMPER_WAIT;
      }
      else
      {
        state_ = DAMPER_MONITOR_HIGH;
      }

      hold_cnt_ = 0;
    }
  }
}

//============================================================================
void Copa3::Damper::Reset()
{
  state_    = DAMPER_MONITOR_HIGH;
  hold_cnt_ = 0;
}

//============================================================================
Copa3::Copa3(EndptId conn_id, bool is_client, CcId cc_id, Connection& conn,
             Framer& framer, PacketPool& pkt_pool, Timer& timer)
    : CongCtrlInterface(conn_id, is_client),
      cc_id_(cc_id),
      conn_(conn),
      framer_(framer),
      packet_pool_(pkt_pool),
      timer_(timer),
      state_(NOT_CONNECTED),
      fs_(),
      srt_(),
      mrt_(),
      mtd_(),
      vel_(0, kInitCwndPkts),
      damper_(),
      anti_jitter_(0.0),
      delta_(kDefaultDelta),
      smoothed_rtt_(kHugeRtt),
      standing_rtt_(kHugeRtt),
      min_rtt_(kHugeRtt),
      loc_min_rtt_(kHugeRtt),
      rmt_min_rtt_(kHugeRtt),
      min_ts_delta_(kHugeRtt),
      cwnd_(kInitCwndPkts),
      ist_(1.0),
      velocity_(1),
      nxt_cc_seq_num_(0),
      sync_send_seq_num_(1),
      sync_recv_seq_num_(0),
      report_min_rtt_(false),
      prev_report_min_rtt_(0),
      next_report_min_rtt_(0),
      next_report_min_rtt_time_(),
      rmt_min_rtt_time_(),
      start_time_point_(),
      next_send_time_(),
      timer_tolerance_(Time::FromMsec(1))
{
  // Initialize the time members.
  if (!start_time_point_.GetNow())
  {
    LogF(kClassName, __func__, "Failed to get current time.\n");
    return;
  }

  next_send_time_ = start_time_point_;
}

//============================================================================
Copa3::~Copa3()
{
  // Cancel all of the timers.
  timer_.CancelTimer(fs_.timer_);

  // Clean up the timer callback object pools.
  CallbackNoArg<Copa3>::EmptyPool();
}

//============================================================================
bool Copa3::Configure(const CongCtrl& cc_params)
{
  if (cc_params.copa3_anti_jitter > 0.0)
  {
    anti_jitter_ = cc_params.copa3_anti_jitter;

    LogC(kClassName, __func__, "Conn %" PRIEndptId ": Setting Copa3 "
         "anti-jitter to %f.\n", conn_id_, anti_jitter_);
  }

  return true;
}

//============================================================================
void Copa3::Connected(const Time& /* now */, const Time& rtt)
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
  smoothed_rtt_ = handshake_rtt;
  standing_rtt_ = handshake_rtt;
  min_rtt_      = handshake_rtt;
  loc_min_rtt_  = handshake_rtt;
  fs_.Clear();

  LogA(kClassName, __func__, "Conn %" PRIEndptId ": Initial min_rtt=%f\n",
       conn_id_, min_rtt_);

  if (handshake_rtt > kSlowStartThreshold)
  {
    state_ = FAST_STARTUP;

    // Send the first packet pair immediately.
    timer_.CancelTimer(fs_.timer_);
    FsPktPairCallback();
  }
  else
  {
    state_ = SLOW_START;
    ist_   = (handshake_rtt / cwnd_);
  }
}

//============================================================================
bool Copa3::UseRexmitPacing()
{
  return true;
}

//============================================================================
bool Copa3::UseCongWinForCapEst()
{
  return true;
}

//============================================================================
bool Copa3::UseUnaPktReporting()
{
  return false;
}

//============================================================================
bool Copa3::SetTcpFriendliness(uint32_t /* num_flows */)
{
  return true;
}

//============================================================================
bool Copa3::ActivateStream(StreamId /* stream_id */,
                           PktSeqNumber /* init_send_seq_num */)
{
  return true;
}

//============================================================================
bool Copa3::DeactivateStream(StreamId /* stream_id */)
{
  return true;
}

//============================================================================
void Copa3::OnAckPktProcessingStart(const Time& /* ack_time */)
{
  return;
}

//============================================================================
void Copa3::OnRttUpdate(StreamId stream_id, const Time& ack_time,
                        PktTimestamp send_ts, PktTimestamp recv_ts,
                        PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                        const Time& rtt, uint32_t bytes, float cc_val)
{
  if (state_ < SLOW_START)
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
       PRIPktSeqNumber " ack_time=%s measured_rtt=%f bytes=%" PRIu32
       " cc_val=%f\n", conn_id_, stream_id, seq_num, cc_seq_num,
       ack_time.ToString().c_str(), measured_rtt, bytes,
       static_cast<double>(cc_val));
#endif

  // Update the minimum timestamp delta using the tracker with a time window
  // of 7*RTTmin or 0.2 seconds, whichever is greater.
  double  ts_delta    = (static_cast<double>(static_cast<int64_t>(recv_ts) -
                                             static_cast<int64_t>(send_ts)) *
                         0.000001);
  double  mtd_win_sec = (7.0 * min_rtt_);

  if (mtd_win_sec < 0.2)
  {
    mtd_win_sec = 0.2;
  }

  mtd_.Update(ts_delta, ack_time, mtd_win_sec, min_ts_delta_);

  // Adjust the RTT measurement in order to eliminate the queueing delay in
  // the reverse path.
  double  adjusted_rtt = (measured_rtt + min_ts_delta_ - ts_delta);

  if (adjusted_rtt < kMinRttSec)
  {
    adjusted_rtt = kMinRttSec;
  }

  // Update the local minimum RTT using the tracker with a time window of
  // 28*RTTmin or 0.8 seconds, whichever is greater.
  double  old_loc_min_rtt = loc_min_rtt_;
  double  mrt_win_sec     = (28.0 * min_rtt_);

  if (mrt_win_sec < 0.8)
  {
    mrt_win_sec = 0.8;
  }

  mrt_.Update(adjusted_rtt, ack_time, mrt_win_sec, loc_min_rtt_);

  // If an anti-jitter value is configured, then reduce the adjusted RTT by
  // the anti-jitter amount while not going lower than the local minimum RTT.
  if (anti_jitter_ > 0.0)
  {
    adjusted_rtt -= anti_jitter_;

    if (adjusted_rtt < loc_min_rtt_)
    {
      adjusted_rtt = loc_min_rtt_;
    }
  }

  // Update the smoothed RTT.
  smoothed_rtt_ = ((kSrttAlpha * adjusted_rtt) +
                   ((1.0 - kSrttAlpha) * smoothed_rtt_));

  // Update the standing RTT using the tracker with a time window of srtt/2.
  double  srt_win_sec = (0.5 * smoothed_rtt_);

  srt_.Update(adjusted_rtt, ack_time, srt_win_sec, standing_rtt_);

  // If the local minimum RTT has changed, then recalculate the minimum RTT.
  if (loc_min_rtt_ != old_loc_min_rtt)
  {
    // If the remote minimum RTT came in more than 3 reporting periods ago,
    // then it is stale and must be eliminated from the calculation.
    if ((!rmt_min_rtt_time_.IsZero()) &&
        (ack_time >= (rmt_min_rtt_time_ + Time(3.1 * kReportMinRttPeriod))))
    {
      rmt_min_rtt_ = kHugeRtt;
      rmt_min_rtt_time_.Zero();
    }

    // The minimum RTT is the minimum of the local and remote minimum RTTs.
    if (rmt_min_rtt_ < kHugeRtt)
    {
      min_rtt_ = ((loc_min_rtt_ < rmt_min_rtt_) ? loc_min_rtt_ :
                  rmt_min_rtt_);
    }
    else
    {
      min_rtt_ = loc_min_rtt_;
    }

    LogA(kClassName, __func__, "Conn %" PRIEndptId ": Updated min_rtt=%f\n",
         conn_id_, min_rtt_);

    // Possibly report the new local minimum RTT to the peer.
    ReportMinRttOnUpdate();
  }

  // Check if it is time to report the local minimum RTT to the peer.
  if ((!report_min_rtt_) && (ack_time > next_report_min_rtt_time_))
  {
    ReportMinRttOnTimeout(ack_time);
  }

  // Estimate the queueing delay, which is in seconds.
  double  queueing_delay = (standing_rtt_ - min_rtt_);

  // Prevent the queueing delay from going negative.
  if (queueing_delay < 0.0)
  {
    queueing_delay = 0.0;
  }

  // Compute the current target rate, which is in packets per second.
  double  lambda_target = kMaxRate;

  if (queueing_delay > 0.0)
  {
    lambda_target = (1.0 / (delta_ * queueing_delay));
  }

  // Compute the current rate, which is in packets per second.
  double  lambda = (cwnd_ / standing_rtt_);

  // Update the congestion window differently depending on the current state.
  if (state_ == SLOW_START)
  {
    // Only increase the congestion window if the current number of packets in
    // flight is close to the current congestion window size.  This prevents
    // the congestion window size from increasing indefinitely when the sender
    // is not keeping the channel full.
    if ((cwnd_ < kIncCwndPkts) ||
        ((cwnd_ - (static_cast<double>(bytes_in_flight_) /
                   static_cast<double>(kNominalPktSizeBytes -
                                       kDataHdrBaseSize))) <=
         (kIncCwndRatio * cwnd_)))
    {
      // Double the congestion window each RTT.
      cwnd_ += (static_cast<double>(bytes) /
                static_cast<double>(kNominalPktSizeBytes -
                                    kDataHdrBaseSize));
    }

    // Determine if slow start is over.
    if (lambda > lambda_target)
    {
      state_ = CLOSED_LOOP;
    }
  }
  else // state_ == CLOSED_LOOP
  {
    // Update the damper.
    if (damper_.OnRttUpdate(queueing_delay, ist_, delta_))
    {
      // Force the congestion window size to the size when this packet was
      // sent, and reset the velocity state.
      cwnd_ = static_cast<double>(cc_val);

      vel_.Reset(nxt_cc_seq_num_, cwnd_, (lambda <= lambda_target),
                 velocity_);

      LogA(kClassName, __func__, "Conn %" PRIEndptId ": Damper, hold cwnd at "
           "%f.\n", conn_id_, cwnd_);
    }

    // Only update the velocity and congestion window size if the damper
    // allows it.
    if (damper_.CanUpdateVelCwnd())
    {
      // Update the velocity.
      if (SEQ_GEQ(cc_seq_num, vel_.start_cc_seq_num_))
      {
        vel_.Update(nxt_cc_seq_num_, cwnd_, (lambda <= lambda_target),
                    velocity_);
      }

      if ((lambda <= lambda_target) != vel_.start_cwnd_increasing_)
      {
        vel_.Reset(nxt_cc_seq_num_, cwnd_, (lambda <= lambda_target),
                   velocity_);
      }

      // Limit the velocity so that the rate can never more than double once
      // per RTT.
      uint32_t  max_velocity = static_cast<uint32_t>(delta_ * cwnd_);

      if (velocity_ > max_velocity)
      {
        velocity_ = max_velocity;
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

      if (lambda <= lambda_target)
      {
        // Only increase the congestion window if the current number of
        // packets in flight is close to the current congestion window size.
        // This prevents the congestion window size from increasing
        // indefinitely when the sender is not keeping the channel full.
        if ((cwnd_ < kIncCwndPkts) ||
            ((cwnd_ - (static_cast<double>(bytes_in_flight_) /
                       static_cast<double>(kNominalPktSizeBytes -
                                           kDataHdrBaseSize))) <=
             (kIncCwndRatio * cwnd_)))
        {
          cwnd_ += cwnd_adj;
        }
      }
      else
      {
        cwnd_ -= cwnd_adj;
      }
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
  ist_ = (standing_rtt_ / cwnd_);

  // Limit the inter-send time if needed.
  if (ist_ < kMinIst)
  {
    ist_ = kMinIst;
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Computed rtt=%f "
       "smoothed_rtt=%f standing_rtt=%f min_rtt=%f queueing_delay=%f "
       "lambda_target=%f lambda=%f cwnd=%f ist=%f\n", conn_id_, adjusted_rtt,
       smoothed_rtt_, standing_rtt_, min_rtt_, queueing_delay, lambda_target,
       lambda, cwnd_, ist_);
  LogA(kClassName, __func__, "Conn %" PRIEndptId ": PLT_COPA3 %f %f %f %f %f "
       "%f %f %f %" PRIu32 " %f %0.9f %f %f %f\n", conn_id_,
       CurrentTime(ack_time), adjusted_rtt, smoothed_rtt_, standing_rtt_,
       min_rtt_, queueing_delay, lambda_target, lambda, velocity_, cwnd_,
       ist_, (static_cast<double>(bytes_in_flight_) /
              static_cast<double>(kNominalPktSizeBytes)), ts_delta,
       min_ts_delta_);
#endif
}

//============================================================================
bool Copa3::OnPacketLost(StreamId /* stream_id */, const Time& /* ack_time */,
                         PktSeqNumber /* seq_num */,
                         PktSeqNumber /* cc_seq_num */, uint32_t /* bytes */)
{
  return true;
}

//============================================================================
void Copa3::OnPacketAcked(StreamId /* stream_id */,
                          const Time& /* ack_time */,
                          PktSeqNumber /* seq_num */,
                          PktSeqNumber /* cc_seq_num */,
                          PktSeqNumber /* ne_seq_num */, uint32_t /* bytes */)
{
  return;
}

//============================================================================
void Copa3::OnAckPktProcessingDone(const Time& /* ack_time */)
{
  return;
}

//============================================================================
PktSeqNumber Copa3::OnPacketSent(StreamId stream_id, const Time& send_time,
                                 PktSeqNumber seq_num, uint32_t pld_bytes,
                                 uint32_t /* tot_bytes */, float& cc_val)
{
  // Assign a CC sequence number to the packet.
  PktSeqNumber  cc_seq_num = nxt_cc_seq_num_;
  ++nxt_cc_seq_num_;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "** Conn %" PRIEndptId ": On Send: stream=%"
       PRIStreamId " seq_num=%" PRIPktSeqNumber " cc_seq_num=%"
       PRIPktSeqNumber " send_time=%s size=%" PRIu32 " cc_val=%f\n", conn_id_,
       stream_id, seq_num, cc_seq_num, send_time.ToString().c_str(),
       pld_bytes, static_cast<double>(cc_val));
#endif

  // Store the current congestion window size.
  cc_val = static_cast<float>(cwnd_);

  // Update the damper.
  damper_.OnPktSend(cwnd_);

  // Update the next send time.
  UpdateNextSendTime(send_time, pld_bytes);

  return cc_seq_num;
}

//============================================================================
void Copa3::OnPacketResent(StreamId stream_id, const Time& send_time,
                           PktSeqNumber seq_num, PktSeqNumber cc_seq_num,
                           uint32_t pld_bytes, uint32_t /* tot_bytes */,
                           bool rto, bool orig_cc, float& cc_val)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "** Conn %" PRIEndptId ": On Resend: stream=%"
       PRIStreamId " seq_num=%" PRIPktSeqNumber " cc_seq_num=%"
       PRIPktSeqNumber " send_time=%s size=%" PRIu32 " rto=%d orig_cc=%d "
       "cc_val=%f\n", conn_id_, stream_id, seq_num, cc_seq_num,
       send_time.ToString().c_str(), pld_bytes, static_cast<int>(rto),
       static_cast<int>(orig_cc), static_cast<double>(cc_val));
#endif

  // Store the current congestion window size.
  cc_val = static_cast<float>(cwnd_);

  // Update the damper.
  damper_.OnPktSend(cwnd_);

  // Update the next send time if this is not due to an RTO event.
  if (!rto)
  {
    UpdateNextSendTime(send_time, pld_bytes);
  }
}

//============================================================================
bool Copa3::RequireFastRto()
{
  // If the congestion window size is too small, then use fast RTOs.
  return (cwnd_ < kFastRtoCwndThres);
}

//============================================================================
void Copa3::OnRto(bool /* pkt_rexmit */)
{
  return;
}

//============================================================================
void Copa3::OnOutageEnd()
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Outage is over.\n",
       conn_id_);
#endif

  return;
}

//============================================================================
bool Copa3::CanSend(const Time& /* now */, uint32_t /* bytes */)
{
  // If the congestion window size is greater than the number of bytes in
  // flight, then the sender is not congestion control blocked.
  return ((state_ >= SLOW_START) &&
          ((cwnd_ * (kNominalPktSizeBytes - kDataHdrBaseSize)) >
           bytes_in_flight_));
}

//============================================================================
bool Copa3::CanResend(const Time& /* now */, uint32_t /* bytes */,
                      bool /* orig_cc */)
{
  // Copa3 paces fast retransmissions, so this can just return true.
  return true;
}

//============================================================================
Time Copa3::TimeUntilSend(const Time& now)
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
Capacity Copa3::PacingRate()
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
Capacity Copa3::CapacityEstimate()
{
  return PacingRate();
}

//============================================================================
bool Copa3::GetSyncParams(uint16_t& seq_num, uint32_t& cc_params)
{
  if (report_min_rtt_)
  {
    // Send the encoded local minimum RTT to the peer.
    seq_num   = sync_send_seq_num_++;
    cc_params = next_report_min_rtt_;

    report_min_rtt_           = false;
    prev_report_min_rtt_      = next_report_min_rtt_;
    next_report_min_rtt_time_ = (Time::Now() + Time(kReportMinRttPeriod));

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Sending cc_params=%"
         PRIu16 "\n", conn_id_, cc_params);
#endif

    return true;
  }

  return false;
}

//============================================================================
void Copa3::ProcessSyncParams(const Time& now, uint16_t seq_num,
                              uint32_t cc_params)
{
  if ((cc_params != 0) && CC_SYNC_SEQ_NUM_OK(seq_num, sync_recv_seq_num_))
  {
    sync_recv_seq_num_ = seq_num;

    rmt_min_rtt_      = (static_cast<double>(cc_params & 0xffff) * 0.0001);
    rmt_min_rtt_time_ = now;

    if (loc_min_rtt_ < kHugeRtt)
    {
      min_rtt_ = ((loc_min_rtt_ < rmt_min_rtt_) ? loc_min_rtt_ : rmt_min_rtt_);
    }
    else
    {
      min_rtt_ = rmt_min_rtt_;
    }

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Received cc_params=%"
         PRIu16 " rmt_min_rtt=%f min_rtt_=%f\n", conn_id_, cc_params,
         rmt_min_rtt_, min_rtt_);
#endif

    LogA(kClassName, __func__, "Conn %" PRIEndptId ": Updated min_rtt=%f\n",
         conn_id_, min_rtt_);
  }
}

//============================================================================
void Copa3::ProcessCcPktTrain(const Time& now, CcPktTrainHeader& hdr)
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

  // Copa3 must be in the fast startup state to process the FS_ACK packet.
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
    // estimate.  Note that the second packet in the pair is not used for an
    // RTT estimate because it was delayed by the first packet.
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
bool Copa3::InSlowStart()
{
  // Consider any state other than CLOSED_LOOP as slow start.
  return (state_ != CLOSED_LOOP);
}

//============================================================================
bool Copa3::InRecovery()
{
  // There is no fast recovery in Copa3.
  return false;
}

//============================================================================
uint32_t Copa3::GetCongestionWindow()
{
  // Convert the congestion window size from packets to bytes.
  return (cwnd_ * (kNominalPktSizeBytes - kDataHdrBaseSize));
}

//============================================================================
uint32_t Copa3::GetSlowStartThreshold()
{
  // There is no slow start threshold in Copa3.
  return 0;
}

//============================================================================
CongCtrlAlg Copa3::GetCongestionControlType()
{
  return COPA3_CC;
}

//============================================================================
void Copa3::Close()
{
  return;
}

//============================================================================
double Copa3::CurrentTime(const Time& now)
{
  return ((now - start_time_point_).ToDouble());
}

//============================================================================
void Copa3::UpdateNextSendTime(const Time& now, size_t bytes)
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
void Copa3::ReportMinRttOnUpdate()
{
  // Report the new local minimum RTT to the peer if the new encoded value is
  // different than the last reported encoded value.  The encoded value is the
  // local minimum RTT to the nearest 100 microseconds.
  double  val = ((loc_min_rtt_ * 10000.0) + 0.5);

  if (val >= static_cast<double>(UINT16_MAX))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Minimum RTT %f too "
         "large for CC sync packet.\n", conn_id_, loc_min_rtt_);
    prev_report_min_rtt_ = 0;
  }
  else if (val < 1.5)
  {
    prev_report_min_rtt_ = 0;
  }
  else
  {
    uint16_t  enc_val = static_cast<uint16_t>(val);

    if (report_min_rtt_)
    {
      next_report_min_rtt_ = enc_val;
    }
    else
    {
      if (enc_val != prev_report_min_rtt_)
      {
        report_min_rtt_      = true;
        next_report_min_rtt_ = enc_val;
      }
    }
  }
}

//============================================================================
void Copa3::ReportMinRttOnTimeout(const Time& now)
{
  // The encoded value is the local minimum RTT to the nearest 100
  // microseconds.
  double  val = ((loc_min_rtt_ * 10000.0) + 0.5);

  if (val >= static_cast<double>(UINT16_MAX))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Minimum RTT %f too "
         "large for CC sync packet.\n", conn_id_, loc_min_rtt_);
    prev_report_min_rtt_ = 0;
  }
  else if (val < 1.5)
  {
    prev_report_min_rtt_ = 0;
  }
  else
  {
    report_min_rtt_      = true;
    next_report_min_rtt_ = static_cast<uint16_t>(val);
  }

  next_report_min_rtt_time_ = (now + Time(kReportMinRttPeriod));
}

//============================================================================
void Copa3::SendPktPair(uint8_t first_seq)
{
  // Send two congestion control packet train FS_DATA packets, each having a
  // length equal to the Copa3 nominal data packet size, as fast as possible.
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
void Copa3::SendPktPairAck(uint8_t seq, uint32_t irt_usec)
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
void Copa3::FsPktPairCallback()
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
    // Start the next timer to send kNumFsPairs packet pairs over 2 RTTs.
    Time                  duration((2.0 * (smoothed_rtt_ + kPktPairRttAdj)) /
                                   static_cast<double>(kNumFsPairs));
    CallbackNoArg<Copa3>  callback(this, &Copa3::FsPktPairCallback);

    if (!timer_.StartTimer(duration, &callback, fs_.timer_))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId ": Error starting "
           "packet pair timer.\n", conn_id_);
    }
  }
  else
  {
    // Wait up to twice the kNumFsPairs RTTs, or a maximum of one second, for
    // FS_ACKs from the last packet pair sent.
    double  wait_time = (2.0 * static_cast<double>(kNumFsPairs) *
                         (smoothed_rtt_ + kPktPairRttAdj));

    if (wait_time > 1.0)
    {
      wait_time = 1.0;
    }

    Time                  duration(wait_time);
    CallbackNoArg<Copa3>  callback(this, &Copa3::FsDoneCallback);

    if (!timer_.StartTimer(duration, &callback, fs_.timer_))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId ": Error starting done "
           "timer.\n", conn_id_);
    }
  }
}

//============================================================================
void Copa3::FsDoneCallback()
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
  // is usually very inaccurate in our testing over high speed networks.
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
  smoothed_rtt_ = mean_rtt;
  standing_rtt_ = rtt_min;
  min_rtt_      = rtt_min;
  loc_min_rtt_  = rtt_min;
  cwnd_         = (lambda_target * rtt_min);
  ist_          = (1.0 / lambda_target);

  LogA(kClassName, __func__, "Conn %" PRIEndptId ": Fast startup, rtt_min=%f "
       "rtt_max=%f mean_rtt=%f mu=%f lambda_target=%f smoothed_rtt=%f "
       "standing_rtt=%f min_rtt=%f cwnd=%f ist=%f\n", conn_id_, rtt_min,
       rtt_max, mean_rtt, mu, lambda_target, smoothed_rtt_, standing_rtt_,
       min_rtt_, cwnd_, ist_);

  // The algorithm is now ready for closed loop operation.
  state_ = CLOSED_LOOP;
}
