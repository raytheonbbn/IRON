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

#include "sliq_cc_hybrid_slow_start.h"

#include "sliq_private_defs.h"

#include "log.h"
#include "unused.h"

#include <inttypes.h>


using ::sliq::HybridSlowStart;
using ::iron::Log;
using ::iron::Time;


namespace
{
  /// Class name for logging.
  const char*     UNUSED(kClassName) = "HybridSlowStart";

  /// The minimum congestion window size, in packets, for leaving slow start.
  const size_t    kHybridStartLowWindow = 16;

  /// Number of delay (RTT) samples for detecting the increase of delay.
  const uint32_t  kHybridStartMinSamples = 8;

  /// Exit slow start if the minimum RTT has increased by more than 1/8th.
  const int       kHybridStartDelayFactorExp = 3;

  // Note that the original paper specifies 2 msec and 8 msec, but those have
  // changed over time.  Use 4 msec and 16 msec.

  /// The hybrid start delay minimum threshold, in microseconds.
  const int64_t   kHybridStartDelayMinThresholdUs = 4000;

  /// The hybrid start delay maximum threshold, in microseconds.
  const int64_t   kHybridStartDelayMaxThresholdUs = 16000;
}

//============================================================================
HybridSlowStart::HybridSlowStart(EndptId conn_id)
    : conn_id_(conn_id),
      started_(false),
      hystart_found_(NOT_FOUND),
      last_sent_seq_num_(0),
      end_seq_num_(0),
      rtt_sample_count_(0),
      current_min_rtt_()
{
}

//============================================================================
HybridSlowStart::~HybridSlowStart()
{
}

//============================================================================
void HybridSlowStart::OnPacketAcked(PktSeqNumber acked_seq_num,
                                    bool in_slow_start)
{
  // OnPacketAcked() gets invoked after ShouldExitSlowStart() (which is called
  // from within OnRttUpdate()), so it's best to end the RTT round when the
  // final packet of the burst is received and start it on the next incoming
  // ACK.
  if (in_slow_start && IsEndOfRound(acked_seq_num))
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": End of hybrid slow "
         "start round, seq %" PRIPktSeqNumber ".\n", conn_id_, acked_seq_num);
#endif

    started_ = false;
  }
}

//============================================================================
bool HybridSlowStart::ShouldExitSlowStart(Time latest_rtt, Time min_rtt,
                                          size_t cwnd_pkts)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args latest_rtt %s "
       "min_rtt %s cwnd %zu\n", conn_id_, latest_rtt.ToString().c_str(),
       min_rtt.ToString().c_str(), cwnd_pkts);
#endif

  if (!started_)
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Start of hybrid slow "
         "start round.\n", conn_id_);
#endif

    // Time to start the hybrid slow start.
    StartReceiveRound();
  }

  if (hystart_found_ != NOT_FOUND)
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Exit slow start, RTT "
         "increase was found previously.\n", conn_id_);
#endif

    return true;
  }

  // Second detection parameter - delay increase detection.  Compare the
  // minimum delay (current_min_rtt_) of the current burst of packets relative
  // to the minimum delay during the session.
  //
  // Note: we only look at the first few(8) packets in each burst, since we
  // only want to compare the lowest RTT of the burst relative to previous
  // bursts.
  rtt_sample_count_++;

  if (rtt_sample_count_ <= kHybridStartMinSamples)
  {
    if (current_min_rtt_.IsZero() || (current_min_rtt_ > latest_rtt))
    {
      current_min_rtt_ = latest_rtt;

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Update "
           "current_min_rtt_ %s.\n", conn_id_,
           current_min_rtt_.ToString().c_str());
#endif
    }
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Updated rtt_sample_cnt %"
       PRIu32 " current_min_rtt %s.\n", conn_id_, rtt_sample_count_,
       current_min_rtt_.ToString().c_str());
#endif

  // We only need to check this once per RTT round.
  if (rtt_sample_count_ == kHybridStartMinSamples)
  {
    // Divide min_rtt by 8 to get an RTT increase threshold for exiting.
    int64_t  min_rtt_increase_threshold_us =
      (min_rtt.GetTimeInUsec() >> kHybridStartDelayFactorExp);

    // Ensure the RTT threshold is never less than 2ms or more than 16ms.
    min_rtt_increase_threshold_us =
      ((min_rtt_increase_threshold_us < kHybridStartDelayMaxThresholdUs) ?
       min_rtt_increase_threshold_us : kHybridStartDelayMaxThresholdUs);

    Time  min_rtt_increase_threshold =
      Time::FromUsec((min_rtt_increase_threshold_us >
                      kHybridStartDelayMinThresholdUs) ?
                     min_rtt_increase_threshold_us :
                     kHybridStartDelayMinThresholdUs);

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Min samples reached,"
         " min_rtt_increase_threshold_us %" PRIu64
         " min_rtt_increase_threshold %s current_min_rtt_ %s\n", conn_id_,
         min_rtt_increase_threshold_us,
         min_rtt_increase_threshold.ToString().c_str(),
         current_min_rtt_.ToString().c_str());
#endif

    // If the RTT has increased enough, then record that this has occurred.
    if (current_min_rtt_ > min_rtt.Add(min_rtt_increase_threshold))
    {
#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Hystart has been "
           "found, RTT increase detected, %s > %s.\n", conn_id_,
           current_min_rtt_.ToString().c_str(),
           min_rtt.Add(min_rtt_increase_threshold).ToString().c_str());
#endif

      hystart_found_= DELAY;
    }
  }

  // Exit from slow start if the cwnd is greater than 16 and increasing delay
  // (RTT) is found.
  bool  exit_ss = ((cwnd_pkts >= kHybridStartLowWindow) &&
                   (hystart_found_ != NOT_FOUND));

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Testing, cwnd %zu "
       "low_win %zu hystart_found %d result %d\n", conn_id_, cwnd_pkts,
       kHybridStartLowWindow, static_cast<int>(hystart_found_),
       static_cast<int>(exit_ss));
#endif

  return exit_ss;
}

//============================================================================
void HybridSlowStart::Restart()
{
  started_       = false;
  hystart_found_ = NOT_FOUND;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Restart.\n", conn_id_);
#endif
}

//============================================================================
void HybridSlowStart::StartReceiveRound()
{
  // Record the last data packet we have sent as the end data packet we are
  // waiting to be ACKed, and reset the RTT state.
  started_          = true;
  end_seq_num_      = last_sent_seq_num_;
  rtt_sample_count_ = 0;
  current_min_rtt_.Zero();
}

//============================================================================
bool HybridSlowStart::IsEndOfRound(PktSeqNumber acked_seq_num) const
{
  // The RTT round ends when the ACK packet sequence number is equal to the
  // end sequence number.
  return SEQ_LEQ(end_seq_num_, acked_seq_num);
}
