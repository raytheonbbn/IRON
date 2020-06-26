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

#include "throttled_release_controller.h"
#include "decoding_state.h"
#include "unused.h"

using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::Time;

namespace
{
  /// Class name for logging.
  const char*  UNUSED(kClassName) = "ThrottledReleaseController";

  /// The default technique used for tracking traversal time.
  const TraversalTracking kDefaultTraversalTracking = AVG_TT;

  /// The maximum latency in the release queue. This is only used
  /// for traversal tracking with bursts. If the latency in the release
  /// queue exceeds this, a burst of packets is emitted to reduce the
  /// latency in the release queue to half this value.
  const uint16_t  kDefaultMaxExitLatencyMs = 100;

  /// The weight applied to the current traversal time when tracking
  /// the average traversal time.
  const double    kDefaultCurTtWeight = 0.1;

  /// If the timestamp wrapped, this value should be added.
  /// The timestamp is 15 bits long, so and overflow will mean
  /// the 16th bit should be 1.
  const uint16_t  kTimestampOverflow = 0x8000;
}

//============================================================================
ThrottledReleaseController::ThrottledReleaseController(
  DecodingState& decoding_state, iron::PacketPool& packet_pool)
    : ReleaseController(decoding_state),
      packet_pool_(packet_pool),
      release_pkts_queue_(packet_pool_),
      traversal_time_(0),
      last_origin_ts_ms_(iron::kUnsetOriginTs),
      origin_rollover_ms_(0),
      tracking_(kDefaultTraversalTracking)
{
  release_pkts_queue_.SetQueueLimits(1000);
}

//============================================================================
ThrottledReleaseController::~ThrottledReleaseController()
{
  // Nothing to destroy. The packets that are currently in the Queue will be
  // recycled by the Queue class.
}

//============================================================================
void ThrottledReleaseController::SvcEvents(Time& now)
{
  int64_t now_ms = now.GetTimeInMsec();
  while (release_pkts_queue_.GetCount())
  {
    Packet* next_pkt = release_pkts_queue_.Peek();

    int64_t origin_ts = next_pkt->origin_ts_ms();
    if (origin_ts <= last_origin_ts_ms_)
    {
      origin_ts +=  origin_rollover_ms_;
    }

    if ((origin_ts + traversal_time_) <= now_ms)
    {
      Packet* pkt = release_pkts_queue_.Dequeue();
      if (!pkt)
      {
        LogD(kClassName, __func__, "No packets in queue to be released.\n");
        break;
      }
      size_t  bytes_sent = decoding_state_.ReleasePkt(pkt);

      if (bytes_sent == 0)
      {
        packet_pool_.Recycle(pkt);
        break;
      }
      LogD(kClassName, __func__, "Bytes sent: %zu, mtt:%" PRId64 "\n",
                                 bytes_sent, traversal_time_);
    }
    else
    {
      break;
    }
  }
}

//============================================================================
bool ThrottledReleaseController::HandlePkt(Packet* pkt)
{

  uint16_t origin_ts_ms = pkt->origin_ts_ms();
  if (origin_ts_ms != iron::kUnsetOriginTs)
  {
    Time now = Time::Now();
    if ((origin_ts_ms < last_origin_ts_ms_) &&
        (last_origin_ts_ms_ != iron::kUnsetOriginTs))
    {
      LogD(kClassName, __func__, "Origin time rollover\n");
      origin_rollover_ms_ += kTimestampOverflow;
    }

    int64_t traversal_time = now.GetTimeInMsec() -
                             (origin_rollover_ms_ + origin_ts_ms);
    if (tracking_ == MAX_TT)
    {
      if (traversal_time > traversal_time_)
      {
        traversal_time_ = traversal_time;
        LogD(kClassName, __func__, "Increase in  max transmission time: %"
                                    PRId64"\n", traversal_time );
      }
    }
    else if (tracking_ == AVG_TT)
    {
      // Track the windowed exponential average of the traversal time.
      traversal_time_ = (1 - kDefaultCurTtWeight)*traversal_time_ +
                        kDefaultCurTtWeight*traversal_time;
    }
    else if (tracking_ == BURST)
    {
      if (traversal_time > traversal_time_)
      {
        traversal_time_ = traversal_time;
        LogD(kClassName, __func__, "Increase in  max transmission time: %"
                                    PRId64"\n", traversal_time );
      }

      Packet* next_pkt              = release_pkts_queue_.Peek();
      if (NULL != next_pkt)
      {
        uint16_t next_origin_ts_ms    = next_pkt->origin_ts_ms();
        uint32_t current_exit_latency = 0;

        // Note: if subtracting two unsigned values would result in a
        // negative number, the result is the negative number modulo MAX+1,
        // which is the same as "counting backwards" around the ring of
        // unsigned values. By casting the result to a signed value of
        // the same size and comparing to 0, we are examining the most
        // significant digit in the result, which is essentially checking
        // whether or not the distance (in the ring) is greater
        // than or equal to 0x8000 (2^15).
        if ((int16_t)(origin_ts_ms - next_origin_ts_ms) <= 0)
        {
          // If the new timestamp is less that the previous timestamp, and
          // packets are in order, then the timestamp must have overflowed.
          // The timestamp is 15 bits long, so we add the 16th bit to
          // account for the overflow.
          current_exit_latency = kTimestampOverflow + origin_ts_ms -
                                 next_origin_ts_ms;
        }
        else
        {
          current_exit_latency = origin_ts_ms - next_origin_ts_ms;
        }
        if (current_exit_latency > kDefaultMaxExitLatencyMs)
        {
          // There is a lot of latency added by packets waiting to exit,
          // so adjust the traversal time such that a burst will be sent to
          // reduce the latency.
          int64_t new_traversal_time  = traversal_time_/2;
          LogD(kClassName, __func__, "Current release latency: %" PRIu16
               "adjusting traversal time from %" PRId64 " to %" PRId64 ".\n",
               current_exit_latency, traversal_time_, new_traversal_time);
          traversal_time_ = new_traversal_time;
        }
      }
    }
    else
    {
      LogF(kClassName, __func__, "Undefined traversal tracking technique.\n");
    }
  }
  last_origin_ts_ms_ = origin_ts_ms;

  return release_pkts_queue_.Enqueue(pkt);
}
