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

/// \file queue_depth_dynamics.cc, provides an implementation of the class for
/// tracking queue depth changes over a short time period.

#include "queue_depth_dynamics.h"

#include "iron_types.h"
#include "log.h"
#include "packet.h"
#include "unused.h"

#include <inttypes.h>

using ::iron::ConfigInfo;
using ::iron::LatencyClass;
using ::iron::Log;
using ::iron::QueueDepthDynamics;
using ::iron::Time;

/// Returns the next index in the circular buffer. Extracted to a macro to
/// avoid having to do modular arithmetic all over the place.
#define NEXT_QDD_INDEX(current_idx)             \
  ((current_idx + 1) % kNumQDDSegments)

namespace
{
  /// Class name for logging.
  const char*     UNUSED(kClassName)            = "QueueDepthDynamics";

  /// QueueDepthDynamics change rates will be the BytesPerSecond change rate
  /// over the most recent time period of approximately this amount of time.
  /// (It will include at most this amount of time, and at least this amount
  /// of time * (1 - kNumQDDSegments).)
  const Time      kChangeRateResetPeriod = Time(0.3);

  /// We will rotate the circular buffer every 1/kNumQDDSegments sections.
  /// Caching that value here saves time when we call CheckReset().
  const Time      kChangeRateRotatePeriod = kChangeRateResetPeriod.Multiply(
    (double)1/kNumQDDSegments);

  /// How long to wait after the last min_bytes_reset_period_ adjustment
  /// before we next consider increasing the value. Increasing this value will
  /// make us slower to adjust when the network patterns cause spikes and dips
  /// in queue depths. Decreasing this value could make us overshoot so that
  /// we cannot quickly react to network dynamics.
  ///
  /// If dynamic floor estimation is disabled, this value will be ignored.
  const Time      kIncrMinBytesFrequency = Time(0.05);

  /// How long to wait after the last min_bytes_reset_period_ adjustment
  /// before we next consider decreasing the value. Increasing this value will
  /// make us slower to recover after a period with a lot of spikes and dips
  /// in queue depth. Decreasing this value could make us overshoot so that
  /// we cannot properly handle spikes and dips in queue depth..
  ///
  /// If dynamic floor estimation is disabled, this value will be ignored.
  const Time      kDecrMinBytesFrequency = Time(0.3);

  /// How long to wait after the latest zombie has been added before we next
  /// consider decreasing the value. Increasing this value will make us slower
  /// to recover after a period with a lot of spikes and dips in queue
  /// depth. Decreasing this value could make us overshoot so that we cannot
  /// properly handle spikes and dips in queue depth.
  ///
  /// If dynamic floor estimation is disabled, this value will be ignored.
  const Time      kDecrMinBytesTimeSinceZombieSent = Time(2.0);

  /// How much to adjust min_bytes_reset_period_ at a time.
  ///
  /// If dynamic floor estimation is disabled, this value will be ignored.
  const Time      kMinBytesResetPeriodDelta = Time(0.2);
}

//============================================================================
QueueDepthDynamics::QueueDepthDynamics()
    : min_bytes_reset_period_(0),
      min_bytes_rotate_period_(),
      last_changed_min_bytes_period_(0),
      zombie_bytes_last_added_(0),
      dynamic_min_depths_window_(false),
      min_bytes_reset_period_lower_bound_(0),
      min_bytes_reset_period_upper_bound_(0),
      net_bytes_(),
      min_bytes_(),
      zombie_bytes_added_(),
      last_reset_net_(),
      last_reset_min_(),
      current_idx_net_(0),
      current_idx_min_(0),
      initializing_net_(true),
      net_sum_(0),
      overall_min_(std::numeric_limits<uint32_t>::max()),
      total_zombies_added_(0)
{
  for (uint8_t index = 0; index < kNumQDDSegments; index++)
  {
    net_bytes_[index]          = 0;
    zombie_bytes_added_[index] = 0;
    min_bytes_[index]          = std::numeric_limits<uint32_t>::max();
    last_reset_net_[index].GetNow();
  }
  last_reset_min_.GetNow();
  zombie_bytes_last_added_.GetNow();
  last_changed_min_bytes_period_.GetNow();
}

//============================================================================
void QueueDepthDynamics::Initialize(bool dynamic_window,
                                    double initial_window_secs,
                                    double window_lower_bound_secs,
                                    double window_upper_bound_secs)
{
  dynamic_min_depths_window_ = dynamic_window;

  min_bytes_reset_period_    = Time(initial_window_secs);
  min_bytes_rotate_period_   = min_bytes_reset_period_.Multiply(
    (double)1/kNumQDDSegments);

  min_bytes_reset_period_lower_bound_ = Time(window_lower_bound_secs);
  min_bytes_reset_period_upper_bound_ = Time(window_upper_bound_secs);
}

//============================================================================
void QueueDepthDynamics::ProcessBytesAdded(
  uint16_t bytes, LatencyClass lat, uint32_t new_depth)
{
  CheckReset();
  if (std::numeric_limits<int32_t>::max() - bytes <
      net_bytes_[current_idx_net_])
  {
    // Just leave it at the max rate to avoid overflow.
    net_bytes_[current_idx_net_] = std::numeric_limits<int32_t>::max();
  }
  else
  {
    net_bytes_[current_idx_net_] += bytes;
  }
  // This can happen if we haven't had a dequeue since the last reset, so
  // min_bytes is still at its initial maximum value.
  if (new_depth < min_bytes_[current_idx_min_])
  {
    min_bytes_[current_idx_min_] = new_depth;
  }
}

//============================================================================
void QueueDepthDynamics::ProcessZombieBytesAdded(uint16_t bytes, LatencyClass lat)
{
  if (std::numeric_limits<uint32_t>::max() - bytes <
      zombie_bytes_added_[current_idx_min_])
  {
    // Just leave it at the max bytes to avoid overflow.
    zombie_bytes_added_[current_idx_min_] =
      std::numeric_limits<uint32_t>::max();
  }
  else
  {
    zombie_bytes_added_[current_idx_min_] += bytes;
  }
  zombie_bytes_last_added_.GetNow();
}

//============================================================================
void QueueDepthDynamics::BytesRemoved(
  uint16_t bytes, LatencyClass lat, uint32_t new_depth)
{
  CheckReset();
  if (std::numeric_limits<int32_t>::min() + bytes >
      net_bytes_[current_idx_net_])
  {
    // Just leave it at the min rate to avoid overflow.
    net_bytes_[current_idx_net_] = std::numeric_limits<int32_t>::min();
  }
  else
  {
    net_bytes_[current_idx_net_] -= bytes;
  }
  if (new_depth < min_bytes_[current_idx_min_])
  {
    min_bytes_[current_idx_min_] = new_depth;
  }
}

//============================================================================
int32_t QueueDepthDynamics::GetChangeRateBytesPerSec()
{
  if (initializing_net_)
  {
    // Still starting up. Return the max allowed, since we're likely quickly
    // building up a queue during system start up.
    return std::numeric_limits<int32_t>::max();
  }
  // Compute the change rate, which is the net bytes over all segments (all
  // except current is already cached in net_sum_) divided by the time over
  // which these values are valid.
  Time time_diff = Time::Now();
  // The next index in the buffer is currently the oldest.
  Time oldest = last_reset_net_[NEXT_QDD_INDEX(current_idx_net_)];
  if (time_diff <= oldest)
  {
    // This is highly unlikely, if not impossible, since we will be in
    // "intializing_net_" period for a full kChangeRateResetPeriod. However,
    // this extra check removes any possibility of a divide by 0 error.
    return std::numeric_limits<int32_t>::max();
  }
  time_diff = time_diff.Subtract(oldest);
  double rate = static_cast<double>(net_sum_ + net_bytes_[current_idx_net_])
    / time_diff.ToDouble();
  // Truncating is fine. We're not being precise enough to care about a
  // difference of less than one byte.
  return static_cast<int32_t>(rate);
}

//============================================================================
uint32_t QueueDepthDynamics::GetMinQueueDepthBytes()
{
  // NOTE: we don't need an initialization period for min bytes the way we do
  // for change rate, because a minimum makes sense (and isn't skewed) from
  // being a minimum over a short period of time.

  // overall_min_ caches the minimum across all segments except the current
  // one.
  uint32_t min = overall_min_;
  if (min_bytes_[current_idx_min_] < overall_min_)
  {
    min = min_bytes_[current_idx_min_];
  }

  if (min < total_zombies_added_ + zombie_bytes_added_[current_idx_min_])
  {
    // This could be possible if the minimum queue depth decreased AND we
    // added zombies during this period.
    min = 0;
  }
  else
  {
    min -= total_zombies_added_;
    min -= zombie_bytes_added_[current_idx_min_];
  }
  return min;
}

//============================================================================
void QueueDepthDynamics::IncrementMinBytesResetPeriod()
{
  if (!dynamic_min_depths_window_ ||
      (Time::Now() - last_changed_min_bytes_period_ < kIncrMinBytesFrequency))
  {
    return;
  }
  if (min_bytes_reset_period_ + kMinBytesResetPeriodDelta >=
      min_bytes_reset_period_upper_bound_)
  {
    min_bytes_reset_period_ = min_bytes_reset_period_upper_bound_;
  }
  else
  {
    min_bytes_reset_period_ += kMinBytesResetPeriodDelta;
  }
  min_bytes_rotate_period_ = min_bytes_reset_period_.Multiply(
    (double)1/kNumQDDSegments);
  last_changed_min_bytes_period_.GetNow();
}

//============================================================================
void QueueDepthDynamics::DecrementMinBytesResetPeriod()
{
  if (!dynamic_min_depths_window_)
  {
    return;
  }
  Time now = Time::Now();
  if ((now - last_changed_min_bytes_period_ < kDecrMinBytesFrequency)
      || (now - zombie_bytes_last_added_ < kDecrMinBytesTimeSinceZombieSent))
  {
    return;
  }
  if (min_bytes_reset_period_ - kMinBytesResetPeriodDelta <=
      min_bytes_reset_period_lower_bound_)
  {
    min_bytes_reset_period_ = min_bytes_reset_period_lower_bound_;
  }
  else
  {
    min_bytes_reset_period_ = min_bytes_reset_period_ -
      kMinBytesResetPeriodDelta;
  }
  min_bytes_rotate_period_ = min_bytes_reset_period_.Multiply(
    (double)1/kNumQDDSegments);
  last_changed_min_bytes_period_.GetNow();
}

//============================================================================
void QueueDepthDynamics::CheckReset()
{
  Time now = Time::Now();
  // Reset and move the circular buffer along once every 1/kNumQDDSegments
  // seconds.
  if (now - last_reset_net_[current_idx_net_] > kChangeRateRotatePeriod)
  {
    if (current_idx_net_ == kNumQDDSegments - 1)
    {
      // We've now filled up an entire buffer. We have sufficient data to
      // start returning it.
      initializing_net_ = false;
    }
    uint8_t next_idx = NEXT_QDD_INDEX(current_idx_net_);
    // Update the cached sum, since we'll have a new current segment to be
    // excluded.
    net_sum_ += (net_bytes_[current_idx_net_] - net_bytes_[next_idx]);
    current_idx_net_ = next_idx;
    net_bytes_[current_idx_net_] = 0;
    last_reset_net_[current_idx_net_] = now;
  }

  if (now - last_reset_min_ > min_bytes_rotate_period_)
  {
    uint8_t next_idx = NEXT_QDD_INDEX(current_idx_min_);
    // Update the cached sum, since we'll have a new current segment to be
    // excluded.
    total_zombies_added_ +=
      (zombie_bytes_added_[current_idx_min_] - zombie_bytes_added_[next_idx]);
    current_idx_min_ = next_idx;
    min_bytes_[current_idx_min_] = std::numeric_limits<uint32_t>::max();
    zombie_bytes_added_[current_idx_min_] = 0;

    // Update the cached minimum, since we'll have a new current segment to be
    // excluded.
    overall_min_ = std::numeric_limits<uint32_t>::max();
    for (uint8_t idx = NEXT_QDD_INDEX(current_idx_min_);
         idx != current_idx_min_;
         idx = NEXT_QDD_INDEX(idx))
    {
      if (min_bytes_[idx] < overall_min_)
      {
        overall_min_ = min_bytes_[idx];
      }
    }
    last_reset_min_ = now;
  }
}
