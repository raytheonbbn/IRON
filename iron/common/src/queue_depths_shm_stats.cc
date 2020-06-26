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

#include "queue_depths_shm_stats.h"

#include "queue_depths.h"
#include "log.h"
#include "itime.h"

#include <sstream>

#include <cstring>
#include <inttypes.h>
#include <limits>

using ::iron::QueueDepths;
using ::iron::QueueDepthsShmStats;
using ::std::string;

namespace
{
  const char      kClassName[] = "QueueDepthsShmStats";
}

//============================================================================
QueueDepthsShmStats::QueueDepthsShmStats(BinMap& bin_map)
    : bin_map_(bin_map),
      last_shared_values_(),
      max_val_since_write_(),
      min_val_since_write_(),
      last_write_time_(0),
      first_change_time_(0),
      max_delta_(0),
      max_outside_range_(0),
      max_stale_time_(0),
      total_delta_(0),
      total_outside_range_(0),
      total_stale_time_(0),
      num_write_periods_(0)
{
  // TODO: These initializations should be inside of an Initialize() method,
  // not the constructor, as they can fail.
  if (!last_shared_values_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize last shared values "
         "array.\n");
  }
  last_shared_values_.Clear(0);

  if (!max_val_since_write_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize maximum value since "
         "write array.\n");
  }
  max_val_since_write_.Clear(0);

  if (!min_val_since_write_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize minimum value since "
         "write array.\n");
  }
  min_val_since_write_.Clear(0);
}

//============================================================================
QueueDepthsShmStats::~QueueDepthsShmStats()
{
}

//============================================================================
void QueueDepthsShmStats::DepthChanged(BinIndex idx, uint32_t new_depth)
{
  Time now = Time::Now();
  if (new_depth > max_val_since_write_[idx])
  {
    max_val_since_write_[idx] = new_depth;
  }
  if (new_depth < min_val_since_write_[idx])
  {
    min_val_since_write_[idx] = new_depth;
  }
  if (last_write_time_ > first_change_time_)
  {
    // This was our first change since the last write was performed.
    first_change_time_ = now;
  }
}

//============================================================================
void QueueDepthsShmStats::ValuesShared(const QueueDepths* shared_vals)
{
  Time now = Time::Now();

  if (first_change_time_ > last_write_time_)
  {
    // There were changes since the last write. Process them.

    // Delta is used to track the biggest change since the last write.
    uint32_t delta = 0;
    // Outside_range, range_max and range_min are used to track biggest delta
    // from the previous-to-current range.
    uint32_t outside_range = 0;
    // We want 0s for all multicast bins, but we still want a complete array.
    BinIndex  idx = kInvalidBinIndex;
    for (bool idx_valid = bin_map_.GetFirstBinIndex(idx);
         idx_valid;
         idx_valid = bin_map_.GetNextBinIndex(idx))
    {
      uint32_t new_val = 0;
      if (!bin_map_.IsMcastBinIndex(idx))
      {
        new_val = shared_vals->GetBinDepthByIdx(idx);
      }
      uint32_t range_max = new_val;
      uint32_t range_min = new_val;
      if (last_shared_values_[idx] > range_max)
      {
        range_max = last_shared_values_[idx];
      }
      else
      {
        range_min = last_shared_values_[idx];
      }

      if (max_val_since_write_[idx] > last_shared_values_[idx])
      {
        uint32_t diff = max_val_since_write_[idx] -
          last_shared_values_[idx];
        if (diff > delta)
        {
          delta = diff;
        }
      }
      if (min_val_since_write_[idx] < last_shared_values_[idx])
      {
        uint32_t diff = last_shared_values_[idx] -
          min_val_since_write_[idx];
        if (diff > delta)
        {
          delta = diff;
        }
      }
      if (max_val_since_write_[idx] > range_max)
      {
        uint32_t diff = max_val_since_write_[idx] - range_max;
        if (diff > outside_range)
        {
          outside_range = diff;
        }
      }
      if (min_val_since_write_[idx] < range_min)
      {
        uint32_t diff = range_min - min_val_since_write_[idx];
        if (diff > outside_range)
        {
          outside_range = diff;
        }
      }
      last_shared_values_[idx] = new_val;
    }
    if (delta > max_delta_)
    {
      max_delta_ = delta;
    }
    if (outside_range > max_outside_range_)
    {
      max_outside_range_ = outside_range;
    }
    Time stale_time = first_change_time_ - last_write_time_;
    if (stale_time > max_stale_time_)
    {
      max_stale_time_ = stale_time;
    }
    uint32_t maxval = std::numeric_limits<uint32_t>::max();
    // Assuming we won't rollover the time, since Time is able
    // to store seconds since epoch, and there's no way the total stale
    // time can exceed that.
    if (maxval - delta < total_delta_
        || maxval - outside_range < total_outside_range_)
    {
      // Refresh stats to avoid a rollover.
      LogI(kClassName, __func__,
           "Shared Memory averages rolling over.\n%s\n",
           ToString().c_str());
      total_delta_ = 0;
      total_outside_range_ = 0;
      total_stale_time_.Zero();
      num_write_periods_ = 0;
    }

    total_delta_              += delta;
    total_outside_range_      += outside_range;
    total_stale_time_         += stale_time;
  }
  last_write_time_ = now;
  ++num_write_periods_;
}

//============================================================================
string QueueDepthsShmStats::ToString() const
{
  std::stringstream  ret_ss;

  ret_ss << "Printing queue depth shared memory statistics \n";
  ret_ss << "\tmax delta from last written:           "
         << max_delta_ << "\n";
  ret_ss << "\tmax delta from current-previous range: "
         << max_outside_range_ << "\n";
  ret_ss << "\tmax stale time:                        "
         << max_stale_time_.ToString() << " \n";

  double  avg_delta = 0.0;
  if (num_write_periods_ > 0)
  {
    avg_delta = (static_cast<double>(total_delta_) /
                 static_cast<double>(num_write_periods_));
  }

  ret_ss << "\tavg delta from last written:           "
         << avg_delta << "\n";

  avg_delta = 0.0;
  if (num_write_periods_ > 0)
  {
    avg_delta = (static_cast<double>(total_outside_range_) /
                 static_cast<double>(num_write_periods_));
  }

  ret_ss << "\tavg delta from current-previous range: "
         << avg_delta << "\n";

  avg_delta = 0.0;
  if (num_write_periods_ > 0)
  {
    // It's possible (though very unlikely) that this cast will lose some
    // information. However, we don't need these stats to be precise, so
    // ignore that corner case for now.
    avg_delta = (static_cast<double>(total_stale_time_.GetTimeInUsec()) /
                 static_cast<double>(num_write_periods_));
  }

  ret_ss << "\tavg stale time:                        "
         << avg_delta << " usec\n";

  return ret_ss.str();
}
