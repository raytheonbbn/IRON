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

#include "debugging_stats.h"
#include "log.h"
#include "unused.h"

#include <sstream>

#include <inttypes.h>
#include <unistd.h>


using ::iron::DebuggingStats;
using ::iron::Log;
using ::iron::Time;
using ::std::map;
using ::std::string;


namespace
{
  const char*  UNUSED(kClassName)    = "DebuggingStats";
  const Time   kStatInterval         = Time(1);
}

//============================================================================
DebuggingStats::DebuggingStats()
    : num_stats_(0),
      num_instant_stats_(0),
      stat_index_map_(),
      recent_vals_(),
      stats_(),
      instant_stats_()
{
  LogA(kClassName, __func__, "STARTTIME = %" PRIu64 "\n", Time::GetNowInUsec());
}

//============================================================================
DebuggingStats::~DebuggingStats()
{
  LogStats();
  LogD(kClassName, __func__, "Debugging stats removed.\n");
}

//============================================================================
void DebuggingStats::TrackStat(const char* name, uint64_t value)
{
  uint16_t index = GetStatIndex(name, false);
  if (recent_vals_[index].done_)
  {
    return;
  }
  Time     now   = Time::Now();
  // First check whether it's time to record the next bundle.
  // If we haven't set the period start time yet, then it's not time to move
  // on - this allows us to use item 0 (otherwise we'd skip over it, since it
  // never had it's start time set).
  if (!recent_vals_[index].period_start_time_.IsZero()
      && now > recent_vals_[index].period_start_time_ + kStatInterval)
  {
    if (stats_[index].num_items_== kMaxItems)
    {
      recent_vals_[index].done_ = true;
      return;
    }
    else
    {
      uint16_t item = stats_[index].num_items_;
      stats_[index].num_items_++;
      stats_[index].items_[item].set_vals(recent_vals_[index]);
      recent_vals_[index].Clear(now);
    }
  }
  if (recent_vals_[index].period_start_time_.IsZero())
  {
    recent_vals_[index].period_start_time_ = now;
  }
  recent_vals_[index].total_ += value;
  recent_vals_[index].count_++;
  if (value < recent_vals_[index].min_)
  {
    recent_vals_[index].min_ = value;
  }
  if (value > recent_vals_[index].max_)
  {
    recent_vals_[index].max_ = value;
  }
}

//============================================================================
void DebuggingStats::CountOccurrences(const char* name, Time period)
{
  uint16_t index = GetStatIndex(name, false);
  if (recent_vals_[index].done_)
  {
    return;
  }

  recent_vals_[index].count_ = 1;
  Time     now   = Time::Now();
  // First check whether it's time to record the next bundle.
  // If we haven't set the period start time yet, then it's not time to move
  // on - this allows us to use item 0 (otherwise we'd skip over it, since it
  // never had it's start time set).
  if (!recent_vals_[index].period_start_time_.IsZero()
      && now > recent_vals_[index].period_start_time_ + period)
  {
    if (stats_[index].num_items_== kMaxItems)
    {
      recent_vals_[index].done_ = true;
      return;
    }
    else
    {
      uint16_t item = stats_[index].num_items_;
      stats_[index].num_items_++;
      stats_[index].items_[item].set_vals(recent_vals_[index]);
      recent_vals_[index].Clear(now);
      recent_vals_[index].min_ = 0;
    }
  }
  if (recent_vals_[index].period_start_time_.IsZero())
  {
    recent_vals_[index].period_start_time_ = now;
  }
  recent_vals_[index].total_++;
  recent_vals_[index].min_++;
  recent_vals_[index].max_++;
}

//============================================================================
void DebuggingStats::TrackInstant(const char* name, uint64_t value,
                                  uint64_t collection_len_usec)
{
  uint16_t index        = GetStatIndex(name, true);
  uint64_t now_usec     = Time::GetNowInUsec();
  if (instant_stats_[index].start_time_usec_ == 0)
  {
    instant_stats_[index].start_time_usec_ = now_usec;
    instant_stats_[index].collection_usec_ = collection_len_usec;
  }

  // collection length of 0 implies just fill the values.
  if (collection_len_usec == 0 &&
      instant_stats_[index].num_instants_ == kMaxVals)
  {
    // Done collecting this stat.
    return;
  }

  if (collection_len_usec > 0 &&
      (now_usec - instant_stats_[index].start_time_usec_ >
       instant_stats_[index].collection_usec_))
  {
    // Done collecting this stat.
    return;
  }

  uint16_t num_instants = instant_stats_[index].num_instants_;

  // Now find the current instant to write or replace.
  num_instants = num_instants % kMaxVals;
  instant_stats_[index].times_[num_instants] = now_usec;
  instant_stats_[index].values_[num_instants] = value;
  instant_stats_[index].num_instants_++;
}

//============================================================================
void DebuggingStats::LogInstant(const char* name, int64_t value)
{
  LogA(kClassName, __func__, "%s, %" PRIu64 ", val: %" PRId32 "\n",
       name,
       Time::GetNowInUsec(),
       value);
}

//============================================================================
void DebuggingStats::LogStats()
{
  for (uint16_t index = 0; index < num_instant_stats_; index++)
  {
    const char* UNUSED(name)  = instant_stats_[index].name_.c_str();
    for (uint16_t val = 0;
         val < instant_stats_[index].num_instants_ && val < kMaxVals;
         val++)
    {
      LogA(kClassName, __func__,
           "%s, %" PRIu64 ", val: %" PRIu64 "\n",
           name,
           instant_stats_[index].times_[val],
           instant_stats_[index].values_[val]);
    }
  }
  for (uint16_t index = 0; index < num_stats_; index++)
  {
    uint64_t    total         = 0.;
    const char* UNUSED(name)  = stats_[index].name_.c_str();

    stats_[index].items_[stats_[index].num_items_].set_vals(recent_vals_[index]);
    stats_[index].num_items_++;
    for (uint16_t item = 0; item < stats_[index].num_items_; item++)
    {
      total += stats_[index].items_[item].max_;
      LogA(kClassName, __func__,
           "%s, %" PRIu64 ", avg: %f, min: %" PRIu64 ", max: %" PRIu64 "\n",
           name,
           stats_[index].items_[item].start_time_usec_,
           stats_[index].items_[item].average_,
           stats_[index].items_[item].min_,
           stats_[index].items_[item].max_);
    }
    if (recent_vals_[index].count_ == 1)
    {
      LogA(kClassName, __func__,
           "%s, Num: %" PRIu64 ".\n", name, total);
    }
  }
}

//============================================================================
uint16_t DebuggingStats::GetStatIndex(const char* name, bool instant)
{
  string sname = string(name);
  uint16_t index = kMaxStats - 1;
  std::map<string, uint16_t>::iterator it =
    stat_index_map_.find(sname);

  if (it != stat_index_map_.end())
  {
    index = (*it).second;
  }
  else if (instant)
  {
    if (num_instant_stats_ == kMaxStats)
    {
      LogW(kClassName, __func__, "Too many instant statistics (%" PRIu16 ") "
           "Trying to add %s.\n", num_instant_stats_, name);
    }
    else
    {
      index = num_instant_stats_;
      ++num_instant_stats_;
      stat_index_map_[sname] = index;
      instant_stats_[index].name_ = sname;
      LogD(kClassName, __func__, "Instant stats index %" PRIu16
           " maps to %s.\n", index, name);
    }
  }
  else
  {
    if (num_stats_ == kMaxStats)
    {
      LogW(kClassName, __func__, "Too many amortized statistics (%" PRIu16 ") "
           "Trying to add %s.\n", num_stats_, name);
    }
    else
    {
      index = num_stats_;
      ++num_stats_;
      stat_index_map_[sname] = index;
      stats_[index].name_ = sname;
      LogD(kClassName, __func__, "Stats index %" PRIu16 " maps to %s.\n",
           index, name);
    }
  }
  return index;
}
