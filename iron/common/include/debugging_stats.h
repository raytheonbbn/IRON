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

///
/// Class used to collect and store various statistics.
///


#ifndef IRON_COMMON_DEBUGGING_STATS_H
#define IRON_COMMON_DEBUGGING_STATS_H

#include "itime.h"

#include <cstring>
#include <inttypes.h>
#include <stdint.h>

namespace iron
{

  /// \brief Class for maintaining statistics in memory and logging during
  /// shut down.
  ///
  /// To track a statistic (average, min, max over short periods of time),
  /// just add a call to "TrackStat" with a unique name and the current
  /// value. Values are collected in memory in CurrentDataItem
  /// structures (there is one structure for each collected statistic). Once
  /// every kStatInterval time intervals, these are converted to an
  /// avg/min/max value and stored in StatDataItem structures (one structure
  /// stored for each statistic, for each time interval). The values are
  /// printed during shut down.
  ///
  /// To track all values of a data item over a short period of time (for
  /// instance, to track variability in a value), add a call to "TrackInstant"
  /// with a unique name, the current value, and the maximum time into the
  /// experiment when we should collect this statistic. The kMaxVals values
  /// leading up to the specified time into the experiment will be stored in
  /// an InstantStatData structure. There is one such structure for each
  /// statistic being collected. Values will be replaced until we hit the
  /// specified time for that statistic, and will be printed during shut down.
  class DebuggingStats
  {

   public:

    /// \brief Default constructor.
    DebuggingStats();

    /// \brief Destructor.
    virtual ~DebuggingStats();

    /// \brief Track the current value of the named statistic for
    /// amortization.
    ///
    /// This stat will be amortized over time intervals with one log statement
    /// per interval.
    ///
    /// \param  name    A unique name for this statistic.
    /// \param  value   The current value of this statistic.
    void TrackStat(const char* name, uint64_t value);

    /// \brief Count how many times something happens during the amortization
    /// period.
    ///
    /// \param  name    A unique name for this statistic.
    /// \param  period  How often we should reset the counter. Applies to
    ///                 resetting the previous period, if we're call this with
    ///                 the same name but different periods.
    void CountOccurrences(const char* name, Time period);

    /// \brief Track the current value of the named statistic without
    /// amortization.
    ///
    /// All values of this stat will be logged (until the array is filled).
    ///
    /// \param  name    A unique name for this statistic.
    /// \param  value   The current value of this statistic.
    /// \param  collection_len_usec After how many seconds (from start time)
    ///         should we stop collecting this stat? Ignored after the first
    ///         call for this stat. If 0, this will collect at the start of
    ///         the experiment until we have the max number of values.
    void TrackInstant(const char* name, uint64_t value,
                      uint64_t collection_len_usec);

    /// \brief Instantly log the current value of the named statistic.
    ///
    /// This is useful to log values in the same format as the LogStats()
    /// function, so that the same script can be used to plot all changes to a
    /// value.
    ///
    /// This function is static so that it can be used even without access to
    /// a DebuggingStats object.
    ///
    /// \param  name    A unique name for this statistic.
    /// \param  value   The current value of this statistic. This is a signed
    ///                 value to make it more flexible.
    static void LogInstant(const char* name, int64_t value);

    /// \brief Logs the statistics table.
    void LogStats();


   private:
    /// Maximum number of statistic periods (amortized stats) in each table.
    static const uint16_t            kMaxItems = 300;

    /// Maximum number of stored statistic values for each instant stat.
    static const uint16_t            kMaxVals = 10000;

    /// Once kMaxVals of an instant stat have been collected, go back and
    /// replace the oldest values with new ones until we've seen this many
    /// values. This will allow us to replace the earliest values in a test
    /// run to remove start up variability when debugging.
    static const uint16_t            kInstantsCycleUntil = 30000;

    /// Struct for tracking the stats as they arrive. These will be
    /// transferred into StatDataItem entries after an amortization period is
    /// over.
    struct CurrentDataItem
    {
      /// Running total (used for averaging).
      uint64_t total_;
      /// Number of tracks (used for averaging).
      uint32_t count_;
      /// Min amount during this period.
      uint64_t min_;
      /// Max amount during this period.
      uint64_t max_;
      /// True if we won't have space to store this stat, and thus should skip
      /// any tracking.
      bool     done_;
      /// Time when we started the fresh CurrentDataItem (so we know when to
      /// transfer to a StatDataItem and start again).
      Time     period_start_time_;

      /// Constructor
      CurrentDataItem():
        total_(0),
        count_(0),
        min_(std::numeric_limits<uint64_t>::max()),
        max_(0),
        done_(false),
        period_start_time_(0) {};

      /// Clears the entry. Called after we transfer this to a StatDataItem.
      ///
      /// \param now Time when we're clearing this.
      inline void Clear(Time now)
      {
        total_ = 0;
        count_ = 0;
        min_ = std::numeric_limits<uint64_t>::max();
        max_ = 0;
        period_start_time_ = now;
      };
    };

    /// Struct for storing amortized data for a single time period.
    struct StatDataItem
    {
      /// Average value over the time period.
      double   average_;
      /// Minimum value over the time period.
      uint64_t min_;
      /// Maximum value over the time period.
      uint64_t max_;
      /// Time when the period starting.
      uint64_t start_time_usec_;

      /// Constructor
      StatDataItem(): average_(0), min_(0), max_(0), start_time_usec_(0) {};

      /// Transfer values from a CurrentDataItem into this.
      ///
      /// \param item Where to get the values.
      inline void set_vals(CurrentDataItem item)
      {
        if (item.count_ != 0)
        {
          average_         = static_cast<double>(item.total_) / item.count_;
          min_             = item.min_;
          max_             = item.max_;
          start_time_usec_ = item.period_start_time_.GetTimeInUsec();
        }
      };
    };

    /// Struct for storing all the StatDataItems for a given statistic.
    struct StatData
    {
      /// The unique name for this stat.
      std::string             name_;
      /// How many periods we've stored for this stat.
      uint16_t                num_items_;
      /// The StatDataItems, one for each period.
      StatDataItem            items_[kMaxItems];

      /// Constructor
      StatData():name_(), num_items_(0)
      {
        memset(items_, 0, kMaxItems * sizeof(items_[0]));
      };
    };

    /// Struct for storing time-val pairs for instant stats.
    struct InstantStatData
    {
      /// The unique name for this stat.
      std::string             name_;
      /// How many instants we've stored for this stat.
      uint16_t                num_instants_;
      /// After how long do we want to stop replacing this stat?
      uint64_t                collection_usec_;
      /// At what time (in usec) did we start collecting this stat?
      uint64_t                start_time_usec_;
      /// The times when we stored this stat.
      uint64_t                times_[kMaxVals];
      /// The values of this stat
      uint64_t                values_[kMaxVals];

      /// Constructor
      InstantStatData():name_(), num_instants_(),
        collection_usec_(), start_time_usec_(), times_(), values_()
      {
        memset(values_, 0, kMaxVals * sizeof(values_[0]));
        memset(times_,  0, kMaxVals * sizeof(times_[0]));
      };
    };

    /// \brief Return the array index for this statistic, with lazy
    /// instantiation.
    ///
    /// \param  name  The string representing the name of this statistic.
    /// \param  instant True if this is an instant stat, false if amortized.
    ///
    /// \return A unique 16-bit unsigned integer that is an index into the
    ///         array of stored data. If this stat has already been tracked,
    ///         the existing index is returned. If this is a new stat, a new
    ///         (unique to this stat) is returned. If no unique index is
    ///         available for a new stat, this will log a warning and return
    ///         kMaxStats -1. In that case, the stat at position kMaxStats - 1
    ///         will be invalid. However, since this is just for debugging
    ///         purposes and will be obvious from the logs, that invalid data
    ///         is an acceptable trade-off against complexity and performance
    ///         time to handle too-many-stats.
    uint16_t GetStatIndex(const char* name, bool instant);

    /// Maximum number of statistic names.
    static const uint16_t            kMaxStats = 64;

    /// Current number of statistics being tracked.
    uint16_t                         num_stats_;

    /// Current number of instant statistics being tracked.
    uint16_t                         num_instant_stats_;

    /// Map from stat name to array index.
    std::map<std::string, uint16_t>  stat_index_map_;

    /// For each stat, the most recent data values that have not yet been
    /// amortized and stored in the stats_ structure.
    CurrentDataItem                  recent_vals_[kMaxStats];

    /// Collection of historical amortized statistics.
    StatData                         stats_[kMaxStats];

    /// Collection of historical non-amortized statistics.
    InstantStatData                  instant_stats_[kMaxStats];
  }; // end class DebuggingStats

} // namespace iron

#endif // IRON_COMMON_DEBUGGING_STATS_H
