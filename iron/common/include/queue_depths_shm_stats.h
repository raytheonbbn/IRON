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

/// \brief Statistics about actual queue depths vs values in shared memory.
///
/// This class is used to track the differences between a QueueDepths object
/// that is up-to-date and the queue depths values that have been written
/// to shared memory.
#ifndef IRON_COMMON_QUEUE_DEPTHS_SHM_STATS_H
#define IRON_COMMON_QUEUE_DEPTHS_SHM_STATS_H

#include "bin_indexable_array.h"
#include "bin_map.h"
#include "iron_constants.h"
#include "itime.h"

#include <map>
#include <string>

#include <stdint.h>

namespace iron
{
  class QueueDepths;

  /// \brief Maintains stats about current values vs most recently written.
  ///
  /// Tracks deltas between the current value and the most recently written
  /// values (for all bins), as well as the max and average delta and the max
  /// and average time between writes.
  class QueueDepthsShmStats
  {
    public:
      /// \brief Default constructor.
      ///
      /// \param bin_map Mapping of IRON bins.
      QueueDepthsShmStats(BinMap& bin_map);

      /// \brief Destructor.
      virtual ~QueueDepthsShmStats();

      /// \brief Track changes to queue depth.
      ///
      /// \param  idx        The index of the bin whose value is changing.
      /// \param  new_depth  The new value of the depth, in bytes.
      void DepthChanged(BinIndex idx, uint32_t new_depth);

      /// \brief Recompute running totals and stats when a write is done.
      ///
      /// \param  shared_vals  The QueueDepths object that just wrote to
      ///                      shared memory. We will compare this to our
      ///                      maintained values.
      void ValuesShared(const QueueDepths* shared_vals);

      /// \brief Convert the QueueDepthShmStats object into a string.
      ///
      /// Returns a string representation of all the statistics, including
      /// computed averages.
      ///
      /// \return  A string object displaying the stats
      std::string ToString() const;

    private:

      /// \brief Copy constructor.
      QueueDepthsShmStats(const QueueDepthsShmStats& qdss);

      /// \brief Assignment operator from a QueueDepthsShmStats object.
      ///
      /// \param qdss A reference to the object to copy.
      ///
      /// \return A reference to the updated object.
      QueueDepthsShmStats& operator=(const QueueDepthsShmStats& qdss);

      /// Mapping of IRON bins.
      BinMap& bin_map_;

      /// Array of last queue depths written to shared memory, keyed by bin
      /// index.
      BinIndexableArray<uint32_t>  last_shared_values_;

      /// Array of the maximum instantaneous queue depth value for each bin
      /// since the queue depths were last written to shared memory. This can
      /// be used (combined with min_val_since_write_) to find (a) the maximum
      /// delta between instantaneous value and shared value and (b) the
      /// maximum delta between the instaneous value and the range of last
      /// shared and next shared (i.e., how far as the instantaneous value
      /// drifted outside the range that the readers learn about).
      /// Keyed by bin index.
      BinIndexableArray<uint32_t>  max_val_since_write_;

      /// Array of the minimum instantaneous queue depth value for each bin
      /// since the queue depths were last written to shared memory. This can
      /// be used (combined with max_val_since_write_) to find (a) the maximum
      /// delta between instantaneous value and shared value and (b) the
      /// maximum delta between the instaneous value and the range of last
      /// shared and next shared (i.e., how far as the instantaneous value
      /// drifted outside the range that the readers learn about).
      /// Keyed by bin index.
      BinIndexableArray<uint32_t>  min_val_since_write_;

      /// The last time we wrote values. Used to track the maximum and average
      /// time between writes.
      Time                    last_write_time_;

      /// The first time values changed since we last wrote them. Used to track
      /// how long shared data has been stale.
      Time                    first_change_time_;

      /// The maximum (over all write-to-write time periods) of the maximum
      /// delta (over the entire period, over all bins) between instanteous
      /// queue depth and currently-written queue depth.
      uint32_t                max_delta_;

      /// The maximum (over all write-to-write time periods) of the maximum
      /// delta (over the entire period, over all bins) between instanteous
      /// queue depth and the range of currently-written queue depth and
      /// next-written queue depth.
      uint32_t                max_outside_range_;

      /// The maximum (over all writes) of the time between the first value
      /// change (to any bin) since the last write and the next write.
      Time                    max_stale_time_;

      /// The sum of all max_delta values (over all write-to-write time
      /// periods). Used to compute the average delta.
      uint32_t                total_delta_;

      /// The sum of all max_outside_range values (over all write-to-write time
      /// periods). Used to compute the average outside_range.
      uint32_t                total_outside_range_;

      /// The sum of all max_stale_time values (over all write-to-write time
      /// periods). Used to compute the average stale time.
      Time                    total_stale_time_;

      /// The number of write periods we've included in the total values.
      /// Used to compute averages.
      uint32_t                num_write_periods_;
  }; // end class QueueDepthsShmStats

} // namespace iron

#endif  // IRON_COMMON_QUEUE_DEPTHS_SHM_STATS_H
