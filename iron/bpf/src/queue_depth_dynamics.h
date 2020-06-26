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

#ifndef IRON_BPF_QUEUE_DEPTH_DYNAMICS_H
#define IRON_BPF_QUEUE_DEPTH_DYNAMICS_H

/// Provides a class for tracking queue depth dynamics over a short time
/// period. Used as part of Zombie Latency Reduction.
///
/// In particular, this tracks two notions of the queue depth over time:
/// 1. Is the queue depth increasing, decreasing, or staying the same? For
///    this, we track the net changes to queue depth over a configurable time
///    period (kChangeRateResetPeriod). If the queue depth is decreasing, we
///    won't add zombies.
/// 2. What was the minimum queue depth over the most recent time period? This
///    is the ZLR floor: how many packets are always in the queue and thus can
///    be replaced by zombies that will likely never be sent? The tricky part
///    of picking the floor is determining the time window over which we want
///    the minimum queue depth. The window should be large enough that we
///    ignore short-lived spikes in queue depth (if we add zombies up to a
///    mid-spike level, those will be sent the next time our queue depth
///    dips), but it should be short enough that we will add more zombies
///    within a resonable time if the network dynamics change and lead to a
///    longer stable queue depth.
///
///    This time window is dynamic (if the system is so configured). Whenever
///    we send a zombie, we assume that our window was too short (i.e., we
///    added zombies based on a fleeting queue depth spike), so we increase
///    the window for the future. If we've gone a long time since sending a
///    zombie, we test out shortening the window, since shorter windows will
///    lead to faster reactions to network events.
///
#include "config_info.h"
#include "iron_types.h"
#include "itime.h"
#include "packet.h"

#include <stdint.h>

/// This class uses circular buffers to maintain data over a rolling time
/// window. The buffer is divided into this many segments. After
/// 1/kNumQDDSegments of the time period have passed, the oldest segment's
/// data is expired and reset. Thus, the dynamics information returned from
/// this class will cover somewhere between a full time period (of length
/// kChangeRateResetPeriod) and [1 - 1/kNumQDDSegments] fraction of a time
/// period.
#define kNumQDDSegments 4

namespace iron
{
  /// \brief Class for tracking queue depth dynamics over a short time.
  ///
  /// This class contains some statistics about queue depth dynamics over a
  /// short time period. As long as this has been triggered at the appropriate
  /// time to maintain the counts, the "Get" functions will return information
  /// about the dynamics over the most recent time period of approximately
  /// length kChangeRateResetPeriod (defined in queue_depth_dynamics.cc).
  class QueueDepthDynamics
  {
    public:

    /// Constructor
    QueueDepthDynamics();

    /// Destructor
    virtual ~QueueDepthDynamics() {}

    /// \brief Initialize the QueueDepthDynamics object.
    ///
    /// \param  dynamic_window True if the minimum queue depth window should
    ///                      be dynamically resized.
    /// \param  initial_window_secs The initial length of the dynamic min
    ///                      queue depth window, in seconds. (Or the only
    ///                      length, if dynamic window adjustment is
    ///                      disabled.)
    /// \param  window_lower_bound_secs The lower bound of the dynamic min
    ///                      queue depth window, in seconds.
    /// \param  window_upper_bound_secs The upper bound of the dynamic min
    ///                      queue depth window, in seconds.
    ///
    /// \return  True if the initialization is successful, false otherwise.
    void Initialize(bool dynamic_window,
                    double initial_window_secs,
                    double window_lower_bound_secs,
                    double window_upper_bound_secs);

    /// \brief Records that the specified number of bytes have been added.
    ///
    /// \param  bytes  How many bytes have been added? uint16_t is sufficient
    ///                because the total length field in the IP header is
    ///                only 16 bits. By using uint16_t instead of uint32_t,
    ///                we avoid the potential for overflow when converting
    ///                to an int32_t to store the net change.
    /// \param  lat    The latency class of the bytes we are adding. This
    ///                function will determine based on this class whether or
    ///                not to count this bytes towards the dynamics we're
    ///                tracking.
    /// \param  new_depth The new queue depth (up to the called to determine
    ///                what is included), used to track the minimum queue
    ///                depth over this period (this may be the new minimum if
    ///                and only if we haven't had a dequeue since the value
    ///                was reset).
    void ProcessBytesAdded(uint16_t bytes, LatencyClass lat, uint32_t new_depth);

    /// \brief Records that the specified number of zombie bytes have been
    /// added, eating away at the ZLR window.
    ///
    /// \param  bytes  How many bytes have been added? uint16_t is sufficient
    ///                because the total length field in the IP header is
    ///                only 16 bits. By using uint16_t instead of uint32_t,
    ///                we avoid the potential for overflow when converting
    ///                to an int32_t to store the net change.
    /// \param  lat    The latency class of the zombie bytes we are
    ///                adding. This function will determine based on this
    ///                class whether or not to count these zombie bytes
    ///                towards the dynamics we're tracking.
    void ProcessZombieBytesAdded(uint16_t bytes, LatencyClass lat);

    /// \brief Process the change in bytes as applicable for this latency class.
    ///
    /// \param  bytes  How many bytes have been removed? uint16_t is
    ///                sufficient because the total length field in the IP
    ///                header is only 16 bits. By using uint16_t instead of
    ///                uint32_t, we avoid the potential for overflow when
    ///                converting to an int32_t to store the net change.
    /// \param  lat    The latency class of the bytes we are removing. This
    ///                function will determine based on this class whether or
    ///                not to count this bytes towards the dynamics we're
    ///                tracking.
    /// \param  new_depth The new queue depth (up to the called to determine
    ///                what is included), used to track the minimum queue
    ///                depth over this period.
    void BytesRemoved(uint16_t bytes, LatencyClass lat, uint32_t new_depth);

    /// \brief Returns the rate of queue depth change over the past time
    /// period, in bytes per second.
    ///
    /// This will return the rate over approximately the last time period, as
    /// long as the system has been running for at least that long. If the
    /// system hasn't been running that long, this just returns the maximum
    /// int32_t value.
    ///
    /// \return  The queue depth change rate, which will be negative if more
    /// bytes were removed than added, or positive if more were added.
    int32_t GetChangeRateBytesPerSec();

    /// \brief Returns the minimum queue depth over approximately the last
    /// time period, as long as the system has been running for at least that
    /// long. If the system hasn't been running that long, this returns 0.
    ///
    /// This subtracts the number of zombie bytes added during the same
    /// period.
    ///
    /// \return  The minimum queue depth, based on queue depth values passed
    /// in via BytesRemoved, minus any zombie bytes added.
    uint32_t GetMinQueueDepthBytes();

    /// \brief If rate limiting allows, increment the min bytes window.
    ///
    /// If dynamic window adjustment is disabled, this does nothing.
    void IncrementMinBytesResetPeriod();

    /// \brief If appropriate, increment the min bytes window.
    ///
    /// If it has been long enough since our last window adjustment AND it's
    /// been long enough since we last added a zombie packet, decrement the
    /// min bytes window.
    ///
    /// If dynamic window adjustment is disabled, this does nothing.
    void DecrementMinBytesResetPeriod();

    /// \brief Return the length of the dynamic ZLR window.
    inline Time min_bytes_reset_period()
    {
      return min_bytes_reset_period_;
    }

    private:

    /// Copy constructor.
    QueueDepthDynamics(const QueueDepthDynamics& other);

    /// Assignment operator
    QueueDepthDynamics& operator=(const QueueDepthDynamics& other);

    /// Check whether it's time to expire the oldest data, and if so, perform
    /// reset and move along the circular buffer of data.
    void CheckReset();

    /// QueueDepthDynamics min queue depths will be the minimum queue depth in
    /// bytes over the  most recent time period of approximately this amount
    /// of time.
    /// (It will include at most this amount of time, and at least this amount
    /// of time * (1 - kNumQDDSegments).)
    ///
    /// This value is dynamic. If we're sending zombies, then this will
    /// increase so that our queue depth floor covers a longer time period to
    /// account for more dynamic network conditions. If we haven't sent
    /// zombies in a while, this will decrease so that we are more likely to
    /// add zombies and lower the latency.
    Time                min_bytes_reset_period_;

    /// We will rotate the circular buffer every 1/kNumQDDSegments seconds.
    /// Caching that value here saves time when we call CheckReset().
    Time                min_bytes_rotate_period_;

    /// At what time did we last change the min_bytes_reset_period_? Used to
    /// rate-limit the dynamics of the min_bytes_reset_period.
    Time                last_changed_min_bytes_period_;

    /// Time when a zombie packet was last added. This is used to determine
    /// whether or not it's been long enough that we should consider
    /// decreasing the length of time over which the queue depth floor is
    /// estimated.
    Time                zombie_bytes_last_added_;

    /// Whether or not the value for min_bytes_reset_period_ is dynamic.
    /// Runtime configurable.
    bool                dynamic_min_depths_window_;

    /// The lower bound (runtime configurable) for min_bytes_reset_period_.
    Time                min_bytes_reset_period_lower_bound_;

    /// The upper bound (runtime configurable) for min_bytes_reset_period_.
    Time                min_bytes_reset_period_upper_bound_;

    /// The net number of bytes added to / removed from the queue during each
    /// segment of the time-based circular buffer. If this is negative, then
    /// more bytes were removed than were added during that period. If
    /// positive, then more bytes were added. There are kNumQDDSegments of
    /// these so that we can expire old data by 0-ing out only the oldest
    /// segment at a time without losing the more recent data.
    ///
    /// Note that int32_t should be sufficient since this is only covering a
    /// very short (sub-second) period of time. If our queue grows or shrinks by
    /// a net of 2 million packets in less than a second, we have worse
    /// problems.
    int32_t             net_bytes_[kNumQDDSegments];

    /// The minimum queue depth seen during each segment of the time-based
    /// circular buffer. There are kNumQDDSegments of these so that we can
    /// expire old data by setting only the oldest segment at a time to the
    /// max allowable (i.e., resetting it) without losing the more recent
    /// data.
    uint32_t            min_bytes_[kNumQDDSegments];

    /// The number of zombie bytes that were added during each segment of the
    /// time-based circular buffer. There are kNumQDDSegments of these so that
    /// we can expire old data by setting only the oldest segment at a time to
    /// 0 without losing the more recent data. This buffer is rotated at the
    /// same time as min_bytes_, since the intent is to subtract zombies added
    /// from the minimum depth to get an accurate floor of the queue depth.
    uint32_t            zombie_bytes_added_[kNumQDDSegments];

    /// What time each of the net_bytes_ entries was most recently reset. This
    /// is used to precisely compute the length of time for which we have
    /// valid data at any point in time, which is necessary for converting the
    /// net bytes into a rate.
    ///
    /// This is also used to determine when it's time to rotate the buffer.
    Time                last_reset_net_[kNumQDDSegments];

    /// What time we most recently rotated/reset a segment of  min_bytes_ (and
    /// its associated zombie_bytes_added_).
    /// This is used to determine when it's time to rotate the buffer.
    Time                last_reset_min_;

    /// Which entry in net_bytes_ is tracking current queue depth
    /// changes. When the queue depth changes, this index is used to find the
    /// right segment to update. When retrieving the queue depth change, we
    /// will retrieve the sum of all segments divided by the total time
    /// tracked by the current data.
    uint8_t             current_idx_net_;

    /// Which entry in min_bytes_ is tracking the current minimum queue depth.
    /// When the queue depth decreases, this index is used to find the
    /// right segment to update. When retrieving the minimum queue depth, we
    /// will retrieve the minimum over all segments.
    uint8_t             current_idx_min_;

    /// True if and only if we don't yet have enough data to cover a full time
    /// period. If this is true, GetChangeRateBytesPerSec will return the max
    /// allowable value, since we are presumably adding packets quickly during
    /// start up.
    bool                initializing_net_;

    /// This is just a cached value of the sum of all entries in net_bytes_
    /// except for the one that is currently changing. This isn't strictly
    /// necessary, since we could re-add the value every time we need them,
    /// but it will make GetChangeRateBytesPerSec faster. The current indexed
    /// value is NOT included, because that would mean we had to add changes
    /// to both the current index and this value every time the queue depth
    /// changes, which would likely be more additional work than just adding
    /// the current value to this sum when GetChangeRateBytesPerSec is
    /// called.
    int32_t             net_sum_;

    /// This is just a cached value of the minimum over all entries in
    /// min_bytes_ except for the one that is currently changing. This isn't
    /// strictly necessary, since we could re-discover the minimum value every
    /// time we need it, but it will make GetMinQueueDepthBytes faster. The
    /// current indexed value is NOT included, because that would mean we had
    /// to track the minimum in both the current index and this value every
    /// time the queue depth decreases, which would likely be more additional
    /// work than just comparing this to the current value when
    /// GetMinQueueDepthBytes is called.
    uint32_t            overall_min_;

    /// This is just a cached value of the sum of all entries in
    /// zombie_bytes_added_ except for the one that is currently
    /// changing. This isn't strictly necessary, since we could re-add the
    /// value every time we need them, but it will make GetMinQueueDepthBytes
    /// faster. The current indexed value is NOT included, because that would
    /// mean we had to add changes to both the current index and this value
    /// every time a zombie is added, which would likely be more additional
    /// work than just adding the current value to this sum when
    /// GetMinQueueDepthBytes is called.
    uint32_t            total_zombies_added_;

  }; // End class QueueDepthDynamics

} // end namespace iron

#endif // IRON_BPF_QUEUE_DEPTH_DYNAMICS_H
