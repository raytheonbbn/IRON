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

#ifndef IRON_BPF_QUEUE_DEPTH_OSC_H
#define IRON_BPF_QUEUE_DEPTH_OSC_H

/// Provides a class for tracking the queue depth oscillation period to be
/// used for queue depth smoothing.
///
#include "config_info.h"
#include "genxplot.h"
#include "iron_types.h"
#include "itime.h"
#include "packet.h"

#include <fftw3.h>
#include <string>
#include <stdint.h>

namespace iron
{
  /// \brief Utility class for loading the QueueDepthOsc configuration
  /// information.
  struct QueueDepthOscConfig
  {
  public:

    /// Constructor
    QueueDepthOscConfig();

    /// Destructor
    virtual ~QueueDepthOscConfig();

    /// Copy constructor.
    QueueDepthOscConfig(const QueueDepthOscConfig& other);

    /// Assignment operator
    QueueDepthOscConfig& operator=(const QueueDepthOscConfig& other);

    /// \brief Sets up the queue depth oscillation manager fields.
    ///
    /// \param  config_info The reference to the config info object used to
    ///                     initialize values.
    ///
    /// \return true if success, false otherwise.
    bool Initialize(const ConfigInfo& config_info);

    /// How many queue depth samples to pass into the FFT, collected once
    /// every fft_sample_time_.
    uint16_t            fft_sample_size;

    /// How often to sample the queue depth for the sake of computing
    /// oscillations, in seconds.
    double              fft_sample_time_interval_secs;

    /// How often to compute the updated FFT.
    double              fft_compute_time_interval_secs;

    /// We won't use a period of longer than this for the purpose of
    /// smoothing. If the highest-energy period is longer than this, then
    /// we'll use the highest-energy period that's *shorter* than this
    /// unless it's completely dwarfed by higher periods in terms of
    /// energy.
    double              max_considered_period_secs;

    /// The minimum time after a reset before we allow another reset. This
    /// should be the maximum amount of time we expect it to take for the
    /// system to converge (if it's going to converge).
    double               min_time_between_resets_secs;

    /// If at least reset_trigger_sample_count_ samples have the actual value
    /// differing from the smoothed value by at least this fraction of the
    /// smoothed value, trigger a reset.
    double              reset_trigger_fraction;

    /// If the actual value has been far from the smoothed value for at
    /// least this many samples, trigger a reset.
    uint16_t            reset_trigger_sample_count;

    /// True if we want soft resets, which means reset the period
    /// computations but continue to use the last computed period of
    /// smoothing. A hard reset, on the other hand, also stops smoothing
    /// until we have a new period.
    bool                use_soft_reset;
  }; // end struct QueueDepthOscConfig

  /// \brief Class for tracking the queue depth oscillation period.
  ///
  /// QueueDepthOsc uses the FFTW library (version 3) to compute the period of
  /// oscillation of a queue depth. It follows these basic steps:
  /// 1.  Every sample time interval (Bpf.Osc.FftSampleTimeSecs), captures a
  ///     sample of the queue depth in Bytes.
  /// 2.  Every FFT computation time interval (Bpf.Osc.FftComputeTimeSecs),
  ///     uses the most recent sample size (Bpf.Osc.FftSampleSize) samples with
  ///     fftw3 to compute the FFT.
  /// 3.  Determine which period to use based on the result of the FFT.
  /// 3a. In the FFT results, if the period with the most energy is less than
  ///     the threshold for a "usable" period
  ///     (Bpf.Osc.MaxConsideredPeriodSecs), updates the period to be returned
  ///     with this value.
  /// 3b. If the period with the most energy is larger than the threshold, it
  ///     considers the greatest-energy period smaller than the threshold. If
  ///     that energy is greater than 10K (kEnergyThreshold) or is greater
  ///     than half (kEnergyFraction) the overall maximum energy (including
  ///     long periods), then we update the period to be returned with this
  ///     value. This handles cases where we have a long period, for instance
  ///     from an high-level queue depth change trend, and also oscillation
  ///     due to transmission and QLAM delays. We want to reduce the
  ///     delay-induced oscillation.
  /// 4.  Determine when our data is unusable.
  /// 4a. Do not start computing FFTs until we have at least a full sample
  ///     size of data.
  /// 4b. If we see a long period of time (Bpf.Osc.ResetTriggerTimeSecs) when
  ///     the smoothed queue depth value is significantly different from the
  ///     exact queue depth value (determined using
  ///     Bpf.Osc.ResetTriggerFraction), reset the oscillation comptuation by
  ///     deleting all sample data and starting over. This can be a soft reset
  ///     that just restarts period computation, or a hard reset that also
  ///     stops smoothing until we have an updated period - configured using
  ///     Bpf.Osc.UseSoftReset.
  class QueueDepthOsc
  {
    public:

    /// Constructor
    QueueDepthOsc();

    /// Destructor
    virtual ~QueueDepthOsc();

    /// \brief Sets up the queue depth oscillation manager.
    ///
    /// \param  config Reference to the object containing the configured
    ///                values to use. (Note: this does not read straight from
    ///                the config_info so that we can log the configured
    ///                values once for all QueueDepthOsc instances instead of
    ///                once for each queue.)
    ///
    /// \return true if success, false otherwise.
    bool Initialize(const QueueDepthOscConfig& config);

    /// \brief Restart the period computation by tossing existing samples.
    ///
    /// This is used when we see symptoms of a network event that drastically
    /// changes the queue depths. It will toss out all the existing samples
    /// and start collecting again so that we don't try to compute a period
    /// that includes values before and after a big change.
    ///
    /// There are two variants of Reset. A soft reset just tosses the samples
    /// and re-starts the period computation. A hard reset also tosses out any
    /// previously-computed period (by flagging it as unusable).
    ///
    /// \param now  The current time, which will be stored as the last reset
    ///             time. Passed in to avoid extra system calls, and so that
    ///             we treat the entire period computation process as atomic
    ///             occurring at the FFT computation time.
    void Reset(Time now);

    /// \brief Update the oscillation period and/or collect data.
    ///
    /// This function should be called at least once every 5 ms, or as close
    /// to that as possible, even if the queue depth isn't changing.
    ///
    /// \param  new_depth  The up-to-date queue depth.
    /// \param  smoothed   The most recent smoothed queue depth.
    void QueueDepthOscCheckPoint(uint32_t new_depth, uint32_t smoothed);

    /// \brief Returns the last good estimated queue depth oscillation period.
    ///
    /// \return  The queue depth oscillation period in usec.
    inline uint64_t GetOscPeriodToUse()
    {
      return oscillation_period_usec_;
    }

    /// \brief Returns true if the latest period we computed can be used.
    ///
    /// \return true if we can use the computed period.
    inline bool have_usable_period()
    {
      return have_usable_period_;
    }

    /// \brief Set the pointer to the queue depth graph.
    ///
    /// \param qd_xplot Pointer to the queue depth graph.
    inline void set_qd_xplot(GenXplot* qd_xplot)
    {
      qd_xplot_ = qd_xplot;
    }

    /// \brief Set the bin identifier for logging purposes.
    ///
    /// \param log_id The unique identifier associated with this queue depth.
    inline void set_log_id(std::string log_id)
    {
      log_id_ = log_id;
    }

    /// \brief Set whether this is a latency sensitive queue for logging.
    ///
    /// \param ls_queue True if this is measuring oscillations of a latency
    ///        sensitive queue.
    inline void set_ls_queue(bool ls_queue)
    {
      ls_queue_ = ls_queue;
    }

    private:

    /// Copy constructor.
    QueueDepthOsc(const QueueDepthOsc& other);

    /// Assignment operator
    QueueDepthOsc& operator=(const QueueDepthOsc& other);

    /// Compute the FFT to find the period of oscillation.
    void ComputeFft();

    /// Adjust FFT-computed frequency by using a second order lagrange
    /// interpolator. This is useful if our samples were to coarse.
    ///
    /// \param new_computed_period_usec The newly computed period, which may
    ///                   or may not be updated by this function.
    /// \param used_index The index corresponding to our current usable period
    ///                   estimate.
    /// \param time_span_usec How long this FFT sample covered, in usec.
    ///
    void Interpolate(uint64_t& new_computed_period_usec,
                     uint16_t used_index, int64_t time_span_usec);

    /// Object used to compute FFTs.
    fftw_plan           fft_plan_;

    /// Dynamically allocated array of queue depth values to be passed into
    /// the FFT computation.
    double*             fft_samples_;

    /// Dynamically allocated array used by the FFT library. Note that this
    /// cannot just use the fft_samples_ array, because the array must be at
    /// the same place in memory for every call, and we want to use the same
    /// samples across multiple FFT computations.
    double*             fft_input_;

    /// Dynamically allocated array of the time when each sample was
    /// collected, indexed to match the input samples.
    Time*               fft_input_times_;

    /// Dynamically allocated array of values returned by the FFT
    /// computation.
    fftw_complex*       fft_output_;

    /// How many queue depth samples to pass into the FFT, collected once
    /// every fft_sample_time_.
    uint16_t            fft_sample_size_;

    /// How often to sample the queue depth for the sake of computing
    /// oscillations.
    Time                fft_sample_time_interval_;

    /// Time when we most recently added a new checkpoint. This is used to
    /// evenly space our queue depth samples over time.
    Time                last_checkpoint_;

    /// The next index to fill in in the fft_input array. This represents the
    /// next input into the point in the array that we're currently using. If
    /// this is within fft_sample_size_ of the end of the array, then we'll
    /// copy the same value to next_index_ - fft_sample_size_.
    uint16_t            next_index_;

    /// How often to compute the updated FFT.
    Time                fft_compute_time_interval_;

    /// The time when we last computed an FFT.
    Time                last_fft_;

    /// The period of oscillation to be used. This may or may not be the most
    /// recently computed period, since we ignore periods that are out of an
    /// acceptable range, but will continue using the last acceptable period
    /// until we have a hard reset.
    uint64_t            oscillation_period_usec_;

    /// We won't use a period of longer than this for the purpose of
    /// smoothing. If the highest-energy period is longer than this, then
    /// we'll use the highest-energy period that's *shorter* than this unless
    /// it's completely dwarfed by higher periods in terms of energy.
    uint64_t            max_considered_period_usec_;

    /// Track whether or not we were able to compute a usable period.
    bool                have_usable_period_;

    /// Used to track when we have enough data to start computing FFTs.
    bool                have_sufficient_data_;

    /// The minimum time after a reset before we allow another reset. This
    /// should be the maximum amount of time we expect it to take for the
    /// system to converge (if it's going to converge).
    Time                min_time_between_resets_;

    /// Time when the last reset occurred. Used to ensure we don't reset again
    /// before it's had time to converge.
    Time                last_reset_;

    /// If at least reset_trigger_sample_count_ samples have the actual value
    /// differing from the smoothed value by at least this fraction of the
    /// smoothed value, trigger a reset.
    double              reset_trigger_fraction_;

    /// If the actual value has been far from the smoothed value for at least
    /// this many samples, trigger a reset.
    uint16_t            reset_trigger_sample_count_;

    /// True if we want soft resets, which means reset the period computations
    /// but continue to use the last computed period of smoothing. A hard
    /// reset, on the other hand, also stops smoothing until we have a new
    /// period.
    bool                use_soft_reset_;

    /// How many samples we've seen in a row that were below the trigger
    /// threshold.
    uint16_t            num_low_for_reset_;

    /// How many samples we've seen in a row that were above the trigger
    /// threshold.
    uint16_t            num_high_for_reset_;

    // identifier for this queue, used for log messages.
    std::string         log_id_;

    // Whether this is a latency sensitive queue: used for log messages.
    bool                ls_queue_;

    /// Queue depths xplot graph, so we can add oscillation information.
    GenXplot*           qd_xplot_;

    /// Next available color for adding period estimates to the queue depth
    /// graph. Not used unless XPLOT compile option is defined.
    uint8_t             next_color_;

  }; // End class QueueDepthOsc

} // end namespace iron

#endif // IRON_BPF_QUEUE_DEPTH_OSC_H
