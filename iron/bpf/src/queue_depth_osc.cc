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

/// \file queue_depth_osc.cc, provides an implementation of the class for
/// tracking the queue depth oscillation period.

#include "queue_depth_osc.h"

#include "iron_types.h"
#include "log.h"
#include "packet.h"
#include "unused.h"

#include <inttypes.h>
#include <math.h>

using ::iron::ConfigInfo;
using ::iron::LatencyClass;
using ::iron::Log;
using ::iron::QueueDepthOsc;
using ::iron::QueueDepthOscConfig;
using ::iron::Time;

namespace
{
  /// Class name for logging.
  const char*     UNUSED(kClassName)                = "QueueDepthOsc";

  /// True to include lines indicating computed periods and resets on the
  /// queue depths xplot graph.
  const bool      UNUSED(kGraphPeriods)             = false;

  /// The default for the number of samples we'll pass into the FFT.
  const uint16_t  kDefaultSampleSize                = 2048;

  /// Default value for how often to sample the queue depth for the sake of
  /// computing oscillations.
  const double    kDefaultSampleTimeSecs            = 0.0025;

  /// How often we want to recompute the FFT to find the latest oscillation
  /// period.
  const double    kDefaultFftComputeTimeSecs        = 1.0;

  /// Default Maximum length of time we would use for smoothing. If the
  /// highest-energy period is longer than this, then we'll use the
  /// highest-energy period that's *shorter* than this unless it's completely
  /// dwarfed by higher periods in terms of energy.
  const double    kDefaultMaxConsideredPeriodSecs   = 1.0;

  /// Default value for the minimum time after a reset before we allow another
  /// reset. This should be the maximum amount of time we expect it to take
  /// for the system to converge (if it's going to converge).
  const double    kDefaultMinTimeBetweenResetsSecs  = 6.0;

  /// If the actual queue depth value differs from the smoothed value by at
  /// least this fraction of the smoothed value for long enough, trigger a
  /// reset.
  const double    kDefaultResetTriggerFraction      = 0.25;

  /// If the actual value is far from the smoothed value for at least this
  /// long, trigger a reset.
  const double    kDefaultResetTriggerTimeSecs      = 0.375;

  /// Default for whether we want to soft (vs hard) resets.
  /// True if we want soft resets, which means reset the period computations
  /// but continue to use the last computed period of smoothing. A hard
  /// reset, on the other hand, also stops smoothing until we have a new
  /// period.
  const bool      kDefaultSoftReset                 = false;

  /// If the max FFT norm for a value that would be a useable period
  /// (according to max_considered_period_secs_) is greater than this value,
  /// we will use that period even if it's not the max over all periods.
  const uint32_t  kEnergyThreshold                  = 10000;

  /// If the max FFT norm for a value that would be a useable period
  /// (according to max_considered_period_secs_) is greater than this fraction
  /// of the overall max norm (including non-considered periods), we will use
  /// that period.
  const double    kEnergyFraction                   = 0.5;

  /// True if we want to do interpolation on the frequency to get a finer
  /// grained estimate.
  const bool      kDoInterpolation                  = false;
}

//============================================================================
QueueDepthOsc::QueueDepthOsc()
    : fft_plan_(NULL),
      fft_samples_(NULL),
      fft_input_(NULL),
      fft_input_times_(NULL),
      fft_output_(NULL),
      fft_sample_size_(0),
      fft_sample_time_interval_(),
      last_checkpoint_(),
      next_index_(0),
      fft_compute_time_interval_(),
      last_fft_(Time::Now()),
      oscillation_period_usec_(0),
      max_considered_period_usec_(0),
      have_usable_period_(false),
      have_sufficient_data_(false),
      min_time_between_resets_(),
      last_reset_(Time::Now()),
      reset_trigger_fraction_(0),
      reset_trigger_sample_count_(0),
      use_soft_reset_(false),
      num_low_for_reset_(0),
      num_high_for_reset_(0),
      log_id_(),
      ls_queue_(false),
      qd_xplot_(NULL),
      next_color_(0)
{
}

//============================================================================
QueueDepthOsc::~QueueDepthOsc()
{
  if (fft_plan_)
  {
    fftw_destroy_plan(fft_plan_);
  }
  if (fft_output_)
  {
    fftw_free(fft_output_);
  }
  if (fft_samples_)
  {
    delete [] fft_samples_;
    fft_samples_ = NULL;
  }
  if (fft_input_)
  {
    delete [] fft_input_;
    fft_input_ = NULL;
  }
  if (fft_input_times_)
  {
    delete [] fft_input_times_;
    fft_input_times_ = NULL;
  }
}

//============================================================================
bool QueueDepthOsc::Initialize(const QueueDepthOscConfig& config)
{
  fft_sample_size_            = config.fft_sample_size;
  fft_sample_time_interval_   = Time(config.fft_sample_time_interval_secs);
  fft_compute_time_interval_  = Time(config.fft_compute_time_interval_secs);
  max_considered_period_usec_ =
    static_cast<uint64_t>(config.max_considered_period_secs * 1000000);
  min_time_between_resets_    = Time(config.min_time_between_resets_secs);
  reset_trigger_fraction_     = config.reset_trigger_fraction;
  reset_trigger_sample_count_ = config.reset_trigger_sample_count;
  use_soft_reset_             = config.use_soft_reset;

  fft_samples_      = new (std::nothrow) double[fft_sample_size_];
  fft_input_        = new (std::nothrow) double[fft_sample_size_];
  fft_input_times_  = new (std::nothrow) Time[fft_sample_size_];
  fft_output_       = static_cast<fftw_complex*>(
    fftw_malloc(sizeof(fftw_complex) * fft_sample_size_));
  if ((fft_samples_ == NULL) ||
      (fft_input_ == NULL) ||
      (fft_input_times_ == NULL) ||
      (fft_output_ == NULL))
  {
    LogF(kClassName, __func__,
         "Error allocating memory for oscillation manager.\n");
    return false;
  }
  // This function sets up the FFTW computation, telling it where to get the
  // input and where to put the output. FFTW_MEASURE will give a more exact
  // frequency that FFTW_ESTIMATE (the alternative), at the expense of
  // efficiency in the case where the input sizes keep changing. In our case,
  // we always have the same size input, so FFTW_MEASURE only takes an
  // efficiency hit the first time we call it (in the constructor).
  fft_plan_ = fftw_plan_dft_r2c_1d(
    fft_sample_size_, fft_input_, fft_output_, FFTW_MEASURE);
  if (fft_plan_ == NULL)
  {
    LogF(kClassName, __func__, "Error setting up FFT plan.\n");
    return false;
  }
  return true;
}

//============================================================================
void QueueDepthOsc::Reset(Time now)
{
  // \TODO Hard resets are really a workaround for not being able to identify
  // which period of oscillation to use.
  //
  // We want to be able to smooth based on the period of oscillation caused by
  // transmission and QLAM delays. Smoothing basically makes these
  // oscillations disappear. Therefore, if we're continuing to smooth after a
  // network event (i.e., a soft reset), then we're more likely to pick up and
  // use a period that's really convergence after the network event because we
  // don't have any better period. Hard resets make the "right" period of
  // oscillation show up again.
  //
  // Performance would be better if we could continue to smooth on the old
  // value and not have these false periods coming from post-network-event
  // convergence, but it's not obvious how to do this.
  have_sufficient_data_ = false;
  next_index_           = 0;
  num_low_for_reset_    = 0;
  num_high_for_reset_   = 0;
  if (!use_soft_reset_)
  {
    have_usable_period_ = false;
  }
  last_reset_ = now;
}

//============================================================================
void QueueDepthOsc::QueueDepthOscCheckPoint(
  uint32_t new_depth, uint32_t smoothed)
{
  Time now = Time::Now();
  if (now - last_checkpoint_ < fft_sample_time_interval_)
  {
    return;
  }

  if ((new_depth == 0) && (next_index_ == 0))
  {
    // Don't start collecting samples until we have data.
    return;
  }

  double threshold = smoothed * reset_trigger_fraction_;
  if (new_depth < smoothed - threshold)
  {
    num_low_for_reset_++;
    num_high_for_reset_ = 0;
  }
  else if (new_depth > smoothed + threshold)
  {
    num_high_for_reset_++;
    num_low_for_reset_  = 0;
  }
  else
  {
    num_low_for_reset_  = 0;
    num_high_for_reset_ = 0;
  }

  if (WouldLogD(kClassName))
  {
    LogD(kClassName, __func__,
         "%s Bin %s: "
         " new_depth = %" PRIu32 ", smoothed = %" PRIu32
         ", num_low_for_reset_ = %" PRIu16 ", num_high_for_reset_ = %" PRIu16
         ", time since last reset = %" PRId64 "\n",
         (ls_queue_ ? "LS" : "ALL"), log_id_,
         new_depth, smoothed, num_low_for_reset_, num_high_for_reset_,
         (now - last_reset_).GetTimeInUsec());
  }

  if ((num_low_for_reset_ > reset_trigger_sample_count_ ||
       num_high_for_reset_ > reset_trigger_sample_count_)
      && now - last_reset_ > min_time_between_resets_)
  {
    // \TODO Resets will toss out all samples and start again for the sake of
    // the FFT computation. This is correct because we don't want the FFT to
    // compute a period that includes the convergence after whatever network
    // event triggered the reset. Ideally, we'd wait until convergence was
    // complete before we start collecting samples again, and then compute the
    // FFT as soon as we have enough data (maybe less than a full sample size)
    // to start smoothing again. However, it's not obvious how to do this.
    Reset(now);
    if (qd_xplot_ && kGraphPeriods)
    {
      qd_xplot_->DrawLine(
        now.GetTimeInUsec() - iron::kStartTime, 0,
        now.GetTimeInUsec() - iron::kStartTime, qd_xplot_->max_y(), WHITE);
    }
  }

  if (qd_xplot_ && kGraphPeriods)
  {
    qd_xplot_->DrawPoint(
      now.GetTimeInUsec() - iron::kStartTime, new_depth, MAGENTA);
  }
  double new_sample = static_cast<double>(new_depth);
  // Taking the log of the sample gives a low pass filter over the data to
  // help reduce the impact of long-timescape fluctuations (which we can't
  // address via smoothing).
  if (new_sample != 0)
  {
    new_sample = log(new_sample);
  }
  fft_samples_[next_index_] = new_sample;
  fft_input_times_[next_index_] = now;
  if (WouldLogD(kClassName))
  {
    LogD(kClassName, __func__,
         "%s Bin %s: "
         "Index %" PRIu16 " now has depth %f, time %f\n",
         (ls_queue_ ? "LS" : "ALL"), log_id_,
         next_index_, fft_samples_[next_index_],
         static_cast<double>(now.GetTimeInUsec())/1e6);
  }

  next_index_++;
  if (next_index_ >= fft_sample_size_)
  {
    next_index_ = 0;
    // Now we have enough data to start computing FFTs.
    have_sufficient_data_ = true;
  }
  last_checkpoint_ = now;

  if (have_sufficient_data_ && ((now - last_fft_) >
                                fft_compute_time_interval_))
  {
    ComputeFft();
    last_fft_ = now;
  }
}

//============================================================================
void QueueDepthOsc::ComputeFft()
{
  uint64_t new_computed_period_usec = 0;
  // FFTW needs the input to be in adjacent memory, and in order
  // to avoid re-planning each time (which overwrites input), the
  // input must always be in the same memory location. Therefore,
  // before executing the FFT, we copy the samples into a single
  // location (fft_input_). This takes two memcpys because of the
  // circular buffer of samples.
  memcpy(&(fft_input_[0]), &(fft_samples_[next_index_]),
         sizeof(fft_input_[0]) * (fft_sample_size_ - next_index_));
  memcpy(&(fft_input_[fft_sample_size_ - next_index_]),
         &(fft_samples_[0]),
         sizeof(fft_input_[0]) * next_index_);
  if (WouldLogD(kClassName))
  {
    LogD(kClassName, __func__,
         "%s Bin %s: "
         "Computing period.\n",
         (ls_queue_ ? "LS" : "ALL"), log_id_);
    uint16_t sample_index = next_index_;
    for (uint16_t count = 0; count < fft_sample_size_; ++count)
    {
      LogD(kClassName, __func__,
           "*** sample %" PRIu16 " = %f\n", sample_index, fft_input_[count]);
      sample_index = (sample_index + 1) % fft_sample_size_;
    }
  }
  // fftw_execute computes the FFT with the parameters set up in the
  // Initialize method.
  fftw_execute(fft_plan_);

  double   norm                    = 0;
  double   max_norm                = 0;
  double   max_norm_low_freq       = 0;
  uint16_t max_norm_index          = 0;
  uint16_t max_norm_low_freq_index = 0;
  uint16_t last_index              = 0;
  if (next_index_ != 0)
  {
    last_index = next_index_ - 1;
  }
  int64_t  time_span_usec          =
      (fft_input_times_[last_index]
       - fft_input_times_[next_index_]).GetTimeInUsec();
  LogI(kClassName, __func__,
       "%s Bin %s: "
       "FFT results are shown below:\n", (ls_queue_ ? "LS" : "ALL"), log_id_);

  // We only want to look at periods less than the nominal time span.
  uint16_t min_i = time_span_usec / max_considered_period_usec_;
  bool update_period = false;
  // This look finds the norm for each FFT output entry, and then evaluates it
  // to find out whether this is (so far) the right frequency for us to
  // use. We want the highest-energy frequency that is for a period of less
  // than max_considered_period_usec_. Anything longer than that would be too
  // long for effective smoothing of queue depths. However, if the
  // highest-energy useable frequency is neglible (and is negligible compared
  // to the overall highest-energy frequency), we will just ignore it and
  // continue smoothing based on the last period we computed.
  for (uint16_t i = 2; i < (fft_sample_size_ + 2) / 2; i++)
  {
    norm = (fft_output_[i][0] * fft_output_[i][0])
      + (fft_output_[i][1] * fft_output_[i][1]);
    if (i < min_i)
    {
      // We can't smooth based on long periods. So for the lowest frequencies
      // (those that would result in a period longer than
      // max_considered_period_usec_), just keep track of the norm so we'll
      // know whether the best period in a usable range is oris not neglible
      // compared to this.
      if (norm > max_norm_low_freq)
      {
        max_norm_low_freq = norm;
        max_norm_low_freq_index = i;
      }
    }
    else
    {
      // Otherwise, this would be a period usable for smoothing, so consider
      // it as a candidate if it's the max energy.
      if (norm > max_norm)
      {
        max_norm = norm;
        max_norm_index = i;
      }
    }
    if (WouldLogI(kClassName) && i < 100)
    {
      // This log message generates a table in the log file. The explanation
      // of what's in the table can be seen in the log message before the for
      // loop. Don't bother printing the lowest frequencies - it just clutters
      // up the log file and (based on preivous experience) is never the right
      // one data look at anyway.
      LogI(kClassName, __func__,
           "***  index %" PRIu16 " | %f + %f i |  norm = %f "
           "| index/T = %f s | period = %f usec \n",
           i,
           fft_output_[i][0], fft_output_[i][1],
           norm/1e6,
           (static_cast<double>(i)*1e6)/time_span_usec,
           static_cast<double>(time_span_usec) / i);
    }
  }
  if (max_norm_index == 0)
  {
    LogD(kClassName, __func__,
         "Max norm index is 0. That's weird except during start-up.\n");
    have_usable_period_ = false;
    return;
  }
  // Period in seconds is 1/frequency * sample time in seconds. (We want
  // usec.)
  new_computed_period_usec = time_span_usec / max_norm_index;
  if (WouldLogI(kClassName))
  {
    LogI(kClassName, __func__,
         "New FFT results (time span %" PRId64 " usec): Max considered "
         "norm = %f, at index = %" PRIu16 ", period = %" PRIu64 " usec.\n",
         time_span_usec, max_norm, max_norm_index, new_computed_period_usec);
    if (max_norm_low_freq_index != 0)
    {
      LogI(kClassName, __func__, "Max norm with frequency too low to use = %f, "
           "at index = %" PRIu16 ", period = %" PRIu64 " usec.\n",
           max_norm_low_freq, max_norm_low_freq_index,
           time_span_usec / max_norm_low_freq_index);
    }
  }

  // We want to use the newly-computed period if the max norm usuable period
  // has enough energy OR if the max norm usable period is close enough to the
  // overall max norm. This effectively ignores tiny fluctuations that are
  // totally overshadowed by large fluctuations.
  update_period = ((max_norm > kEnergyThreshold) ||
                   (max_norm > max_norm_low_freq * kEnergyFraction));
  have_usable_period_ = have_usable_period_ || update_period;

  if (update_period)
  {
    // Interpolation helps if we didn't have enough samples to exactly capture
    // the right frequency.
    if (kDoInterpolation)
    {
      Interpolate(new_computed_period_usec, max_norm_index, time_span_usec);
    }
    oscillation_period_usec_ = new_computed_period_usec;
  }

  LogI(kClassName, __func__, "Period is usable? %c\n",
       (update_period ? 'Y' : 'N'));

#ifdef XPLOT
  if (qd_xplot_ && kGraphPeriods)
  {
    // Usable periods are graphed in colors GREEN, RED, BLUE, and YELLOW.
    // Non-usable periods are graphed in colors PURPLE, ORANGE, MAGENTA, and
    // PINK.
    uint8_t color = next_color_ + 1;
    if (!update_period)
    {
      color += 4;
    }
    uint64_t t =
      fft_input_times_[last_index].GetTimeInUsec() - iron::kStartTime;
    int64_t  y = qd_xplot_->max_y();
    // This log message can help trace back to how the FFT results looked for
    // a particular period displayed on the graph.
    // The graph includes 4 lines for each computed period. One at the start
    // of the sample set, and then three evenly spaced showing the computed
    // period.
    LogI(kClassName, __func__,
         "Printing periods in color %d, compute time %" PRId64 "\n",
         color, t);
    qd_xplot_->DrawLine(t, 0, t, y, static_cast<XPLOT_COLOR>(color));
    t -= new_computed_period_usec;
    qd_xplot_->DrawLine(t, 0, t, y, static_cast<XPLOT_COLOR>(color));
    t -= new_computed_period_usec;
    qd_xplot_->DrawLine(t, 0, t, y, static_cast<XPLOT_COLOR>(color));
    t = fft_input_times_[next_index_].GetTimeInUsec() - iron::kStartTime;
    qd_xplot_->DrawLine(t, 0, t, y, static_cast<XPLOT_COLOR>(color));
    next_color_ = ((next_color_ + 1) % 4);
  }
#endif // XPLOT
}

//============================================================================
void QueueDepthOsc::Interpolate(
  uint64_t& computed_period_usec, uint16_t used_index, int64_t time_span_usec)
{
  if (used_index + 1 < (fft_sample_size_ + 2) / 2)
  {
    // Second order lagrange interpolator to get a finer grained estimate,
    // using one sample on either side of the peak index.
    //
    // f1 = peak index - 1, f2 = peak index, f3 = peak index + 1
    // q1 = val(f1), q2 = val(f2), q3 = val(f3)

    double norm =
      (fft_output_[used_index][0] * fft_output_[used_index][0])
      + (fft_output_[used_index][1] * fft_output_[used_index][1]);

    double norm_above =
      (fft_output_[used_index + 1][0] * fft_output_[used_index + 1][0])
      + (fft_output_[used_index + 1][1] * fft_output_[used_index + 1][1]);

    double norm_below =
      (fft_output_[used_index - 1][0] * fft_output_[used_index - 1][0])
      + (fft_output_[used_index - 1][1] * fft_output_[used_index - 1][1]);


    // denominator = (f1 - f2) * (f1 - f3) * (f2 - f3) = -2
    // a = ((f3 * (q2 - q1)) + (f2 * (q1 - q3)) + (f1 * (q3 - q2)))
    //      / denominator
    // b = ((f3^2 * (q1 - q2)) + (f2^2 * (q3 - q1)) + (f1^2 * (q2 - q3)))
    //      / denominator
    // c = ((f2 * f3 * (f2 - f3) * q1) + (f3 * f1 * (f3 - f1) * q3)
    //     + (f1 * f2 * (f1 - f2) * q3))

    // The interpolator fits a quadratic of the form q = af^2 + bf + c
    // Hence the estimated peak location should be when dq/df = 2af + b = 0,
    // which implies the estimated peak location (i.e., estimated frequency)
    // should be at f = -b/2a
    //
    // The estimated peak value is a(-b/2a)^2 + b(-b/2a) + c = -b^2/4a + c,
    // but this is unused.
    double f2 = static_cast<double>(used_index);
    // Note that denominator of a = -2, so multiplying the numerator by -1
    // effectively multiplies a by 2.
    double a_times_2 =
      (((f2 + 1) * (norm - norm_below))
       + (f2 * (norm_below - norm_above))
       + ((f2 - 1) * (norm_above - norm)))
      * -1;
    // Similarly, dividing the numerator of b by 2 is the same as multiplying
    // all of b by -1, since the denominator of b is -2.
    double neg_b =
      (((f2 + 1) * (f2 + 1) * (norm_below - norm))
       + (f2 * f2 * (norm_above - norm_below))
       + ((f2 - 1) * (f2 - 1) * (norm - norm_above))
       ) / 2;

    double frequency = neg_b / a_times_2;
    computed_period_usec =
      static_cast<uint64_t>(static_cast<double>(time_span_usec) / frequency);
  }
}

//============================================================================
QueueDepthOscConfig::QueueDepthOscConfig()
    : fft_sample_size(kDefaultSampleSize),
      fft_sample_time_interval_secs(kDefaultSampleTimeSecs),
      fft_compute_time_interval_secs(kDefaultFftComputeTimeSecs),
      max_considered_period_secs(kDefaultMaxConsideredPeriodSecs),
      min_time_between_resets_secs(kDefaultMinTimeBetweenResetsSecs),
      reset_trigger_fraction(kDefaultResetTriggerFraction),
      reset_trigger_sample_count(
        kDefaultResetTriggerTimeSecs / kDefaultSampleTimeSecs),
      use_soft_reset(kDefaultSoftReset)
{
}

//============================================================================
QueueDepthOscConfig::QueueDepthOscConfig(const QueueDepthOscConfig& other)
    : fft_sample_size(other.fft_sample_size),
      fft_sample_time_interval_secs(other.fft_sample_time_interval_secs),
      fft_compute_time_interval_secs(other.fft_compute_time_interval_secs),
      max_considered_period_secs(other.max_considered_period_secs),
      min_time_between_resets_secs(other.min_time_between_resets_secs),
      reset_trigger_fraction(other.reset_trigger_fraction),
      reset_trigger_sample_count(other.reset_trigger_sample_count),
      use_soft_reset(other.use_soft_reset)
{
}

//============================================================================
QueueDepthOscConfig& QueueDepthOscConfig::operator=(
  const QueueDepthOscConfig& other)
{
  fft_sample_size                = other.fft_sample_size;
  fft_sample_time_interval_secs  = other.fft_sample_time_interval_secs;
  fft_compute_time_interval_secs = other.fft_compute_time_interval_secs;
  max_considered_period_secs     = other.max_considered_period_secs;
  min_time_between_resets_secs   = other.min_time_between_resets_secs;
  reset_trigger_fraction         = other.reset_trigger_fraction;
  reset_trigger_sample_count     = other.reset_trigger_sample_count;
  use_soft_reset                 = other.use_soft_reset;
  return *this;
}

//============================================================================
QueueDepthOscConfig::~QueueDepthOscConfig()
{
}

//============================================================================
bool QueueDepthOscConfig::Initialize(const ConfigInfo& config_info)
{
  fft_sample_size                 = static_cast<uint16_t>(
    config_info.GetUint("Bpf.Osc.FftSampleSize", kDefaultSampleSize));
  if (fft_sample_size == 0)
  {
    LogF(kClassName, __func__,
         "Misconfiguration. Bpf.Osc.FftSampleSize cannot be 0\n.");
    return false;
  }
  fft_sample_time_interval_secs   = config_info.GetDouble(
    "Bpf.Osc.FftSampleTimeSecs", kDefaultSampleTimeSecs);
  if (fft_sample_time_interval_secs == 0)
  {
    LogF(kClassName, __func__,
         "Misconfiguration. Bpf.Osc.FftSampleTimeSecs cannot be 0.\n");
    return false;
  }

  fft_compute_time_interval_secs  = config_info.GetDouble(
    "Bpf.Osc.FftComputeTimeSecs", kDefaultFftComputeTimeSecs);

  max_considered_period_secs      = config_info.GetDouble(
    "Bpf.Osc.MaxConsideredPeriodSecs", kDefaultMaxConsideredPeriodSecs);

  min_time_between_resets_secs    = config_info.GetDouble(
    "Bpf.Osc.MinTimeBetweenResetsSecs", kDefaultMinTimeBetweenResetsSecs);

  reset_trigger_fraction          = config_info.GetDouble(
    "Bpf.Osc.ResetTriggerFraction", kDefaultResetTriggerFraction);

  double reset_trigger_time_secs  = config_info.GetDouble(
    "Bpf.Osc.ResetTriggerTimeSecs", kDefaultResetTriggerTimeSecs);
  reset_trigger_sample_count      =
    reset_trigger_time_secs / fft_sample_time_interval_secs;

  use_soft_reset                  = config_info.GetBool(
    "Bpf.Osc.UseSoftReset", kDefaultSoftReset);

  LogC(kClassName, __func__,
       "Bpf.Osc.FftSampleSize                    : %" PRIu16 "\n",
       fft_sample_size);
  LogC(kClassName, __func__,
       "Bpf.Osc.Bpf.Osc.FftSampleTimeSecs        : %f\n",
       fft_sample_time_interval_secs);
  LogC(kClassName, __func__,
       "Bpf.Osc.Bpf.Osc.FftComputeTimeSecs       : %f\n",
       fft_compute_time_interval_secs);
  LogC(kClassName, __func__,
       "Bpf.Osc.Bpf.Osc.MaxConsideredPeriodSecs  : %f\n",
       max_considered_period_secs);
  LogC(kClassName, __func__,
       "Bpf.Osc.Bpf.Osc.MinTimeBetweenResetsSecs : %f\n",
       min_time_between_resets_secs);
  LogC(kClassName, __func__,
       "Bpf.Osc.Bpf.Osc.ResetTriggerFraction     : %f\n",
       reset_trigger_fraction);
  LogC(kClassName, __func__,
       "Bpf.Osc.Bpf.Osc.ResetTriggerTimeSecs     : %f\n",
       reset_trigger_time_secs);
  LogC(kClassName, __func__,
       "Reset trigger sample count               : %" PRIu16 "\n",
       reset_trigger_sample_count);
  LogC(kClassName, __func__,
       "Bpf.Osc.UseSoftReset                     : %s\n",
       (use_soft_reset ? "true" : "false"));
  LogC(kClassName, __func__,
       "Energy Threshold                         : %" PRIu32 "\n",
       kEnergyThreshold);
  LogC(kClassName, __func__,
       "Energy Fraction                          : %f\n",
       kEnergyFraction);
  LogC(kClassName, __func__,
       "Do Interpolation                         : %s\n",
       (kDoInterpolation ? "true" : "false"));

  return true;
}
