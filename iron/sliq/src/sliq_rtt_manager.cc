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

#include "sliq_rtt_manager.h"
#include "sliq_connection.h"
#include "sliq_private_defs.h"

#include "log.h"
#include "unused.h"

#include <cstdlib>
#include <inttypes.h>
#include <math.h>


using ::sliq::RttManager;
using ::iron::Log;
using ::iron::Time;


namespace
{
  /// Class name for logging.
  const char*   UNUSED(kClassName) = "RttManager";

  /// Initial smoothed RTT used before any samples are received, per RFC 6298.
  const int          kInitialRttMsec    = 1000;

  /// Initial RTO used before any samples are received, per RFC 6298.
  const int          kInitialRtoMsec    = 1000;

  /// The mimimum allowable RTO in milliseconds.  Note that RFC 6298 specifies
  /// that this should be set to 1 second, but this uses 200 milliseconds to
  /// be more aggressive.
  const int          kMinRtoMsec        = 200;

  /// The RTO tolerance in microseconds.
  const suseconds_t  kRtoToleranceUsec  = 4000;

  /// The gain, g, used to compute the smoothed RTT.  Set to 1/8 (0.125) per
  /// RFC 6298.
  const double       kAlpha             = 0.125;

  /// One minus the alpha parameter.
  const double       kOneMinusAlpha     = (1.0 - kAlpha);

  /// The gain, h, used to compute the mean deviation.  Set to 1/4 (0.25) per
  /// RFC 6298.
  const double       kBeta              = 0.25;

  /// One minus the beta parameter.
  const double       kOneMinusBeta      = (1.0 - kBeta);

  /// The smoothed RTT alpha parameter for the max/min filter.
  const double       kMmfAlpha          = 0.01;
}

//============================================================================
RttManager::RttManager()
    : initialized_(false),
      srtt_(0.0),
      srtt_obj_(0, 0),
      mdev_(0.0),
      mdev_obj_(0, 0),
      mmf_interval_srtt_(0.0),
      mmf_rtt_(),
      mmf_owd_(),
      latest_rtt_(0, 0)
{
  srtt_obj_ = Time::FromMsec(kInitialRttMsec);
  srtt_     = srtt_obj_.ToDouble();
}

//============================================================================
RttManager::~RttManager()
{
  // Nothing to destroy.
}

//============================================================================
void RttManager::ConfigureRttOutlierRejection(bool enable_ror)
{
  mmf_rtt_.outlier_rejection_ = enable_ror;
}

//============================================================================
void RttManager::UpdateRtt(const Time& now, EndptId conn_id,
                           const Time& rtt_sample)
{
  // Get the RTT sample value as a double in seconds, and make sure that it is
  // a valid RTT sample.
  double  rtt_val = rtt_sample.ToDouble();

  if (rtt_val <= 0.0)
  {
    return;
  }

  // Store the latest RTT sample.
  latest_rtt_ = rtt_sample;

  // Next, update the smoothed RTT and the RTT's smoothed mean deviation.
  if (!initialized_)
  {
    // This is the first RTT sample received.  Update following RFC 6298.
    srtt_     = rtt_val;
    srtt_obj_ = rtt_sample;
    mdev_     = (0.5 * rtt_val);
    mdev_obj_ = Time(mdev_);

    // Initialize the max/min filter smoothed RTT value.
    mmf_interval_srtt_ = rtt_val;

    initialized_ = true;
  }
  else
  {
    // This is a subsequent RTT sample.  Update following RFC 6298.
    mdev_     = ((kOneMinusBeta * mdev_) + (kBeta * fabs(srtt_ - rtt_val)));
    mdev_obj_ = Time(mdev_);
    srtt_     = ((kOneMinusAlpha * srtt_) + (kAlpha * rtt_val));
    srtt_obj_ = Time(srtt_);

    // Update the max/min filter smoothed RTT value.
    mmf_interval_srtt_ = (((1.0 - kMmfAlpha) * mmf_interval_srtt_) +
                          (kMmfAlpha * rtt_val));
  }

  // Pass the updated max/min filter smoothed RTT value into the filters.
  mmf_rtt_.interval_srtt_ = mmf_interval_srtt_;
  mmf_owd_.interval_srtt_ = mmf_interval_srtt_;

  // Update the max/min filter for RTTs.
  mmf_rtt_.Update(now, rtt_val);

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": RTT sample %f srtt %f "
       "mdev %f min %f max %f.\n", conn_id, rtt_val, srtt_, mdev_,
       mmf_rtt_.min_est_, mmf_rtt_.max_est_);
#endif
}

//============================================================================
void RttManager::UpdateRmtToLocOwd(const Time& now, EndptId conn_id,
                                   const Time& rtl_owd_sample)
{
  // The UpdateRtt() method must have initialized the object before this
  // method can do anything, as a valid RTT sample is required here.
  if (!initialized_)
  {
    return;
  }

  // Get the OWD sample value as a double in seconds, and make sure that it is
  // a valid OWD sample.
  double  owd_val = rtl_owd_sample.ToDouble();

  if (owd_val <= 0.0)
  {
    return;
  }

  // Update the max/min filter for OWDs.
  mmf_owd_.Update(now, owd_val);

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": OWD sample %f min %f max "
       "%f.\n", conn_id, owd_val, mmf_owd_.min_est_, mmf_owd_.max_est_);
#endif
}

//============================================================================
Time RttManager::GetRtoTime() const
{
  // Until a RTT measurement has been made, the RTO should be set to 1 second.
  // See RFC 6298.
  if (!initialized_)
  {
    return Time::FromMsec(kInitialRtoMsec);
  }

  // The RTO is the smoothed RTT plus 4 times the RTT mean deviation.  Since
  // ACKs can be delayed at the receiver, include that time too.
  double  ack_del = (0.000001 * static_cast<double>(kAckTimerUsec +
                                                    kRtoToleranceUsec));
  double  rto_val = (srtt_ + (4.0 * mdev_) + ack_del);

  // Round up to a mimimum allowable RTO.  See RFC 6298.
  double  min_rto = (0.001 * static_cast<double>(kMinRtoMsec));

  if (rto_val < min_rto)
  {
    rto_val = min_rto;
  }

  return Time(rto_val);
}

//============================================================================
Time RttManager::GetRexmitTime(int multiplier) const
{
  // Until a RTT measurement has been made, the retransmission time should be
  // set to 1 second.  See RFC 6298.
  if (!initialized_)
  {
    return Time::FromMsec(kInitialRtoMsec);
  }

  // The retransmission time is the smoothed RTT plus the specified multiplier
  // times the RTT mean deviation.  Since ACKs can be delayed at the receiver,
  // include that time too.
  double  k       = static_cast<double>(multiplier);
  double  ack_del = (0.000001 * static_cast<double>(kAckTimerUsec +
                                                    kRtoToleranceUsec));
  double  rxt_val = (srtt_ + (k * mdev_) + ack_del);

  return Time(rxt_val);
}

//============================================================================
Time RttManager::GetFastRexmitTime() const
{
  // Until a RTT measurement has been made, the fast retransmission time
  // should be set to 1 second.  See RFC 6298.
  if (!initialized_)
  {
    return Time::FromMsec(kInitialRtoMsec);
  }

  // The fast retransmission time is the smoothed RTT plus 4 times the RTT
  // mean deviation.
  double  frxt_val = (srtt_ + (4.0 * mdev_));

  return Time(frxt_val);
}

//============================================================================
void RttManager::MaxMinFilter::Update(const Time& now, double sample)
{
  if (!init_)
  {
    // This is the first sample received.
    init_          = true;
    curr_min_      = sample;
    curr_max_      = sample;
    curr_end_time_ = (now + Time(kMmfIntvMult * interval_srtt_));
    min_est_       = sample;
    max_est_       = sample;

    return;
  }

  // This is a subsequent sample.  Test if the current interval's end time has
  // been reached.
  if (now < curr_end_time_)
  {
    // Add the sample to the current interval.
    if (sample < curr_min_)
    {
      curr_min_ = sample;
    }

    if (sample > curr_max_)
    {
      curr_max_ = sample;
    }
  }
  else
  {
    // Complete the current interval.
    size_t  next_idx = ((prev_end_idx_ + 1) % kNumMmfIntv);

    prev_min_[next_idx] = curr_min_;
    prev_max_[next_idx] = curr_max_;

    if (prev_cnt_ < kNumMmfIntv)
    {
      ++prev_cnt_;
    }

    prev_end_idx_ = next_idx;

    // Update the minimum and maximum value estimates.
    min_est_ = MinValue();
    max_est_ = (outlier_rejection_ ? MedianFilterMaxValue() : MaxValue());

    // Start the next interval.
    curr_min_      = sample;
    curr_max_      = sample;
    curr_end_time_ = (now + Time(kMmfIntvMult * interval_srtt_));
  }

  // Update the minimum value estimate immediately.
  if (sample < min_est_)
  {
    min_est_ = sample;
  }

  // Possibly update the maximum value estimate immediately.
  if ((!outlier_rejection_) && (sample > max_est_))
  {
    max_est_ = sample;
  }
}

//============================================================================
double RttManager::MaxMinFilter::MinValue()
{
  // Return the minimum of the previous two intervals.
  if (prev_cnt_ < 2)
  {
    return prev_min_[prev_end_idx_];
  }

  double  val_1   = prev_min_[((prev_end_idx_ + kNumMmfIntv - 1) %
                               kNumMmfIntv)];
  double  val_2   = prev_min_[prev_end_idx_];
  double  min_val = ((val_1 < val_2) ? val_1 : val_2);

  return min_val;
}

//============================================================================
double RttManager::MaxMinFilter::MaxValue()
{
  // Return the maximum of the previous two intervals.
  if (prev_cnt_ < 2)
  {
    return prev_max_[prev_end_idx_];
  }

  double  val_1   = prev_max_[((prev_end_idx_ + kNumMmfIntv - 1) %
                               kNumMmfIntv)];
  double  val_2   = prev_max_[prev_end_idx_];
  double  max_val = ((val_1 > val_2) ? val_1 : val_2);

  return max_val;
}

//============================================================================
double RttManager::MaxMinFilter::MedianFilterMaxValue()
{
  // Return the median of the previous five intervals.  Handle the easy cases
  // first.
  if (prev_cnt_ == 1)
  {
    // The median of a single value is the value.
    return prev_max_[prev_end_idx_];
  }

  if (prev_cnt_ == 2)
  {
    // The median of two values is the average of the two values.
    return ((prev_max_[((prev_end_idx_ + kNumMmfIntv - 1) % kNumMmfIntv)] +
             prev_max_[prev_end_idx_]) * 0.5);
  }

  // There are 3, 4, or 5 previous interval maximum values.  Copy the previous
  // maximum values into another array that can be sorted.
  size_t  i         = 0;
  size_t  idx       = 0;
  size_t  start_idx = ((prev_end_idx_ + kNumMmfIntv + 1 - prev_cnt_) %
                       kNumMmfIntv);
  size_t  num       = prev_cnt_;
  double  buf[kNumMmfIntv];

  for (i = 0, idx = start_idx; i < num; ++i, idx = ((idx + 1) % kNumMmfIntv))
  {
    buf[i] = prev_max_[idx];
  }

  // Sort the copied values.  Since this is such a small array, just use
  // bubblesort.  The worst case (num=5 with reversed values) requires 5
  // loops, 10 value swaps, and 20 value comparisons.
  bool    sorted = false;
  double  tmp    = 0.0;

  while (!sorted)
  {
    sorted = true;

    for (i = 1; i < num; ++i)
    {
      if (buf[i] < buf[i - 1])
      {
        tmp        = buf[i];
        buf[i]     = buf[i - 1];
        buf[i - 1] = tmp;
        sorted     = false;
      }
    }
  }

  // Return the median of the sorted array.
  if ((num % 2) == 0)
  {
    // There is an even number of values.  Return an average of the middle
    // two elements in the array.
    tmp = ((buf[(num / 2) - 1] + buf[num / 2]) * 0.5);
  }
  else
  {
    // There is an odd number of values.  Return the middle element in the
    // array.
    tmp = buf[num / 2];
  }

  return tmp;
}
