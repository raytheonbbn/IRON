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

#include "src_rate_estimator.h"
#include "itime.h"
#include "log.h"
#include "unused.h"

using ::iron::Time;

namespace
{
  /// Class name for logging.
  const char*  UNUSED(kClassName) = "SrcRateEstimator";
  
  /// The weight of the current measurement used in the EWMA of the source rate.
  const double kCurWeight = 0.1;

  /// The minimum interval over which packets are aggregated to
  /// compute the source rate.
  const uint32_t kRateCompIntervalUsec = 200000;

  /// The startup release rate, in bits per seconds. This is used until
  /// there is enough information to estimate the source rate.
  const double kStartUpAvgSrcRate = 1e3;
}

//============================================================================
SrcRateEstimator::SrcRateEstimator()
    : rate_comp_ttg_usec_(0),
      rate_comp_bytes_(0),
      avg_src_rate_(0.0)
{
}

//============================================================================
SrcRateEstimator::~SrcRateEstimator()
{
  // Nothing to destroy.
}

//============================================================================
void SrcRateEstimator::UpdateRate(uint64_t bytes_sourced, uint64_t ttg)
{
  Time  now             = Time::Now();
  uint64_t pkt_exp_time = now.GetTimeInUsec() + ttg;
  if (rate_comp_ttg_usec_ == 0)
  {
    rate_comp_ttg_usec_ = now.GetTimeInUsec() + ttg;
    rate_comp_bytes_    = bytes_sourced;
    avg_src_rate_       = kStartUpAvgSrcRate;
    return;
  }
  else if (bytes_sourced < rate_comp_bytes_)
  {
    // This is an out-of-order packet and we have already considered a
    // later packet in the rate computation.
    // Note: This will not work if we allow bytes_sourced to
    // wrap in the future.
    return;
  }

  if ((pkt_exp_time) > (rate_comp_ttg_usec_ + kRateCompIntervalUsec))
  {
    uint64_t  new_bytes    = bytes_sourced - rate_comp_bytes_;
    uint64_t  current_rate = new_bytes * 8 * 1000000/
      (pkt_exp_time - rate_comp_ttg_usec_);

    if (avg_src_rate_ == 0)
    {
      // The first time we compute a rate, there is no history.
      avg_src_rate_ = current_rate;
    }
    else
    {
      avg_src_rate_ = current_rate * kCurWeight +
        avg_src_rate_ * (1 - kCurWeight);
    }

    rate_comp_ttg_usec_ = pkt_exp_time;
    rate_comp_bytes_    = bytes_sourced;
    LogD(kClassName, __func__, "Average source rate: %f\n", avg_src_rate_);
  }
}

//============================================================================
double SrcRateEstimator::avg_src_rate()
{
  if (avg_src_rate_ > 0)
  {
    return avg_src_rate_;
  }
  else
  {
    return kStartUpAvgSrcRate;
  }
}
