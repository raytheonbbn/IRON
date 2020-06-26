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

#include "flog_utility.h"
#include "config_info.h"
#include "itime.h"
#include "iron_constants.h"
#include "k_val.h"
#include "string_utils.h"
#include "unused.h"

#include <algorithm>
#include <list>

#include <inttypes.h>
#include "math.h"

using ::iron::ConfigInfo;
using ::iron::KVal;
using ::iron::StringUtils;
using ::iron::FlogUtility;
using ::iron::UtilityFn;
using std::list;
using ::std::min;
using std::string;

namespace
{
  /// Class name for logging.
  const char*     UNUSED(kClassName)        = "FlogUtility";

  /// The default maximum queuing latency.
  const double    kDefaultMaxLatencySec     = 1.0;

  /// The default averaging interval: 50ms.
  const double    kDefaultIntSec            = 0.1;

  /// The default priority: 1.
  const int       kDefaultPriority          = 1;

  /// The maximum send rate for the flow.
  const double    kMaxAdmRate               = 1e8;

  /// The minimum admission rate for the flow.
  const double    kDefaultMinRateBps        = 0.0;

  /// The maximum penalty a flow can incur before being triaged.
  const uint8_t   kMaxPenalty               = 15;
}

class EncodingState;

//============================================================================
FlogUtility::FlogUtility(SrcRateEstimator& src_rate_estimator,
                           SrcInfo& src_info, QueueDepths& queue_depths,
                           BinIndex bin_idx, KVal& k_val, uint32_t flow_id)
    : UtilityFn(queue_depths, bin_idx, flow_id),
      src_rate_estimator_(src_rate_estimator),
      src_info_(src_info),
      m_val_(kMaxAdmRate),
      a_val_(0.0),
      k_val_(k_val),
      min_rate_bps_(kDefaultMinRateBps),
      size_penalty_(0),
      growth_penalty_(0),
      rate_penalty_(0),
      prev_backlog_(0.0),
      prev_adm_rate_(0.0),
      int_length_sec_(kDefaultIntSec),
      time_interval_end_usec_(0),
      rng_(),
      flog_timer_tag_(0),
      scale_factor_(1),
      avg_adm_rate_bps_(0.0)
{
  Time now;
  if (!now.GetNow())
  {
    LogF(kClassName, __func__, "Failed to get current time\n");
  }
  rng_.SetSeed((now.GetTimeInUsec()%1000)*1000);
}

//============================================================================
FlogUtility::~FlogUtility()
{
  // Nothing to destroy.
}

//============================================================================
bool FlogUtility::Initialize(const ConfigInfo& ci)
{
  a_val_ = ci.GetDouble("a", 0, false);
  if (a_val_ == 0)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 ", a value not provided.\n",
         flow_id_);
    return false;
  }

  Time now             = Time::Now();
  p_val_               = ci.GetDouble("p", kDefaultPriority, false);
  scale_factor_        = ((2*p_val_) + 10)/(p_val_ + 10);
  int_length_sec_      = (ci.GetDouble("avgint", kDefaultIntSec, false))*scale_factor_;
  min_rate_bps_        = (ci.GetDouble("f", kDefaultMinRateBps, false));
  time_interval_end_usec_  = now.GetTimeInUsec() + int_length_sec_*1000000;

  LogC(kClassName, __func__, "FLOG configuration   :\n");
  LogC(kClassName, __func__, "a                    : %.03f\n", a_val_);
  LogC(kClassName, __func__, "k                    : %.2e\n",
       static_cast<double>(k_val_.GetValue()));
  LogC(kClassName, __func__, "p                    : %.03f\n", p_val_);
  LogC(kClassName, __func__, "min acceptable rate  : %.03f\n", min_rate_bps_); 
  LogC(kClassName, __func__, "scale factor         : %.03f\n", scale_factor_);
  LogC(kClassName, __func__, "Interval length      : %.03f\n",
       int_length_sec_);
  LogC(kClassName, __func__, "Min admission rate   : %.03f\n",
       min_rate_bps_);
  LogC(kClassName, __func__, "FLOG configuration complete\n");

  LogI(kClassName, __func__, "FLOG initialized. Now %" PRId64 " , interval end: "
       "%" PRId64 "\n", Time::GetNowInUsec(), time_interval_end_usec_);
  return true;
}

//==============================================================================
double FlogUtility::GetSendRate()
{
  if (flow_state_ != FLOW_ON)
  {
    LogD(kClassName, __func__, "fid: %" PRIu32 ", is off\n", flow_id_);
    return 0.0;
  }

  double  send_rate         = 0.0;
  double  queue_depth_bits  = queue_depths_.GetBinDepthByIdx(bin_idx_)*8;

  if (queue_depth_bits >= k_val_.GetValue() * p_val_ * a_val_)
  {
    LogD(kClassName, __func__, "fid: %" PRIu32 ", queue is too large, not "
         "sending.\n", flow_id_);
    send_rate = 0.0;
  }
  else if (queue_depth_bits == 0.0)
  {
    send_rate = m_val_;
  }
  else
  {
    send_rate = min((a_val_ * k_val_.GetValue() * p_val_ - queue_depth_bits) /
                    (a_val_ * queue_depth_bits), m_val_);
  }

  LogA(kClassName, __func__, "f_id: %" PRIu32 ", queue: %.03fb, rate: "
       "%.03fbps.\n", flow_id_, queue_depth_bits, send_rate);

  if (avg_adm_rate_bps_ == 0.0)
  {
    avg_adm_rate_bps_ = send_rate;
  }
  else
  {
    avg_adm_rate_bps_ = send_rate*0.2 + avg_adm_rate_bps_*0.8;
    LogD(kClassName, __func__, "Avg adm rate is %f\n", avg_adm_rate_bps_);
  }

  return send_rate;
}

//==============================================================================
bool FlogUtility::ConsiderTriage()
{
  double current_backlog   = src_info_.cur_backlog_bytes() * 8;
  double current_queue_lat = 0;

  // Incur penalty if the backlog is above a threshold and the admission
  // rate is not growing.
  if (avg_adm_rate_bps_ > 0)
  {
    current_queue_lat = current_backlog/avg_adm_rate_bps_;
      LogD(kClassName, __func__,
           "f_id: %" PRIu32 "Backlog: %f, current admission rate: %f\n",
           flow_id_, current_backlog, avg_adm_rate_bps_);

    if ((current_queue_lat > kDefaultMaxLatencySec) && 
        (avg_adm_rate_bps_ < prev_adm_rate_*1.1))
    {
      ++size_penalty_;
      LogE(kClassName, __func__, "f_id: %" PRIu32 "Backlog is too large: %f, "
                                 "given current admission rate: %f .\n",
                                 flow_id_, current_backlog, avg_adm_rate_bps_);
    }
    else
    {
      size_penalty_ = 0;
    }

    // Incur penalty if the backlog is above a threshold and is increasing.
    if ((current_queue_lat > (kDefaultMaxLatencySec)) && 
        (current_backlog > prev_backlog_))
    {
      ++growth_penalty_;
      LogD(kClassName, __func__, "f_id: %" PRIu32 "Backlog is growing: %f, "
                                 "given current admission rate: %f\n",
                                 flow_id_, current_backlog, avg_adm_rate_bps_);
    }
    else
    {
      growth_penalty_ = 0;
    }

    // Incur penalty if the admission rate is less that the minimum acceptable rate.
    if (avg_adm_rate_bps_ < min_rate_bps_)
    {
      ++rate_penalty_;
      LogD(kClassName, __func__, "f_id: %" PRIu32 "Low admission rate: %f, "
                                 "given current admission rate: %f.",
                                 flow_id_, avg_adm_rate_bps_, min_rate_bps_);
    }
    else
    {
      rate_penalty_ = 0;
    }
  }
  
  prev_backlog_  = current_backlog;
  prev_adm_rate_ = avg_adm_rate_bps_;
  if ((size_penalty_ > kMaxPenalty) || (growth_penalty_ > kMaxPenalty ) || 
      (rate_penalty_ > kMaxPenalty ))
  {
    flow_state_ = FLOW_TRIAGED;
    LogD(kClassName, __func__, "Triage of flow: %" PRIu32 "\n", flow_id_);
    return true;
  } 
  
  return false;
}

//==============================================================================
void FlogUtility::SetFlowOn()
{
  Time now = Time::Now();

  // If the flow is already on, we don't need to do anything.
  if (flow_state_ == FLOW_ON)
  {
    LogW(kClassName, __func__, "Attempt to turn on flow %" PRIu32
         " but it is already on.\n", flow_id_);
    return;
  }

  LogD(kClassName, __func__, "Turning flow %" PRIu32 " ON.\n", flow_id_);
  flow_state_ = FLOW_ON;

  time_interval_end_usec_   = now.GetTimeInUsec() + int_length_sec_*1000000;
}

//==========================================================================
double FlogUtility::ComputeUtility(double send_rate)
{
  if (a_val_ * send_rate <= -1)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 ", Error: Cannot take log "
         "of negative value a*r + 1 = %.3f.\n", flow_id_,
         a_val_ * send_rate + 1);
    return 0;
  }

  // utility = p * log(ar + 1)
  return p_val_ * log(a_val_ * send_rate + 1);
}

