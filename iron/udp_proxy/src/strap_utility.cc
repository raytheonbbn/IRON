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

#include "strap_utility.h"
#include "config_info.h"
#include "itime.h"
#include "iron_constants.h"
#include "k_val.h"
#include "string_utils.h"
#include "unused.h"

#include <algorithm>
#include <list>

#include <inttypes.h>

using ::iron::ConfigInfo;
using ::iron::KVal;
using ::iron::StringUtils;
using ::iron::StrapUtility;
using ::iron::UtilityFn;
using std::list;
using std::string;

namespace
{
  /// Class name for logging.
  const char*     UNUSED(kClassName)        = "StrapUtility";

  /// The default restart interval: 6s.
  const double    kDefaultResIntSec         = 6.0;

  /// The default number of steps: 8.
  const int       kDefaultNSteps            = 8;

  /// The default step interval: 5ms.
  const double    kDefaultStepIntSec        = 0.01;

  /// The default averaging interval: 200ms.
  const double    kDefaultAvgIntSec         = 0.2;

  /// The default priority: 1.
  const int       kDefaultPriority          = 1;

  /// The minimum interval over which the nominal rate is updated.
  const double    kMIntervalSec             = 0.1;

  /// The default amount by which inertia is increased.
  const double    kInertiaInc               = 0.05;
}

class EncodingState;

//============================================================================
StrapUtility::StrapUtility(SrcRateEstimator& src_rate_estimator,
                           SrcInfo& src_info, QueueDepths& queue_depths,
                           BinIndex bin_idx, KVal& k_val, uint32_t flow_id)
    : UtilityFn(queue_depths, bin_idx, flow_id),
      src_rate_estimator_(src_rate_estimator),
      src_info_(src_info),
      k_val_(k_val),
      delta_(iron::kDefaultMaxLossThreshold),
      penalty_(0.0),
      time_interval_end_(0),
      avg_interval_sec_(0.0),
      step_interval_sec_(0.0),
      restart_interval_sec_(0.0),
      n_steps_(1),
      curr_step_(1),
      current_utility_(0),
      rng_(),
      strap_timer_tag_(0),
      scale_factor_(1),
      inertia_(kInertiaInc),
      max_queue_depths_(0),
      max_queue_time_ms_(0),
      admitted_seq_num_(0),
      last_admitted_seq_num_(0),
      acked_seq_num_(0),
      last_acked_seq_num_(0),
      curr_loss_rate_pct_(0),
      time_to_go_(iron::Time(0)),
      last_step_time_(iron::Time(0)),
      last_acked_time_(iron::Time(0))
{
  Time now;
  if (!now.GetNow())
  {
    LogF(kClassName, __func__, "Failed to get current time\n");
  }
  rng_.SetSeed((now.GetTimeInUsec()%1000)*1000);
}

//============================================================================
StrapUtility::~StrapUtility()
{
  // Nothing to destroy.
}

//============================================================================
bool StrapUtility::Initialize(const ConfigInfo& ci)
{
  Time now              = Time::Now();
  p_val_                = ci.GetDouble("p", kDefaultPriority, false);
  scale_factor_         = ((2*p_val_) + 10)/(p_val_ + 10);
  delta_                = ci.GetDouble("delta", kDefaultMaxLossThreshold,
                                       false);
  restart_interval_sec_ = ci.GetDouble("resint",
                                       kDefaultResIntSec,
                                       false)/scale_factor_;
  n_steps_              = ci.GetInt("nsteps", kDefaultNSteps, false);
  step_interval_sec_    = ci.GetDouble("stepint", kDefaultStepIntSec, false);
  avg_interval_sec_     = (ci.GetDouble("avgint", kDefaultAvgIntSec, false) +
                          rng_.GetDouble(0.02))*scale_factor_;
  int ttg_usec          = ci.GetInt("ttg", 0, false);
  time_to_go_           = Time::FromUsec(ttg_usec);
  inertia_              = ci.GetDouble("inertia", kInertiaInc, false);

  if (ttg_usec > 0)
  {
    avg_interval_sec_ = 6 * static_cast<double>(ttg_usec)/1000000.0;
  }
  time_interval_end_    = now.GetTimeInUsec() + avg_interval_sec_*1000000;
  last_step_time_       = now;
  last_acked_time_      = now;

  // Make sure that the is more than 0 steps.
  if (n_steps_ == 0)
  {
    n_steps_ = kDefaultNSteps;
    LogW(kClassName, __func__, "STRAP utility configured with 0 steps, "
      "using default value instead\n");
  }

  LogC(kClassName, __func__, "STRAP configuration   :\n");
  LogC(kClassName, __func__, "flow id              : %" PRIu32 "\n", flow_id_);
  LogC(kClassName, __func__, "k                    : %.2e\n",
       static_cast<double>(k_val_.GetValue()));
  LogC(kClassName, __func__, "p                    : %.03f\n", p_val_);
  LogC(kClassName, __func__, "scale factor         : %.03f\n", scale_factor_);
  LogC(kClassName, __func__, "delta                : %.03f\n", delta_);
  LogC(kClassName, __func__, "Interval length      : %.03f\n",
       avg_interval_sec_);
  LogC(kClassName, __func__, "Step duration        : %.03f\n",
       step_interval_sec_);
  LogC(kClassName, __func__, "Number steps         : %" PRIu8 "\n", n_steps_);
  LogC(kClassName, __func__, "Restart interval     : %.03f\n",
       restart_interval_sec_);
  LogC(kClassName, __func__, "Time to go           : %s\n",
       time_to_go_.ToString().c_str());
  LogC(kClassName, __func__, "Inertia              : %.03f\n", inertia_);
  LogC(kClassName, __func__, "STRAP configuration complete\n");

  LogI(kClassName, __func__, "STRAP initialized. Now %" PRId64 " , interval end: "
       "%" PRId64 "\n", Time::GetNowInUsec(), time_interval_end_);

  return true;
}

//==============================================================================
double StrapUtility::GetSendRate()
{
  if (flow_state_ != FLOW_ON)
  {
    LogD(kClassName, __func__, "fid: %" PRIu32 ", is off\n", flow_id_);
    return 0.0;
  }

  double current_backlog   = src_info_.cur_backlog_bytes() * 8;
  return (static_cast<double>(curr_step_)/n_steps_)*
              (current_backlog*1000000);

}
//==============================================================================
double StrapUtility::GetAdmFrac()
{
  if (flow_state_ != FLOW_ON)
  {
    LogD(kClassName, __func__, "fid: %" PRIu32 ", is off\n", flow_id_);
    return 0.0;
  }

  uint32_t cur_qd  = queue_depths_.GetBinDepthByIdx(bin_idx_);
  if (cur_qd > max_queue_depths_)
  {
    max_queue_depths_  = cur_qd;
    max_queue_time_ms_ = Time::GetNowInUsec();
  }

  return static_cast<double>(curr_step_)/n_steps_;
}

//==============================================================================
void StrapUtility::Step()
{
  if (flow_state_ != FLOW_ON)
  {
    return;
  }

  LogD(kClassName, __func__, "Last acked pkt: %" PRIu32 ", curr loss rate: %"
       PRIu32 "\n", acked_seq_num_, curr_loss_rate_pct_);

  // If we don't yet have an average of the nominal rate, use a small rate
  // to avoid incurring penalty until we have a better handle on the rate.
  double nom_rate  = std::max(1.0, src_rate_estimator_.avg_src_rate());
  uint32_t cur_qd  = queue_depths_.GetBinDepthByIdx(bin_idx_);
  Time now         = Time::Now();

  LogD(kClassName, __func__, "Checking Step for flow % " PRIu32 
        " cur step: % " PRIu8 " \n", flow_id_, curr_step_);

  // If the queues are large, then we should not be sending. We do this
  // gradually by stepping down rather than stopping. If the queues are
  // less tham the k*p/m threshold, then we should step up.
  if (cur_qd * 8 > k_val_.GetValue() *
                   p_val_ / (nom_rate * (1 - (delta_*inertia_))))
  {
    curr_step_ = std::max(0,curr_step_-1);
    LogD(kClassName, __func__, "Flow %" PRIu32 " Stepping down to %" PRIu8
      ", using m=%f, inertia=%f.\n", flow_id_, curr_step_, nom_rate, inertia_);

    // Incur penalty if the backlog is growning.
    penalty_ += std::max(0.0, (1.0 - GetAdmFrac()) * step_interval_sec_);
  }
  else if (time_to_go_.IsZero() || !enable_loss_triage())
  {
    curr_step_    = std::min(static_cast<int>(n_steps_), curr_step_ + 1);
    LogD(kClassName, __func__, "Stepping up to %" PRIu8 ", using m=%f.\n",
       curr_step_, nom_rate);
  }
  else if ((now - last_step_time_) > time_to_go_)
  {
    if (curr_loss_rate_pct_ > (delta_*inertia_*100))
    {
      curr_step_ = std::max(0,curr_step_-1);
      LogD(kClassName, __func__, "Flow %" PRIu32 " Stepping down to %" PRIu8
           ", using m=%f, inertia=%f due to loss %u.\n",
           flow_id_, curr_step_, nom_rate, inertia_, curr_loss_rate_pct_);

      // Incur penalty if the backlog is growning.
      penalty_ += std::max(0.0, (1.0 - GetAdmFrac()) * 2 *
                  (static_cast<double>(time_to_go_.GetTimeInUsec())/1000000));
    }
    else
    {
      curr_step_    = std::min(static_cast<int>(n_steps_), curr_step_ + 1);
    }
    if (last_acked_seq_num_ < acked_seq_num_)
    {
      last_acked_time_ = now;
    }

    last_step_time_        = now;
    last_acked_seq_num_    = acked_seq_num_;
    last_admitted_seq_num_ = admitted_seq_num_;

  }

  double UNUSED(send_rate) = (static_cast<float>(curr_step_)/
                                static_cast<float>(n_steps_))*nom_rate;

  LogD(kClassName, __func__,
       "At step %" PRIu8 ", for tag %" PRIu32 ", with queue %" PRIu8 
       "B, rate %f.\n",
       curr_step_, flow_id_, cur_qd, send_rate);

  // This output is for the netanim trace parser.
  LogD(kClassName, __func__,
       "f_id: %" PRIu32 ", queue: %" PRIu32 "b, rate: %.03fbps, "
       "step:%" PRIu8 "\n", flow_id_, cur_qd*8, send_rate,
       curr_step_);
}

//==============================================================================
bool StrapUtility::CheckUtility()
{
  if (flow_state_ != FLOW_ON)
  {
    LogD(kClassName, __func__, "flow %" PRIu32 " is off\n", flow_id_);
    return false;
  }

  Time now;
  if (!now.GetNow())
  {
    LogF(kClassName, __func__, "Failed to get current time\n");
    return false;
  }
 
  double max_penalty = delta_ * inertia_ * avg_interval_sec_;

  LogD(kClassName, __func__, "Flow %" PRIu32 ", penalty now: %f, inertia: %f\n",
                             flow_id_, penalty_, inertia_);

  if (penalty_ > max_penalty)
  {
    if (curr_loss_rate_pct_ > delta_*inertia_*100)
    {
      flow_state_ = LOSS_TRIAGED;
    }
    else
    {
      flow_state_ = FLOW_TRIAGED;
    }
    current_utility_ = 0;
    return true;
  }
  else
  {
    // The flow is being properly serviced, we get full utility and
    // increased inertia.
    current_utility_ = p_val_;
  }

  // Reset the counters if the averaging interval has ended.
  if (now.GetTimeInUsec() > time_interval_end_)
  {
    penalty_           = 0;
    time_interval_end_ = now.GetTimeInUsec() + (avg_interval_sec_ * 1000000);
    if (max_queue_time_ms_ <
        (now.GetTimeInUsec() - (avg_interval_sec_ * 1000000)))
    {
      inertia_           = std::min(1.0, inertia_ + kInertiaInc);
    }
  }
  return false;
}

//==============================================================================
void StrapUtility::SetFlowOn()
{
  Time now = Time::Now();

  // If the flow is already on, we don't need to do anything.
  if (flow_state_ == FLOW_ON)
  {
    LogW(kClassName, __func__, "Attempt to turn on flow %" PRIu32
         " but it is already on.\n", flow_id_);
    return;
  }

  LogD(kClassName, __func__, "Turning flow %" PRIu32 " on.\n", flow_id_);

  flow_state_         = FLOW_ON;
  curr_step_          = 1;
  penalty_            = 0;
  curr_loss_rate_pct_ = 0;
}

//==============================================================================
void StrapUtility::SetAvgIntervalEnd()
{
  Time now            = Time::Now();
  time_interval_end_  = now.GetTimeInUsec() + (avg_interval_sec_*1000000);
}
