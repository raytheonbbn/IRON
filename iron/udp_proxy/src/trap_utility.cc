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

#include "trap_utility.h"
#include "config_info.h"
#include "itime.h"
#include "k_val.h"
#include "string_utils.h"
#include "unused.h"

#include <algorithm>
#include <list>

#include <inttypes.h>

using ::iron::ConfigInfo;
using ::iron::KVal;
using ::iron::StringUtils;
using ::iron::TrapUtility;
using ::iron::UtilityFn;
using std::list;
using std::string;

namespace
{
  /// Class name for logging.
  const char*     UNUSED(kClassName)  = "TrapUtility";

  /// The default restart interval: 6s.
  const uint32_t  kDefaultResIntS     = 6000000;

  /// The default number of steps: 8.
  const int       kDefaultNSteps      = 8;

  /// The default step interval: 5ms.
  const int       kDefaultStepIntMs   = 5000;

  /// The default averaging interval: 30ms.
  const int       kDefaultAvgIntUsec    = 30000;

  /// The default priority: 1.
  const int       kDefaultPriority    = 1;

  /// The default delta: 0.9.
  const double    kDefaultDelta       = 0.90;

  /// The default amount by which inertia is increased.
  const uint32_t  kDefaultInertiaInc  = 10000;

  /// The maximum value of inertia for a flow.
  const uint32_t  kDefaultMaxInertia  = 300000;
}

class EncodingState;

//============================================================================
// TrapUtility::TrapUtility(ProxyState& state,
//                          QueueDepths& queue_depths,
//                          KVal& k_val,
//                          uint32_t flow_id)
TrapUtility::TrapUtility(QueueDepths& queue_depths, BinIndex bin_idx,
                         KVal& k_val, uint32_t flow_id)
    : UtilityFn(queue_depths, bin_idx, flow_id),
      m_val_(0.0),
      k_val_(k_val),
      b_val_(0.0),
      delta_(0.0),
      penalty_(0),
      interval_length_(0),
      time_interval_end_(0),
      time_of_last_update_(0),
      avg_interval_usec_(0),
      step_interval_us_(0),
      restart_interval_us_(0),
      n_steps_(1),
      curr_step_(1),
      last_step_size_(1),
      current_utility_(0),
      rng_(),
      trap_timer_tag_(0),
      inertia_usec_(0)
{
  last_send_rate_ = 0;

  Time now;
  if (!now.GetNow())
  {
    LogF(kClassName, __func__, "Failed to get current time\n");
  }
  rng_.SetSeed((now.GetTimeInUsec()%1000)*1000);
}

//============================================================================
TrapUtility::~TrapUtility()
{
  // Nothing to destroy.
}

//============================================================================
bool TrapUtility::Initialize(const ConfigInfo& ci)
{
  m_val_            = ci.GetDouble("m", 0);
  if (m_val_ == 0)
  {
    LogF(kClassName, __func__,
         "m value not provided.\n");
    return false;
  }
  b_val_            = ci.GetDouble("b", 0);
  if (b_val_ == 0)
  {
    LogF(kClassName, __func__,
         "b value not provided.\n");
    return false;
  }
  p_val_              = ci.GetDouble("p", kDefaultPriority, false);
  delta_              = ci.GetDouble("delta", kDefaultDelta, false);
  // TODO: Explain magic numbers.
  restart_interval_us_ =
    ci.GetUint("resint", kDefaultResIntS, false) - p_val_ * 100000/2
    + rng_.GetInt(500000);
  n_steps_            = ci.GetInt("nsteps", kDefaultNSteps, false);
  step_interval_us_   = ci.GetInt("stepint", kDefaultStepIntMs, false);

  avg_interval_usec_  = ci.GetInt("avgint", kDefaultAvgIntUsec, false);
  avg_interval_usec_ += p_val_*30000 + rng_.GetInt(30000);
  time_interval_end_  = Time::GetNowInUsec() + avg_interval_usec_;

  LogC(kClassName, __func__, "TRAP configuration   :\n");
  LogC(kClassName, __func__, "k                    : %.2e\n",
       static_cast<double>(k_val_.GetValue()));
  LogC(kClassName, __func__, "m                    : %.03e\n", m_val_);
  LogC(kClassName, __func__, "b                    : %.03e\n", b_val_);
  LogC(kClassName, __func__, "p                    : %.03f\n", p_val_);
  LogC(kClassName, __func__, "delta                : %.03f\n", delta_);
  LogC(kClassName, __func__, "Interval length      : %" PRIu64 "\n",
       avg_interval_usec_);
  LogC(kClassName, __func__, "Step duration        : %" PRIu64 "\n",
       step_interval_us_);
  LogC(kClassName, __func__, "Number steps         : %" PRIu8 "\n", n_steps_);
  LogC(kClassName, __func__, "Restart interval     : %" PRIu64 "\n",
       restart_interval_us_);
  LogC(kClassName, __func__, "TRAP configuration complete\n");

  LogI(kClassName, __func__, "TRAP initialized. Now %" PRId64 " , interval end: "
       "%" PRId64 "\n", Time::GetNowInUsec(), time_interval_end_);
  return true;
}

//==============================================================================
double TrapUtility::GetSendRate()
{
  if (flow_state_ != FLOW_ON)
  {
    LogD(kClassName, __func__, "flow %" PRIu32 " is off\n", flow_id_);
    return 0.0;
  }

  // keep track of the queue length over the
  Time now = Time::Now();
  double send_rate = (static_cast<float>(curr_step_)/
                      static_cast<float>(n_steps_))*b_val_;

  if (!time_of_last_update_)
  {
    time_of_last_update_ = now.GetTimeInUsec();
  }
  else
  {
    if (last_step_size_ == 0)
    {
      // if the last step was down, increase the penalty proportional
      // to the deviation from the top step.
      penalty_ += (b_val_ - last_send_rate_)*
                  (now.GetTimeInUsec() - time_of_last_update_);
      LogD(kClassName, __func__,
           "Flow %" PRIu32 ", penalty now: %" PRIu64 ".\n", flow_id_, penalty_);
    }
    interval_length_ += now.GetTimeInUsec() - time_of_last_update_;
    time_of_last_update_ = now.GetTimeInUsec();
  }

  last_send_rate_ = send_rate;
  LogD(kClassName, __func__, "Send rate: %f.\n", send_rate);

  return send_rate;
}

//==============================================================================
bool TrapUtility::ConsiderTriage()
{
  // Check for early triage.
  uint64_t max_penalty = b_val_ * (1 - delta_) * 
                         (avg_interval_usec_ + inertia_usec_);
  LogD(kClassName, __func__,
       "Flow %" PRIu32 ": Curr penalty: %" PRIu64 ", max: %" PRIu64 
       "\n, delta: %f", flow_id_, penalty_, max_penalty, delta_);

  if (penalty_ > max_penalty)
  {
    // The flow is not being properly serviced, we get no utility.
    LogA(kClassName, __func__, "Triage of Flow %" PRIu32 ", with inertia %u.\n",
                               flow_id_, inertia_usec_);

    flow_state_ = FLOW_TRIAGED;
    current_utility_ = 0;
    // Set last_step_size_ positive so when flow is turned on, penalty is not
    // added.
    last_step_size_ = 1;

    // timer_admit_control will turn the timers off and set the restart
    // timer if we return true.
    return true;
  }
  return false;
}

//==============================================================================
void TrapUtility::Step()
{
  if (flow_state_ != FLOW_ON)
  {
    return;
  }

  // Check if we should step up or step down if cost is greater than utility
  // then step down.
  uint32_t cur_qd  = queue_depths_.GetBinDepthByIdx(bin_idx_);

  LogD(kClassName, __func__, "Checking Step for flow % " PRIu32 
        " cur step: % " PRIu8 " \n", flow_id_, curr_step_);

  // If the queues are large, then we should not be sending. We do this
  // gradually by stepping down rather than stopping. If the queues are
  // less tham the k*p/m threshold, then we should step up. The size of
  // the step depends on the previous stepping action. If the previous
  // step was down, we ramp up more slowly than if the previous step
  // was up.
  if (cur_qd * 8 > k_val_.GetValue() * p_val_ / m_val_)
  {
    curr_step_ = std::max(0,curr_step_-1);
    last_step_size_ = 0;
    LogD(kClassName, __func__, "Stepping down to %" PRIu8 "\n", curr_step_);
  }
  else if (last_step_size_ == 0)
  {
    last_step_size_ = 1;
    curr_step_ =
         std::min(static_cast<int>(n_steps_), curr_step_ + last_step_size_);
    LogD(kClassName, __func__, "Stepping up to %" PRIu8 ".\n" ,curr_step_);
  }
  else
  {
    last_step_size_ =
         std::min(last_step_size_*2, static_cast<int>(n_steps_));
    curr_step_ =
         std::min(static_cast<int>(n_steps_), curr_step_ + last_step_size_);
    LogD(kClassName, __func__, "Stepping up to %" PRIu8 ".\n", curr_step_);
  }
  double UNUSED(send_rate) = (static_cast<float>(curr_step_)/
                                static_cast<float>(n_steps_))*b_val_;

  LogD(kClassName, __func__,
       "At step %" PRIu8 ", for tag %" PRIu32 ", with queue %" PRIu8 
       "B, rate %f.\n", curr_step_, flow_id_, cur_qd, send_rate);

  // This output is for the netanim trace parser.
  LogA(kClassName, __func__,
       "f_id: %" PRIu32 ", queue: %" PRIu32 "b, rate: %.03fbps, "
       "step:%" PRIu8 "\n", flow_id_, cur_qd*8, send_rate, curr_step_);
}

//==============================================================================
bool TrapUtility::CheckUtility()
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

  if ((time_of_last_update_ != 0) && (last_step_size_ == 0))
  {
    // if the last step was down, increase the penalty proportional
    // to the deviation from the top step.
    penalty_ += (b_val_ - last_send_rate_)*
                (now.GetTimeInUsec() - time_of_last_update_);
    LogD(kClassName, __func__, "Flow %" PRIu32 ", penalty now: %" PRIu64 "\n",
                 flow_id_, penalty_);
  }

  interval_length_ += now.GetTimeInUsec() - time_of_last_update_;

  // Check if the time interval has ended and if so, update the state.
  uint64_t max_penalty = b_val_ * (1 - delta_) *
                         (avg_interval_usec_ + inertia_usec_);
  if ((now.GetTimeInUsec() > time_interval_end_ && interval_length_) ||
      (penalty_ > max_penalty))
  {
    LogD(kClassName, __func__, "Flow %" PRIu32 ", penalty now: %" PRIu64 "\n",
                 flow_id_, penalty_);

    if (ConsiderTriage())
    {
      return true;
    }
    else
    {
      // The flow is being properly serviced, we get full utility
      current_utility_ = p_val_;
      if (inertia_usec_ < kDefaultMaxInertia)
      {
        inertia_usec_ += kDefaultInertiaInc;
      }
    }

    // reset the counters
    penalty_ = 0;
    interval_length_ = 0;
    time_interval_end_ = now.GetTimeInUsec() + avg_interval_usec_ +
                         inertia_usec_;
  }

  time_of_last_update_ = now.GetTimeInUsec();

  return false;
}

//==============================================================================
void TrapUtility::SetFlowOn()
{
  Time now = Time::Now();

  // If the flow is already on, we don't need to do anything.
  if (flow_state_ == FLOW_ON)
  {
    LogW(kClassName, __func__, "Attempt to turn on flow %" PRIu32
         " but it is already on.\n", flow_id_);
    return;
  }

  // Check that the flow has been off for at last the duration of the
  // restart interval. The following if statement should never be true.
  if ((now.GetTimeInUsec() - time_of_last_update_) < restart_interval_us_)
  {
    LogE(kClassName, __func__, "Attempt to turn flow on before duration"
         " of restart interval. Flow has been off for %" PRId64 ", and "
         " restart interval is %" PRId64 ".\n",
         now.GetTimeInUsec() - time_of_last_update_, restart_interval_us_);
    return;
  }
  LogD(kClassName, __func__, "Turning flow %" PRIu32 " on.\n", flow_id_);
  flow_state_ = FLOW_ON;

  curr_step_  = 1;

  // Set the callback to resume checking utility at intervals.
  interval_length_      = 0;
  penalty_              = 0;
  inertia_usec_         = 0;
  time_of_last_update_  = now.GetTimeInUsec();
  avg_interval_usec_    = std::min(static_cast<double>(avg_interval_usec_),
    p_val_*100000/2 + rng_.GetInt(50000));
  time_interval_end_    = Time::GetNowInUsec() + avg_interval_usec_;
}
