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

#include "strap_admission_controller.h"
#include "list.h"
#include "string_utils.h"
#include "udp_proxy.h"

using ::iron::FlowState;
using ::iron::List;
using ::iron::QueueDepths;
using ::iron::StrapUtility;
using ::iron::StringUtils;
using ::iron::Time;
using ::std::string;

namespace
{
  const char*  kClassName = "StrapAdmissionController";
}

//============================================================================
StrapAdmissionController::StrapAdmissionController(
  EncodingState& encoding_state,
  SrcRateEstimator& src_rate_estimator, SrcInfo& src_info)
    : AdmissionController(encoding_state),
      src_rate_estimator_(src_rate_estimator),
      src_info_(src_info),
      strap_utility_(NULL),
      restart_time_(Time::Infinite()),
      step_time_(Time::Infinite())
{
}

//============================================================================
StrapAdmissionController::~StrapAdmissionController()
{
  if (strap_utility_ != NULL)
  {
    delete strap_utility_;
    strap_utility_ = NULL;
  }
}

//============================================================================
bool StrapAdmissionController::CreateUtilityFn(string& utility_def,
                                               uint32_t flow_id,
                                               QueueDepths& queue_depths)
{
  // Validate that the provided utility definition string is for the Strap
  // utility.
  if (GetUtilityFnType(utility_def, flow_id) != "STRAP")
  {
    LogW(kClassName, __func__, "fid: %" PRIu32 ", utility definition is not "
         "for a Strap utility function.\n", flow_id);
    return false;
  }

  strap_utility_ = new (std::nothrow) StrapUtility(src_rate_estimator_,
                                                   src_info_,
                                                   queue_depths,
                                                   encoding_state_.bin_idx(),
                                                   encoding_state_.k_val(),
                                                   flow_id);
  if (strap_utility_ == NULL)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 "Unable to allocate memory "
         "for Strap utility function.\n", flow_id);
    return false;
  }

  ConfigureUtilityFn(strap_utility_, utility_def);

  strap_utility_->set_enable_loss_triage(
                  encoding_state_.udp_proxy()->enable_loss_triage());

  ScheduleStepTime();

  return true;
}

//============================================================================
void StrapAdmissionController::SvcEvents(Time& now)
{
  // First, service the admission event.
  SvcAdmissionEvent(now, strap_utility_);

  // Now, service the Strap admission controller specific events.
  if (restart_time_ <= now)
  {
    RestartTimeout(now);
  }

  if (step_time_ <= now)
  {
    StepTimeout(now);
  }
}

//============================================================================
double StrapAdmissionController::ComputeUtility(double rate)
{
  if (strap_utility_ == NULL)
  {
    return 0.0;
  }

  return strap_utility_->ComputeUtility(rate);
}

//============================================================================
void StrapAdmissionController::set_flow_state(iron::FlowState flow_state)
{
  if (strap_utility_ == NULL)
  {
    // If we get here and don't have a utility function something is very very
    // wrong.
    LogF(kClassName, __func__, "Attempting to set the flow's state and there "
         "isn't a utility function.\n");
    return;
  }
  
  Time  now = Time::Now();
  
  if ((flow_state == iron::FLOW_OFF) || (flow_state == iron::FLOW_TRIAGED))
  {
    CancelScheduledEvent(next_admission_time_);
    CancelScheduledEvent(step_time_);

    if (flow_state == iron::FLOW_OFF)
    {
      CancelScheduledEvent(restart_time_);
    }

    if ((flow_state == iron::FLOW_TRIAGED) &&
        (strap_utility_->flow_state() == iron::FLOW_ON))
    {
      ScheduleRestartTime();
    }
  }
  else if (flow_state == iron::FLOW_ON)
  {
    start_time_          = now;
    next_admission_time_ = now;
    strap_utility_->SetAvgIntervalEnd();
    ScheduleStepTime();
    CancelScheduledEvent(restart_time_);
  }

  strap_utility_->set_flow_state(flow_state);
}

//============================================================================
FlowState StrapAdmissionController::flow_state()
{
  if (strap_utility_ == NULL)
  {
    return iron::UNDEFINED;
  }

  return strap_utility_->flow_state();
}

//============================================================================
double StrapAdmissionController::priority()
{
  if (strap_utility_ == NULL)
  {
    return 0.0;
  }

  return strap_utility_->priority();
}

//============================================================================

void StrapAdmissionController::UpdateScheduledAdmissionEvent(
       iron::Time& now, iron::UtilityFn* utility_fn)
{
  last_send_rate_ = utility_fn->GetSendRate();
}

//============================================================================
void StrapAdmissionController::AdmitPkts(iron::Time& now)
{
  LogD(kClassName, __func__,
       "fid: %" PRIu32 ", adm frac: %f, backlog: %" PRIu32 ".\n",
        encoding_state_.flow_tag(), strap_utility_->GetAdmFrac(),
        src_info_.cur_backlog_bytes());

  double bytes_to_send = strap_utility_->GetAdmFrac() *
                         src_info_.cur_backlog_bytes();
  size_t  bytes_sent   = 0;
  if (strap_utility_->curr_step() > 0)
  {
    while (bytes_to_send > bytes_sent)
    {
      bytes_sent += AdmitPkt();
      if (bytes_sent == 0)
      {
        break;
      }
    }
  }
  next_admission_time_ = now.Add(bpf_min_burst_);
}
//============================================================================
void StrapAdmissionController::UpdateUtilityFn(std::string key_val)
{
  List<string> tokens;
  StringUtils::Tokenize(key_val, ":", tokens);
  if (tokens.size() != 2)
  {
    LogE(kClassName, __func__, "Parameter %s must be of the form key:value.\n",
                                key_val.c_str());
    return;
  }

  string key;
  string value;
  tokens.Peek(key);
  tokens.PeekBack(value);

  if (key == "delta")
  {
    // This is currently used by AMP for making probes less aggressive.
    // STRAP utility has its own delta management that makes probing less
    // agressive without AMP's aid. Should this change, uncomment the
    // following line.
    //strap_utility_->set_delta(StringUtils::GetDouble(value));
    return;
  }
  else if (key == "p")
  {
    strap_utility_->set_priority(StringUtils::GetDouble(value,0.0));
  }
  else
  {
    LogE(kClassName, __func__, "Update of %s not supported.\n", key.c_str());
  }
}

//============================================================================
void StrapAdmissionController::RestartTimeout(Time& now)
{
  // Turn the flow on. All packets in the backlog are flushed because they are
  // old.
  strap_utility_->SetFlowOn();
  strap_utility_->ResetInertia();
  encoding_state_.FlushBacklog();

  // Adjust next admission time to be now. We are turning the flow back on so
  // we can send any packets that are in the proxy queue.
  next_admission_time_ = now;
  SvcAdmissionEvent(now, strap_utility_);

  // Set the end time for the current interval.
  strap_utility_->SetAvgIntervalEnd();

  // Adjust the event timers.
  ScheduleStepTime();
  CancelScheduledEvent(restart_time_);
}

//============================================================================
void StrapAdmissionController::StepTimeout(Time& now)
{
  // Update the receiver stats.
  strap_utility_->set_acked_seq_num(encoding_state_.acked_seq_num());
  strap_utility_->set_curr_loss_rate_pct(encoding_state_.loss_rate_pct());

  uint8_t prev_step = strap_utility_->curr_step();
  strap_utility_->Step();
  ScheduleStepTime();
  uint8_t curr_step = strap_utility_->curr_step();

  // Check if the flow toggled on/off.
  if ((curr_step == 0) && (prev_step != 0) && (flow_state() != iron::FLOW_OFF))
  {
      LogD(kClassName, __func__, "fid: %" PRIu32 " toggled down.\n",
                                 encoding_state_.flow_tag());
      ++toggle_count_;
      push_stats_ = true;
  }
  else if ((curr_step != 0) && (prev_step == 0.0) &&
           (start_time_ < (now - kStartupTime)))
  {
    LogD(kClassName, __func__, "fid: %" PRIu32 " toggled up.\n",
                               encoding_state_.flow_tag());
    ++toggle_count_;
    push_stats_    = true;
  }

  if (strap_utility_->CheckUtility())
  {
    // The flow is not being properly serviced and should be triaged.
    //
    //   - Cancel the step event
    //   - Schedule the restart event
    LogI(kClassName, __func__, "fid: %" PRIu32 " was triaged.\n",
                               encoding_state_.flow_tag());
    ++toggle_count_;
    push_stats_    = true;
    CancelScheduledEvent(step_time_);
    ScheduleRestartTime();
  }

  // Update admitted_seq_num
  strap_utility_->set_admitted_seq_num(encoding_state_.admitted_seq_num());

}

//============================================================================
void StrapAdmissionController::ScheduleStepTime()
{
  step_time_ = Time::Now() + Time(strap_utility_->step_interval_sec());
}

//============================================================================
void StrapAdmissionController::ScheduleRestartTime()
{
  restart_time_ = Time::Now() + Time(strap_utility_->restart_interval_sec());
}
