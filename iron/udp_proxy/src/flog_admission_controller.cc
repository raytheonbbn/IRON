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

#include "flog_admission_controller.h"
#include "list.h"
#include "string_utils.h"
#include "udp_proxy.h"

using ::iron::FlowState;
using ::iron::List;
using ::iron::QueueDepths;
using ::iron::FlogUtility;
using ::iron::StringUtils;
using ::iron::Time;
using ::std::string;

namespace
{
  const char*  kClassName = "FlogAdmissionController";
}

//============================================================================
FlogAdmissionController::FlogAdmissionController(
  EncodingState& encoding_state,
  SrcRateEstimator& src_rate_estimator, SrcInfo& src_info)
    : AdmissionController(encoding_state),
      src_rate_estimator_(src_rate_estimator),
      src_info_(src_info),
      flog_utility_(NULL),
      check_utility_time_(Time::Infinite())
{
}

//============================================================================
FlogAdmissionController::~FlogAdmissionController()
{
  if (flog_utility_ != NULL)
  {
    delete flog_utility_;
    flog_utility_ = NULL;
  }
}

//============================================================================
bool FlogAdmissionController::CreateUtilityFn(string& utility_def,
                                               uint32_t flow_id,
                                               QueueDepths& queue_depths)
{
  // Validate that the provided utility definition string is for the Flog
  // utility.
  if (GetUtilityFnType(utility_def, flow_id) != "FLOG")
  {
    LogW(kClassName, __func__, "fid: %" PRIu32 ", utility definition is not "
         "for a Flog utility function.\n", flow_id);
    return false;
  }

  flog_utility_ = new (std::nothrow) FlogUtility(src_rate_estimator_,
                                                 src_info_,
                                                 queue_depths,
                                                 encoding_state_.bin_idx(),
                                                 encoding_state_.k_val(),
                                                 flow_id);
  if (flog_utility_ == NULL)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 "Unable to allocate memory "
         "for Flog utility function.\n", flow_id);
    return false;
  }

  ConfigureUtilityFn(flog_utility_, utility_def);

  ScheduleCheckUtilityTime();

  return true;
}

//============================================================================
void FlogAdmissionController::SvcEvents(Time& now)
{
  // First, service the admission event.
  SvcAdmissionEvent(now, flog_utility_);

  if (check_utility_time_ <= now)
  {
    CheckUtilityTimeout(now);
  }
}

//============================================================================
double FlogAdmissionController::ComputeUtility(double rate)
{
  if (flog_utility_ == NULL)
  {
    return 0.0;
  }

  return flog_utility_->ComputeUtility(rate);
}

//============================================================================
void FlogAdmissionController::set_flow_state(iron::FlowState flow_state)
{
  if (flog_utility_ == NULL)
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
    CancelScheduledEvent(check_utility_time_);
  }
  else if (flow_state == iron::FLOW_ON)
  {
    start_time_          = now;
    next_admission_time_ = now;
    ScheduleCheckUtilityTime();
  }

  flog_utility_->set_flow_state(flow_state);
}

//============================================================================
FlowState FlogAdmissionController::flow_state()
{
  if (flog_utility_ == NULL)
  {
    return iron::UNDEFINED;
  }

  return flog_utility_->flow_state();
}

//============================================================================
double FlogAdmissionController::priority()
{
  if (flog_utility_ == NULL)
  {
    return 0.0;
  }

  return flog_utility_->priority();
}

//============================================================================
void FlogAdmissionController::UpdateUtilityFn(std::string key_val)
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

  if (key == "p")
  {
    flog_utility_->set_priority(StringUtils::GetDouble(value,0.0));
  }
  else
  {
    LogE(kClassName, __func__, "Update of %s not supported.\n", key.c_str());
  } 
}

//============================================================================
void FlogAdmissionController::CheckUtilityTimeout(Time& now)
{
  if (flog_utility_->ConsiderTriage())
  {
    // The flow is not being properly serviced and should be triaged.
    CancelScheduledEvent(check_utility_time_);
  }
  else
  {
    ScheduleCheckUtilityTime();
  }
}

//============================================================================
void FlogAdmissionController::ScheduleCheckUtilityTime()
{
  check_utility_time_ = Time::Now() +
    Time(flog_utility_->int_length_sec());
}
