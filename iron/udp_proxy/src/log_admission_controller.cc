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

#include "log_admission_controller.h"
#include "list.h"
#include "log.h"
#include "string_utils.h"
#include "udp_proxy.h"

using ::iron::FlowState;
using ::iron::List;
using ::iron::LogUtility;
using ::iron::QueueDepths;
using ::iron::StringUtils;
using ::iron::Time;
using ::std::string;

namespace
{
  const char*  kClassName = "LogAdmissionController";
}

//============================================================================
LogAdmissionController::LogAdmissionController(EncodingState& encoding_state)
    : AdmissionController(encoding_state),
      log_utility_(NULL)
{
}

//============================================================================
LogAdmissionController::~LogAdmissionController()
{
  if (log_utility_ != NULL)
  {
    delete log_utility_;
    log_utility_ = NULL;
  }
}

//============================================================================
bool LogAdmissionController::CreateUtilityFn(string& utility_def,
                                             uint32_t flow_id,
                                             QueueDepths& queue_depths)
{
  // Validate that the provided utility definition string is for the Log
  // utility.
  if (GetUtilityFnType(utility_def, flow_id) != "LOG")
  {
    LogW(kClassName, __func__, "fid: %" PRIu32 ", utility definition is not "
         "for a Log utility function.\n", flow_id);
    return false;
  }

  log_utility_ = new (std::nothrow) LogUtility(queue_depths,
                                               encoding_state_.bin_idx(),
                                               encoding_state_.k_val(),
                                               flow_id);
  if (log_utility_ == NULL)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 "Unable to allocate memory "
         "for log utility function.\n", flow_id);
    return false;
  }

  ConfigureUtilityFn(log_utility_, utility_def);

  return true;
}

//============================================================================
void LogAdmissionController::SvcEvents(Time& now)
{
  SvcAdmissionEvent(now, log_utility_);
}

//============================================================================
double LogAdmissionController::ComputeUtility(double rate)
{
  if (log_utility_ == NULL)
  {
    return 0.0;
  }

  return log_utility_->ComputeUtility(rate);
}

//============================================================================
void LogAdmissionController::set_flow_state(FlowState flow_state)
{
  if (flow_state == iron::FLOW_TRIAGED)
  {
    LogW(kClassName, __func__, "Unable to triage a log utility flow.\n");
    return;
  }

  if (log_utility_ == NULL)
  {
    // If we get here and don't have a utility function something is very very
    // wrong.
    LogF(kClassName, __func__, "Attempting to set the flow's state and there "
         "isn't a utility function.\n");
    return;
  }

  if (flow_state == iron::FLOW_OFF)
  {
    CancelScheduledEvent(next_admission_time_);
  }

  log_utility_->set_flow_state(flow_state);
}

//============================================================================
FlowState LogAdmissionController::flow_state()
{
  if (log_utility_ == NULL)
  {
    return iron::UNDEFINED;
  }

  return log_utility_->flow_state();
}

//============================================================================
double LogAdmissionController::priority()
{
  if (log_utility_ == NULL)
  {
    return 0.0;
  }

  return log_utility_->priority();
}

//============================================================================
void LogAdmissionController::UpdateUtilityFn(std::string key_val)
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
    log_utility_->set_priority(StringUtils::GetDouble(value,0.0));
  }
  else
  {
    LogE(kClassName, __func__, "Update of %s not supported.\n", key.c_str());
  }
}
