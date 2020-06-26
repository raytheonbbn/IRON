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

#include "admission_controller.h"
#include "config_info.h"
#include "iron_constants.h"
#include "list.h"
#include "log.h"
#include "packet.h"
#include "string_utils.h"
#include "udp_proxy.h"

using ::iron::ConfigInfo;
using ::iron::List;
using ::iron::Packet;
using ::iron::StringUtils;
using ::iron::Time;
using ::iron::UtilityFn;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*  kClassName = "AdmissionController";
}

//============================================================================
AdmissionController::AdmissionController(EncodingState& encoding_state)
    : encoding_state_(encoding_state),
      next_admission_time_(Time::Now()),
      start_time_(Time::Now()),
      bpf_min_burst_(0, iron::kDefaultBpfMinBurstUsec),
      last_send_rate_(0.0),
      toggle_count_(0),
      push_stats_(false),
      flow_is_idle_(true),
      rng_()
{
}

//============================================================================
AdmissionController::~AdmissionController()
{
  // Nothing to destroy.
}

//============================================================================
string AdmissionController::GetUtilityFnType(string& utility_def,
                                             uint32_t flow_id) const
{
  size_t  type_str_pos = utility_def.find("type=");
  if (type_str_pos == string::npos)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 ", invalid utility definition "
         "string, type not provided.\n", flow_id);
    return "";
  }

  size_t  type_str_end_pos = utility_def.find(":", type_str_pos);
  if (type_str_end_pos == string::npos)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 ", invalid utility definition "
         "string format.\n", flow_id);
    return "";
  }

  return utility_def.substr(type_str_pos + 5, type_str_end_pos -
                            (type_str_pos + 5));
}

//============================================================================
bool AdmissionController::ConfigureUtilityFn(UtilityFn* utility_fn,
                                             string& utility_def)
{
  ConfigInfo    ci;
  List<string>  tokens;
  
  StringUtils::Tokenize(utility_def, ":", tokens);

  List<string>::WalkState tokens_ws;
  tokens_ws.PrepareForWalk();

  string  token;
  while (tokens.GetNextItem(tokens_ws, token))
  {
    if (token.find("=") == string::npos)
    {
      continue;
    }

    List<string>  token_values;
    StringUtils::Tokenize(token, "=", token_values);

    if (token_values.size() == 2)
    {
      string  name;
      string  value;

      token_values.Pop(name);
      token_values.Peek(value);
      ci.Add(name, value);
    }
  }

  ci.Add("ttg", StringUtils::ToString(
         static_cast<uint64_t>(encoding_state_.time_to_go().GetTimeInUsec())));
  if (!utility_fn->Initialize(ci))
  {
    return false;
  }

  return true;
}

//============================================================================
void AdmissionController::SvcAdmissionEvent(Time& now, UtilityFn* utility_fn)
{
  push_stats_ = false;

  // Update the scheduled admission event time.
  UpdateScheduledAdmissionEvent(now, utility_fn);

  // Admit packets.
  AdmitPkts(now);
}

//============================================================================
size_t AdmissionController::AdmitPkt()
{
  return encoding_state_.AdmitPacket();
}

//============================================================================
void AdmissionController::AdmitPkts(Time& now)
{
  // last_send_rate_ is updated in the UpdateScheduledAdmissionEvent method,
  // which is always called before this method. So using last_send_rate_
  // instead of calling GetSendRate in the utility function is OK.
  LogD(kClassName, __func__, "fid: %" PRIu32 ", send rate is %f.\n",
       encoding_state_.flow_tag(), last_send_rate_);

  if (last_send_rate_ > 0)
  {
    // Make sure we don't allow for an indefinite amount of catch up time.
    Time  low_adm_time = now.Subtract(bpf_min_burst_);
    if (next_admission_time_ < low_adm_time)
    {
      next_admission_time_ = low_adm_time;
    }

    Time  burst_time = now.Add(bpf_min_burst_ +
            Time(0,rng_.GetInt(bpf_min_burst_.GetTimeInUsec()/2)));

    while (next_admission_time_ <= burst_time)
    {
      size_t  bytes_sent = AdmitPkt();

      if (bytes_sent == 0)
      {
        // XXX DO WE REALLY SET THE FLOW IDLE IN THIS CASE?
        flow_is_idle_ = true;
        break;
      }

      // Compute the serialization time for the transmission.
      Time  serialization_time(static_cast<double>(bytes_sent) * 8.0 /
                               last_send_rate_);

      // Adjust the next admission time.
      if (flow_is_idle_ == true)
      {
        LogD(kClassName, __func__, "fid: %" PRIu32 ", flow is idle.\n",
             encoding_state_.flow_tag());

        next_admission_time_ = Time::Now() + serialization_time;
        flow_is_idle_        = false;
      }
      else
      {
        next_admission_time_ = next_admission_time_.Add(serialization_time);
      }
    }
  }
  else if (last_send_rate_ < 0)
  {
    LogE(kClassName, __func__, "fid: %" PRIu32 ", computed send rate is "
         "negative %.03f.\n", encoding_state_.flow_tag(), last_send_rate_);
  }
}

//============================================================================
void AdmissionController::UpdateScheduledAdmissionEvent(Time& now,
                                                        UtilityFn* utility_fn)
{
  double  new_rate = utility_fn->GetSendRate();

  if ((new_rate == 0) && (last_send_rate_ != 0))
  {
    if ((encoding_state_.GetCountFromEncodedPktsQueue() > 0) &&
        (flow_state() != iron::FLOW_OFF))
    {
      LogD(kClassName, __func__, "fid: %" PRIu32 " toggled down.\n",
                                 encoding_state_.flow_tag());
      ++toggle_count_;
      push_stats_ = true;
    }
  }
  else if ((new_rate != 0) && (last_send_rate_ == 0) &&
           (start_time_ < (now - kStartupTime)))
  {
    LogD(kClassName, __func__, "fid: %" PRIu32 " toggled up.\n",
         encoding_state_.flow_tag());
    ++toggle_count_;
    push_stats_    = true;
  }

  // Adjust the next_admission_time_.
  Time  sched_svc_time        = encoding_state_.sched_svc_time();
  Time  admission_target_time = next_admission_time_;
  Time  admission_delta       = admission_target_time - sched_svc_time;

  if (admission_delta > Time())
  {
    Time
      next_target_time(static_cast<double>(admission_delta.GetTimeInUsec()) *
                       last_send_rate_ / (new_rate * 1000000.0));

    next_target_time = next_target_time.Add(sched_svc_time);
    next_admission_time_ = next_target_time;

    LogD(kClassName, __func__, "fid: %" PRIu32 ", updated admission time, "
         "now is %s, original admission time is %s, new admission time is "
         "%s, last send rate is %f, new send rate is %f.\n",
         encoding_state_.flow_tag(), now.ToString().c_str(),
         admission_target_time.ToString().c_str(),
         next_admission_time_.ToString().c_str(),
         last_send_rate_, new_rate);
  }
  else
  {
    LogD(kClassName, __func__, "fid: %" PRIu32 ", next admission time is in "
         "the past, now is %s, next admission time is %s.\n",
         encoding_state_.flow_tag(), now.ToString().c_str(),
         next_admission_time_.ToString().c_str());
  }

  // Finally, save the new old rate.
  last_send_rate_ = new_rate;
}
