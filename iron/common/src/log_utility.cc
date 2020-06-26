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

#include "log_utility.h"
#include "utility_fn_if.h"
#include "config_info.h"
#include "k_val.h"
#include "log.h"
#include "queue_depths.h"
#include "string_utils.h"
#include "unused.h"

#include <list>
#include <string>

#include "math.h"

// Only used if doing shroff send rate.
//#include <math.h>

using ::iron::ConfigInfo;
using ::iron::KVal;
using ::iron::Log;
using ::iron::LogUtility;
using ::iron::ProxyState;
using ::iron::StringUtils;
using ::iron::QueueDepths;
using ::iron::UtilityFn;
using ::std::list;
using ::std::min;
using ::std::string;

namespace
{
  /// Class name used for logging.
  const char*  UNUSED(kClassName) = "LogUtility";

  /// The default priority: 1.
  const int    kDefaultPriority    = 1;
}

//============================================================================
LogUtility::LogUtility(QueueDepths& queue_depths, BinIndex bin_idx,
                       KVal& k_val, uint32_t flow_id)
    : UtilityFn(queue_depths, bin_idx, flow_id),
      m_val_(0.0),
      k_val_(k_val),
      a_val_(0.0)
{
  LogD(kClassName, __func__, "fid: %" PRIu32 ", LOG utility created for bin "
       "idx %" PRIBinIndex ".\n", flow_id_, bin_idx);
}

//============================================================================
bool LogUtility::Initialize(const ConfigInfo& ci)
{
  m_val_ = ci.GetDouble("m", 0, false);
  if (m_val_ == 0)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 ", m value not provided.\n",
         flow_id_);
    return false;
  }

  a_val_ = ci.GetDouble("a", 0, false);
  if (a_val_ == 0)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 ", a value not provided.\n",
         flow_id_);
    return false;
  }

  p_val_ = ci.GetDouble("p", kDefaultPriority, false);

  LogC(kClassName, __func__, "LOG configuration    :\n");
  LogC(kClassName, __func__, "k                    : %.2e\n",
       static_cast<double>(k_val_.GetValue()));
  LogC(kClassName, __func__, "m                    : %.03e\n", m_val_);
  LogC(kClassName, __func__, "a                    : %.03f\n", a_val_);
  LogC(kClassName, __func__, "p                    : %.03f\n", p_val_);
  LogC(kClassName, __func__, "LOG configuration complete\n");

  LogI(kClassName, __func__, "Log initialized.\n");

  return true;
}

//============================================================================
double LogUtility::GetSendRate()
{
  if (flow_state_ == FLOW_OFF)
  {
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

  return send_rate;
}

//==========================================================================
double LogUtility::ComputeUtility(double send_rate)
{
  if (a_val_ * send_rate <= -1)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 ", Error: Cannot take log "
         "of negative value a*r + 1 = %.3f.\n", flow_id_,
         a_val_ * send_rate + 1);
    return 0;
  }

  // p * log(ar + 1)
  return p_val_ * log(a_val_ * send_rate + 1);
}
