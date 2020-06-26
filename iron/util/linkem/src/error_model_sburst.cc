/* IRON: iron_headers */
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

#include "error_model_sburst.h"
#include "log.h"
#include "string_utils.h"
#include <time.h>
#include <string>

#include <cstdlib>
#include <cmath>

namespace
{
  /// Class name for logging.
  const char*  kClassName = "SBURSTModel";
}

using ::iron::StringUtils;
using ::std::string;

//============================================================================
SBURSTModel::SBURSTModel()
    : g_(1000.0),
      b_(0.0),
      ber_(1.0),
      log_arg_(0.0),
      hrc_()
{
  name_ = ERR_MODEL_SBURST;
  hrc_.Initialize();
  burst_start_time_ = hrc_.GetTimeInNsec();
  burst_end_time_ = hrc_.GetTimeInNsec();
  sber_model = new (std::nothrow) SBERModel();
  
  SetFeature("G", "0.0");
  SetFeature("B", "1.0");
  SetFeature("BER", "0.0");
  srand(time(0));

  LogC(kClassName, __func__, "SRAND %d\n", rand() );
}

//============================================================================
SBURSTModel::~SBURSTModel()
{
  delete sber_model;
}

//============================================================================
bool SBURSTModel::CheckForErrors(const char* buf, unsigned int length)
{
  
  unsigned long long current_time = hrc_.GetTimeInNsec();

  
  if (current_time < burst_start_time_)  // Not to burst outage yet
  {
    return false;
  } 
  else  
  {
    if (current_time > burst_end_time_)  // The burst outage has ended
    {
      int g_rand_int = rand();
      int b_rand_int = rand();
      double g_rand = (double)g_rand_int/(double)RAND_MAX;
      double b_rand = (double)b_rand_int/(double)RAND_MAX;
        
      // factor of 1000000 converts from ms to ns
      // log(g_rand) is same as log(1-g_rand) because g_rand ~U(0,1)

      burst_start_time_ = current_time - 1000000*g_*log(g_rand);
      burst_end_time_ = burst_start_time_ - 1000000*b_*log(b_rand);
      
      return false;
    } 
    else // In the burst outage
    {
      // In B State, send packet on to bit error model
      return sber_model->CheckForErrors(buf, length); 
    }
  } 
}

//============================================================================
void SBURSTModel::SetFeature(const std::string& name,
                           const std::string& value)
{
  if (name == "G")
  {
    g_ = atof(value.c_str());

    LogC(kClassName, __func__, 
            "Setting Median time spent in G State to %f\n", g_);
  } 
  else if (name == "B")
  {
    b_ = atof(value.c_str());

    LogC(kClassName, __func__, 
            "Setting Median time spent in B State to %f\n", b_);
  }
  else if (name == "BER")
  {
    ber_ = atof(value.c_str());
    sber_model->SetFeature(name, value);

    if (ber_ >= 1.0)
    {
      log_arg_ = 0.0;
    }
    else
    {
      log_arg_ = log(1.0 - ber_);
    }

    LogC(kClassName, __func__, "Setting BER to %f\n", ber_);
  }
  else
  {
    LogW(kClassName, __func__, "Invalid %s model feature: %s\n",
         name_.c_str(), name.c_str());
  }
}

//============================================================================
std::string SBURSTModel::GetFeature(const std::string& name)
{
  if (name == "B")
  {
      return StringUtils::ToString(b_);
  }
  else if (name == "G")
  {
      return StringUtils::ToString(g_);
  }
  else if (name == "BER")
  {
      return StringUtils::ToString(ber_);
  }

  return "fail";
}

//============================================================================
string SBURSTModel::FeaturesToString() const
{
    string  res_str = StringUtils::FormatString(256,
        "G=%f B=%f BER=%f", g_, b_, ber_);
    return res_str;
}
