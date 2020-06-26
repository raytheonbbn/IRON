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

#include "error_model_sper.h"
#include "log.h"
#include "string_utils.h"

#include <string>

#include <cstdlib>
#include <cmath>

namespace
{
  /// Class name for logging.
  const char*  kClassName = "SPERModel";
}

using ::iron::StringUtils;
using ::std::string;

//============================================================================
SPERModel::SPERModel()
    : per_(0.0),
      per_equiv_(0)
{
  name_ = ERR_MODEL_PACKET;

  SetFeature("PER", "0.0");
}

//============================================================================
SPERModel::~SPERModel()
{
  // Nothing to destroy.
}

//============================================================================
bool SPERModel::CheckForErrors(const char* buf, unsigned int length)
{
  // Packet Error Rates are not a function of the packet contents or length.
  int flip = rand();

  LogD(kClassName, __func__, "Testing flip of %d against %d\n", flip,
       perEquiv);

  if (flip < per_equiv_)
  {
    return true;
  }
  else
  {
    return false;
  }
}

//============================================================================
void SPERModel::SetFeature(const std::string& name,
                           const std::string& value)
{
  if (name == "PER")
  {
    per_ = atof(value.c_str());

    if (per_ < 0.0)
    {
      per_ = 0.0;
    }
    else if (per_ > 1.0)
    {
      per_ = 1.0;
    }

    per_equiv_ = (int)(per_ * RAND_MAX);

    LogC(kClassName, __func__, "Setting PER to %f\n", per_);
  }
  else
  {
    LogW(kClassName, __func__, "Invalid %s model feature: %s\n",
         name_.c_str(), name.c_str());
  }
}

//============================================================================
std::string SPERModel::GetFeature(const std::string& name)
{
  if (name == "PER")
  {
    return StringUtils::ToString(per_);
  }

  return "fail";
}

//============================================================================
string SPERModel::FeaturesToString() const
{
  string  res_str = StringUtils::FormatString(256, "PER=%f", per_);

  return res_str;
}
