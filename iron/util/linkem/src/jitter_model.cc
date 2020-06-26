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

#include "jitter_model.h"
#include "jitter_model_dmm.h"
#include "jitter_model_gmm.h"
#include "log.h"
#include "string_utils.h"

using ::iron::StringUtils;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char* kClassName = "JitterModel";
}

//============================================================================
JitterModel* JitterModel::Create(const string& type)
{
  JitterModel*  jm = NULL;

  if (type == JITTER_MODEL_GMM)
  {
    jm = new (std::nothrow) JitterModelGMM();
  }
  else if (type == JITTER_MODEL_DMM)
  {
    jm = new (std::nothrow) JitterModelDMM();
  }
  else if (type == JITTER_MODEL_NONE)
  {
    jm = NULL;
  }
  else
  {
    LogW(kClassName, __func__, "Unsupported Jitter Model type: %s\n",
         type.c_str());

    jm = NULL;
  }

  return jm;
}

//============================================================================
JitterModel::JitterModel()
    : name_()
{
}

//============================================================================
JitterModel::~JitterModel()
{
  // Nothing to destroy.
}

//============================================================================
string JitterModel::ToString() const
{
  string  ret_str;
  ret_str.append(StringUtils::FormatString(256, "J=%s", name_.c_str()));

  string  features_str = FeaturesToString();

  if (!features_str.empty())
  {
    ret_str.append(";");
    ret_str.append(features_str);
  }

  return ret_str;
}
