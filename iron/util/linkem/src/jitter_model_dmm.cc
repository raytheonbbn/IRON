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

#include "jitter_model_dmm.h"
#include "log.h"

#include <cmath>
#include <cstdlib>

using ::std::string;

#define TWOPI (8.0 * atan(1.0))

namespace
{
  /// Class name for logging.
  const char* kClassName = "JitterModelDMM";
}

//============================================================================
JitterModelDMM::JitterModelDMM()
{
  name_ = "DMM";

  // Note: probabilities must sum to 1 or the element selection loop
  // can go past the end of the array.
  dme_[0].prob = 0.32;
  dme_[0].mu   = 0.89255;
  dme_[1].prob = 0.49;
  dme_[1].mu   = 1.10355;
  dme_[2].prob = 0.19;
  dme_[2].mu   = 1.35455;
}

//============================================================================
JitterModelDMM::~JitterModelDMM()
{
  // Nothing to destroy.
}

//============================================================================
unsigned long long JitterModelDMM::GetJitterInNsec()
{
  // Make a random draw to figure out which element to use.
  double  urv = (double)rand() / (double)(RAND_MAX);

  int     index = 0;
  double  sum   = dme_[index].prob;

  while (urv > sum)
  {
    index++;
    sum += dme_[index].prob;
  }

  // The computed jitter is in milliseconds. We need the return value to be in
  // nanoseconds.
  return (unsigned long long)dme_[index].mu * 1000000;
}

//============================================================================
bool JitterModelDMM::SetFeature(const string& name, const string& value)
{
  // There are no features for this model.

  LogW(kClassName, __func__, "Jitter Model %s has no configurable "
       "features.\n", name_.c_str());

  return false;
}

//===========================================================================
string JitterModelDMM::GetFeature(const std::string& name)
{
  // There are no features for this model.

  LogW(kClassName, __func__, "Jitter Model %s has no configurable "
       "features.\n", name_.c_str());

  return "";
}

//============================================================================
string JitterModelDMM::FeaturesToString() const
{
  // There are no features for this model.
  return "";
}
