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

/// \brief The IRON Random Number Generator source file.
///
/// Provides the IRON software with a Random Number Generator capability.

#include "rng.h"

#include "log.h"
#include "unused.h"

#include <cerrno>
#include <cstring>
#include <inttypes.h>


using ::iron::RNG;
using ::iron::Log;
using ::std::string;

namespace
{
  const char*  UNUSED(kClassName) = "RNG";
}

//============================================================================
RNG::RNG()
    : state_array_(), state_info_(), seed_(0)
{
  // Initialize the RNG with a number based off of a very high accuracy time
  // value.
  struct timespec  curr_time = { 0, 0 };

  if (clock_gettime(CLOCK_REALTIME, &curr_time) != 0)
  {
    LogE(kClassName, __func__, "Error in clock_gettime(): %s\n",
         strerror(errno));
  }

  InitRNG(static_cast<uint32_t>(curr_time.tv_nsec));
}

//============================================================================
RNG::RNG(uint32_t seed)
    : state_array_(), state_info_(), seed_(seed)
{
  InitRNG(seed);
}

//============================================================================
void RNG::InitRNG(uint32_t seed)
{
  // Store the seed value.
  seed_ = seed;

  // Initialize the RNG with the state array size and the seed.
  if (initstate_r(seed_, state_array_, sizeof(state_array_),
                  &state_info_) != 0)
  {
    LogE(kClassName, __func__, "Error in initstate_r(): %s\n",
         strerror(errno));
  }
}

//============================================================================
RNG::~RNG()
{
}

//============================================================================
bool RNG::SetSeed(uint32_t seed)
{
  // Store the seed value.
  seed_ = seed;

  if (srandom_r(seed_, &state_info_) != 0)
  {
    LogE(kClassName, __func__, "Error in srandom_r(): %s\n", strerror(errno));
    return false;
  }

  return true;
}

//============================================================================
string RNG::ToString()
{
  char  ret_str[120];

  snprintf(ret_str, sizeof(ret_str),
           "RNG started with seed of %" PRIu32", maximum value is %" PRIu32
           ".\n", seed_, static_cast<uint32_t>(RAND_MAX));

  return ret_str;
}

//============================================================================
int32_t RNG::GetInt(int32_t upper)
{
  // Validate upper.
  if ((upper < 1) || (upper > RAND_MAX))
  {
    LogE(kClassName, __func__, "Upper value %" PRId32 " is invalid.\n",
         upper);
    return -1;
  }

  // Get a random number.
  int32_t  rand_num = GetRand();

  if (rand_num < 0)
  {
    return -1;
  }

  // Avoid potential int32_t overflow when adding 1 to upper.
  if (upper == RAND_MAX)
  {
    return rand_num;
  }

  return(rand_num % (upper + 1));
}

//============================================================================
float RNG::GetFloat(float upper)
{
  // Validate upper.
  if (upper < 0.000001f)
  {
    LogE(kClassName, __func__, "Upper value %f is invalid.\n",
         static_cast<double>(upper));
    return -1.0f;
  }

  // Get a random number.
  int32_t  rand_num = GetRand();

  if (rand_num < 0)
  {
    return -1.0f;
  }

  return(upper * (static_cast<float>(rand_num) /
                  static_cast<float>(RAND_MAX)));
}

//============================================================================
double RNG::GetDouble(double upper)
{
  // Validate upper.
  if (upper < 0.000001)
  {
    LogE(kClassName, __func__, "Upper value %f is invalid.\n", upper);
    return -1.0;
  }

  // Get a random number.
  int32_t  rand_num = GetRand();

  if (rand_num < 0)
  {
    return -1.0;
  }

  return(upper * (static_cast<double>(rand_num) /
                  static_cast<double>(RAND_MAX)));
}

//============================================================================
bool RNG::GetByteSequence(uint8_t* dst, size_t bytes)
{
  // Validate the parameters.
  if ((dst == NULL) || (bytes < 0))
  {
    LogE(kClassName, __func__, "Invalid parameter, dst = %p, bytes = %zd.\n",
         dst, bytes);
    return false;
  }

  // Create the random byte sequence.
  int32_t  rand_num = 0;

  for (size_t i = 0; i < bytes; ++i)
  {
    if (random_r(&state_info_, &rand_num) != 0)
    {
      LogE(kClassName, __func__, "Error in random_r(): %s\n", strerror(errno));
      return false;
    }

    // Of the random 31 bits generated, the upper bits are more random than
    // the lower bits.  Use the third byte of the random number to place in
    // the byte sequence.  Using the third byte was verified to generate good
    // random bytes in a separate test program.
    dst[i] = static_cast<uint8_t>((rand_num >> 16) & 0xff);
  }

  return true;
}

//============================================================================
int32_t RNG::GetRand()
{
  int32_t  rv = 0;

  if (random_r(&state_info_, &rv) != 0)
  {
    LogE(kClassName, __func__, "Error in random_r(): %s\n", strerror(errno));
    return -1;
  }

  return rv;
}
