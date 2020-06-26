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

#include "high_resolution_clock.h"
#include "log.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>

namespace
{
  /// Class name for logging.
  const char*  kClassName = "HighResolutionClock";

  /// The buffer size for reading the CPU information.
  size_t  kBufSize = 4096;
}

//============================================================================
HighResolutionClock::HighResolutionClock()
  : ns_per_tick_(0.0),
    offset_(0)
{
}

//============================================================================
HighResolutionClock::~HighResolutionClock()
{
  // Nothing to destroy.
}

//============================================================================
bool HighResolutionClock::Initialize()
{
#ifdef CONFIG_X86_TSC
  int    fd  = -1;
  int    len = 0;
  char   buf[kBufSize];
  char*  pos = NULL;

  // Read the CPU frequency from /proc/cpuinfo
  if ((fd = open("/proc/cpuinfo", O_RDONLY)) < 0)
  {
    LogF(kClassName, __func__, "Error opening /proc/cpuinfo: %s\n",
         strerror(errno));

    return false;
  }

  if ((len = read(fd, buf, kBufSize)) < 0)
  {
    close(fd);
    LogF(kClassName, __func__, "read error: %s\n", strerror(errno));

    return false;
  }

  pos = strstr(buf, "cpu MHz");
  do
  {
    pos++;
  } while (*pos != ':');
  pos++;

  double  frequency = atof(pos);
  close(fd);

  // Compute the period. Loop until we get 3 consecutive periods that are the
  // same to within a small error.
  const unsigned long long  error          = 2000000;
  const int                 max_iterations = 20;
  unsigned long long        period;
  unsigned long long        period1 = error * 2;
  unsigned long long        period2 = 0;
  unsigned long long        period3 = 0;

  int  count;
  for (count = 0; count < max_iterations; count++)
  {
    unsigned long long  start_tsc;
    unsigned long long  end_tsc;
    unsigned long long  diff1;
    unsigned long long  diff2;
    unsigned long long  diff3;
    unsigned long long  start_time;
    unsigned long long  end_time;

    struct timeval sleep = {1, 0};

    start_time = GetCalibrationTimeInNsec();
    start_tsc  = GetTickCount();

    select(0, NULL, NULL, NULL, &sleep);

    end_time = GetCalibrationTimeInNsec();
    end_tsc  = GetTickCount();

    period3 = (end_tsc - start_tsc) * 1000000000 / (end_time - start_time);

    if (period1 > period2)
    {
      diff1 = period1 - period2;
    }
    else
    {
      diff1 = period2 - period1;
    }

    if (period2 > period3)
    {
      diff2 = period2 - period3;
    }
    else
    {
      diff2 = period3 - period2;
    }

    if (period3 > period1)
    {
      diff3 = period3 - period1;
    }
    else
    {
      diff3 = period1 - period3;
    }

    if (diff1 <= error && diff2 <= error && diff3 <= error)
    {
      break;
    }

    period1 = period2;
    period2 = period3;
  }

  if (count == max_iterations)
  {
    LogF(kClassName, __func__, "clock_gettime or Pentium TSC not stable "
         "enough for accurate high-resolution timing.\n");
    return false;
  }

  // Set the period to the average period measured.
  period = (period1 + period2 + period3) / 3;

  if (period < 10000000)
  {
    LogF(kClassName, __func__, "Pentium TSC seems to be broken on this "
         "CPU.\n");
    return false;
  }

  frequency = period/1000000.0;

  LogC(kClassName, __func__, "Calibrated Pentium timestamp counter: %f "
       "MHz.\n", frequency);

  ns_per_tick_ = 1000.0 / frequency;

  LogC(kClassName, __func__, "High resolution clock set to frequency=%f, "
       "ns per tick=%f\n", frequency, ns_per_tick_);

  offset_ = GetTickCount();

  return true;
#else
  return true;
#endif
}
